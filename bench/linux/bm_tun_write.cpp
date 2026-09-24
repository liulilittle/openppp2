// bm_tun_write — isolated Linux TUN write() service microbenchmark.
//
// This deliberately does not use the production TapLinux wrapper: the measured
// loop is only write(TUN) over a packet-size mix observed in the c1 datapath.

#if !defined(__linux__)
#error "bm_tun_write is Linux-only"
#endif

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
constexpr size_t kCyclePackets = 125;
constexpr size_t kLargePackets = 97; // 77.6% of the measured packet stream.
constexpr size_t kSmallPackets = 28; // 22.4% of the measured packet stream.
constexpr uint16_t kMinSmallPacket = 20;
constexpr uint16_t kMaxSmallPacket = 128;
constexpr uint16_t kMinLargePacket = 1401;
constexpr uint16_t kMaxLargePacket = 1500;

struct Options {
    double duration_seconds = 10.0;
    double warmup_seconds = 1.0;
    uint64_t seed = 1;
    std::string json_out;
    bool self_test = false;
};

struct Packet {
    std::vector<uint8_t> bytes;
    bool large = false;
};

struct Counters {
    uint64_t attempted = 0;
    uint64_t completed = 0;
    uint64_t completed_bytes = 0;
    uint64_t eagain = 0;
    uint64_t eintr_retries = 0;
    uint64_t short_write = 0;
    uint64_t other_errors = 0;
    uint64_t large_completed = 0;
    uint64_t small_completed = 0;
};

struct Measurement {
    Counters counters;
    uint64_t wall_ns = 0;
    uint64_t thread_cpu_ns = 0;
    uint64_t process_cpu_ns = 0;
    std::vector<uint64_t> latency_ns;
};

uint64_t clock_ns(clockid_t clock_id) {
    timespec value{};
    if (clock_gettime(clock_id, &value) != 0) {
        throw std::runtime_error("clock_gettime failed: " + std::string(std::strerror(errno)));
    }
    return static_cast<uint64_t>(value.tv_sec) * 1000000000ULL + static_cast<uint64_t>(value.tv_nsec);
}

uint16_t ipv4_checksum(const uint8_t* data, size_t size) {
    uint32_t sum = 0;
    for (size_t i = 0; i < size; i += 2) {
        sum += static_cast<uint16_t>(data[i] << 8U | data[i + 1]);
    }
    while (sum >> 16U) {
        sum = (sum & 0xffffU) + (sum >> 16U);
    }
    return static_cast<uint16_t>(~sum);
}

Packet make_ipv4_packet(uint16_t size, bool large, uint32_t ordinal) {
    Packet packet;
    packet.bytes.resize(size);
    packet.large = large;
    uint8_t* const data = packet.bytes.data();
    data[0] = 0x45; // IPv4, five 32-bit header words.
    data[1] = 0;
    const uint16_t total_length = htons(size);
    std::memcpy(data + 2, &total_length, sizeof(total_length));
    const uint16_t identification = htons(static_cast<uint16_t>(ordinal));
    std::memcpy(data + 4, &identification, sizeof(identification));
    data[6] = 0x40; // Don't fragment.
    data[7] = 0;
    data[8] = 64;
    data[9] = IPPROTO_UDP;
    data[10] = 0;
    data[11] = 0;
    const uint32_t source = htonl(0xc6120001U);      // 198.18.0.1
    const uint32_t destination = htonl(0xc6120002U); // 198.18.0.2
    std::memcpy(data + 12, &source, sizeof(source));
    std::memcpy(data + 16, &destination, sizeof(destination));
    for (size_t i = 20; i < packet.bytes.size(); ++i) {
        data[i] = static_cast<uint8_t>((i * 131U + ordinal * 17U) & 0xffU);
    }
    const uint16_t checksum = htons(ipv4_checksum(data, 20));
    std::memcpy(data + 10, &checksum, sizeof(checksum));
    return packet;
}

std::vector<Packet> make_packet_cycle(uint64_t seed) {
    std::mt19937_64 random(seed);
    std::uniform_int_distribution<uint16_t> small_size(kMinSmallPacket, kMaxSmallPacket);
    std::uniform_int_distribution<uint16_t> large_size(kMinLargePacket, kMaxLargePacket);
    std::vector<Packet> packets;
    packets.reserve(kCyclePackets);
    for (size_t i = 0; i < kLargePackets; ++i) {
        packets.push_back(make_ipv4_packet(large_size(random), true, static_cast<uint32_t>(i)));
    }
    for (size_t i = 0; i < kSmallPackets; ++i) {
        packets.push_back(make_ipv4_packet(small_size(random), false, static_cast<uint32_t>(kLargePackets + i)));
    }
    std::shuffle(packets.begin(), packets.end(), random);
    return packets;
}

bool valid_ipv4_packet(const Packet& packet) {
    if (packet.bytes.size() < 20 || packet.bytes[0] != 0x45) {
        return false;
    }
    uint16_t total_length = 0;
    std::memcpy(&total_length, packet.bytes.data() + 2, sizeof(total_length));
    if (ntohs(total_length) != packet.bytes.size()) {
        return false;
    }
    return ipv4_checksum(packet.bytes.data(), 20) == 0;
}

void verify_packet_cycle(const std::vector<Packet>& packets) {
    if (packets.size() != kCyclePackets) {
        throw std::runtime_error("packet cycle has the wrong length");
    }
    size_t large = 0;
    size_t small = 0;
    for (const Packet& packet : packets) {
        if (!valid_ipv4_packet(packet)) {
            throw std::runtime_error("packet cycle contains an invalid IPv4 packet");
        }
        if (packet.large) {
            ++large;
            if (packet.bytes.size() < kMinLargePacket || packet.bytes.size() > kMaxLargePacket) {
                throw std::runtime_error("large packet is outside the expected range");
            }
        } else {
            ++small;
            if (packet.bytes.size() < kMinSmallPacket || packet.bytes.size() > kMaxSmallPacket) {
                throw std::runtime_error("small packet is outside the expected range");
            }
        }
    }
    if (large != kLargePackets || small != kSmallPackets) {
        throw std::runtime_error("packet cycle bucket counts do not match the measured distribution");
    }
}

class TunDevice {
public:
    TunDevice() = default;
    TunDevice(const TunDevice&) = delete;
    TunDevice& operator=(const TunDevice&) = delete;

    ~TunDevice() {
        if (fd_ >= 0) {
            close(fd_);
        }
    }

    void open_and_set_up() {
        fd_ = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (fd_ < 0) {
            throw std::runtime_error("open /dev/net/tun failed (requires TUN permission): " + std::string(std::strerror(errno)));
        }

        ifreq ifr{};
        const unsigned int suffix = static_cast<unsigned int>(getpid() % 100000U);
        std::snprintf(ifr.ifr_name, IFNAMSIZ, "pmtun%u", suffix);
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        if (ioctl(fd_, TUNSETIFF, &ifr) != 0) {
            throw std::runtime_error("TUNSETIFF failed (requires CAP_NET_ADMIN): " + std::string(std::strerror(errno)));
        }
        name_ = ifr.ifr_name;

        const int control_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (control_fd < 0) {
            throw std::runtime_error("control socket failed: " + std::string(std::strerror(errno)));
        }
        ifreq flags{};
        std::strncpy(flags.ifr_name, name_.c_str(), IFNAMSIZ - 1);
        if (ioctl(control_fd, SIOCGIFFLAGS, &flags) != 0) {
            const std::string error = std::strerror(errno);
            close(control_fd);
            throw std::runtime_error("SIOCGIFFLAGS failed: " + error);
        }
        flags.ifr_flags |= IFF_UP;
        if (ioctl(control_fd, SIOCSIFFLAGS, &flags) != 0) {
            const std::string error = std::strerror(errno);
            close(control_fd);
            throw std::runtime_error("SIOCSIFFLAGS failed (requires CAP_NET_ADMIN): " + error);
        }
        close(control_fd);
    }

    int fd() const { return fd_; }
    const std::string& name() const { return name_; }

private:
    int fd_ = -1;
    std::string name_;
};

void write_one(int fd, const Packet& packet, Counters& counters, std::vector<uint64_t>* latency_ns) {
    ++counters.attempted;
    const uint64_t started = latency_ns != nullptr ? clock_ns(CLOCK_MONOTONIC_RAW) : 0;
    ssize_t result = 0;
    do {
        result = write(fd, packet.bytes.data(), packet.bytes.size());
        if (result < 0 && errno == EINTR) {
            ++counters.eintr_retries;
        }
    } while (result < 0 && errno == EINTR);
    if (latency_ns != nullptr) {
        latency_ns->push_back(clock_ns(CLOCK_MONOTONIC_RAW) - started);
    }

    if (result == static_cast<ssize_t>(packet.bytes.size())) {
        ++counters.completed;
        counters.completed_bytes += packet.bytes.size();
        if (packet.large) {
            ++counters.large_completed;
        } else {
            ++counters.small_completed;
        }
    } else if (result >= 0) {
        ++counters.short_write;
    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        ++counters.eagain;
    } else {
        ++counters.other_errors;
    }
}

void warm_up(int fd, const std::vector<Packet>& packets, double seconds) {
    const uint64_t deadline = clock_ns(CLOCK_MONOTONIC_RAW) + static_cast<uint64_t>(seconds * 1000000000.0);
    Counters discarded;
    size_t index = 0;
    while (clock_ns(CLOCK_MONOTONIC_RAW) < deadline) {
        write_one(fd, packets[index], discarded, nullptr);
        index = (index + 1) % packets.size();
    }
}

Measurement measure(int fd, const std::vector<Packet>& packets, double seconds) {
    Measurement measurement;
    measurement.latency_ns.reserve(1024 * 1024);
    const uint64_t wall_started = clock_ns(CLOCK_MONOTONIC_RAW);
    const uint64_t thread_started = clock_ns(CLOCK_THREAD_CPUTIME_ID);
    const uint64_t process_started = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
    const uint64_t deadline = wall_started + static_cast<uint64_t>(seconds * 1000000000.0);
    size_t index = 0;
    while (clock_ns(CLOCK_MONOTONIC_RAW) < deadline) {
        write_one(fd, packets[index], measurement.counters, &measurement.latency_ns);
        index = (index + 1) % packets.size();
    }
    measurement.wall_ns = clock_ns(CLOCK_MONOTONIC_RAW) - wall_started;
    measurement.thread_cpu_ns = clock_ns(CLOCK_THREAD_CPUTIME_ID) - thread_started;
    measurement.process_cpu_ns = clock_ns(CLOCK_PROCESS_CPUTIME_ID) - process_started;
    return measurement;
}

uint64_t percentile(std::vector<uint64_t> values, unsigned int numerator) {
    if (values.empty()) {
        return 0;
    }
    const size_t index = (values.size() * numerator + 99U) / 100U - 1U;
    std::nth_element(values.begin(), values.begin() + static_cast<std::ptrdiff_t>(index), values.end());
    return values[index];
}

uint64_t max_latency(const std::vector<uint64_t>& values) {
    return values.empty() ? 0 : *std::max_element(values.begin(), values.end());
}

double mean_latency(const std::vector<uint64_t>& values) {
    if (values.empty()) {
        return 0.0;
    }
    long double sum = 0;
    for (const uint64_t value : values) {
        sum += value;
    }
    return static_cast<double>(sum / values.size());
}

std::string render_json(const Measurement& measurement, uint64_t seed, const std::string& interface_name) {
    const double seconds = static_cast<double>(measurement.wall_ns) / 1000000000.0;
    const Counters& c = measurement.counters;
    const double writes_per_second = seconds > 0 ? c.completed / seconds : 0.0;
    const double bytes_per_second = seconds > 0 ? c.completed_bytes / seconds : 0.0;
    const double writer_utilization = measurement.wall_ns > 0
        ? static_cast<double>(measurement.thread_cpu_ns) / measurement.wall_ns
        : 0.0;
    const double cpu_ns_per_write = c.completed > 0
        ? static_cast<double>(measurement.thread_cpu_ns) / c.completed
        : 0.0;

    std::string json;
    auto field = [&](std::string_view name, auto value, bool comma = true) {
        json += "  \"" + std::string(name) + "\": " + std::to_string(value) + (comma ? ",\n" : "\n");
    };
    json += "{\n";
    json += "  \"interface\": \"" + interface_name + "\",\n";
    field("seed", seed);
    field("cycle_packets", kCyclePackets);
    json += "  \"packet_distribution\": {\n";
    field("large_1401_1500", c.large_completed);
    field("small_20_128", c.small_completed, false);
    json += "  },\n";
    json += "  \"writes\": {\n";
    field("attempted", c.attempted);
    field("completed", c.completed);
    field("completed_per_second", writes_per_second);
    field("completed_bytes", c.completed_bytes);
    field("completed_bytes_per_second", bytes_per_second, false);
    json += "  },\n";
    json += "  \"latency_ns\": {\n";
    field("samples", measurement.latency_ns.size());
    field("mean", mean_latency(measurement.latency_ns));
    field("p50", percentile(measurement.latency_ns, 50));
    field("p95", percentile(measurement.latency_ns, 95));
    field("p99", percentile(measurement.latency_ns, 99));
    field("max", max_latency(measurement.latency_ns), false);
    json += "  },\n";
    json += "  \"cpu\": {\n";
    field("wall_ns", measurement.wall_ns);
    field("thread_cpu_ns", measurement.thread_cpu_ns);
    field("process_cpu_ns", measurement.process_cpu_ns);
    field("writer_utilization", writer_utilization);
    field("thread_cpu_ns_per_completed_write", cpu_ns_per_write, false);
    json += "  },\n";
    json += "  \"errors\": {\n";
    field("eagain", c.eagain);
    field("eintr_retries", c.eintr_retries);
    field("short_write", c.short_write);
    field("other", c.other_errors, false);
    json += "  }\n";
    json += "}\n";
    return json;
}

std::string option_value(int& index, int argc, char** argv, std::string_view name) {
    const std::string current = argv[index];
    const std::string prefix = std::string(name) + "=";
    if (current.rfind(prefix, 0) == 0) {
        return current.substr(prefix.size());
    }
    if (current == name && index + 1 < argc) {
        return argv[++index];
    }
    throw std::runtime_error("missing value for " + std::string(name));
}

Options parse_options(int argc, char** argv) {
    Options options;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument = argv[index];
        if (argument == "--self-test") {
            options.self_test = true;
        } else if (argument.rfind("--duration-seconds", 0) == 0) {
            options.duration_seconds = std::stod(option_value(index, argc, argv, "--duration-seconds"));
        } else if (argument.rfind("--warmup-seconds", 0) == 0) {
            options.warmup_seconds = std::stod(option_value(index, argc, argv, "--warmup-seconds"));
        } else if (argument.rfind("--seed", 0) == 0) {
            options.seed = std::stoull(option_value(index, argc, argv, "--seed"));
        } else if (argument.rfind("--json-out", 0) == 0) {
            options.json_out = option_value(index, argc, argv, "--json-out");
        } else if (argument == "--help") {
            std::cout << "usage: bm_tun_write [--duration-seconds N] [--warmup-seconds N] [--seed N] [--json-out PATH] [--self-test]\n";
            std::exit(0);
        } else {
            throw std::runtime_error("unknown option: " + std::string(argument));
        }
    }
    if (options.duration_seconds <= 0 || options.warmup_seconds < 0) {
        throw std::runtime_error("duration must be positive and warmup must be non-negative");
    }
    return options;
}
} // namespace

int main(int argc, char** argv) {
    try {
        const Options options = parse_options(argc, argv);
        const std::vector<Packet> packets = make_packet_cycle(options.seed);
        verify_packet_cycle(packets);
        if (options.self_test) {
            std::cout << "{\"self_test\":\"pass\",\"cycle_packets\":125,\"large_1401_1500\":97,\"small_20_128\":28}\n";
            return 0;
        }

        TunDevice device;
        device.open_and_set_up();
        warm_up(device.fd(), packets, options.warmup_seconds);
        const Measurement measurement = measure(device.fd(), packets, options.duration_seconds);
        const std::string json = render_json(measurement, options.seed, device.name());
        std::cout << json;
        if (!options.json_out.empty()) {
            std::ofstream output(options.json_out);
            if (!output) {
                throw std::runtime_error("cannot open JSON output: " + options.json_out);
            }
            output << json;
            if (!output) {
                throw std::runtime_error("cannot write JSON output: " + options.json_out);
            }
        }
        return measurement.counters.other_errors == 0 ? 0 : 2;
    } catch (const std::exception& error) {
        std::cerr << "bm_tun_write: " << error.what() << "\n";
        return 1;
    }
}

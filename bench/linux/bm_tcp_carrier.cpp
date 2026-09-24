// bm_tcp_carrier — isolated Linux TCP carrier microbenchmark.
// It intentionally uses only POSIX sockets and does not depend on PPP or XTCP.
#if !defined(__linux__)
#error "bm_tcp_carrier is Linux-only"
#endif

#include <arpa/inet.h>
#include <endian.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

namespace {
constexpr size_t kRecordBytes = 5152;
constexpr uint64_t kSelfTestRecords = 32;
constexpr size_t kAckBytes = sizeof(uint64_t);

struct Options {
    enum class Mode { SelfTest, Listen, Connect } mode = Mode::SelfTest;
    std::string address;
    uint16_t port = 0;
    double duration_seconds = 1.0;
    double warmup_seconds = 0.0;
};

struct SocketOptions {
    int sndbuf = 0;
    int rcvbuf = 0;
    int nodelay = 0;
    int keepalive = 0;
};

struct Counters {
    uint64_t bytes = 0;
    uint64_t records = 0;
    uint64_t send_calls = 0;
    uint64_t recv_calls = 0;
    uint64_t partial_sends = 0;
    uint64_t eintr_retries = 0;
    uint64_t errors = 0;
};

struct Measurement {
    Counters counters;
    uint64_t wall_ns = 0;
    uint64_t thread_cpu_ns = 0;
    uint64_t process_cpu_ns = 0;
    uint64_t warmup_bytes = 0;
    uint64_t peer_confirmed_bytes = 0;
    bool clean_shutdown = false;
    SocketOptions socket_options;
};

uint64_t clock_ns(clockid_t id) {
    timespec value{};
    if (clock_gettime(id, &value) != 0) {
        throw std::runtime_error("clock_gettime: " + std::string(std::strerror(errno)));
    }
    return static_cast<uint64_t>(value.tv_sec) * 1000000000ULL + static_cast<uint64_t>(value.tv_nsec);
}

class Fd {
public:
    explicit Fd(int fd = -1) : fd_(fd) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : fd_(other.release()) {}
    Fd& operator=(Fd&& other) noexcept { if (this != &other) reset(other.release()); return *this; }
    ~Fd() { reset(); }
    int get() const { return fd_; }
    int release() { int result = fd_; fd_ = -1; return result; }
    void reset(int fd = -1) { if (fd_ >= 0) close(fd_); fd_ = fd; }
private:
    int fd_;
};

void fail_errno(const char* operation) { throw std::runtime_error(std::string(operation) + ": " + std::strerror(errno)); }

uint16_t parse_port(const std::string& text) {
    const unsigned long value = std::stoul(text);
    if (value == 0 || value > 65535) throw std::runtime_error("port must be in 1..65535");
    return static_cast<uint16_t>(value);
}

std::string option_value(int& index, int argc, char** argv, std::string_view option) {
    const std::string current(argv[index]);
    const std::string prefix = std::string(option) + "=";
    if (current.rfind(prefix, 0) == 0) return current.substr(prefix.size());
    if (current == option && index + 1 < argc) return argv[++index];
    throw std::runtime_error("missing value for " + std::string(option));
}

Options parse_options(int argc, char** argv) {
    Options options;
    bool mode_seen = false;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--self-test") {
            if (mode_seen) throw std::runtime_error("only one mode may be selected");
            mode_seen = true; options.mode = Options::Mode::SelfTest;
        } else if (argument == "--listen" || argument.rfind("--listen=", 0) == 0) {
            if (mode_seen) throw std::runtime_error("only one mode may be selected");
            mode_seen = true; options.mode = Options::Mode::Listen; options.address = option_value(index, argc, argv, "--listen");
        } else if (argument == "--connect" || argument.rfind("--connect=", 0) == 0) {
            if (mode_seen) throw std::runtime_error("only one mode may be selected");
            mode_seen = true; options.mode = Options::Mode::Connect; options.address = option_value(index, argc, argv, "--connect");
        } else if (argument == "--port" || argument.rfind("--port=", 0) == 0) {
            options.port = parse_port(option_value(index, argc, argv, "--port"));
        } else if (argument == "--duration" || argument.rfind("--duration=", 0) == 0) {
            options.duration_seconds = std::stod(option_value(index, argc, argv, "--duration"));
        } else if (argument == "--warmup" || argument.rfind("--warmup=", 0) == 0) {
            options.warmup_seconds = std::stod(option_value(index, argc, argv, "--warmup"));
        } else if (argument == "--help") {
            std::cout << "usage: bm_tcp_carrier --self-test | --listen IP --port P | --connect IP --port P [--duration N] [--warmup N]\n";
            std::exit(0);
        } else {
            throw std::runtime_error("unknown option: " + std::string(argument));
        }
    }
    if (!mode_seen) throw std::runtime_error("select --self-test, --listen, or --connect");
    if (options.mode != Options::Mode::SelfTest && options.port == 0) throw std::runtime_error("--port is required");
    if (options.duration_seconds <= 0 || options.warmup_seconds < 0) throw std::runtime_error("duration must be positive and warmup non-negative");
    return options;
}

sockaddr_in make_address(const std::string& address, uint16_t port) {
    sockaddr_in result{};
    result.sin_family = AF_INET;
    result.sin_port = htons(port);
    if (inet_pton(AF_INET, address.c_str(), &result.sin_addr) != 1) throw std::runtime_error("address must be an IPv4 literal: " + address);
    return result;
}

SocketOptions read_socket_options(int fd) {
    SocketOptions result;
    socklen_t length = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &result.sndbuf, &length) != 0) fail_errno("getsockopt(SO_SNDBUF)");
    length = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &result.rcvbuf, &length) != 0) fail_errno("getsockopt(SO_RCVBUF)");
    length = sizeof(int);
    if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &result.nodelay, &length) != 0) fail_errno("getsockopt(TCP_NODELAY)");
    length = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &result.keepalive, &length) != 0) fail_errno("getsockopt(SO_KEEPALIVE)");
    return result;
}

void enable_nodelay(int fd) {
    const int enabled = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) != 0) fail_errno("setsockopt(TCP_NODELAY)");
    if (read_socket_options(fd).nodelay != 1) throw std::runtime_error("TCP_NODELAY readback is not enabled");
}

Fd make_listener(const std::string& address, uint16_t port) {
    Fd listener(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (listener.get() < 0) fail_errno("socket");
    const sockaddr_in endpoint = make_address(address, port);
    if (bind(listener.get(), reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint)) != 0) fail_errno("bind");
    if (listen(listener.get(), 1) != 0) fail_errno("listen");
    return listener;
}

Fd accept_one(int listener) {
    while (true) {
        const int accepted = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if (accepted >= 0) return Fd(accepted);
        if (errno == EINTR) continue;
        fail_errno("accept");
    }
}

Fd connect_one(const std::string& address, uint16_t port) {
    Fd connection(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (connection.get() < 0) fail_errno("socket");
    enable_nodelay(connection.get());
    const sockaddr_in endpoint = make_address(address, port);
    while (connect(connection.get(), reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint)) != 0) {
        if (errno == EINTR) continue;
        fail_errno("connect");
    }
    return connection;
}

void send_all(int fd, const void* data, size_t bytes, Counters& counters) {
    const auto* current = static_cast<const uint8_t*>(data);
    size_t remaining = bytes;
    while (remaining != 0) {
        const ssize_t sent = send(fd, current, remaining, MSG_NOSIGNAL);
        ++counters.send_calls;
        if (sent > 0) {
            if (static_cast<size_t>(sent) != remaining) ++counters.partial_sends;
            current += sent; remaining -= static_cast<size_t>(sent);
        } else if (sent < 0 && errno == EINTR) {
            ++counters.eintr_retries;
        } else {
            ++counters.errors;
            fail_errno("send");
        }
    }
}

void receive_all(int fd, void* data, size_t bytes, Counters& counters) {
    auto* current = static_cast<uint8_t*>(data);
    size_t remaining = bytes;
    while (remaining != 0) {
        const ssize_t received = recv(fd, current, remaining, 0);
        ++counters.recv_calls;
        if (received > 0) { current += received; remaining -= static_cast<size_t>(received); }
        else if (received == 0) throw std::runtime_error("unexpected EOF");
        else if (errno == EINTR) ++counters.eintr_retries;
        else { ++counters.errors; fail_errno("recv"); }
    }
}

Measurement drain_server(Fd connection) {
    enable_nodelay(connection.get());
    Measurement result;
    result.socket_options = read_socket_options(connection.get());
    const uint64_t wall_started = clock_ns(CLOCK_MONOTONIC_RAW);
    const uint64_t thread_started = clock_ns(CLOCK_THREAD_CPUTIME_ID);
    const uint64_t process_started = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
    std::array<uint8_t, 64 * 1024> buffer{};
    while (true) {
        const ssize_t received = recv(connection.get(), buffer.data(), buffer.size(), 0);
        ++result.counters.recv_calls;
        if (received > 0) result.counters.bytes += static_cast<uint64_t>(received);
        else if (received == 0) { result.clean_shutdown = true; break; }
        else if (errno == EINTR) ++result.counters.eintr_retries;
        else { ++result.counters.errors; fail_errno("server recv"); }
    }
    result.counters.records = result.counters.bytes / kRecordBytes;
    if (result.counters.bytes % kRecordBytes != 0) throw std::runtime_error("server received a non-record-aligned byte count");
    const uint64_t wire_bytes = htobe64(result.counters.bytes);
    send_all(connection.get(), &wire_bytes, sizeof(wire_bytes), result.counters);
    if (shutdown(connection.get(), SHUT_WR) != 0) fail_errno("server shutdown");
    result.wall_ns = clock_ns(CLOCK_MONOTONIC_RAW) - wall_started;
    result.thread_cpu_ns = clock_ns(CLOCK_THREAD_CPUTIME_ID) - thread_started;
    result.process_cpu_ns = clock_ns(CLOCK_PROCESS_CPUTIME_ID) - process_started;
    return result;
}

Measurement run_client(Fd connection, double duration_seconds, double warmup_seconds, uint64_t exact_records = 0) {
    Measurement result;
    result.socket_options = read_socket_options(connection.get());
    std::array<uint8_t, kRecordBytes> record{};
    for (size_t i = 0; i < record.size(); ++i) record[i] = static_cast<uint8_t>(i);
    Counters discarded;
    const uint64_t warmup_deadline = clock_ns(CLOCK_MONOTONIC_RAW) + static_cast<uint64_t>(warmup_seconds * 1e9);
    while (exact_records == 0 && clock_ns(CLOCK_MONOTONIC_RAW) < warmup_deadline) {
        send_all(connection.get(), record.data(), record.size(), discarded);
        result.warmup_bytes += kRecordBytes;
    }
    const uint64_t wall_started = clock_ns(CLOCK_MONOTONIC_RAW);
    const uint64_t thread_started = clock_ns(CLOCK_THREAD_CPUTIME_ID);
    const uint64_t process_started = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
    const uint64_t deadline = wall_started + static_cast<uint64_t>(duration_seconds * 1e9);
    while ((exact_records != 0 && result.counters.records < exact_records) || (exact_records == 0 && clock_ns(CLOCK_MONOTONIC_RAW) < deadline)) {
        send_all(connection.get(), record.data(), record.size(), result.counters);
        result.counters.bytes += kRecordBytes;
        ++result.counters.records;
    }
    if (shutdown(connection.get(), SHUT_WR) != 0) fail_errno("client shutdown");
    uint64_t wire_bytes = 0;
    receive_all(connection.get(), &wire_bytes, sizeof(wire_bytes), result.counters);
    result.peer_confirmed_bytes = be64toh(wire_bytes);
    uint8_t eof = 0;
    const ssize_t final_read = recv(connection.get(), &eof, sizeof(eof), 0);
    if (final_read == 0) result.clean_shutdown = true;
    else if (final_read < 0) fail_errno("client final recv");
    else throw std::runtime_error("server sent unexpected trailing data");
    result.wall_ns = clock_ns(CLOCK_MONOTONIC_RAW) - wall_started;
    result.thread_cpu_ns = clock_ns(CLOCK_THREAD_CPUTIME_ID) - thread_started;
    result.process_cpu_ns = clock_ns(CLOCK_PROCESS_CPUTIME_ID) - process_started;
    if (result.peer_confirmed_bytes != result.warmup_bytes + result.counters.bytes) throw std::runtime_error("server byte confirmation mismatch");
    return result;
}

std::string json(const char* mode, const Measurement& m, bool self_test) {
    const double seconds = static_cast<double>(m.wall_ns) / 1e9;
    const double bytes_per_second = seconds > 0 ? static_cast<double>(m.counters.bytes) / seconds : 0;
    const double records_per_second = seconds > 0 ? static_cast<double>(m.counters.records) / seconds : 0;
    std::string result = "{\n";
    result += "  \"mode\": \"" + std::string(mode) + "\",\n";
    result += "  \"self_test\": " + std::string(self_test ? "true" : "false") + ",\n";
    result += "  \"record_bytes\": 5152,\n";
    result += "  \"records\": " + std::to_string(m.counters.records) + ",\n";
    result += "  \"bytes\": " + std::to_string(m.counters.bytes) + ",\n";
    result += "  \"warmup_bytes\": " + std::to_string(m.warmup_bytes) + ",\n";
    result += "  \"rates\": {\"bytes_per_second\": " + std::to_string(bytes_per_second) + ", \"records_per_second\": " + std::to_string(records_per_second) + "},\n";
    result += "  \"cpu_clocks_ns\": {\"wall\": " + std::to_string(m.wall_ns) + ", \"thread\": " + std::to_string(m.thread_cpu_ns) + ", \"process\": " + std::to_string(m.process_cpu_ns) + "},\n";
    result += "  \"send_calls\": " + std::to_string(m.counters.send_calls) + ",\n";
    result += "  \"recv_calls\": " + std::to_string(m.counters.recv_calls) + ",\n";
    result += "  \"partial_sends\": " + std::to_string(m.counters.partial_sends) + ",\n";
    result += "  \"errors\": {\"eintr_retries\": " + std::to_string(m.counters.eintr_retries) + ", \"other\": " + std::to_string(m.counters.errors) + "},\n";
    result += "  \"socket_options\": {\"sndbuf\": " + std::to_string(m.socket_options.sndbuf) + ", \"rcvbuf\": " + std::to_string(m.socket_options.rcvbuf) + ", \"tcp_nodelay\": " + std::to_string(m.socket_options.nodelay) + ", \"keepalive\": " + std::to_string(m.socket_options.keepalive) + "},\n";
    result += "  \"peer_confirmed_bytes\": " + std::to_string(m.peer_confirmed_bytes) + ",\n";
    result += "  \"clean_shutdown\": " + std::string(m.clean_shutdown ? "true" : "false") + "\n}\n";
    return result;
}

Measurement run_server(const std::string& address, uint16_t port) {
    Fd listener = make_listener(address, port);
    return drain_server(accept_one(listener.get()));
}

Measurement run_self_test() {
    Fd listener = make_listener("127.0.0.1", 0);
    sockaddr_in endpoint{};
    socklen_t endpoint_size = sizeof(endpoint);
    if (getsockname(listener.get(), reinterpret_cast<sockaddr*>(&endpoint), &endpoint_size) != 0) fail_errno("getsockname");
    Measurement server;
    std::exception_ptr server_error;
    std::thread drain([&] { try { server = drain_server(accept_one(listener.get())); } catch (...) { server_error = std::current_exception(); } });
    const Measurement client = run_client(connect_one("127.0.0.1", ntohs(endpoint.sin_port)), 1.0, 0.0, kSelfTestRecords);
    drain.join();
    if (server_error) std::rethrow_exception(server_error);
    if (client.counters.bytes != kSelfTestRecords * kRecordBytes || server.counters.bytes != client.counters.bytes || !client.clean_shutdown || !server.clean_shutdown) throw std::runtime_error("self-test transfer contract failed");
    return client;
}
} // namespace

int main(int argc, char** argv) {
    try {
        const Options options = parse_options(argc, argv);
        if (options.mode == Options::Mode::SelfTest) {
            std::cout << json("self-test", run_self_test(), true);
        } else if (options.mode == Options::Mode::Listen) {
            std::cout << json("listen", run_server(options.address, options.port), false);
        } else {
            std::cout << json("connect", run_client(connect_one(options.address, options.port), options.duration_seconds, options.warmup_seconds), false);
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "bm_tcp_carrier: " << error.what() << "\n";
        return 1;
    }
}

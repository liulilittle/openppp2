// bm_tun_gso — B0/B1 GSO ns-per-payload-byte sweep for the isolated TUN path.
//
// kinds:
//   baseline: N pre-built ordinary TCP packets, N writes per payload unit.
//   b0:       one write of a pre-built GSO superpacket (kernel-path upper bound).
//   b1:       the superpacket is built from the N ordinary packets inside the
//             measured loop (realistic TapLinux-edge merge cost) then written.
//
// Contract verification (--execute) and timing (--bench) are separate modes.

#if !defined(__linux__)
#error "bm_tun_gso is Linux-only"
#endif

#include <arpa/inet.h>
#include <endian.h>
#include <fcntl.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
// Linux's UAPI header has a member named `class`, which is a C++ keyword.
#define class class_
#include <linux/virtio_net.h>
#undef class
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {
constexpr size_t kIpv4HeaderSize = 20;
constexpr size_t kTcpHeaderSize = 20;
constexpr size_t kHeaderSize = kIpv4HeaderSize + kTcpHeaderSize;
constexpr size_t kVirtioHeaderSize = sizeof(virtio_net_hdr);
constexpr uint16_t kMss = 1460;
constexpr uint32_t kSourceAddress = 0x0a2a0001U;      // 10.42.0.1
constexpr uint32_t kDestinationAddress = 0x0a2a0002U; // 10.42.0.2
constexpr uint16_t kSourcePort = 40000;
constexpr uint16_t kDestinationPort = 40001;
constexpr uint32_t kInitialSequence = 0x10203040U;
constexpr int kUnsupported = 77;

struct Options {
    double duration_seconds = 1.5;
    double warmup_seconds = 0.3;
    int cpu_a = 2;
    int cpu_b = 3;
    double max_segments_per_second = 150000.0; // keeps the sink queue lossless
    std::string json_out;
};

class SystemError : public std::runtime_error {
public:
    SystemError(const std::string& message, int code) : std::runtime_error(message + ": " + std::strerror(code)), code_(code) {}
    int code() const { return code_; }
private:
    int code_;
};

class Fd {
public:
    Fd() = default;
    explicit Fd(int fd) : fd_(fd) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    ~Fd() { if (fd_ >= 0) close(fd_); }
    int get() const { return fd_; }
    void reset(int value = -1) { if (fd_ >= 0) close(fd_); fd_ = value; }
private:
    int fd_ = -1;
};

uint16_t fold_checksum(uint32_t sum) {
    while (sum >> 16U) sum = (sum & 0xffffU) + (sum >> 16U);
    return static_cast<uint16_t>(~sum);
}

uint32_t checksum_sum(const uint8_t* bytes, size_t size, uint32_t sum = 0) {
    while (size >= 2) { sum += static_cast<uint16_t>((bytes[0] << 8U) | bytes[1]); bytes += 2; size -= 2; }
    if (size != 0) sum += static_cast<uint16_t>(bytes[0] << 8U);
    return sum;
}

uint16_t checksum(const uint8_t* bytes, size_t size) { return fold_checksum(checksum_sum(bytes, size)); }

uint16_t tcp_checksum(const uint8_t* ip, const uint8_t* tcp, size_t tcp_size) {
    uint32_t sum = checksum_sum(ip + 12, 8);
    const uint8_t pseudo[] = {0, IPPROTO_TCP, static_cast<uint8_t>(tcp_size >> 8U), static_cast<uint8_t>(tcp_size)};
    sum = checksum_sum(pseudo, sizeof(pseudo), sum);
    return fold_checksum(checksum_sum(tcp, tcp_size, sum));
}

void put16(uint8_t* p, uint16_t value) { const uint16_t wire = htons(value); std::memcpy(p, &wire, sizeof(wire)); }
void put32(uint8_t* p, uint32_t value) { const uint32_t wire = htonl(value); std::memcpy(p, &wire, sizeof(wire)); }
uint16_t get16(const uint8_t* p) { uint16_t value; std::memcpy(&value, p, sizeof(value)); return ntohs(value); }
uint32_t get32(const uint8_t* p) { uint32_t value; std::memcpy(&value, p, sizeof(value)); return ntohl(value); }

uint8_t payload_byte(size_t offset) { return static_cast<uint8_t>((offset * 37U + 11U) & 0xffU); }

std::vector<uint8_t> make_tcp_packet(uint16_t payload_size, uint32_t sequence) {
    std::vector<uint8_t> packet(kHeaderSize + payload_size, 0);
    uint8_t* ip = packet.data();
    ip[0] = 0x45;
    put16(ip + 2, static_cast<uint16_t>(packet.size()));
    put16(ip + 4, 0x4242);
    put16(ip + 6, 0x4000);
    ip[8] = 64;
    ip[9] = IPPROTO_TCP;
    put32(ip + 12, kSourceAddress);
    put32(ip + 16, kDestinationAddress);
    uint8_t* tcp = ip + kIpv4HeaderSize;
    put16(tcp, kSourcePort);
    put16(tcp + 2, kDestinationPort);
    put32(tcp + 4, sequence);
    tcp[12] = 0x50;
    tcp[13] = 0x18;
    put16(tcp + 14, 65535);
    for (size_t i = 0; i < payload_size; ++i) tcp[kTcpHeaderSize + i] = payload_byte(sequence - kInitialSequence + i);
    put16(ip + 10, checksum(ip, kIpv4HeaderSize));
    put16(tcp + 16, tcp_checksum(ip, tcp, kTcpHeaderSize + payload_size));
    return packet;
}

// The checksum field holds the uncomplemented pseudo-header seed exactly as
// the production edge merger would leave it for the kernel's GSO work.
void fill_superpacket(std::vector<uint8_t>& frame, size_t payload_bytes) {
    auto* virtio = reinterpret_cast<virtio_net_hdr*>(frame.data());
    virtio->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    virtio->gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
    virtio->hdr_len = htole16(kHeaderSize);
    virtio->gso_size = htole16(kMss);
    virtio->csum_start = htole16(kIpv4HeaderSize);
    virtio->csum_offset = htole16(16);
    uint8_t* ip = frame.data() + kVirtioHeaderSize;
    ip[0] = 0x45;
    put16(ip + 2, static_cast<uint16_t>(kHeaderSize + payload_bytes));
    put16(ip + 4, 0x4242);
    put16(ip + 6, 0x4000);
    ip[8] = 64;
    ip[9] = IPPROTO_TCP;
    put32(ip + 12, kSourceAddress);
    put32(ip + 16, kDestinationAddress);
    uint8_t* tcp = ip + kIpv4HeaderSize;
    put16(tcp, kSourcePort);
    put16(tcp + 2, kDestinationPort);
    tcp[12] = 0x50;
    tcp[13] = 0x18;
    put16(tcp + 14, 65535);
    for (size_t i = 0; i < payload_bytes; ++i) tcp[kTcpHeaderSize + i] = payload_byte(i);
    const uint8_t pseudo[] = {0, IPPROTO_TCP, static_cast<uint8_t>((kTcpHeaderSize + payload_bytes) >> 8U), static_cast<uint8_t>(kTcpHeaderSize + payload_bytes)};
    uint32_t partial = checksum_sum(ip + 12, 8);
    partial = checksum_sum(pseudo, sizeof(pseudo), partial);
    put16(tcp + 16, static_cast<uint16_t>(~fold_checksum(partial)));
    // Zero the field first: when the header comes from an ordinary packet, its
    // valid old checksum would otherwise fold into the sum (old-checksum +
    // complement(old-checksum) = 0xFFFF) and yield a final checksum of zero.
    put16(ip + 10, 0);
    put16(ip + 10, checksum(ip, kIpv4HeaderSize));
}

std::vector<uint8_t> make_superpacket(size_t mss_count, uint32_t sequence) {
    std::vector<uint8_t> frame(kVirtioHeaderSize + kHeaderSize + mss_count * kMss, 0);
    fill_superpacket(frame, mss_count * kMss);
    put32(frame.data() + kVirtioHeaderSize + kIpv4HeaderSize + 4, sequence);
    return frame;
}

// On a VNET_HDR TUN every write must carry the virtio header; ordinary
// packets use gso_type=NONE. The baseline pays this header too, which is the
// honest production comparison.
std::vector<uint8_t> make_vnet_none(const std::vector<uint8_t>& packet) {
    std::vector<uint8_t> frame(kVirtioHeaderSize + packet.size(), 0);
    std::memcpy(frame.data() + kVirtioHeaderSize, packet.data(), packet.size());
    return frame;
}

bool mergeable(const std::vector<uint8_t>& base, const std::vector<uint8_t>& packet, size_t position, std::string* reason) {
    if (packet.size() != kHeaderSize + kMss) { *reason = "payload_not_full_mss"; return false; }
    if (std::memcmp(packet.data(), base.data(), 16) != 0) { *reason = "ip_header_change"; return false; }
    const uint8_t* tcp_a = base.data() + kIpv4HeaderSize;
    const uint8_t* tcp_b = packet.data() + kIpv4HeaderSize;
    if (std::memcmp(tcp_a, tcp_b, 4) != 0) { *reason = "flow_change"; return false; }
    if (get32(tcp_b + 4) != kInitialSequence + position * kMss) { *reason = "seq_gap"; return false; }
    if (tcp_b[12] != 0x50 || tcp_b[13] != 0x18) { *reason = "flags_change"; return false; }
    // Compare window and urgent pointer but never the checksum field (bytes
    // 16-17), which legitimately differs between ordinary packets.
    if (std::memcmp(tcp_a + 14, tcp_b + 14, 2) != 0) { *reason = "window_change"; return false; }
    if (std::memcmp(tcp_a + 18, tcp_b + 18, 2) != 0) { *reason = "urg_ptr_change"; return false; }
    return true;
}

// B1: merge already-validated ordinary packets into one GSO frame. This is the
// work a TapLinux-edge merger would pay inside its measured window.
std::vector<uint8_t> build_superpacket_from(const std::vector<std::vector<uint8_t>>& packets, std::string* reason) {
    const size_t count = packets.size();
    for (size_t i = 0; i < count; ++i) {
        if (!mergeable(packets[0], packets[i], i, reason)) return {};
    }
    std::vector<uint8_t> frame(kVirtioHeaderSize + kHeaderSize + count * kMss, 0);
    std::memcpy(frame.data() + kVirtioHeaderSize, packets[0].data(), kHeaderSize);
    for (size_t i = 0; i < count; ++i) {
        const uint8_t* tcp = packets[i].data() + kIpv4HeaderSize;
        std::memcpy(frame.data() + kVirtioHeaderSize + kHeaderSize + i * kMss, tcp + kTcpHeaderSize, kMss);
    }
    fill_superpacket(frame, count * kMss);
    return frame;
}

bool valid_ipv4(const std::vector<uint8_t>& packet) {
    if (packet.size() < kHeaderSize || packet[0] != 0x45) return false;
    if (get16(packet.data() + 2) != packet.size()) return false;
    if (checksum(packet.data(), kIpv4HeaderSize) != 0) return false;
    const uint8_t* tcp = packet.data() + kIpv4HeaderSize;
    return tcp_checksum(packet.data(), tcp, packet.size() - kIpv4HeaderSize) == 0;
}

void verify_segment(const uint8_t* packet, size_t size, size_t payload_offset, size_t expected_payload) {
    if (size != kHeaderSize + expected_payload) throw std::runtime_error("unexpected segment length");
    if (packet[0] != 0x45 || get16(packet + 2) != size || packet[9] != IPPROTO_TCP) throw std::runtime_error("invalid IPv4 segment metadata");
    if (checksum(packet, kIpv4HeaderSize) != 0) throw std::runtime_error("invalid IPv4 checksum");
    const uint8_t* tcp = packet + kIpv4HeaderSize;
    if (get16(tcp) != kSourcePort || get16(tcp + 2) != kDestinationPort) throw std::runtime_error("unexpected TCP ports");
    if (get32(tcp + 4) != kInitialSequence + payload_offset) throw std::runtime_error("unexpected TCP sequence");
    // The pseudo-header length is the TCP length (header + payload), which is
    // NOT the IPv4 total length (an extra 20 bytes would poison the sum).
    if (tcp_checksum(packet, tcp, kTcpHeaderSize + expected_payload) != 0) throw std::runtime_error("invalid TCP checksum");
    for (size_t i = 0; i < expected_payload; ++i) {
        if (tcp[kTcpHeaderSize + i] != payload_byte(payload_offset + i)) throw std::runtime_error("unexpected TCP payload");
    }
}

// ---------------------------------------------------------------- topology

class Netlink {
public:
    Netlink() : fd_(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)) { if (fd_.get() < 0) throw SystemError("netlink socket", errno); }
    void link_up(const std::string& name) {
        const int index = if_nametoindex(name.c_str()); if (!index) throw SystemError("if_nametoindex", errno);
        request(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, [&](std::vector<uint8_t>& message) { auto* info = append<ifinfomsg>(message); info->ifi_family = AF_UNSPEC; info->ifi_index = index; info->ifi_change = IFF_UP; info->ifi_flags = IFF_UP; });
    }
    void route(uint32_t destination, const std::string& output) {
        const int index = if_nametoindex(output.c_str()); if (!index) throw SystemError("if_nametoindex", errno);
        request(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, [&](std::vector<uint8_t>& message) {
            auto* route = append<rtmsg>(message); route->rtm_family = AF_INET; route->rtm_dst_len = 32; route->rtm_table = RT_TABLE_MAIN; route->rtm_protocol = RTPROT_STATIC; route->rtm_scope = RT_SCOPE_LINK; route->rtm_type = RTN_UNICAST;
            const uint32_t wire = htonl(destination); attribute(message, RTA_DST, &wire, sizeof(wire)); attribute(message, RTA_OIF, &index, sizeof(index));
        });
    }
private:
    template<typename T> static T* append(std::vector<uint8_t>& message) { const size_t old = message.size(); message.resize(old + NLMSG_ALIGN(sizeof(T)), 0); return reinterpret_cast<T*>(message.data() + old); }
    static void attribute(std::vector<uint8_t>& message, uint16_t type, const void* data, size_t size) { const size_t old = message.size(); const size_t length = RTA_LENGTH(size); message.resize(old + RTA_ALIGN(length), 0); auto* attr = reinterpret_cast<rtattr*>(message.data() + old); attr->rta_type = type; attr->rta_len = length; std::memcpy(RTA_DATA(attr), data, size); }
    template<typename Fill> void request(uint16_t type, uint16_t flags, Fill fill) {
        std::vector<uint8_t> message(NLMSG_SPACE(0), 0); auto* header = reinterpret_cast<nlmsghdr*>(message.data()); header->nlmsg_len = NLMSG_LENGTH(0); header->nlmsg_type = type; header->nlmsg_flags = flags; header->nlmsg_seq = ++sequence_; fill(message); header = reinterpret_cast<nlmsghdr*>(message.data()); header->nlmsg_len = message.size();
        sockaddr_nl address{}; address.nl_family = AF_NETLINK;
        if (sendto(fd_.get(), message.data(), header->nlmsg_len, 0, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) throw SystemError("netlink request", errno);
        std::array<uint8_t, 4096> reply{}; const ssize_t received = recv(fd_.get(), reply.data(), reply.size(), 0); if (received < 0) throw SystemError("netlink reply", errno);
        int remaining = static_cast<int>(received);
        for (nlmsghdr* current = reinterpret_cast<nlmsghdr*>(reply.data()); NLMSG_OK(current, remaining); current = NLMSG_NEXT(current, remaining)) {
            if (current->nlmsg_type == NLMSG_ERROR) { const auto* error = reinterpret_cast<const nlmsgerr*>(NLMSG_DATA(current)); if (error->error != 0) throw SystemError("netlink operation", -error->error); return; }
        }
        throw std::runtime_error("netlink operation returned no acknowledgement");
    }
    Fd fd_; uint32_t sequence_ = 0;
};

class Tun {
public:
    Tun(const std::string& name, bool vnet) {
        fd_.reset(open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC)); if (fd_.get() < 0) throw SystemError("open /dev/net/tun", errno);
        ifreq request{}; std::snprintf(request.ifr_name, IFNAMSIZ, "%s", name.c_str()); request.ifr_flags = IFF_TUN | IFF_NO_PI | (vnet ? IFF_VNET_HDR : 0);
        if (ioctl(fd_.get(), TUNSETIFF, &request) < 0) throw SystemError("TUNSETIFF", errno); name_ = request.ifr_name;
    }
    int fd() const { return fd_.get(); }
    const std::string& name() const { return name_; }
private: Fd fd_; std::string name_;
};

bool isolate_procfs_for_current_netns() {
    if (unshare(CLONE_NEWNS) != 0) return false;
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) return false;
    umount2("/proc", MNT_DETACH);
    return mount("proc", "/proc", "proc", 0, NULL) == 0;
}

void write_sysctl(const std::string& path, const std::string& value) {
    Fd control(open(path.c_str(), O_WRONLY | O_CLOEXEC));
    if (control.get() < 0) throw SystemError("open " + path, errno);
    if (write(control.get(), value.c_str(), value.size()) != static_cast<ssize_t>(value.size())) throw SystemError("write " + path, errno);
}

struct Topology {
    std::unique_ptr<Tun> ingress;
    std::unique_ptr<Tun> sink;
};

Topology setup_topology() {
    if (unshare(CLONE_NEWNET) != 0) throw SystemError("unshare(CLONE_NEWNET)", errno);
    // Sysctl writes must never leak into another namespace: without a fresh
    // procfs mount they would target the original network namespace.
    if (!isolate_procfs_for_current_netns()) throw SystemError("isolate procfs", EPERM);
    const std::string suffix = std::to_string(getpid() % 100000U);
    Topology topology;
    topology.ingress = std::make_unique<Tun>("gsoin" + suffix, true);
    topology.sink = std::make_unique<Tun>("gsout" + suffix, false);
    unsigned int features = 0;
    if (ioctl(topology.ingress->fd(), TUNGETFEATURES, &features) != 0) throw SystemError("TUNGETFEATURES", errno);
    if ((features & IFF_VNET_HDR) == 0) throw SystemError("IFF_VNET_HDR unavailable", EOPNOTSUPP);
    int header_size = kVirtioHeaderSize;
    if (ioctl(topology.ingress->fd(), TUNSETVNETHDRSZ, &header_size) != 0) throw SystemError("TUNSETVNETHDRSZ", errno);
    int readback = 0;
    if (ioctl(topology.ingress->fd(), TUNGETVNETHDRSZ, &readback) != 0) throw SystemError("TUNGETVNETHDRSZ", errno);
    if (readback != header_size) throw std::runtime_error("virtio header size readback mismatch");
    if (ioctl(topology.ingress->fd(), TUNSETOFFLOAD, TUN_F_CSUM | TUN_F_TSO4) != 0) throw SystemError("TUNSETOFFLOAD", errno);
    Netlink netlink;
    netlink.link_up("lo");
    netlink.link_up(topology.ingress->name());
    netlink.link_up(topology.sink->name());
    // The injected source address must stay non-local: assigning it to the
    // ingress interface turns forwarded frames into martian sources, which the
    // kernel drops silently before output.
    write_sysctl("/proc/sys/net/ipv4/ip_forward", "1\n");
    write_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0\n");
    write_sysctl("/proc/sys/net/ipv4/conf/" + topology.ingress->name() + "/rp_filter", "0\n");
    netlink.route(kDestinationAddress, topology.sink->name());
    // Deepen the sink queue: the drain thread must not become the bottleneck
    // whose drops corrupt the byte-count contract.
    {
        ifreq qlen{};
        std::strncpy(qlen.ifr_name, topology.sink->name().c_str(), IFNAMSIZ - 1);
        qlen.ifr_qlen = 65535;
        Fd control(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
        if (control.get() < 0) throw SystemError("qlen control socket", errno);
        if (ioctl(control.get(), SIOCSIFTXQLEN, &qlen) != 0) throw SystemError("SIOCSIFTXQLEN", errno);
    }
    return topology;
}

bool limitation_errno(int code) { return code == EPERM || code == EACCES || code == ENODEV || code == EOPNOTSUPP || code == ENOTTY || code == EINVAL; }
void print_unsupported(const std::string& reason) { std::cout << "{\"status\":\"unsupported\",\"reason\":\"" << reason << "\"}\n"; }

// ---------------------------------------------------------------- timing

uint64_t clock_ns(clockid_t clock_id) {
    timespec value{};
    if (clock_gettime(clock_id, &value) != 0) throw SystemError("clock_gettime", errno);
    return static_cast<uint64_t>(value.tv_sec) * 1000000000ULL + static_cast<uint64_t>(value.tv_nsec);
}

void pin_to_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) throw SystemError("sched_setaffinity", errno);
}

struct CpuSample {
    // Indexed by cpu id; order: user nice system idle iowait irq softirq steal.
    std::vector<std::array<uint64_t, 8>> cpu;
};

CpuSample read_proc_stat() {
    std::ifstream stat("/proc/stat");
    CpuSample sample;
    std::string line;
    while (std::getline(stat, line)) {
        if (line.rfind("cpu", 0) != 0 || line.size() < 5 || !std::isdigit(static_cast<unsigned char>(line[3]))) continue;
        unsigned long long fields[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        const int parsed = std::sscanf(line.c_str(), "cpu%*u %llu %llu %llu %llu %llu %llu %llu %llu",
            &fields[0], &fields[1], &fields[2], &fields[3], &fields[4], &fields[5], &fields[6], &fields[7]);
        if (parsed >= 8) {
            std::array<uint64_t, 8> entry{};
            for (size_t i = 0; i < 8; ++i) entry[i] = fields[i];
            sample.cpu.push_back(entry);
        }
    }
    return sample;
}

uint64_t jiffies_to_ns(uint64_t jiffies) {
    static const uint64_t tck = [] { const long value = sysconf(_SC_CLK_TCK); return value > 0 ? static_cast<uint64_t>(value) : 100; }();
    return jiffies * 1000000000ULL / tck;
}

struct CpuDelta {
    uint64_t nonidle_ns = 0;
    uint64_t softirq_ns = 0;
    uint64_t system_ns = 0;
};

CpuDelta cpu_delta(const CpuSample& before, const CpuSample& after, size_t index) {
    CpuDelta delta;
    if (index >= before.cpu.size() || index >= after.cpu.size()) return delta;
    uint64_t nonidle = 0, softirq = 0, system = 0;
    for (size_t field = 0; field < 8; ++field) {
        const uint64_t difference = after.cpu[index][field] - std::min(after.cpu[index][field], before.cpu[index][field]);
        if (field == 3 || field == 4) continue; // idle + iowait are excluded
        nonidle += difference;
        if (field == 6) softirq += difference;
        if (field == 2) system += difference;
    }
    delta.nonidle_ns = jiffies_to_ns(nonidle);
    delta.softirq_ns = jiffies_to_ns(softirq);
    delta.system_ns = jiffies_to_ns(system);
    return delta;
}

uint64_t percentile(std::vector<uint64_t> values, unsigned int numerator) {
    if (values.empty()) return 0;
    const size_t index = (values.size() * numerator + 99U) / 100U - 1U;
    std::nth_element(values.begin(), values.begin() + static_cast<std::ptrdiff_t>(index), values.end());
    return values[index];
}

std::string json_escape(const std::string& text) {
    std::string out;
    for (const char c : text) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (static_cast<unsigned char>(c) >= 0x20 && c != 0x7f) out += c;
    }
    return out;
}

// ---------------------------------------------------------------- sink

struct SinkCounters {
    uint64_t reads = 0;
    uint64_t bytes = 0;
    uint64_t segments = 0;
    uint64_t noise = 0;
    uint64_t cpu_ns = 0;
};

void drain_sink(int cpu, int sink_fd, std::atomic<bool>* stop, SinkCounters* counters) {
    try {
        pin_to_cpu(cpu);
    } catch (const std::exception&) {
        // Measurement still works unpinned; the JSON lacks isolation then.
    }
    const uint64_t cpu_started = clock_ns(CLOCK_THREAD_CPUTIME_ID);
    pollfd wait{sink_fd, POLLIN, 0};
    while (!stop->load(std::memory_order_relaxed)) {
        if (poll(&wait, 1, 20) <= 0) continue;
        // Batch-drain: one poll, then read until the queue is empty. A single
        // read per poll cannot keep up with the writer and drops segments.
        for (;;) {
            std::array<uint8_t, 65536> packet{};
            const ssize_t length = read(sink_fd, packet.data(), packet.size());
            if (length <= 0) break;
            ++counters->reads;
            // Only IPv4 payload counts toward the byte contract; control
            // noise (link-up RS and friends) is reported separately.
            if ((packet[0] >> 4U) == 4) { counters->bytes += static_cast<uint64_t>(length); ++counters->segments; }
            else counters->noise += static_cast<uint64_t>(length);
        }
    }
    for (;;) { // final non-blocking drain of frames queued before the stop flag
        pollfd check{sink_fd, POLLIN, 0};
        if (poll(&check, 1, 0) <= 0) break;
        std::array<uint8_t, 65536> packet{};
        const ssize_t length = read(sink_fd, packet.data(), packet.size());
        if (length <= 0) break;
        ++counters->reads;
        counters->bytes += static_cast<uint64_t>(length);
        if (length >= 1 && (packet[0] >> 4U) == 4) ++counters->segments;
        else ++counters->noise;
    }
    counters->cpu_ns = clock_ns(CLOCK_THREAD_CPUTIME_ID) - cpu_started;
}

void flush_sink(int sink_fd) {
    timespec pause{0, 100 * 1000 * 1000}; // 100 ms
    nanosleep(&pause, nullptr);
    for (;;) {
        pollfd check{sink_fd, POLLIN, 0};
        if (poll(&check, 1, 0) <= 0) break;
        std::array<uint8_t, 65536> packet{};
        if (read(sink_fd, packet.data(), packet.size()) <= 0) break;
    }
}

// ---------------------------------------------------------------- phases

struct PhaseResult {
    std::string kind;
    size_t mss_count = 0;
    uint64_t units = 0;
    uint64_t write_calls = 0;
    uint64_t payload_bytes = 0;
    uint64_t sink_bytes = 0;
    uint64_t sink_segments = 0;
    uint64_t expected_sink_bytes = 0;
    uint64_t writer_wall_ns = 0;
    uint64_t writer_cpu_ns = 0;
    uint64_t process_cpu_ns = 0;
    uint64_t sink_cpu_ns = 0;
    uint64_t cpu_a_nonidle_ns = 0;
    uint64_t cpu_a_softirq_ns = 0;
    uint64_t softirq_other_cpus_ns = 0;
    uint64_t whole_system_nonidle_ns = 0;
    unsigned active_cpu_count = 0;
    uint64_t latency_p50 = 0, latency_p95 = 0, latency_p99 = 0, latency_max = 0;
    uint64_t eagain = 0, eintr = 0, short_write = 0, other_errors = 0;
    uint64_t sink_mismatch = 0;
    double improvement_writer_cpu = 0.0;
    double improvement_cpu_a_system = 0.0;
};

void write_frame(int fd, const std::vector<uint8_t>& frame, PhaseResult& result, std::vector<uint64_t>* latency) {
    const uint64_t started = latency != nullptr ? clock_ns(CLOCK_MONOTONIC_RAW) : 0;
    ssize_t written = 0;
    do {
        written = write(fd, frame.data(), frame.size());
        if (written < 0 && errno == EINTR) ++result.eintr;
    } while (written < 0 && errno == EINTR);
    if (latency != nullptr) latency->push_back(clock_ns(CLOCK_MONOTONIC_RAW) - started);
    if (written == static_cast<ssize_t>(frame.size())) ++result.write_calls;
    else if (written >= 0) ++result.short_write;
    else if (errno == EAGAIN || errno == EWOULDBLOCK) ++result.eagain;
    else ++result.other_errors;
}

PhaseResult run_phase(int ingress_fd, int sink_fd, const std::string& kind, size_t mss_count, const Options& options) {
    std::vector<std::vector<uint8_t>> packets;
    packets.reserve(mss_count);
    for (size_t i = 0; i < mss_count; ++i) packets.push_back(make_tcp_packet(static_cast<uint16_t>(kMss), kInitialSequence + i * kMss));
    std::vector<std::vector<uint8_t>> baseline;
    baseline.reserve(mss_count);
    for (size_t i = 0; i < mss_count; ++i) baseline.push_back(make_vnet_none(packets[i]));
    std::vector<uint8_t> superpacket;
    if (kind == "b0") superpacket = make_superpacket(mss_count, kInitialSequence);
    if (kind == "b1") {
        std::string reason;
        superpacket = build_superpacket_from(packets, &reason);
        if (superpacket.empty()) throw std::runtime_error("b1 build failed: " + reason);
    }

    // Warm-up window: its traffic and cost are fully discarded.
    {
        std::atomic<bool> stop{false};
        SinkCounters discarded;
        std::thread sink(drain_sink, options.cpu_b, sink_fd, &stop, &discarded);
        const uint64_t deadline = clock_ns(CLOCK_MONOTONIC_RAW) + static_cast<uint64_t>(options.warmup_seconds * 1000000000.0);
        PhaseResult warmup;
        while (clock_ns(CLOCK_MONOTONIC_RAW) < deadline) {
            if (kind == "baseline") for (size_t i = 0; i < baseline.size(); ++i) write_frame(ingress_fd, baseline[i], warmup, nullptr);
            else write_frame(ingress_fd, superpacket, warmup, nullptr);
        }
        stop.store(true, std::memory_order_relaxed);
        sink.join();
    }
    flush_sink(sink_fd);

    PhaseResult result;
    result.kind = kind;
    result.mss_count = mss_count;
    std::atomic<bool> stop{false};
    SinkCounters sink_counters;
    std::thread sink(drain_sink, options.cpu_b, sink_fd, &stop, &sink_counters);

    std::vector<uint64_t> latency;
    const CpuSample stat_before = read_proc_stat();
    const uint64_t wall_started = clock_ns(CLOCK_MONOTONIC_RAW);
    const uint64_t writer_cpu_started = clock_ns(CLOCK_THREAD_CPUTIME_ID);
    const uint64_t process_cpu_started = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
    const uint64_t deadline = wall_started + static_cast<uint64_t>(options.duration_seconds * 1000000000.0);
    // Token pacing keeps the enqueue rate below the sink drain capacity so no
    // segment is dropped: every kind and N then works at the same segment
    // rate, which is the fair basis for the per-byte comparison.
    const double segment_cost = kind == "baseline" ? 1.0 : static_cast<double>(mss_count);
    double allowed_segments = 0.0;
    double segments_sent = 0.0;
    while (clock_ns(CLOCK_MONOTONIC_RAW) < deadline) {
        const uint64_t now = clock_ns(CLOCK_MONOTONIC_RAW);
        allowed_segments = (now - wall_started) / 1e9 * options.max_segments_per_second;
        if (segments_sent > allowed_segments) {
            timespec pause{0, 50 * 1000}; // 50 us
            nanosleep(&pause, nullptr);
            continue;
        }
        if (kind == "baseline") for (size_t i = 0; i < baseline.size(); ++i) write_frame(ingress_fd, baseline[i], result, &latency);
        else write_frame(ingress_fd, superpacket, result, &latency);
        segments_sent += segment_cost;
    }
    result.writer_wall_ns = clock_ns(CLOCK_MONOTONIC_RAW) - wall_started;
    result.writer_cpu_ns = clock_ns(CLOCK_THREAD_CPUTIME_ID) - writer_cpu_started;
    result.process_cpu_ns = clock_ns(CLOCK_PROCESS_CPUTIME_ID) - process_cpu_started;
    const CpuSample stat_after = read_proc_stat();

    stop.store(true, std::memory_order_relaxed);
    sink.join();
    flush_sink(sink_fd);

    result.units = kind == "baseline" ? result.write_calls / mss_count : result.write_calls;
    result.payload_bytes = result.units * mss_count * kMss;
    result.sink_bytes = sink_counters.bytes;
    result.sink_segments = sink_counters.segments;
    result.expected_sink_bytes = result.units * mss_count * (kHeaderSize + kMss);
    result.sink_cpu_ns = sink_counters.cpu_ns;
    result.latency_p50 = percentile(latency, 50);
    result.latency_p95 = percentile(latency, 95);
    result.latency_p99 = percentile(latency, 99);
    result.latency_max = latency.empty() ? 0 : *std::max_element(latency.begin(), latency.end());

    const size_t cpu_a = static_cast<size_t>(options.cpu_a);
    const size_t cpu_b = static_cast<size_t>(options.cpu_b);
    const CpuDelta a = cpu_delta(stat_before, stat_after, cpu_a);
    result.cpu_a_nonidle_ns = a.nonidle_ns;
    result.cpu_a_softirq_ns = a.softirq_ns;
    uint64_t softirq_other = 0;
    uint64_t whole_nonidle = a.nonidle_ns;
    unsigned active = 0;
    const size_t cpus = std::min(stat_before.cpu.size(), stat_after.cpu.size());
    for (size_t index = 0; index < cpus; ++index) {
        const CpuDelta delta = cpu_delta(stat_before, stat_after, index);
        if (index != cpu_a) softirq_other += delta.softirq_ns;
        if (index != cpu_a && index != cpu_b) whole_nonidle += delta.nonidle_ns;
        if (delta.nonidle_ns > 10000000ULL) ++active;
    }
    result.softirq_other_cpus_ns = softirq_other;
    result.whole_system_nonidle_ns = whole_nonidle;
    result.active_cpu_count = active;
    if (result.sink_bytes != result.expected_sink_bytes || result.sink_segments != result.units * mss_count) {
        result.sink_mismatch = result.expected_sink_bytes > result.sink_bytes ? result.expected_sink_bytes - result.sink_bytes : result.sink_bytes - result.expected_sink_bytes;
    }
    return result;
}

std::string render_entry(const PhaseResult& r) {
    char buffer[1024];
    std::snprintf(buffer, sizeof(buffer),
        "{\"kind\":\"%s\",\"mss_count\":%zu,\"units\":%llu,\"tun_write_calls\":%llu,\"payload_bytes\":%llu,"
        "\"writer_wall_ns_per_payload_byte\":%.4f,\"writer_cpu_ns_per_payload_byte\":%.4f,"
        "\"process_cpu_ns_per_payload_byte\":%.4f,\"cpuA_system_ns_per_payload_byte\":%.4f,"
        "\"whole_test_system_ns_per_payload_byte\":%.4f,\"sink_cpu_ns_per_payload_byte\":%.4f,"
        "\"writes_per_payload_MiB\":%.4f,\"segments_per_payload_MiB\":%.4f,"
        "\"write_latency_p50\":%llu,\"write_latency_p95\":%llu,\"write_latency_p99\":%llu,\"write_latency_max\":%llu,"
        "\"cpuA_softirq_ns\":%llu,\"softirq_other_cpus_ns\":%llu,\"active_cpu_count\":%u,"
        "\"sink_bytes\":%llu,\"expected_sink_bytes\":%llu,\"sink_segments\":%llu,\"sink_mismatch\":%llu,"
        "\"eagain\":%llu,\"eintr\":%llu,\"short_write\":%llu,\"other_errors\":%llu,"
        "\"improvement_writer_cpu\":%.4f,\"improvement_cpuA_system\":%.4f}",
        json_escape(r.kind).c_str(), r.mss_count,
        (unsigned long long)r.units, (unsigned long long)r.write_calls, (unsigned long long)r.payload_bytes,
        r.payload_bytes ? r.writer_wall_ns / static_cast<double>(r.payload_bytes) : 0.0,
        r.payload_bytes ? r.writer_cpu_ns / static_cast<double>(r.payload_bytes) : 0.0,
        r.payload_bytes ? r.process_cpu_ns / static_cast<double>(r.payload_bytes) : 0.0,
        r.payload_bytes ? r.cpu_a_nonidle_ns / static_cast<double>(r.payload_bytes) : 0.0,
        r.payload_bytes ? r.whole_system_nonidle_ns / static_cast<double>(r.payload_bytes) : 0.0,
        r.payload_bytes ? r.sink_cpu_ns / static_cast<double>(r.payload_bytes) : 0.0,
        r.payload_bytes ? r.write_calls * 1048576.0 / r.payload_bytes : 0.0,
        r.payload_bytes ? r.sink_segments * 1048576.0 / r.payload_bytes : 0.0,
        (unsigned long long)r.latency_p50, (unsigned long long)r.latency_p95, (unsigned long long)r.latency_p99, (unsigned long long)r.latency_max,
        (unsigned long long)r.cpu_a_softirq_ns, (unsigned long long)r.softirq_other_cpus_ns, r.active_cpu_count,
        (unsigned long long)r.sink_bytes, (unsigned long long)r.expected_sink_bytes, (unsigned long long)r.sink_segments, (unsigned long long)r.sink_mismatch,
        (unsigned long long)r.eagain, (unsigned long long)r.eintr, (unsigned long long)r.short_write, (unsigned long long)r.other_errors,
        r.improvement_writer_cpu, r.improvement_cpu_a_system);
    return buffer;
}

// ---------------------------------------------------------------- modes

std::string run_contract() {
    const Topology topology = setup_topology();
    {
        const std::vector<uint8_t> probe_packet = make_tcp_packet(static_cast<uint16_t>(kMss), kInitialSequence);
        if (!valid_ipv4(probe_packet)) {
            throw std::runtime_error("contract-built baseline invalid: verify=" + std::to_string(tcp_checksum(probe_packet.data(), probe_packet.data() + kIpv4HeaderSize, kHeaderSize + kMss)) + " size=" + std::to_string(probe_packet.size()));
        }
    }
    std::string out = "{\"mode\":\"execute\",\"status\":\"pass\",\"cases\":[";
    bool first_case = true;
    for (const size_t mss_count : {1U, 2U, 4U, 8U, 16U}) {
        std::vector<std::vector<uint8_t>> baseline;
        for (size_t i = 0; i < mss_count; ++i) baseline.push_back(make_tcp_packet(static_cast<uint16_t>(kMss), kInitialSequence + i * kMss));
        const std::vector<uint8_t> b0 = make_superpacket(mss_count, kInitialSequence);
        std::string reason;
        const std::vector<uint8_t> b1 = build_superpacket_from(baseline, &reason);
        if (b1.empty()) throw std::runtime_error("b1 build failed: " + reason);
        for (int variant = 0; variant < 3; ++variant) {
            const std::vector<uint8_t>* frame = variant == 0 ? &baseline.front() : (variant == 1 ? &b0 : &b1);
            if (variant == 0) {
                for (const std::vector<uint8_t>& packet : baseline) {
                    const std::vector<uint8_t> vnet = make_vnet_none(packet);
                    if (write(topology.ingress->fd(), vnet.data(), vnet.size()) != static_cast<ssize_t>(vnet.size())) throw SystemError("write baseline packet", errno);
                }
            } else {
                if (write(topology.ingress->fd(), frame->data(), frame->size()) != static_cast<ssize_t>(frame->size())) throw SystemError("write superpacket", errno);
            }
            // Collect every segment the sink delivers and match them by
            // sequence number instead of assuming wire order.
            std::vector<size_t> remaining;
            for (size_t off = 0; off < mss_count * kMss; off += kMss) remaining.push_back(off);
            std::string observed;
            size_t noise = 0;
            const int64_t quiet_deadline = static_cast<int64_t>(clock_ns(CLOCK_MONOTONIC_RAW)) + 500000000LL;
            while (!remaining.empty()) {
                const int64_t now = static_cast<int64_t>(clock_ns(CLOCK_MONOTONIC_RAW));
                if (now >= quiet_deadline) break;
                pollfd wait{topology.sink->fd(), POLLIN, 0};
                const int polled = poll(&wait, 1, static_cast<int>((quiet_deadline - now) / 1000000) + 1);
                if (polled <= 0) break;
                std::array<uint8_t, 65536> received{};
                const ssize_t length = read(topology.sink->fd(), received.data(), received.size());
                if (length < 0) throw SystemError("read sink packet", errno);
                if (length < 1 || (received[0] >> 4U) != 4) { ++noise; continue; }
                const uint32_t seq = get32(received.data() + kIpv4HeaderSize + 4);
                std::vector<size_t>::iterator match = std::find(remaining.begin(), remaining.end(), seq - kInitialSequence);
                observed += " [" + std::to_string(length) + "@" + std::to_string(seq - kInitialSequence) + "]";
                try {
                    verify_segment(received.data(), static_cast<size_t>(length), seq - kInitialSequence, kMss);
                } catch (const std::exception& error) {
                    throw std::runtime_error(std::string(error.what()) + " (variant=" + (variant == 0 ? "baseline" : variant == 1 ? "b0" : "b1") + " mss_count=" + std::to_string(mss_count) + " offset=" + std::to_string(seq - kInitialSequence) + " length=" + std::to_string(length) + " noise=" + std::to_string(noise) + ")");
                }
                if (match != remaining.end()) remaining.erase(match);
            }
            if (!remaining.empty()) {
                throw std::runtime_error(std::string("missing segments (variant=") + (variant == 0 ? "baseline" : variant == 1 ? "b0" : "b1") + " mss_count=" + std::to_string(mss_count) + " observed:" + observed + ")");
            }
            if (first_case) first_case = false;
            else out += ",";
            char buffer[256];
            std::snprintf(buffer, sizeof(buffer), "{\"mss_count\":%zu,\"variant\":\"%s\",\"segments\":%zu,\"noise\":%zu}",
                mss_count, variant == 0 ? "baseline" : (variant == 1 ? "b0" : "b1"), mss_count, noise);
            out += buffer;
        }
    }
    out += "]}";
    return out;
}

std::string run_bench(const Options& options) {
    pin_to_cpu(options.cpu_a);
    const Topology topology = setup_topology();
    std::vector<PhaseResult> entries;
    std::vector<PhaseResult> baselines;
    for (const size_t mss_count : {1U, 2U, 4U, 8U, 16U}) {
        PhaseResult baseline;
        for (const std::string& kind : {"baseline", "b0", "b1"}) {
            PhaseResult entry = run_phase(topology.ingress->fd(), topology.sink->fd(), kind, mss_count, options);
            if (kind == "baseline") {
                baseline = entry;
                baselines.push_back(entry);
            } else {
                if (baseline.payload_bytes > 0 && entry.payload_bytes > 0) {
                    const double baseline_writer_ns_per_byte = static_cast<double>(baseline.writer_cpu_ns) / baseline.payload_bytes;
                    const double candidate_writer_ns_per_byte = static_cast<double>(entry.writer_cpu_ns) / entry.payload_bytes;
                    entry.improvement_writer_cpu = baseline_writer_ns_per_byte / candidate_writer_ns_per_byte;
                    const double baseline_system_ns_per_byte = static_cast<double>(baseline.cpu_a_nonidle_ns) / baseline.payload_bytes;
                    const double candidate_system_ns_per_byte = static_cast<double>(entry.cpu_a_nonidle_ns) / entry.payload_bytes;
                    entry.improvement_cpu_a_system = baseline_system_ns_per_byte / candidate_system_ns_per_byte;
                }
                entries.push_back(entry);
            }
        }
        flush_sink(topology.sink->fd());
    }
    std::string out = "{\"mode\":\"bench\",\"cpu_a\":" + std::to_string(options.cpu_a) + ",\"cpu_b\":" + std::to_string(options.cpu_b) + ",\"duration_seconds\":" + std::to_string(options.duration_seconds) + ",\"entries\":[";
    bool first = true;
    for (const PhaseResult& entry : baselines) {
        if (!first) out += ",";
        first = false;
        out += render_entry(entry);
    }
    for (const PhaseResult& entry : entries) {
        if (!first) out += ",";
        first = false;
        out += render_entry(entry);
        const bool gate_writer = entry.kind == "b0" ? entry.improvement_writer_cpu >= 1.5 : entry.improvement_writer_cpu >= 1.25;
        const bool gate_system = entry.kind == "b0" ? entry.improvement_cpu_a_system >= 1.4 : entry.improvement_cpu_a_system >= 1.2;
        const bool gate_clean = entry.sink_mismatch == 0 && entry.eagain == 0 && entry.short_write == 0 && entry.other_errors == 0;
        char gate[200];
        std::snprintf(gate, sizeof(gate), "{\"gate_for\":\"%s\",\"mss_count\":%zu,\"gate_writer\":%s,\"gate_system\":%s,\"gate_clean\":%s,\"gate_pass\":%s}",
            json_escape(entry.kind).c_str(), entry.mss_count, gate_writer ? "true" : "false", gate_system ? "true" : "false", gate_clean ? "true" : "false",
            gate_writer && gate_system && gate_clean ? "true" : "false");
        out += ",";
        out += gate;
    }
    out += "]}";
    return out;
}

std::string run_self_test() {
    std::string out = "{\"mode\":\"self-test\",\"status\":\"pass\",\"cases\":[";
    for (const size_t mss_count : {1U, 2U, 4U, 8U, 16U}) {
        std::vector<std::vector<uint8_t>> baseline;
        for (size_t i = 0; i < mss_count; ++i) baseline.push_back(make_tcp_packet(static_cast<uint16_t>(kMss), kInitialSequence + i * kMss));
        for (const std::vector<uint8_t>& packet : baseline) {
            if (!valid_ipv4(packet)) throw std::runtime_error("baseline packet checksum invalid");
        }
        const std::vector<uint8_t> b0 = make_superpacket(mss_count, kInitialSequence);
        std::string reason;
        const std::vector<uint8_t> b1 = build_superpacket_from(baseline, &reason);
        if (b1.empty()) throw std::runtime_error("b1 build failed: " + reason);
        if (b1 != b0) {
            size_t offset = 0;
            while (offset < std::min(b1.size(), b0.size()) && b1[offset] == b0[offset]) ++offset;
            std::string dump;
            for (size_t i = (offset > 6 ? offset - 6 : 0); i < std::min(offset + 6, std::min(b1.size(), b0.size())); ++i) {
                dump += " @" + std::to_string(i) + ":" + std::to_string(static_cast<int>(b1[i])) + "/" + std::to_string(static_cast<int>(b0[i]));
            }
            throw std::runtime_error("b1 build differs from b0 superpacket at offset " + std::to_string(offset) + dump);
        }
        if (b1.size() != kVirtioHeaderSize + kHeaderSize + mss_count * kMss) throw std::runtime_error("superpacket length contract failed");
        // Rejection paths must refuse incompatible packets.
        if (mss_count >= 2) {
            std::vector<std::vector<uint8_t>> broken = baseline;
            broken[1] = make_tcp_packet(static_cast<uint16_t>(kMss), kInitialSequence + (mss_count + 3U) * kMss);
            if (!build_superpacket_from(broken, &reason).empty() || reason != "seq_gap") {
                throw std::runtime_error("seq_gap rejection failed");
            }
        }
        char buffer[64];
        std::snprintf(buffer, sizeof(buffer), "{\"mss_count\":%zu},", mss_count);
        out += buffer;
    }
    out.resize(out.size() - 1);
    out += "]}";
    return out;
}

std::string option_value(int& index, int argc, char** argv, std::string_view name) {
    const std::string current = argv[index];
    const std::string prefix = std::string(name) + "=";
    if (current.rfind(prefix, 0) == 0) return current.substr(prefix.size());
    if (current == name && index + 1 < argc) return argv[++index];
    throw std::runtime_error("missing value for " + std::string(name));
}
} // namespace

int main(int argc, char** argv) {
    try {
        Options options;
        std::string mode;
        for (int index = 1; index < argc; ++index) {
            const std::string_view argument = argv[index];
            if (argument == "--self-test" || argument == "--execute" || argument == "--bench") mode = std::string(argument);
            else if (argument.rfind("--duration-seconds", 0) == 0) options.duration_seconds = std::stod(option_value(index, argc, argv, "--duration-seconds"));
            else if (argument.rfind("--warmup-seconds", 0) == 0) options.warmup_seconds = std::stod(option_value(index, argc, argv, "--warmup-seconds"));
            else if (argument.rfind("--cpu-a", 0) == 0) options.cpu_a = std::stoi(option_value(index, argc, argv, "--cpu-a"));
            else if (argument.rfind("--cpu-b", 0) == 0) options.cpu_b = std::stoi(option_value(index, argc, argv, "--cpu-b"));
            else if (argument.rfind("--max-segments-per-second", 0) == 0) options.max_segments_per_second = std::stod(option_value(index, argc, argv, "--max-segments-per-second"));
            else if (argument.rfind("--json-out", 0) == 0) options.json_out = option_value(index, argc, argv, "--json-out");
            else if (argument == "--help") { std::cout << "usage: bm_tun_gso --self-test|--execute|--bench [--duration-seconds N] [--warmup-seconds N] [--cpu-a N] [--cpu-b N] [--json-out PATH]\n"; return 0; }
            else throw std::runtime_error("unknown option: " + std::string(argument));
        }
        if (mode.empty()) {
            std::cout << "usage: bm_tun_gso --self-test|--execute|--bench\n";
            return 2;
        }
        std::string out;
        int status = 0;
        if (mode == "--self-test") out = run_self_test();
        else if (mode == "--execute") out = run_contract();
        else out = run_bench(options);
        std::cout << out << "\n";
        if (!options.json_out.empty()) {
            std::ofstream output(options.json_out);
            if (!output) throw std::runtime_error("cannot open JSON output: " + options.json_out);
            output << out << "\n";
            if (!output) throw std::runtime_error("cannot write JSON output: " + options.json_out);
        }
        return status;
    } catch (const SystemError& error) {
        if (limitation_errno(error.code())) { print_unsupported(error.what()); return kUnsupported; }
        std::cout << "{\"status\":\"failure\",\"error\":\"" << json_escape(error.what()) << "\"}\n";
        return 1;
    } catch (const std::exception& error) {
        std::cout << "{\"status\":\"failure\",\"error\":\"" << json_escape(error.what()) << "\"}\n";
        return 1;
    }
}

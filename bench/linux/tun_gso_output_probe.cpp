// Isolated Linux TUN GSO output probe.  It intentionally does not use any
// production tunnel wrapper and --execute creates all state in a private netns.
#if !defined(__linux__)
#error "tun_gso_output_probe is Linux-only"
#endif

#include <arpa/inet.h>
#include <endian.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
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
#include <unistd.h>

#include "linux/ppp/tap/TapGsoCoalescer.h"
#include "linux/ppp/tap/TapVnetCodec.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
constexpr size_t kIpv4HeaderSize = 20;
constexpr size_t kTcpHeaderSize = 20;
constexpr size_t kVirtioHeaderSize = sizeof(virtio_net_hdr);
constexpr uint16_t kMss = 512;
constexpr uint32_t kSourceAddress = 0x0a2a0001U;      // 10.42.0.1
constexpr uint32_t kDestinationAddress = 0x0a2a0002U; // 10.42.0.2
constexpr uint16_t kSourcePort = 40000;
constexpr uint16_t kDestinationPort = 40001;
constexpr uint32_t kInitialSequence = 0x10203040U;
constexpr int kUnsupported = 77;

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
    Fd(Fd&& other) noexcept : fd_(other.release()) {}
    Fd& operator=(Fd&& other) noexcept { if (this != &other) { reset(other.release()); } return *this; }
    ~Fd() { reset(); }
    int get() const { return fd_; }
    int release() { const int value = fd_; fd_ = -1; return value; }
    void reset(int value = -1) { if (fd_ >= 0) { close(fd_); } fd_ = value; }
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

struct Superpacket {
    std::vector<uint8_t> bytes;
    size_t payload_bytes = 0;
};

uint8_t payload_byte(size_t offset) { return static_cast<uint8_t>((offset * 37U + 11U) & 0xffU); }

enum class ChecksumMode {
    Partial,
    Complete,
};

const char* checksum_mode_name(ChecksumMode mode) {
    return mode == ChecksumMode::Complete ? "complete" : "partial";
}

Superpacket make_superpacket(size_t mss_count, ChecksumMode checksum_mode = ChecksumMode::Partial) {
    if (mss_count == 0) throw std::runtime_error("MSS count must be positive");
    const size_t payload_bytes = mss_count * kMss;
    Superpacket result;
    result.payload_bytes = payload_bytes;
    result.bytes.assign(kVirtioHeaderSize + kIpv4HeaderSize + kTcpHeaderSize + payload_bytes, 0);
    auto* virtio = reinterpret_cast<virtio_net_hdr*>(result.bytes.data());
    virtio->flags = checksum_mode == ChecksumMode::Partial ? VIRTIO_NET_HDR_F_NEEDS_CSUM : 0;
    virtio->gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
    virtio->hdr_len = htole16(kIpv4HeaderSize + kTcpHeaderSize);
    virtio->gso_size = htole16(kMss);
    if (checksum_mode == ChecksumMode::Partial) {
        virtio->csum_start = htole16(kIpv4HeaderSize);
        virtio->csum_offset = htole16(16);
    }

    uint8_t* ip = result.bytes.data() + kVirtioHeaderSize;
    ip[0] = 0x45;
    put16(ip + 2, static_cast<uint16_t>(kIpv4HeaderSize + kTcpHeaderSize + payload_bytes));
    put16(ip + 4, 0x4242);
    put16(ip + 6, 0x4000);
    ip[8] = 64;
    ip[9] = IPPROTO_TCP;
    put32(ip + 12, kSourceAddress);
    put32(ip + 16, kDestinationAddress);
    put16(ip + 10, checksum(ip, kIpv4HeaderSize));

    uint8_t* tcp = ip + kIpv4HeaderSize;
    put16(tcp, kSourcePort);
    put16(tcp + 2, kDestinationPort);
    put32(tcp + 4, kInitialSequence);
    put32(tcp + 8, 0);
    tcp[12] = 0x50;
    tcp[13] = 0x18;
    put16(tcp + 14, 65535);
    for (size_t i = 0; i < payload_bytes; ++i) tcp[kTcpHeaderSize + i] = payload_byte(i);

    if (checksum_mode == ChecksumMode::Partial) {
        // TUN_F_CSUM requires the one's-complement partial checksum, not a final TCP checksum.
        const uint8_t pseudo[] = {0, IPPROTO_TCP, static_cast<uint8_t>((kTcpHeaderSize + payload_bytes) >> 8U), static_cast<uint8_t>(kTcpHeaderSize + payload_bytes)};
        uint32_t partial = checksum_sum(ip + 12, 8);
        partial = checksum_sum(pseudo, sizeof(pseudo), partial);
        // The transport checksum field holds the uncomplemented pseudo-header seed;
        // the kernel adds TCP header/payload while performing checksum/GSO work.
        put16(tcp + 16, static_cast<uint16_t>(~fold_checksum(partial)));
    } else {
        put16(tcp + 16, tcp_checksum(ip, tcp, kTcpHeaderSize + payload_bytes));
    }
    return result;
}

void verify_segment(const uint8_t* packet, size_t size, size_t payload_offset, size_t expected_payload) {
    if (size != kIpv4HeaderSize + kTcpHeaderSize + expected_payload) throw std::runtime_error("unexpected segment length");
    if (packet[0] != 0x45 || get16(packet + 2) != size || packet[9] != IPPROTO_TCP) throw std::runtime_error("invalid IPv4 segment metadata");
    if (checksum(packet, kIpv4HeaderSize) != 0) throw std::runtime_error("invalid IPv4 checksum");
    const uint8_t* tcp = packet + kIpv4HeaderSize;
    if (get16(tcp) != kSourcePort || get16(tcp + 2) != kDestinationPort) throw std::runtime_error("unexpected TCP ports");
    if (get32(tcp + 4) != kInitialSequence + payload_offset) throw std::runtime_error("unexpected TCP sequence");
    if (tcp_checksum(packet, tcp, kTcpHeaderSize + expected_payload) != 0) throw std::runtime_error("invalid TCP checksum");
    for (size_t i = 0; i < expected_payload; ++i) if (tcp[kTcpHeaderSize + i] != payload_byte(payload_offset + i)) throw std::runtime_error("unexpected TCP payload");
}

void verify_contract(size_t mss_count, ChecksumMode checksum_mode) {
    const Superpacket superpacket = make_superpacket(mss_count, checksum_mode);
    if (superpacket.bytes.size() != kVirtioHeaderSize + kIpv4HeaderSize + kTcpHeaderSize + mss_count * kMss) throw std::runtime_error("superpacket length contract failed");
    const auto* virtio = reinterpret_cast<const virtio_net_hdr*>(superpacket.bytes.data());
    const uint8_t expected_flags = checksum_mode == ChecksumMode::Partial ? VIRTIO_NET_HDR_F_NEEDS_CSUM : 0;
    const uint16_t expected_csum_start = checksum_mode == ChecksumMode::Partial ? kIpv4HeaderSize : 0;
    const uint16_t expected_csum_offset = checksum_mode == ChecksumMode::Partial ? 16 : 0;
    if (virtio->flags != expected_flags || virtio->gso_type != VIRTIO_NET_HDR_GSO_TCPV4 || le16toh(virtio->hdr_len) != 40 || le16toh(virtio->gso_size) != kMss || le16toh(virtio->csum_start) != expected_csum_start || le16toh(virtio->csum_offset) != expected_csum_offset) throw std::runtime_error("virtio GSO metadata contract failed");
    const uint8_t* ip = superpacket.bytes.data() + kVirtioHeaderSize;
    const uint8_t* tcp = ip + kIpv4HeaderSize;
    if (checksum_mode == ChecksumMode::Partial) {
        const uint8_t pseudo[] = {0, IPPROTO_TCP, static_cast<uint8_t>((kTcpHeaderSize + superpacket.payload_bytes) >> 8U), static_cast<uint8_t>(kTcpHeaderSize + superpacket.payload_bytes)};
        const uint16_t expected_partial = static_cast<uint16_t>(~fold_checksum(checksum_sum(pseudo, sizeof(pseudo), checksum_sum(ip + 12, 8))));
        if (get16(tcp + 16) != expected_partial) throw std::runtime_error("TCP partial checksum contract failed");
        if (tcp_checksum(ip, tcp, kTcpHeaderSize + superpacket.payload_bytes) == 0) throw std::runtime_error("TCP checksum was finalized instead of partial");
    } else if (tcp_checksum(ip, tcp, kTcpHeaderSize + superpacket.payload_bytes) != 0) {
        throw std::runtime_error("TCP complete checksum contract failed");
    }
    for (size_t offset = 0; offset < superpacket.payload_bytes; offset += kMss) {
        const size_t length = std::min<size_t>(kMss, superpacket.payload_bytes - offset);
        std::vector<uint8_t> packet(kIpv4HeaderSize + kTcpHeaderSize + length);
        std::memcpy(packet.data(), ip, kIpv4HeaderSize + kTcpHeaderSize);
        put16(packet.data() + 2, static_cast<uint16_t>(packet.size()));
        put16(packet.data() + 10, 0);
        put16(packet.data() + 10, checksum(packet.data(), kIpv4HeaderSize));
        std::memcpy(packet.data() + kIpv4HeaderSize + kTcpHeaderSize, tcp + kTcpHeaderSize + offset, length);
        put32(packet.data() + kIpv4HeaderSize + 4, kInitialSequence + offset);
        put16(packet.data() + kIpv4HeaderSize + 16, 0);
        put16(packet.data() + kIpv4HeaderSize + 16, tcp_checksum(packet.data(), packet.data() + kIpv4HeaderSize, kTcpHeaderSize + length));
        verify_segment(packet.data(), packet.size(), offset, length);
    }
}

struct PacketExpectation {
    uint32_t sequence = 0;
    uint32_t acknowledgement = 0;
    uint8_t flags = 0;
    size_t payload_offset = 0;
    size_t payload_bytes = 0;
};

std::vector<uint8_t> make_packet(const PacketExpectation& expected) {
    std::vector<uint8_t> packet(kIpv4HeaderSize + kTcpHeaderSize + expected.payload_bytes, 0);
    uint8_t* ip = packet.data();
    ip[0] = 0x45;
    put16(ip + 2, static_cast<uint16_t>(packet.size()));
    put16(ip + 4, 0x4242);
    put16(ip + 6, 0x4000);
    ip[8] = 64;
    ip[9] = IPPROTO_TCP;
    put32(ip + 12, kSourceAddress);
    put32(ip + 16, kDestinationAddress);
    put16(ip + 10, checksum(ip, kIpv4HeaderSize));
    uint8_t* tcp = ip + kIpv4HeaderSize;
    put16(tcp, kSourcePort);
    put16(tcp + 2, kDestinationPort);
    put32(tcp + 4, expected.sequence);
    put32(tcp + 8, expected.acknowledgement);
    tcp[12] = 0x50;
    tcp[13] = expected.flags;
    put16(tcp + 14, 65535);
    for (size_t i = 0; i < expected.payload_bytes; ++i) tcp[kTcpHeaderSize + i] = payload_byte(expected.payload_offset + i);
    put16(tcp + 16, tcp_checksum(ip, tcp, kTcpHeaderSize + expected.payload_bytes));
    return packet;
}

void verify_expected_packet(const uint8_t* packet, size_t size, const PacketExpectation& expected) {
    if (size != kIpv4HeaderSize + kTcpHeaderSize + expected.payload_bytes) throw std::runtime_error("unexpected production segment length");
    if (packet[0] != 0x45 || get16(packet + 2) != size || packet[9] != IPPROTO_TCP || checksum(packet, kIpv4HeaderSize) != 0) throw std::runtime_error("invalid production IPv4 segment");
    const uint8_t* tcp = packet + kIpv4HeaderSize;
    if (get16(tcp) != kSourcePort || get16(tcp + 2) != kDestinationPort || get32(tcp + 4) != expected.sequence || get32(tcp + 8) != expected.acknowledgement || tcp[12] != 0x50 || tcp[13] != expected.flags) throw std::runtime_error("unexpected production TCP metadata");
    if (tcp_checksum(packet, tcp, kTcpHeaderSize + expected.payload_bytes) != 0) throw std::runtime_error("invalid production TCP checksum");
    for (size_t i = 0; i < expected.payload_bytes; ++i) if (tcp[kTcpHeaderSize + i] != payload_byte(expected.payload_offset + i)) throw std::runtime_error("unexpected production TCP payload");
}

struct ProductionScenario {
    std::string name;
    std::vector<PacketExpectation> packets;
    size_t expected_gso = 0;
    size_t expected_ordinary = 0;
};

std::vector<ProductionScenario> production_scenarios() {
    constexpr uint32_t kAcknowledgement = 0x55667788U;
    const auto data = [](size_t offset, size_t bytes, uint8_t flags = 0x10) { return PacketExpectation{kInitialSequence + static_cast<uint32_t>(offset), kAcknowledgement, flags, offset, bytes}; };
    return {
        {"cap4", {data(0, 512), data(512, 512), data(1024, 512), data(1536, 512)}, 1, 0},
        {"short_tail", {data(0, 512), data(512, 512), data(1024, 512), data(1536, 173)}, 1, 0},
        {"psh_insert", {data(0, 512), data(512, 512, 0x18), data(1024, 512)}, 0, 3},
        {"ack_only_insert", {data(0, 512), {kInitialSequence + 512, kAcknowledgement + 1, 0x10, 0, 0}, data(512, 512)}, 0, 3},
    };
}

bool is_gso_frame(const uint8_t* frame, size_t size) {
    return size >= kVirtioHeaderSize && reinterpret_cast<const virtio_net_hdr*>(frame)->gso_type == VIRTIO_NET_HDR_GSO_TCPV4;
}

struct WriterCounts {
    size_t gso = 0;
    size_t ordinary = 0;
    void record(const uint8_t* frame, size_t size) { if (is_gso_frame(frame, size)) ++gso; else ++ordinary; }
};

void verify_gso_frame(const std::vector<uint8_t>& frame, const std::vector<PacketExpectation>& expected) {
    if (expected.empty() || frame.size() < kVirtioHeaderSize + kIpv4HeaderSize + kTcpHeaderSize) throw std::runtime_error("short production GSO frame");
    const auto* virtio = reinterpret_cast<const virtio_net_hdr*>(frame.data());
    if (virtio->flags != VIRTIO_NET_HDR_F_NEEDS_CSUM || virtio->gso_type != VIRTIO_NET_HDR_GSO_TCPV4 || le16toh(virtio->hdr_len) != 40 || le16toh(virtio->gso_size) != kMss || le16toh(virtio->csum_start) != 20 || le16toh(virtio->csum_offset) != 16) throw std::runtime_error("invalid production GSO metadata");
    size_t total_payload = 0;
    for (const PacketExpectation& item : expected) {
        if (item.payload_bytes == 0 || item.payload_bytes > kMss || item.flags != 0x10) throw std::runtime_error("unexpected production GSO input");
        total_payload += item.payload_bytes;
    }
    if (frame.size() != kVirtioHeaderSize + kIpv4HeaderSize + kTcpHeaderSize + total_payload) throw std::runtime_error("unexpected production GSO frame length");
    const uint8_t* ip = frame.data() + kVirtioHeaderSize;
    const uint8_t* tcp = ip + kIpv4HeaderSize;
    if (get16(ip + 2) != kIpv4HeaderSize + kTcpHeaderSize + total_payload || checksum(ip, kIpv4HeaderSize) != 0 || get32(tcp + 4) != expected.front().sequence || get32(tcp + 8) != expected.front().acknowledgement || tcp[13] != 0x10) throw std::runtime_error("invalid production GSO packet metadata");
    size_t payload_offset = 0;
    for (const PacketExpectation& item : expected) {
        std::vector<uint8_t> segment(kIpv4HeaderSize + kTcpHeaderSize + item.payload_bytes);
        std::memcpy(segment.data(), ip, kIpv4HeaderSize + kTcpHeaderSize);
        put16(segment.data() + 2, static_cast<uint16_t>(segment.size()));
        put16(segment.data() + 10, 0);
        put16(segment.data() + 10, checksum(segment.data(), kIpv4HeaderSize));
        put32(segment.data() + kIpv4HeaderSize + 4, item.sequence);
        std::memcpy(segment.data() + kIpv4HeaderSize + kTcpHeaderSize, tcp + kTcpHeaderSize + payload_offset, item.payload_bytes);
        put16(segment.data() + kIpv4HeaderSize + 16, 0);
        put16(segment.data() + kIpv4HeaderSize + 16, tcp_checksum(segment.data(), segment.data() + kIpv4HeaderSize, kTcpHeaderSize + item.payload_bytes));
        verify_expected_packet(segment.data(), segment.size(), item);
        payload_offset += item.payload_bytes;
    }
}

void verify_production_frames(const ProductionScenario& scenario, const std::vector<std::vector<uint8_t>>& frames, const WriterCounts& counts) {
    if (counts.gso != scenario.expected_gso || counts.ordinary != scenario.expected_ordinary) throw std::runtime_error("unexpected production writer frame counts");
    size_t expected_index = 0;
    for (const auto& frame : frames) {
        if (is_gso_frame(frame.data(), frame.size())) {
            if (expected_index != 0 || scenario.expected_gso != 1) throw std::runtime_error("unexpected production GSO frame placement");
            verify_gso_frame(frame, scenario.packets);
            expected_index = scenario.packets.size();
        } else {
            if (frame.size() < kVirtioHeaderSize || expected_index == scenario.packets.size()) throw std::runtime_error("unexpected production ordinary frame");
            const auto* virtio = reinterpret_cast<const virtio_net_hdr*>(frame.data());
            if (virtio->flags != 0 || virtio->gso_type != 0) throw std::runtime_error("ordinary production frame has offload metadata");
            verify_expected_packet(frame.data() + kVirtioHeaderSize, frame.size() - kVirtioHeaderSize, scenario.packets[expected_index++]);
        }
    }
    if (expected_index != scenario.packets.size()) throw std::runtime_error("production writer omitted packets");
}

void verify_production_builder_logical() {
    if (ppp::tap::TunGsoCoalescer::kSegmentCap != 4) throw std::runtime_error("production coalescer cap contract changed");
    for (const ProductionScenario& scenario : production_scenarios()) {
        std::vector<std::vector<uint8_t>> frames;
        WriterCounts counts;
        ppp::tap::TunGsoCoalescer coalescer([&](const uint8_t* frame, size_t size) -> ssize_t {
            counts.record(frame, size); frames.emplace_back(frame, frame + size); return static_cast<ssize_t>(size);
        });
        for (size_t index = 0; index < scenario.packets.size(); ++index) {
            const std::vector<uint8_t> packet = make_packet(scenario.packets[index]);
            if (!coalescer.Push(packet.data(), packet.size(), 1000 + index)) throw std::runtime_error("production coalescer rejected " + scenario.name);
        }
        if (!coalescer.Flush()) throw std::runtime_error("production coalescer flush failed " + scenario.name);
        verify_production_frames(scenario, frames, counts);
    }
}

void verify_inbound_vnet_codec_contract() {
    const Superpacket superpacket = make_superpacket(2);
    std::vector<uint8_t> gso_frame = superpacket.bytes;
    ppp::tap::vnet::TcpV4GsoFrame gso;
    if (!ppp::tap::vnet::ParseTcpV4Gso(gso_frame.data(), gso_frame.size(), kVirtioHeaderSize, 1500, gso)) {
        throw std::runtime_error("inbound TCPv4 GSO metadata contract failed");
    }
    std::array<uint8_t, 1500> segment{};
    size_t segment_size = 0;
    if (!ppp::tap::vnet::BuildTcpV4GsoSegment(gso, 0, segment.data(), segment.size(), segment_size) || segment_size != 20 + 20 + kMss) {
        throw std::runtime_error("inbound TCPv4 GSO segmentation contract failed");
    }
    verify_segment(segment.data(), segment_size, 0, kMss);

    virtio_net_hdr bad_header{};
    std::memcpy(&bad_header, gso_frame.data(), sizeof(bad_header));
    bad_header.csum_start = htole16(19);
    std::memcpy(gso_frame.data(), &bad_header, sizeof(bad_header));
    if (ppp::tap::vnet::ParseTcpV4Gso(gso_frame.data(), gso_frame.size(), kVirtioHeaderSize, 1500, gso)) {
        throw std::runtime_error("inbound TCPv4 GSO accepted invalid checksum offset");
    }

    const PacketExpectation expected{kInitialSequence, 0x55667788U, 0x18, 0, 23};
    const std::vector<uint8_t> packet = make_packet(expected);
    std::vector<uint8_t> checksum_frame(kVirtioHeaderSize, 0);
    virtio_net_hdr checksum_header{};
    checksum_header.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    checksum_header.gso_type = VIRTIO_NET_HDR_GSO_NONE;
    checksum_header.csum_start = htole16(kIpv4HeaderSize);
    checksum_header.csum_offset = htole16(16);
    std::memcpy(checksum_frame.data(), &checksum_header, sizeof(checksum_header));
    checksum_frame.insert(checksum_frame.end(), packet.begin(), packet.end());
    put16(checksum_frame.data() + kVirtioHeaderSize + kIpv4HeaderSize + 16, 0x1234);
    if (!ppp::tap::vnet::CompleteChecksumOnlyTcpV4(checksum_frame.data(), checksum_frame.size(), kVirtioHeaderSize)) {
        throw std::runtime_error("inbound checksum-only TCPv4 contract failed");
    }
    verify_expected_packet(checksum_frame.data() + kVirtioHeaderSize, packet.size(), expected);
}

class Netlink {
public:
    Netlink() : fd_(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)) { if (fd_.get() < 0) throw SystemError("netlink socket", errno); }
    void link_up(const std::string& name) { change_link(name, IFF_UP, IFF_UP); }
    void address(const std::string& name, uint32_t host_address) {
        const int index = if_nametoindex(name.c_str()); if (!index) throw SystemError("if_nametoindex", errno);
        request(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, [&](std::vector<uint8_t>& message) {
            auto* info = append<ifaddrmsg>(message); info->ifa_family = AF_INET; info->ifa_prefixlen = 32; info->ifa_index = index;
            const uint32_t wire = htonl(host_address); attribute(message, IFA_LOCAL, &wire, sizeof(wire)); attribute(message, IFA_ADDRESS, &wire, sizeof(wire));
        });
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
    void change_link(const std::string& name, unsigned int change, unsigned int flags) {
        const int index = if_nametoindex(name.c_str()); if (!index) throw SystemError("if_nametoindex", errno);
        request(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, [&](std::vector<uint8_t>& message) { auto* info = append<ifinfomsg>(message); info->ifi_family = AF_UNSPEC; info->ifi_index = index; info->ifi_change = change; info->ifi_flags = flags; });
    }
    template<typename Fill> void request(uint16_t type, uint16_t flags, Fill fill) {
        std::vector<uint8_t> message(NLMSG_SPACE(0), 0); auto* header = reinterpret_cast<nlmsghdr*>(message.data()); header->nlmsg_len = NLMSG_LENGTH(0); header->nlmsg_type = type; header->nlmsg_flags = flags; header->nlmsg_seq = ++sequence_; fill(message); header = reinterpret_cast<nlmsghdr*>(message.data()); header->nlmsg_len = message.size();
        sockaddr_nl address{}; address.nl_family = AF_NETLINK;
        if (sendto(fd_.get(), message.data(), header->nlmsg_len, 0, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) throw SystemError("netlink request", errno);
        std::array<uint8_t, 4096> reply{}; const ssize_t received = recv(fd_.get(), reply.data(), reply.size(), 0); if (received < 0) throw SystemError("netlink reply", errno);
        int remaining = static_cast<int>(received);
        for (nlmsghdr* current = reinterpret_cast<nlmsghdr*>(reply.data()); NLMSG_OK(current, remaining); current = NLMSG_NEXT(current, remaining)) { if (current->nlmsg_type == NLMSG_ERROR) { const auto* error = reinterpret_cast<const nlmsgerr*>(NLMSG_DATA(current)); if (error->error != 0) throw SystemError("netlink operation", -error->error); return; } }
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

// After unshare(CLONE_NEWNET), a previously mounted procfs still exposes the
// sysctls of the ORIGINAL network namespace. Remount procfs so sysctl writes
// reach this namespace only. Returns false when isolation is impossible;
// callers must not touch sysctls in that case.
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

bool limitation_errno(int code) { return code == EPERM || code == EACCES || code == ENODEV || code == EOPNOTSUPP || code == ENOTTY || code == EINVAL; }
void print_unsupported(const std::string& reason) { std::cout << "{\"mode\":\"execute\",\"status\":\"unsupported\",\"reason\":\"" << reason << "\"}\n"; }

std::string lengths_json(const std::vector<size_t>& lengths) {
    std::string json = "[";
    for (size_t index = 0; index < lengths.size(); ++index) {
        if (index != 0) json += ",";
        json += std::to_string(lengths[index]);
    }
    return json + "]";
}

std::vector<size_t> expected_lengths(size_t mss_count) {
    return std::vector<size_t>(mss_count, kIpv4HeaderSize + kTcpHeaderSize + kMss);
}

std::string hex_dump(const uint8_t* bytes, size_t size) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    const size_t limit = std::min<size_t>(size, 24);
    for (size_t index = 0; index < limit; ++index) {
        out += digits[bytes[index] >> 4U];
        out += digits[bytes[index] & 0xfU];
    }
    return out;
}

class CaseError : public std::runtime_error {
public:
    CaseError(size_t mss_count, std::vector<size_t> observed, std::vector<size_t> noise, std::string noise_hex, const std::string& error)
        : std::runtime_error(error), mss_count(mss_count), observed_lengths(std::move(observed)), noise_lengths(std::move(noise)), first_noise_hex(std::move(noise_hex)) {}
    size_t mss_count;
    std::vector<size_t> observed_lengths;
    std::vector<size_t> noise_lengths;
    std::string first_noise_hex;
};

struct CaseResult {
    size_t mss_count = 0;
    std::vector<size_t> observed_lengths;
    std::vector<size_t> noise_lengths;
    std::string first_noise_hex;
};

CaseResult run_case(int ingress_fd, int sink_fd, size_t mss_count) {
    const Superpacket superpacket = make_superpacket(mss_count, ChecksumMode::Complete);
    if (write(ingress_fd, superpacket.bytes.data(), superpacket.bytes.size()) != static_cast<ssize_t>(superpacket.bytes.size())) throw SystemError("write GSO superpacket", errno);
    CaseResult result; result.mss_count = mss_count;
    size_t payload_offset = 0;
    while (payload_offset < superpacket.payload_bytes) {
        pollfd wait{sink_fd, POLLIN, 0};
        if (poll(&wait, 1, 2000) <= 0) {
            // Diagnose the drop: any ICMP error generated by the forward path
            // is delivered back through the ingress fd, not the sink.
            std::string drained;
            for (;;) {
                pollfd check{ingress_fd, POLLIN, 0};
                if (poll(&check, 1, 0) <= 0) break;
                std::array<uint8_t, 65536> extra{};
                const ssize_t got = read(ingress_fd, extra.data(), extra.size());
                if (got <= 0) break;
                if (drained.empty()) drained = hex_dump(extra.data(), static_cast<size_t>(got));
            }
            std::string message = "timed out waiting for sink packet";
            if (!drained.empty()) message += " [ingress drained head: " + drained + "]";
            throw CaseError(mss_count, std::move(result.observed_lengths), std::move(result.noise_lengths), std::move(result.first_noise_hex), message);
        }
        std::array<uint8_t, 65536> received{};
        const ssize_t length = read(sink_fd, received.data(), received.size());
        if (length < 0) throw SystemError("read sink packet", errno);
        // The private netns emits its own control traffic on link-up (for
        // example IPv6 Router Solicitations from the sink interface). It is
        // not part of the GSO contract, so skip non-IPv4 frames instead of
        // counting them as segments.
        if (length < 1 || (received[0] >> 4U) != 4) {
            if (result.first_noise_hex.empty()) result.first_noise_hex = hex_dump(received.data(), static_cast<size_t>(length));
            result.noise_lengths.push_back(static_cast<size_t>(length));
            continue;
        }
        result.observed_lengths.push_back(static_cast<size_t>(length));
        const size_t expected = std::min<size_t>(kMss, superpacket.payload_bytes - payload_offset);
        try {
            verify_segment(received.data(), static_cast<size_t>(length), payload_offset, expected);
        } catch (const std::exception& error) {
            throw CaseError(mss_count, std::move(result.observed_lengths), std::move(result.noise_lengths), std::move(result.first_noise_hex), std::string(error.what()) + " [packet head: " + hex_dump(received.data(), static_cast<size_t>(length)) + "]");
        }
        payload_offset += expected;
    }
    if (result.observed_lengths.size() != mss_count) throw CaseError(mss_count, std::move(result.observed_lengths), std::move(result.noise_lengths), std::move(result.first_noise_hex), "unexpected segment count");
    return result;
}

class ProductionCaseError : public std::runtime_error {
public:
    ProductionCaseError(std::string case_name, WriterCounts counts, std::vector<size_t> observed, std::vector<size_t> noise, std::string noise_hex, const std::string& error)
        : std::runtime_error(error), name(std::move(case_name)), writer_counts(counts), observed_lengths(std::move(observed)), noise_lengths(std::move(noise)), first_noise_hex(std::move(noise_hex)) {}
    std::string name;
    WriterCounts writer_counts;
    std::vector<size_t> observed_lengths;
    std::vector<size_t> noise_lengths;
    std::string first_noise_hex;
};

struct ProductionCaseResult {
    std::string name;
    WriterCounts writer_counts;
    std::vector<size_t> observed_lengths;
    std::vector<size_t> noise_lengths;
    std::string first_noise_hex;
};

ProductionCaseResult run_production_builder_case(int ingress_fd, int sink_fd, const ProductionScenario& scenario) {
    ProductionCaseResult result; result.name = scenario.name;
    try {
        ppp::tap::TunGsoCoalescer coalescer([&](const uint8_t* frame, size_t size) -> ssize_t {
            result.writer_counts.record(frame, size);
            return write(ingress_fd, frame, size);
        });
        for (size_t index = 0; index < scenario.packets.size(); ++index) {
            const std::vector<uint8_t> packet = make_packet(scenario.packets[index]);
            if (!coalescer.Push(packet.data(), packet.size(), 1000 + index)) throw std::runtime_error("production coalescer write failed");
        }
        if (!coalescer.Flush()) throw std::runtime_error("production coalescer flush failed");
        if (result.writer_counts.gso != scenario.expected_gso || result.writer_counts.ordinary != scenario.expected_ordinary) throw std::runtime_error("unexpected production writer frame counts");
        size_t expected_index = 0;
        while (expected_index < scenario.packets.size()) {
            pollfd wait{sink_fd, POLLIN, 0};
            if (poll(&wait, 1, 2000) <= 0) {
                std::string drained;
                for (;;) {
                    pollfd check{ingress_fd, POLLIN, 0};
                    if (poll(&check, 1, 0) <= 0) break;
                    std::array<uint8_t, 65536> extra{};
                    const ssize_t got = read(ingress_fd, extra.data(), extra.size());
                    if (got <= 0) break;
                    if (drained.empty()) drained = hex_dump(extra.data(), static_cast<size_t>(got));
                }
                std::string message = "timed out waiting for production sink packet";
                if (!drained.empty()) message += " [ingress drained head: " + drained + "]";
                throw std::runtime_error(message);
            }
            std::array<uint8_t, 65536> received{};
            const ssize_t length = read(sink_fd, received.data(), received.size());
            if (length < 0) throw SystemError("read production sink packet", errno);
            if (length < 1 || (received[0] >> 4U) != 4) {
                if (result.first_noise_hex.empty()) result.first_noise_hex = hex_dump(received.data(), static_cast<size_t>(length));
                result.noise_lengths.push_back(static_cast<size_t>(length));
                continue;
            }
            result.observed_lengths.push_back(static_cast<size_t>(length));
            try {
                verify_expected_packet(received.data(), static_cast<size_t>(length), scenario.packets[expected_index]);
            } catch (const std::exception& error) {
                throw std::runtime_error(std::string(error.what()) + " [packet head: " + hex_dump(received.data(), static_cast<size_t>(length)) + "]");
            }
            ++expected_index;
        }
        return result;
    } catch (const SystemError&) {
        throw;
    } catch (const std::exception& error) {
        throw ProductionCaseError(scenario.name, result.writer_counts, std::move(result.observed_lengths), std::move(result.noise_lengths), std::move(result.first_noise_hex), error.what());
    }
}

int run_execute() {
    if (unshare(CLONE_NEWNET) != 0) { print_unsupported(std::string("unshare(CLONE_NEWNET): ") + std::strerror(errno)); return kUnsupported; }
    // Sysctl writes must never leak into another namespace: without a fresh
    // procfs mount they would target the original network namespace.
    if (!isolate_procfs_for_current_netns()) { print_unsupported("cannot mount a netns-private procfs for sysctl isolation"); return kUnsupported; }
    try {
        const std::string suffix = std::to_string(getpid() % 100000U);
        Tun ingress("gsoin" + suffix, true); Tun sink("gsout" + suffix, false);
        unsigned int features = 0;
        if (ioctl(ingress.fd(), TUNGETFEATURES, &features) != 0) throw SystemError("TUNGETFEATURES", errno);
        if ((features & IFF_VNET_HDR) == 0) { print_unsupported("IFF_VNET_HDR is unavailable"); return kUnsupported; }
        int header_size = kVirtioHeaderSize;
        if (ioctl(ingress.fd(), TUNSETVNETHDRSZ, &header_size) != 0) throw SystemError("TUNSETVNETHDRSZ", errno);
        int readback = 0; if (ioctl(ingress.fd(), TUNGETVNETHDRSZ, &readback) != 0) throw SystemError("TUNGETVNETHDRSZ", errno);
        if (readback != header_size) throw std::runtime_error("virtio header size readback mismatch");
        const unsigned int offloads = TUN_F_CSUM | TUN_F_TSO4;
        if (ioctl(ingress.fd(), TUNSETOFFLOAD, offloads) != 0) throw SystemError("TUNSETOFFLOAD", errno);
        Netlink netlink;
        netlink.link_up("lo");
        netlink.link_up(ingress.name());
        netlink.link_up(sink.name());
        // The injected source address must stay non-local: assigning it to the
        // ingress interface makes forwarded frames carrying it a martian, and
        // the kernel silently drops them before output. Keep the interface
        // unaddressed and disable rp_filter for the injected flow instead.
        write_sysctl("/proc/sys/net/ipv4/ip_forward", "1\n");
        write_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0\n");
        write_sysctl("/proc/sys/net/ipv4/conf/" + ingress.name() + "/rp_filter", "0\n");
        // kDestinationAddress must remain non-local so ingress traffic takes
        // this unicast route through sink instead of local input processing.
        netlink.route(kDestinationAddress, sink.name());
        std::vector<CaseResult> cases;
        for (const size_t mss_count : {2U, 4U, 8U, 16U}) cases.push_back(run_case(ingress.fd(), sink.fd(), mss_count));
        std::vector<ProductionCaseResult> production_cases;
        for (const ProductionScenario& scenario : production_scenarios()) production_cases.push_back(run_production_builder_case(ingress.fd(), sink.fd(), scenario));
        std::cout << "{\"mode\":\"execute\",\"status\":\"pass\",\"tun_features\":" << features << ",\"virtio_header_size\":" << readback << ",\"mss\":" << kMss << ",\"cases\":[";
        for (size_t index = 0; index < cases.size(); ++index) {
            if (index != 0) std::cout << ",";
            const CaseResult& result = cases[index];
            std::cout << "{\"checksum_mode\":\"" << checksum_mode_name(ChecksumMode::Complete) << "\",\"mss_count\":" << result.mss_count << ",\"expected_segments\":" << result.mss_count << ",\"expected_lengths\":" << lengths_json(expected_lengths(result.mss_count)) << ",\"observed_lengths\":" << lengths_json(result.observed_lengths) << ",\"noise_packets\":" << result.noise_lengths.size() << "}";
        }
        std::cout << "],\"production_builder_cases\":[";
        for (size_t index = 0; index < production_cases.size(); ++index) {
            if (index != 0) std::cout << ",";
            const ProductionCaseResult& result = production_cases[index];
            std::cout << "{\"name\":\"" << result.name << "\",\"writer_gso_count\":" << result.writer_counts.gso << ",\"writer_ordinary_count\":" << result.writer_counts.ordinary << ",\"observed_lengths\":" << lengths_json(result.observed_lengths) << ",\"noise_packets\":" << result.noise_lengths.size() << "}";
        }
        std::cout << "]}\n";
        return 0;
    } catch (const ProductionCaseError& error) {
        std::cout << "{\"mode\":\"execute\",\"status\":\"failure\",\"production_builder_case\":\"" << error.name << "\",\"writer_gso_count\":" << error.writer_counts.gso << ",\"writer_ordinary_count\":" << error.writer_counts.ordinary << ",\"observed_lengths\":" << lengths_json(error.observed_lengths) << ",\"noise_lengths\":" << lengths_json(error.noise_lengths) << ",\"first_noise_hex\":\"" << error.first_noise_hex << "\",\"error\":\"" << error.what() << "\"}\n";
        return 1;
    } catch (const CaseError& error) {
        std::cout << "{\"mode\":\"execute\",\"status\":\"failure\",\"case\":" << error.mss_count << ",\"expected\":{\"segments\":" << error.mss_count << ",\"packet_lengths\":" << lengths_json(expected_lengths(error.mss_count)) << "},\"observed_lengths\":" << lengths_json(error.observed_lengths) << ",\"noise_lengths\":" << lengths_json(error.noise_lengths) << ",\"first_noise_hex\":\"" << error.first_noise_hex << "\",\"error\":\"" << error.what() << "\"}\n";

        return 1;
    } catch (const SystemError& error) { if (limitation_errno(error.code())) { print_unsupported(error.what()); return kUnsupported; } throw; }
}

void usage() { std::cout << "usage: tun_gso_output_probe --self-test|--execute\n"; }
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 2) { usage(); return 2; }
        const std::string_view mode(argv[1]);
        if (mode == "--self-test") { for (const size_t count : {2U, 4U, 8U, 16U}) { verify_contract(count, ChecksumMode::Partial); verify_contract(count, ChecksumMode::Complete); } verify_production_builder_logical(); verify_inbound_vnet_codec_contract(); std::cout << "{\"mode\":\"self-test\",\"status\":\"pass\",\"mss\":512,\"checksum_modes\":[\"partial\",\"complete\"],\"segment_contracts\":[2,4,8,16],\"production_builder_cases\":[\"cap4\",\"short_tail\",\"psh_insert\",\"ack_only_insert\"],\"inbound_vnet_codec\":true}\n"; return 0; }
        if (mode == "--execute") return run_execute();
        usage(); return 2;
    } catch (const std::exception& error) { std::cout << "{\"status\":\"failure\",\"error\":\"" << error.what() << "\"}\n"; return 1; }
}

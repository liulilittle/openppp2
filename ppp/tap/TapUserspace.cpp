#include <ppp/tap/TapUserspace.h>
#include <ppp/tap/TapUserspaceRoute.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>

#include <cstring>

namespace ppp {
    namespace tap {
        static constexpr const char* kTapUserspaceDeviceId = "proxy-userspace";

        TapUserspace::TapUserspace(const std::shared_ptr<boost::asio::io_context>& context,
            const ppp::string& id,
            uint32_t ip,
            uint32_t gw,
            uint32_t mask) noexcept
            : ITap(context, id, INVALID_HANDLE_VALUE, ip, gw, mask, false) {
        }

        std::shared_ptr<TapUserspace> TapUserspace::Create(
            const std::shared_ptr<boost::asio::io_context>& context,
            uint32_t ip,
            uint32_t gw,
            uint32_t mask) noexcept {
            if (NULLPTR == context) {
                return NULLPTR;
            }

            return ppp::make_shared_object<TapUserspace>(context, kTapUserspaceDeviceId, ip, gw, mask);
        }

        bool TapUserspace::IsReady() noexcept {
            return NULLPTR != GetContext();
        }

        bool TapUserspace::IsOpen() noexcept {
            return opened_ && IsReady();
        }

        bool TapUserspace::SetInterfaceMtu(int /*mtu*/) noexcept {
            return true;
        }

        bool TapUserspace::Open() noexcept {
            if (!IsReady()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
            }

            if (opened_) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
            }

            opened_ = true;
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tap", "TapUserspace opened (proxy-only virtual subnet)");
            ppp::telemetry::Count("tap.userspace.open", 1);
            return true;
        }

        void TapUserspace::Dispose() noexcept {
            SetHostInput(NULLPTR);
            {
                std::lock_guard<std::mutex> scope(datagram_lock_);
                datagrams_.clear();
            }
            ITap::Dispose();
        }

        uint16_t TapUserspace::BindDatagram(const DatagramHandler& handler) noexcept {
            if (NULLPTR == handler) {
                return 0;
            }

            std::lock_guard<std::mutex> scope(datagram_lock_);
            // Ephemeral range 49152-65535; wraps and skips ports still in use.
            for (int attempt = 0; attempt < 16384; ++attempt) {
                const uint16_t port = next_datagram_port_;
                next_datagram_port_ = port == UINT16_MAX ? 49152 : static_cast<uint16_t>(port + 1);
                if (datagrams_.find(port) == datagrams_.end()) {
                    datagrams_.emplace(port, handler);
                    return port;
                }
            }
            return 0;
        }

        void TapUserspace::ReleaseDatagram(uint16_t port) noexcept {
            std::lock_guard<std::mutex> scope(datagram_lock_);
            datagrams_.erase(port);
        }

        /** @brief One's-complement sum used by the IPv4 and UDP checksums. */
        static uint32_t ChecksumAdd(uint32_t sum, const Byte* data, int length) noexcept {
            for (int i = 0; i + 1 < length; i += 2) {
                sum += static_cast<uint32_t>((data[i] << 8) | data[i + 1]);
            }
            if (length & 1) {
                sum += static_cast<uint32_t>(data[length - 1] << 8);
            }
            return sum;
        }

        static uint16_t ChecksumFinish(uint32_t sum) noexcept {
            while (sum >> 16) {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            return static_cast<uint16_t>(~sum & 0xffff);
        }

        bool TapUserspace::SendDatagram(uint16_t local_port, uint32_t destination, uint16_t destination_port,
            const void* payload, int length) noexcept {
            if (!opened_ || 0 == local_port || 0 == destination_port || NULLPTR == payload ||
                length < 0 || length > MaxDatagramPayload) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
            }

            constexpr int kIPv4Header = 20;
            constexpr int kUdpHeader = 8;
            const int total = kIPv4Header + kUdpHeader + length;
            Byte packet[kIPv4Header + kUdpHeader + MaxDatagramPayload];
            memset(packet, 0, kIPv4Header + kUdpHeader);

            uint16_t packet_id = 0;
            {
                std::lock_guard<std::mutex> scope(datagram_lock_);
                packet_id = next_packet_id_++;
            }

            const uint32_t source = IPAddress;
            packet[0] = 0x45;
            packet[2] = static_cast<Byte>(total >> 8);
            packet[3] = static_cast<Byte>(total);
            packet[4] = static_cast<Byte>(packet_id >> 8);
            packet[5] = static_cast<Byte>(packet_id);
            packet[8] = 64;
            packet[9] = 17;
            memcpy(packet + 12, &source, sizeof(source));
            memcpy(packet + 16, &destination, sizeof(destination));
            const uint16_t ip_checksum = ChecksumFinish(ChecksumAdd(0, packet, kIPv4Header));
            packet[10] = static_cast<Byte>(ip_checksum >> 8);
            packet[11] = static_cast<Byte>(ip_checksum);

            Byte* udp = packet + kIPv4Header;
            const int udp_length = kUdpHeader + length;
            udp[0] = static_cast<Byte>(local_port >> 8);
            udp[1] = static_cast<Byte>(local_port);
            udp[2] = static_cast<Byte>(destination_port >> 8);
            udp[3] = static_cast<Byte>(destination_port);
            udp[4] = static_cast<Byte>(udp_length >> 8);
            udp[5] = static_cast<Byte>(udp_length);
            if (length > 0) {
                memcpy(udp + kUdpHeader, payload, length);
            }

            // Pseudo header: source, destination, zero, protocol, UDP length.
            uint32_t sum = ChecksumAdd(0, packet + 12, 8);
            sum += 17;
            sum += static_cast<uint32_t>(udp_length);
            uint16_t udp_checksum = ChecksumFinish(ChecksumAdd(sum, udp, udp_length));
            if (0 == udp_checksum) {
                udp_checksum = 0xffff;
            }
            udp[6] = static_cast<Byte>(udp_checksum >> 8);
            udp[7] = static_cast<Byte>(udp_checksum);
            return RaiseHostOutput(packet, total);
        }

        bool TapUserspace::DispatchDatagram(const void* packet, int packet_size) noexcept {
            const Byte* bytes = static_cast<const Byte*>(packet);
            if (bytes[9] != 17) {
                return false;
            }

            const int header_length = (bytes[0] & 0x0f) * 4;
            if (packet_size < header_length + 8) {
                return true;
            }

            const Byte* udp = bytes + header_length;
            const uint16_t source_port = static_cast<uint16_t>((udp[0] << 8) | udp[1]);
            const uint16_t destination_port = static_cast<uint16_t>((udp[2] << 8) | udp[3]);
            const int udp_length = (udp[4] << 8) | udp[5];
            if (udp_length < 8 || header_length + udp_length > packet_size) {
                return true;
            }

            DatagramHandler handler;
            {
                std::lock_guard<std::mutex> scope(datagram_lock_);
                auto tail = datagrams_.find(destination_port);
                if (tail != datagrams_.end()) {
                    handler = tail->second;
                }
            }

            // Datagrams for unbound ports are dropped: the in-process TCP stack has no UDP.
            if (NULLPTR != handler) {
                uint32_t source = 0;
                memcpy(&source, bytes + 12, sizeof(source));
                handler(source, source_port, udp + 8, udp_length - 8);
            }
            return true;
        }

        void TapUserspace::SetHostInput(const HostInputHandler& handler) noexcept {
            std::lock_guard<std::mutex> scope(host_input_lock_);
            host_input_ = handler;
        }

        void TapUserspace::SetInboundTcpPorts(const std::unordered_set<uint16_t>& ports) noexcept {
            std::lock_guard<std::mutex> scope(inbound_lock_);
            inbound_tcp_ports_ = ports;
        }

        TapUserspace::HostInputHandler TapUserspace::GetHostInput() noexcept {
            std::lock_guard<std::mutex> scope(host_input_lock_);
            return host_input_;
        }

        bool TapUserspace::Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept {
            return Output(packet.get(), packet_size);
        }

        bool TapUserspace::Output(const void* packet, int packet_size) noexcept {
            if (!opened_) {
                return true;
            }

            switch (ClassifyTapUserspacePacket(packet, packet_size, IPAddress)) {
            case TapUserspaceRoute::Host: {
                if (DispatchDatagram(packet, packet_size)) {
                    return true;
                }

                HostInputHandler host_input = GetHostInput();
                return NULLPTR == host_input || host_input(packet, packet_size);
            }
            case TapUserspaceRoute::HostSyn: {
                // Peers may only open connections to explicitly forwarded ports.
                const uint16_t port = TapUserspaceTcpDestinationPort(packet, packet_size);
                {
                    std::lock_guard<std::mutex> scope(inbound_lock_);
                    if (0 == port || inbound_tcp_ports_.find(port) == inbound_tcp_ports_.end()) {
                        return true;
                    }
                }

                HostInputHandler host_input = GetHostInput();
                return NULLPTR == host_input || host_input(packet, packet_size);
            }
            case TapUserspaceRoute::Tunnel:
                return RaiseHostOutput(packet, packet_size);
            default:
                return true;
            }
        }

        /** @brief Raises a host-stack packet as adapter input on the adapter's context. */
        bool TapUserspace::RaiseHostOutput(const void* packet, int packet_size) noexcept {
            std::shared_ptr<boost::asio::io_context> context = GetContext();
            if (NULLPTR == context) {
                return false;
            }

            std::shared_ptr<Byte> copy = ppp::make_shared_alloc<Byte>(packet_size);
            if (NULLPTR == copy) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
            }

            memcpy(copy.get(), packet, packet_size);
            std::shared_ptr<ITap> self = shared_from_this();
            boost::asio::post(*context,
                [self, this, copy, packet_size]() noexcept {
                    if (!opened_) {
                        return;
                    }

                    PacketInputEventArgs e;
                    e.Packet = copy.get();
                    e.PacketLength = packet_size;
                    OnInput(e);
                });
            return true;
        }
    }
}

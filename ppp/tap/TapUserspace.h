#pragma once

/**
 * @file TapUserspace.h
 * @brief In-process adapter for proxy-only runs that cannot create a host adapter.
 */

#include <ppp/tap/ITap.h>

#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace ppp {
    namespace tap {
        /**
         * @brief Loops virtual-subnet packets between an in-process host stack and the tunnel.
         *
         * The "host" behind this adapter is the in-process TCP/IP stack rather than the
         * operating system. Packets written to the adapter (Output) are addressed either to
         * the local virtual IP, which come from peers and are handed to the host stack, or
         * from it, which the host stack produced and which are raised as adapter input so
         * the normal client path forwards them through the tunnel (relay or P2P).
         */
        class TapUserspace : public ITap {
        public:
            /** @brief Delivers a peer packet addressed to the local virtual IP to the host stack. */
            typedef ppp::function<bool(const void* packet, int packet_size)>  HostInputHandler;
            /** @brief Receives a peer datagram; the address is in network byte order, the port in host order. */
            typedef ppp::function<void(uint32_t source, uint16_t source_port, const void* payload, int length)>
                                                                              DatagramHandler;

            /** @brief Largest datagram payload sent without IP fragmentation across the tunnel. */
            static constexpr int                                              MaxDatagramPayload = 1372;

        public:
            TapUserspace(const std::shared_ptr<boost::asio::io_context>& context,
                const ppp::string& id,
                uint32_t ip,
                uint32_t gw,
                uint32_t mask) noexcept;

            bool IsReady() noexcept override;
            bool IsOpen() noexcept override;
            bool SetInterfaceMtu(int mtu) noexcept override;
            bool Open() noexcept override;
            void Dispose() noexcept override;
            bool Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept override;
            bool Output(const void* packet, int packet_size) noexcept override;

            void SetHostInput(const HostInputHandler& handler) noexcept;
            /** @brief TCP ports on the virtual IP that peers may connect to (inbound forwards). */
            void SetInboundTcpPorts(const std::unordered_set<uint16_t>& ports) noexcept;

            /** @brief Reserves a local UDP port on the virtual IP; returns 0 when none is free. */
            uint16_t BindDatagram(const DatagramHandler& handler) noexcept;
            void ReleaseDatagram(uint16_t port) noexcept;
            /** @brief Sends a datagram from the virtual IP; the destination address uses network byte order. */
            bool SendDatagram(uint16_t local_port, uint32_t destination, uint16_t destination_port,
                const void* payload, int length) noexcept;

            /** @brief Addresses use network byte order, matching ITap::IPAddress. */
            static std::shared_ptr<TapUserspace> Create(
                const std::shared_ptr<boost::asio::io_context>& context,
                uint32_t ip,
                uint32_t gw,
                uint32_t mask) noexcept;

        private:
            bool RaiseHostOutput(const void* packet, int packet_size) noexcept;
            HostInputHandler GetHostInput() noexcept;
            /** @return true when the packet was a datagram for a bound port (and was consumed). */
            bool DispatchDatagram(const void* packet, int packet_size) noexcept;

        private:
            bool opened_ = false;
            std::mutex host_input_lock_;
            HostInputHandler host_input_;
            std::mutex inbound_lock_;
            std::unordered_set<uint16_t> inbound_tcp_ports_;
            std::mutex datagram_lock_;
            std::unordered_map<uint16_t, DatagramHandler> datagrams_;
            uint16_t next_datagram_port_ = 49152;
            uint16_t next_packet_id_ = 0;
        };
    }
}

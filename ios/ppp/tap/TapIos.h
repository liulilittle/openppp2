#pragma once

#include <ppp/stdafx.h>
#include <ppp/tap/ITap.h>

namespace ppp::p2p {
    class IP2PDatagramTransportFactory;
}

namespace ppp
{
    namespace tap
    {
        /**
         * @brief iOS Packet Tunnel TAP facade.
         *
         * iOS does not expose a utun file descriptor to apps. NetworkExtension
         * delivers packets through NEPacketTunnelFlow, so this backend exposes
         * packet input/output callbacks instead of owning a POSIX descriptor.
         */
        class TapIos final : public ppp::tap::ITap
        {
        public:
            typedef void (*PacketOutputReleaseHandler)(void*);
            typedef ppp::function<bool(const void*, int, void*, PacketOutputReleaseHandler)> PacketOutputEventHandler;

        public:
            TapIos(
                const std::shared_ptr<boost::asio::io_context>& context,
                const ppp::string&                              dev,
                uint32_t                                        address,
                uint32_t                                        gw,
                uint32_t                                        mask,
                bool                                            hosted_network) noexcept;

        public:
            static std::shared_ptr<TapIos> Create(
                const std::shared_ptr<boost::asio::io_context>& context,
                const ppp::string&                              dev,
                uint32_t                                        ip,
                uint32_t                                        gw,
                uint32_t                                        mask,
                bool                                            promisc,
                bool                                            hosted_network,
                const ppp::vector<uint32_t>&                    dns_addresses) noexcept;

        public:
            void SetPacketOutput(PacketOutputEventHandler output) noexcept;
            bool Input(const void* packet, int packet_size) noexcept;
            void SetP2PDatagramTransportFactory(
                const std::shared_ptr<ppp::p2p::IP2PDatagramTransportFactory>& factory) noexcept;
            std::shared_ptr<ppp::p2p::IP2PDatagramTransportFactory>
                GetP2PDatagramTransportFactory() const noexcept;

        public:
            virtual bool IsReady() noexcept override;
            virtual bool IsOpen() noexcept override;
            virtual bool Open() noexcept override;
            virtual void Dispose() noexcept override;
            virtual bool Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept override;
            virtual bool Output(const void* packet, int packet_size) noexcept override;
            virtual bool SetInterfaceMtu(int mtu) noexcept override;

        private:
            std::atomic<bool>       opened_;
            PacketOutputEventHandler output_;
            /** @brief Serialises output_ assignment/clear/copy (SetPacketOutput vs Dispose vs Output). */
            mutable std::mutex      output_mutex_;
            mutable std::mutex      p2p_factory_mutex_;
            std::shared_ptr<ppp::p2p::IP2PDatagramTransportFactory> p2p_factory_;
        };
    }
}

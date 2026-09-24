#pragma once

#include <boost/asio.hpp>
#include <cstdint>
#include <functional>
#include <memory>

namespace ppp {
    namespace p2p {

        enum class P2PDatagramPlatform : uint8_t {
            Linux,
            Android,
            IosPacketTunnel,
            Other,
        };

        constexpr bool RequiresProviderOwnedP2PDatagramTransport(
                P2PDatagramPlatform platform) noexcept {
            return platform == P2PDatagramPlatform::IosPacketTunnel;
        }

        constexpr bool AllowsNativeSocketP2PDatagramTransport(
                P2PDatagramPlatform platform) noexcept {
            return !RequiresProviderOwnedP2PDatagramTransport(platform);
        }

        enum class P2PDatagramReceiveStatus : uint8_t {
            Packet,
            Error,
        };

        using P2PDatagramReceiveCallback = std::function<void(
            P2PDatagramReceiveStatus status,
            const boost::asio::ip::udp::endpoint& sender,
            const uint8_t* packet,
            int packet_size)>;

        class IP2PDatagramTransport {
        public:
            virtual ~IP2PDatagramTransport() noexcept = default;
            virtual bool IsReady() const noexcept = 0;
            virtual bool Start(const P2PDatagramReceiveCallback& callback) noexcept = 0;
            virtual boost::asio::ip::udp::endpoint LocalEndpoint() const noexcept = 0;
            virtual bool SendTo(
                const uint8_t* packet,
                int packet_size,
                const boost::asio::ip::udp::endpoint& endpoint) noexcept = 0;
            virtual void Close() noexcept = 0;
        };

        class IP2PDatagramTransportFactory {
        public:
            virtual ~IP2PDatagramTransportFactory() noexcept = default;
            virtual std::shared_ptr<IP2PDatagramTransport> Create(
                boost::asio::io_context& io_context) noexcept = 0;
        };

        class ISocketProtector;

        std::shared_ptr<IP2PDatagramTransportFactory>
        CreateNativeSocketP2PDatagramTransportFactory(
            const std::shared_ptr<ISocketProtector>& protector) noexcept;

    }
}

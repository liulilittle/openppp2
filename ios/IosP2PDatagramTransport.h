#pragma once

#include <ios/OpenPPP2PacketTunnelBridge.h>
#include <ppp/p2p/P2PDatagramTransport.h>

namespace ppp {
    namespace p2p {

        std::shared_ptr<IP2PDatagramTransportFactory>
        CreateIosProviderP2PDatagramTransportFactory(
            const openppp2_ios_p2p_datagram_provider& provider,
            void* user_data) noexcept;

        std::shared_ptr<IP2PDatagramTransportFactory>
        GetIosProviderP2PDatagramTransportFactory(
            openppp2_ios_tap* tap) noexcept;

    }
}

#pragma once

namespace boost::asio::ip { class address; }

namespace ppp::app::client {
    class VEthernetNetworkSwitcher;

    class RemoteEndpointLoader {
    public:
        void Bind(VEthernetNetworkSwitcher* owner) noexcept;
        bool PrepareForwarding() noexcept;
        bool Apply(const boost::asio::ip::address& gw) noexcept;

    private:
        VEthernetNetworkSwitcher* owner_ = nullptr;
    };
}

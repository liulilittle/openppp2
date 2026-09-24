#include <ppp/app/client/RemoteEndpointLoader.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/transmissions/proxys/IForwarding.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/ip.h>
#include <ppp/coroutines/YieldContext.h>
#include <common/aggligator/aggligator.h>

using ppp::net::IPEndPoint;
using ppp::transmissions::proxys::IForwarding;

namespace ppp::app::client {

void RemoteEndpointLoader::Bind(VEthernetNetworkSwitcher* owner) noexcept {
    owner_ = owner;
}

bool RemoteEndpointLoader::PrepareForwarding() noexcept {
    if (owner_->forwarding_) {
        return true;
    }

    VEthernetNetworkSwitcher::IForwardingPtr forwarding =
        make_shared_object<IForwarding>(owner_->GetContext(), owner_->configuration_);
    if (NULLPTR == forwarding) {
        return false;
    }
    if (forwarding->Open()) {
        owner_->forwarding_ = forwarding;
#if defined(_LINUX)
        forwarding->ProtectorNetwork = owner_->GetProtectorNetwork();
#endif
    }
    else {
        forwarding->Dispose();
    }
    return true;
}

bool RemoteEndpointLoader::Apply(const boost::asio::ip::address& gw) noexcept {
    using ProtocolType = VEthernetExchanger::ProtocolType;

    // This function must be executed after the remote exchanger object has been created.
    std::shared_ptr<VEthernetExchanger> exchanger = owner_->exchanger_;
    if (NULLPTR == exchanger || !PrepareForwarding()) {
        return false;
    }

    VEthernetNetworkSwitcher::IForwardingPtr forwarding = owner_->forwarding_;

    boost::asio::ip::tcp::endpoint remoteEP;
    ppp::string hostname;
    ppp::string address;
    ppp::string path;
    ppp::string server;
    int port;
    ProtocolType protocol_type = ProtocolType::ProtocolType_PPP;

    // Obtaining the IP endpoint address of the VPN remote server may involve synchronizing the network, as it may be in domain-name format.
    static constexpr ppp::coroutines::YieldContext* y = NULLPTR;

    if (!exchanger->GetRemoteEndPoint(y, hostname, address, path, port, protocol_type, server, remoteEP)) {
        return false;
    }
    else {
        owner_->server_ru_ = "[";
        owner_->server_ru_ += hostname;
        owner_->server_ru_ += "]";
        owner_->server_ru_ += ":";
        owner_->server_ru_ += stl::to_string<ppp::string>(NULLPTR != forwarding ? forwarding->GetRemotePort() : port);
        owner_->server_ru_ += "/";

        if (protocol_type == ProtocolType::ProtocolType_Http || protocol_type == ProtocolType::ProtocolType_WebSocket) {
            owner_->server_ru_ += "ppp+ws";
        }
        elif(protocol_type == ProtocolType::ProtocolType_HttpSSL || protocol_type == ProtocolType::ProtocolType_WebSocketSSL) {
            owner_->server_ru_ += "ppp+wss";
        }
        else {
            owner_->server_ru_ += "ppp+tcp";
        }

        if (NULLPTR != forwarding) {
            remoteEP = forwarding->GetProxyEndPoint();
        }
    }

    // Add the default IP address of the vpn virtual network adapter to the RIB route table.
    route::RouteInformationTablePtr rib = owner_->route_coordinator_->Snapshot().rib;
    if (NULLPTR == rib) {
        rib = make_shared_object<ppp::net::native::RouteInformationTable>();
        owner_->route_coordinator_->ReplaceRib(rib);
    }

    // CIDR: 0.0.0.0/0; 0.0.0.0/1; 128.0.0.0/1
    if (NULLPTR != rib) {
        if (auto tap = owner_->GetTap(); NULLPTR != tap) {
            rib->AddRoute(IPEndPoint::AnyAddress, 0, tap->GatewayServer);
            rib->AddRoute(IPEndPoint::AnyAddress, 1, tap->GatewayServer);
            rib->AddRoute(inet_addr("128.0.0.0"), 1, tap->GatewayServer);
        }
    }

    // Note that we only need to set IPV4 routes, not IPV6 routes.
    boost::asio::ip::address remoteIP = remoteEP.address();
    IPEndPoint serverEP = IPEndPoint::ToEndPoint(remoteEP);
    if (IPEndPoint::IsInvalid(serverEP)) {
        return false;
    }

    // Add IPV4 route table settings.
    auto fib_add_route_ipv4 =
        [&rib, &gw](const boost::asio::ip::address& remoteIP) noexcept {
            if (remoteIP.is_v6()) {
                return true;
            }

            if (NULLPTR == rib) {
                return false;
            }

            bool processed = gw.is_v4() && remoteIP.is_v4();
            if (!processed) {
                return false;
            }

            // First convert the IP addresses of both.
            uint32_t ip = htonl(remoteIP.to_v4().to_uint());
            uint32_t nx = htonl(gw.to_v4().to_uint());

            // Add route information to rib!
            return rib->AddRoute(ip, 32, nx);
        };

    // Check whether the static tunnel specifies an IP address endpoint (required for transit).
    ppp::unordered_set<boost::asio::ip::tcp::endpoint> servers;
    /** @brief Parses and registers one static tunnel server endpoint. */
    auto StaticEchoAddRemoteEndPoint =
        [this, &servers, &fib_add_route_ipv4](const ppp::string& server_string) noexcept {
            if (server_string.empty()) {
                return false;
            }

            ppp::string host_string;
            int port;

            if (!ppp::net::Ipep::ParseEndPoint(server_string, host_string, port)) {
                return false;
            }

            if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                return false;
            }

            IPEndPoint remoteEP = ppp::net::Ipep::GetEndPoint(host_string, port);
            if (IPEndPoint::IsInvalid(remoteEP)) {
                return false;
            }

            boost::asio::ip::udp::endpoint ep =
                IPEndPoint::ToEndPoint<boost::asio::ip::udp>(remoteEP);
            if (!remoteEP.IsLoopback() && !fib_add_route_ipv4(ep.address())) {
                return false;
            }

            if (owner_->aggligator_) {
                auto r = servers.emplace(
                    IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(remoteEP));
                return r.second;
            }

            return owner_->StaticEchoAddRemoteEndPoint(ep);
        };

    for (const ppp::string& server_string : owner_->configuration_->udp.static_.servers) {
        if (!StaticEchoAddRemoteEndPoint(server_string)) {
            return false;
        }
    }

    // Open the beast network bandwidth aggregator.
    if (std::shared_ptr<aggligator::aggligator> aggligator = owner_->aggligator_; NULLPTR != aggligator) {
        if (servers.empty()) {
            owner_->aggligator_.reset();
            aggligator->close();
        }
        elif(!aggligator->client_open(owner_->configuration_->udp.static_.aggligator, servers)) {
            return false;
        }
    }

    // The gateway address must be IPV4 or it is considered a failure because there is no V6 gateway serving the V4 address.
    if (serverEP.IsLoopback()) {
        return true;
    }

    return fib_add_route_ipv4(remoteIP);
}

}  // namespace ppp::app::client

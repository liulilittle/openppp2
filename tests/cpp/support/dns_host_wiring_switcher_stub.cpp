#include <ppp/app/client/AssignedAddressManager.h>
#include <ppp/app/client/ClientBypassRouteLoader.h>
#include <ppp/app/client/ClientConnectionOpener.h>
#include <ppp/app/client/ClientConnectionTeardown.h>
#include <ppp/app/client/ClientPacketDispatchHandler.h>
#include <ppp/app/client/dns/DnsInterceptor.h>
#include <ppp/app/client/PeerPrefixRouteManager.h>
#include <ppp/app/client/QuicRejectRateLimiter.h>
#include <ppp/app/client/AggregatorLoader.h>
#include <ppp/app/client/RemoteEndpointLoader.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/client/SwitcherTimeoutRegistry.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/ethernet/VEthernet.h>

namespace {

bool g_inject_ok = true;

}  // namespace

namespace ppp {

int RandomNext() noexcept {
    return 0;
}

}  // namespace ppp

namespace ppp::configurations {

AppConfiguration::AppConfiguration() noexcept = default;

}  // namespace ppp::configurations

namespace ppp::ethernet {

VEthernet::VEthernet(
    const std::shared_ptr<boost::asio::io_context>& context,
    bool lwip,
    bool vnet,
    bool mta) noexcept
    : disposed_(false)
    , lwip_(lwip)
    , vnet_(vnet)
    , mta_(mta)
    , context_(context) {}

VEthernet::~VEthernet() noexcept {
    Finalize();
}

void VEthernet::Finalize() noexcept {
    disposed_.store(true, std::memory_order_release);
}

bool VEthernet::IsDisposed() noexcept {
    return disposed_.load(std::memory_order_acquire);
}

bool VEthernet::Open(const std::shared_ptr<ppp::tap::ITap>&) noexcept {
    return true;
}

void VEthernet::Dispose() noexcept {
    Finalize();
}

std::shared_ptr<ppp::threading::BufferswapAllocator> VEthernet::GetBufferAllocator() noexcept {
    return std::shared_ptr<ppp::threading::BufferswapAllocator>();
}

bool VEthernet::OnPacketInput(ppp::net::native::ip_hdr*, int, int, int, bool) noexcept {
    return false;
}

bool VEthernet::OnPacketInput(ppp::Byte*, int, bool) noexcept {
    return false;
}

bool VEthernet::OnPacketInput(const std::shared_ptr<ppp::net::packet::IPFrame>&) noexcept {
    return false;
}

bool VEthernet::OnTick(uint64_t) noexcept {
    return true;
}

bool VEthernet::OnUpdate(uint64_t) noexcept {
    return true;
}

bool VEthernet::Output(const void*, int) noexcept {
    return false;
}

bool VEthernet::Output(const std::shared_ptr<ppp::Byte>&, int) noexcept {
    return false;
}

bool VEthernet::OutputGso(const std::shared_ptr<ppp::Byte>&, int,
    ppp::tap::TxGsoMetadata) noexcept {
    return false;
}

bool VEthernet::CanConsumeTcpV4Gso() noexcept {
    return false;
}

std::shared_ptr<ppp::net::packet::IPFragment> VEthernet::NewFragment() noexcept {
    return std::shared_ptr<ppp::net::packet::IPFragment>();
}

}  // namespace ppp::ethernet

namespace ppp::app::client {

route::RouteCoordinator::RouteCoordinator(
    std::unique_ptr<route::IRoutePlatform>) noexcept {}
route::RouteCoordinator::~RouteCoordinator() noexcept = default;

VEthernetNetworkSwitcher::VEthernetNetworkSwitcher(
    const std::shared_ptr<boost::asio::io_context>& context,
    bool lwip,
    bool vnet,
    bool mta,
    const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept
    : VEthernet(context, lwip, vnet, mta)
    , configuration_(configuration)
    , timeout_registry_(std::make_unique<SwitcherTimeoutRegistry>())
    , aggregator_loader_(std::make_unique<AggregatorLoader>()) {

    timeout_registry_->Bind(&GetSynchronizedObject());
    aggregator_loader_->Bind(this);
    static_mode_ = false;
    block_quic_ = false;
    icmppackets_aid_ = RandomNext();
}

VEthernetNetworkSwitcher::~VEthernetNetworkSwitcher() noexcept {
    Finalize();
}

std::shared_ptr<ppp::configurations::AppConfiguration> VEthernetNetworkSwitcher::GetConfiguration() noexcept {
    return configuration_;
}

std::shared_ptr<aggligator::aggligator> VEthernetNetworkSwitcher::GetAggligator() noexcept {
    return aggligator_;
}

void VEthernetNetworkSwitcher::Finalize() noexcept {
    if (timeout_registry_) {
        timeout_registry_->ReleaseAll();
    }
}

bool VEthernetNetworkSwitcher::Open(const std::shared_ptr<ppp::tap::ITap>& tap) noexcept {
    return VEthernet::Open(tap);
}

void VEthernetNetworkSwitcher::Dispose() noexcept {
    VEthernet::Dispose();
}

std::shared_ptr<ppp::threading::BufferswapAllocator> VEthernetNetworkSwitcher::GetBufferAllocator() noexcept {
    if (NULLPTR == configuration_) {
        return std::shared_ptr<ppp::threading::BufferswapAllocator>();
    }
    return configuration_->GetBufferAllocator();
}

bool VEthernetNetworkSwitcher::BlockQUIC(bool) noexcept {
    return false;
}

bool VEthernetNetworkSwitcher::CanConsumeTcpV4Gso() noexcept {
    return false;
}

bool VEthernetNetworkSwitcher::OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept {
    return VEthernet::OnPacketInput(packet, packet_length, header_length, proto, vnet);
}

bool VEthernetNetworkSwitcher::OnPacketInput(ppp::Byte* packet, int packet_length, bool vnet) noexcept {
    return VEthernet::OnPacketInput(packet, packet_length, vnet);
}

bool VEthernetNetworkSwitcher::OnPacketInput(const std::shared_ptr<ppp::net::packet::IPFrame>& packet) noexcept {
    return VEthernet::OnPacketInput(packet);
}

bool VEthernetNetworkSwitcher::OnTick(uint64_t now) noexcept {
    return VEthernet::OnTick(now);
}

bool VEthernetNetworkSwitcher::OnUpdate(uint64_t now) noexcept {
    return VEthernet::OnUpdate(now);
}

bool VEthernetNetworkSwitcher::OnInformation(const std::shared_ptr<VirtualEthernetInformation>&) noexcept {
    return true;
}

bool VEthernetNetworkSwitcher::OnInformation(
    const std::shared_ptr<VirtualEthernetInformation>&,
    const VirtualEthernetInformationExtensions&) noexcept {
    return true;
}

std::shared_ptr<VEthernetExchanger> VEthernetNetworkSwitcher::NewExchanger() noexcept {
    return std::shared_ptr<VEthernetExchanger>();
}

std::shared_ptr<ppp::ethernet::VNetstack> VEthernetNetworkSwitcher::NewNetstack() noexcept {
    return std::shared_ptr<ppp::ethernet::VNetstack>();
}

VEthernetNetworkSwitcher::VEthernetHttpProxySwitcherPtr VEthernetNetworkSwitcher::NewHttpProxy(
    const std::shared_ptr<VEthernetExchanger>&) noexcept {
    return VEthernetHttpProxySwitcherPtr();
}

VEthernetNetworkSwitcher::VEthernetSocksProxySwitcherPtr VEthernetNetworkSwitcher::NewSocksProxy(
    const std::shared_ptr<VEthernetExchanger>&) noexcept {
    return VEthernetSocksProxySwitcherPtr();
}

std::shared_ptr<ppp::transmissions::ITransmissionQoS> VEthernetNetworkSwitcher::NewQoS() noexcept {
    return std::shared_ptr<ppp::transmissions::ITransmissionQoS>();
}

VEthernetNetworkSwitcher::ITransmissionStatisticsPtr VEthernetNetworkSwitcher::NewStatistics() noexcept {
    return ITransmissionStatisticsPtr();
}

#if defined(_LINUX)
VEthernetNetworkSwitcher::ProtectorNetworkPtr VEthernetNetworkSwitcher::NewProtectorNetwork() noexcept {
    return ProtectorNetworkPtr();
}
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
ppp::string VEthernetNetworkSwitcher::GetRemoteUri() noexcept {
    return ppp::string();
}

bool VEthernetNetworkSwitcher::AddLoadIPList(
    const ppp::string&,
#if defined(_LINUX)
    const ppp::string&,
#endif
    const boost::asio::ip::address&,
    const ppp::string&) noexcept {
    return false;
}

bool VEthernetNetworkSwitcher::AddLoadIPListText(
    const ppp::string&,
#if defined(_LINUX)
    const ppp::string&,
#endif
    const boost::asio::ip::address&) noexcept {
    return false;
}

void VEthernetNetworkSwitcher::PreferredNic(const ppp::string&) noexcept {}

void VEthernetNetworkSwitcher::PreferredNgw(const boost::asio::ip::address&) noexcept {}
#endif

bool VEthernetNetworkSwitcher::LoadAllDnsRules(const ppp::string&, bool) noexcept {
    return false;
}

#if defined(_LINUX)
VEthernetNetworkSwitcher::ProtectorNetworkPtr VEthernetNetworkSwitcher::GetProtectorNetwork() noexcept {
    return protect_network_;
}
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
bool VEthernetNetworkSwitcher::AddRoute() noexcept { return true; }

bool VEthernetNetworkSwitcher::DeleteRoute() noexcept { return true; }
#endif

bool VEthernetNetworkSwitcher::DatagramOutput(
    const boost::asio::ip::udp::endpoint&,
    const boost::asio::ip::udp::endpoint&,
    void*,
    int,
    bool) noexcept {

    return g_inject_ok;
}

bool VEthernetNetworkSwitcher::DatagramOutput(
    const boost::asio::ip::udp::endpoint&,
    const boost::asio::ip::udp::endpoint&,
    const std::shared_ptr<Byte>&,
    void*,
    int,
    bool) noexcept {

    return g_inject_ok;
}

bool VEthernetNetworkSwitcher::PreparedAggregator() noexcept {
    if (NULLPTR == aggregator_loader_) {
        return false;
    }
    return aggregator_loader_->Prepare();
}

bool VEthernetNetworkSwitcher::EmplaceTimeout(
    void* key,
    const std::shared_ptr<ppp::threading::Timer::TimeoutEventHandler>& timeout) noexcept {
    if (NULLPTR == timeout_registry_) {
        return false;
    }
    return timeout_registry_->Emplace(key, timeout);
}

bool VEthernetNetworkSwitcher::DeleteTimeout(void* key) noexcept {
    if (NULLPTR == timeout_registry_) {
        return false;
    }
    return timeout_registry_->Delete(key);
}

}  // namespace ppp::app::client

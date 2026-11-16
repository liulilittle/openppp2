#include <ppp/app/client/udp/DirectDatagramFlow.h>
#include <iostream>
#include <stdexcept>
#include <cstdlib>

namespace ppp::coroutines {
bool YieldContext::Spawn(ppp::threading::BufferswapAllocator*, boost::asio::io_context&,
    boost::asio::strand<boost::asio::io_context::executor_type>*, SpawnHander&&, int) noexcept {
    std::cerr << "Unexpected native socket/resolver coroutine in offline provider test\n";
    std::abort();
}
}

using namespace ppp::app::client::udp;
namespace {
void Require(bool ok, const char* why) { if (!ok) throw std::runtime_error(why); }
class Provider final : public ppp::p2p::IP2PDatagramTransport {
public:
    bool IsReady() const noexcept override { return !closed; }
    bool Start(const ppp::p2p::P2PDatagramReceiveCallback& callback) noexcept override { receive = callback; return true; }
    boost::asio::ip::udp::endpoint LocalEndpoint() const noexcept override { return {}; }
    bool SendTo(const uint8_t*, int size, const boost::asio::ip::udp::endpoint& endpoint) noexcept override {
        ++sent; bytes += size; last = endpoint; return !closed;
    }
    void Close() noexcept override { closed = true; }
    bool closed = false;
    int sent = 0, bytes = 0;
    boost::asio::ip::udp::endpoint last;
    ppp::p2p::P2PDatagramReceiveCallback receive;
};
void Drain(const std::shared_ptr<boost::asio::io_context>& context) {
    context->restart(); while (context->poll()) {}
}
}
int main() {
    try {
        using namespace ppp::app::client::policy;
        PolicySource source;
        source.rules_text = "default reject\ndns direct local\ndns proxy remote\n[direct]\n192.0.2.0/24\n[reject]\n=deny.test\n";
        source.resolvers["local"] = {PolicyAction::Direct, {"udp://192.0.2.53:53"}};
        source.resolvers["remote"] = {PolicyAction::Proxy, {"udp://198.51.100.53:53"}};
        auto compiled = PolicyCompiler::Compile(source);
        Require(compiled.Ok(), "Default reject/IP direct fixture failed");
        auto pending = PolicyEvaluator::Evaluate(*compiled.snapshot, "allowed.test");
        Require(pending.action == PolicyAction::Reject && pending.needs_ip_resolution,
            "Unresolved domain must retain IP fallback despite default reject");
        auto resolved = PolicyEvaluator::Evaluate(*compiled.snapshot, "allowed.test", "192.0.2.7");
        Require(resolved.action == PolicyAction::Direct && !resolved.needs_ip_resolution,
            "IP direct must override provisional default reject");
        auto blocked = PolicyEvaluator::Evaluate(*compiled.snapshot, "allowed.test", "203.0.113.7");
        Require(blocked.action == PolicyAction::Reject && !blocked.needs_ip_resolution,
            "Unmatched real IP must preserve final reject");
        auto explicit_reject = PolicyEvaluator::Evaluate(*compiled.snapshot, "deny.test");
        Require(explicit_reject.action == PolicyAction::Reject && !explicit_reject.needs_ip_resolution,
            "Explicit domain reject must not wait for resolution");
        auto context = std::make_shared<boost::asio::io_context>();
        auto provider = std::make_shared<Provider>();
        auto owner = std::make_shared<int>(1);
        const DirectDatagramFlow::Endpoint target(boost::asio::ip::make_address_v4("192.0.2.1"), 1234);
        const DirectDatagramFlow::Endpoint logical(boost::asio::ip::make_address_v4("198.18.0.1"), 1234);
        int replies = 0;
        auto flow = std::make_shared<DirectDatagramFlow>(context, owner, target, logical,
            ppp::app::client::ClientUnderlyingSocketProtector(), provider, nullptr, 60,
            [&](const DirectDatagramFlow::Endpoint& endpoint, void*, int length) {
                Require(endpoint == logical && length == 1, "Reply lost original fake destination"); ++replies;
            });
        const uint8_t byte = 1;
        for (int n = 0; n < 32; ++n) Require(flow->Send(&byte, 1), "Queue rejected first 32 packets");
        Require(!flow->Send(&byte, 1), "Queue admitted 33rd packet before drain");
        Drain(context);
        Require(provider->sent == 32 && provider->bytes == 32 && provider->last == target,
            "Provider drain lost datagrams or real destination");
        Require(flow->Send(&byte, 1), "Completed sends did not release queue admission");
        Drain(context);
        provider->receive(ppp::p2p::P2PDatagramReceiveStatus::Packet,
            {target.address(), 9999}, &byte, 1);
        Drain(context);
        Require(replies == 0, "Spoofed source port reached client");
        provider->receive(ppp::p2p::P2PDatagramReceiveStatus::Packet, target, &byte, 1);
        Drain(context);
        Require(replies == 1, "Legitimate peer reply missing");
        flow->TunnelReply({target.address(), 9999}, &byte, 1);
        Drain(context);
        Require(replies == 1, "Tunnel reply bypassed peer validation");
        flow->TunnelReply(target, &byte, 1);
        Drain(context);
        Require(replies == 2, "Tunnel reply did not restore logical endpoint");
        std::vector<uint8_t> large(32768, 1);
        Require(flow->Send(large.data(), static_cast<int>(large.size())), "First 32 KiB rejected");
        Require(flow->Send(large.data(), static_cast<int>(large.size())), "Exactly 64 KiB rejected");
        Require(!flow->Send(&byte, 1), "Byte limit admitted over 64 KiB");
        Drain(context);
        flow->Close(); Drain(context);
        Require(provider->closed && flow->IsClosed() && !flow->Send(&byte, 1), "Close did not cancel flow");
        provider->receive(ppp::p2p::P2PDatagramReceiveStatus::Packet, target, &byte, 1);
        Drain(context);
        Require(replies == 2, "Closed flow emitted reply");
        std::cout << "UDP direct flow tests passed (mock provider, no sockets opened)\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    return 0;
}

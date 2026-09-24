#define BOOST_TEST_MODULE p2p_channel_lifecycle_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PChannel.h>

#include <chrono>

using namespace ppp;
using namespace ppp::p2p;

namespace ppp {

uint64_t GetTickCount() noexcept {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

} // namespace ppp

namespace {

class TestProtector final : public ISocketProtector {
public:
    explicit TestProtector(bool result) noexcept : result_(result) {}

    bool IsReady() const noexcept override { return true; }
    bool Protect(int) noexcept override {
        ++calls;
        return result_;
    }

    int calls = 0;

private:
    bool result_;
};

class TestDatagramTransport final : public IP2PDatagramTransport {
public:
    bool IsReady() const noexcept override { return true; }

    bool Start(const P2PDatagramReceiveCallback& callback) noexcept override {
        ++start_calls;
        callback_ = callback;
        return true;
    }

    boost::asio::ip::udp::endpoint LocalEndpoint() const noexcept override {
        return {boost::asio::ip::address_v4::loopback(), 41000};
    }

    bool SendTo(const uint8_t*, int packet_size,
                const boost::asio::ip::udp::endpoint&) noexcept override {
        ++send_calls;
        return packet_size > 0;
    }

    void Close() noexcept override { ++close_calls; }

    int start_calls = 0;
    int send_calls = 0;
    int close_calls = 0;

private:
    P2PDatagramReceiveCallback callback_;
};

class TestDatagramTransportFactory final : public IP2PDatagramTransportFactory {
public:
    explicit TestDatagramTransportFactory(
            const std::shared_ptr<TestDatagramTransport>& transport) noexcept
        : transport_(transport) {}

    std::shared_ptr<IP2PDatagramTransport> Create(
            boost::asio::io_context&) noexcept override {
        ++create_calls;
        return transport_;
    }

    int create_calls = 0;

private:
    std::shared_ptr<TestDatagramTransport> transport_;
};

std::shared_ptr<P2PChannel> MakeChannel(
        boost::asio::io_context& context,
        const std::shared_ptr<ISocketProtector>& protector,
        const std::shared_ptr<IP2PDatagramTransportFactory>& transport_factory = nullptr) {
    uint8_t session_key[SESSION_KEY_SIZE] = {};
    uint8_t token_key[SESSION_KEY_SIZE] = {};
    session_key[0] = 1;
    token_key[0] = 2;
    P2PConfig config;
    config.probe_timeout_ms = 1;
    return std::make_shared<P2PChannel>(
        context, protector, Int128(1), session_key, token_key, config,
        P2PCipher::ChaCha20Poly1305, transport_factory);
}

ppp::vector<P2PCandidate> LoopbackCandidates() {
    return {{boost::asio::ip::udp::endpoint(
        boost::asio::ip::address_v4::loopback(), 9), "test"}};
}

} // namespace

BOOST_AUTO_TEST_CASE(provider_transport_owns_socket_lifecycle_and_first_probe) {
    boost::asio::io_context context;
    auto protector = std::make_shared<TestProtector>(true);
    auto transport = std::make_shared<TestDatagramTransport>();
    auto factory = std::make_shared<TestDatagramTransportFactory>(transport);
    auto channel = MakeChannel(context, protector, factory);

    channel->StartProbing(LoopbackCandidates(), Int128(2), "offer-token");

    BOOST_TEST(factory->create_calls == 1);
    BOOST_TEST(transport->start_calls == 1);
    BOOST_TEST(transport->send_calls == 1);
    BOOST_TEST(protector->calls == 0);
    BOOST_TEST(static_cast<int>(channel->GetState()) ==
        static_cast<int>(P2PChannelState::Probing));

    channel->Close();
    BOOST_TEST(transport->close_calls == 1);
}

BOOST_AUTO_TEST_CASE(close_is_idempotent_and_cancelled_handlers_stay_on_relay) {
    boost::asio::io_context context;
    auto protector = std::make_shared<TestProtector>(true);
    auto channel = MakeChannel(context, protector);

    channel->StartProbing(LoopbackCandidates(), Int128(2), "offer-token");
    BOOST_TEST(static_cast<int>(channel->GetState()) ==
        static_cast<int>(P2PChannelState::Probing));
    BOOST_TEST(protector->calls == 1);

    channel->Close();
    channel->Close();
    context.run();

    BOOST_TEST(channel->IsClosed());
    BOOST_TEST(static_cast<int>(channel->GetState()) ==
        static_cast<int>(P2PChannelState::Relay));
    BOOST_TEST(static_cast<int>(channel->GetFallbackReason()) ==
        static_cast<int>(P2PFallbackReason::None));
}

BOOST_AUTO_TEST_CASE(first_fallback_reason_survives_repeated_stop) {
    boost::asio::io_context context;
    auto channel = MakeChannel(context, std::make_shared<TestProtector>(true));

    channel->StartProbing(LoopbackCandidates(), Int128(2), "");
    channel->StartProbing(LoopbackCandidates(), Int128(2), "offer-token");
    channel->Close();

    BOOST_TEST(channel->IsClosed());
    BOOST_TEST(static_cast<int>(channel->GetState()) ==
        static_cast<int>(P2PChannelState::Relay));
    BOOST_TEST(static_cast<int>(channel->GetFallbackReason()) ==
        static_cast<int>(P2PFallbackReason::AuthenticationFailure));
}

BOOST_AUTO_TEST_CASE(socket_protection_failure_falls_back_and_cleans_up) {
    boost::asio::io_context context;
    auto protector = std::make_shared<TestProtector>(false);
    auto channel = MakeChannel(context, protector);

    channel->StartProbing(LoopbackCandidates(), Int128(2), "offer-token");
    context.run();

    BOOST_TEST(protector->calls == 1);
    BOOST_TEST(channel->IsClosed());
    BOOST_TEST(static_cast<int>(channel->GetState()) ==
        static_cast<int>(P2PChannelState::Relay));
    BOOST_TEST(static_cast<int>(channel->GetFallbackReason()) ==
        static_cast<int>(P2PFallbackReason::SocketError));
}

BOOST_AUTO_TEST_CASE(udp_blocked_probe_timeout_falls_back_to_relay) {
    boost::asio::io_context context;
    boost::asio::ip::udp::socket blackhole(context,
        boost::asio::ip::udp::endpoint(
            boost::asio::ip::address_v4::loopback(), 0));
    auto channel = MakeChannel(context, std::make_shared<TestProtector>(true));
    ppp::vector<P2PCandidate> candidates = {{blackhole.local_endpoint(), "blackhole"}};

    channel->StartProbing(candidates, Int128(2), "offer-token");
    context.run();

    BOOST_TEST(channel->IsClosed());
    BOOST_TEST(static_cast<int>(channel->GetState()) ==
        static_cast<int>(P2PChannelState::Relay));
    BOOST_TEST(static_cast<int>(channel->GetFallbackReason()) ==
        static_cast<int>(P2PFallbackReason::Timeout));
}

BOOST_AUTO_TEST_CASE(fresh_channel_does_not_restore_previous_attempt_state) {
    boost::asio::io_context first_context;
    auto first = MakeChannel(first_context, std::make_shared<TestProtector>(true));
    first->StartProbing(LoopbackCandidates(), Int128(2), "");
    BOOST_REQUIRE(first->IsClosed());

    boost::asio::io_context restarted_context;
    auto restarted = MakeChannel(
        restarted_context, std::make_shared<TestProtector>(true));

    BOOST_TEST(!restarted->IsClosed());
    BOOST_TEST(static_cast<int>(restarted->GetState()) ==
        static_cast<int>(P2PChannelState::Relay));
    BOOST_TEST(static_cast<int>(restarted->GetFallbackReason()) ==
        static_cast<int>(P2PFallbackReason::None));
}

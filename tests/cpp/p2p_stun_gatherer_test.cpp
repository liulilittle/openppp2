#define BOOST_TEST_MODULE p2p_stun_gatherer_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PStunClient.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <functional>
#include <thread>
#include <vector>

// Only the retained legacy Query helper requires these runtime functions.
namespace ppp {
uint64_t GetTickCount() noexcept {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}
void Sleep(int milliseconds) noexcept {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}
}

using namespace ppp::p2p;
using Udp = boost::asio::ip::udp;

namespace {

Udp::endpoint Endpoint(unsigned ordinal, unsigned port = 3478) {
    return {boost::asio::ip::address_v4(0xc0000200u + ordinal),
        static_cast<unsigned short>(port)};
}

void Write16(uint8_t* output, unsigned value) {
    output[0] = static_cast<uint8_t>(value >> 8);
    output[1] = static_cast<uint8_t>(value);
}

std::vector<uint8_t> Response(
    const std::vector<uint8_t>& request,
    Udp::endpoint mapped = Endpoint(99, 54321)) {
    std::vector<uint8_t> result(32, 0);
    Write16(result.data(), 0x0101);
    Write16(result.data() + 2, 12);
    std::copy(request.begin() + 4, request.begin() + 20, result.begin() + 4);
    Write16(result.data() + 20, 0x0020);
    Write16(result.data() + 22, 8);
    result[25] = 1;
    Write16(result.data() + 26, mapped.port() ^ 0x2112u);
    const auto address = mapped.address().to_v4().to_uint() ^ 0x2112a442u;
    for (int i = 0; i < 4; ++i) {
        result[28 + i] = static_cast<uint8_t>(address >> (24 - i * 8));
    }
    return result;
}

class FakeTransport final : public IP2PDatagramTransport {
public:
    struct Sent {
        std::vector<uint8_t> bytes;
        Udp::endpoint endpoint;
        std::chrono::steady_clock::time_point at;
    };
    bool IsReady() const noexcept override { return !closed; }
    bool Start(const P2PDatagramReceiveCallback&) noexcept override {
        ++start_calls;
        return true;
    }
    Udp::endpoint LocalEndpoint() const noexcept override { return local_endpoint; }
    bool SendTo(const uint8_t* packet, int size, const Udp::endpoint& endpoint) noexcept override {
        if (closed) return false;
        sent.push_back({{packet, packet + size}, endpoint, std::chrono::steady_clock::now()});
        if (on_send) on_send(sent.back());
        return send_success;
    }
    void Close() noexcept override { closed = true; ++close_calls; }

    std::vector<Sent> sent;
    std::function<void(const Sent&)> on_send;
    bool closed = false;
    bool send_success = true;
    Udp::endpoint local_endpoint = Endpoint(10, 40000);
    unsigned start_calls = 0;
    unsigned close_calls = 0;
};

struct Fixture {
    boost::asio::io_context io;
    P2PStunGatherer::Strand owner{boost::asio::make_strand(io)};
    std::shared_ptr<FakeTransport> transport = std::make_shared<FakeTransport>();
    std::shared_ptr<P2PStunGatherer> gatherer = P2PStunGatherer::Create(owner);
    unsigned completions = 0;
    P2PStunClient::StunResult result;
    uint64_t completed_generation = 0;
    uint64_t completed_registration = 0;

    void Poll() { io.restart(); io.poll(); }
    template <typename Function>
    void OnOwner(Function function) {
        boost::asio::post(owner, std::move(function));
        Poll();
    }
    void RunFor(unsigned milliseconds) {
        io.restart(); io.run_for(std::chrono::milliseconds(milliseconds));
    }
    bool Start(std::vector<Udp::endpoint> servers = {Endpoint(1)},
        P2PStunClient::RequestProfile profile = P2PStunClient::RequestProfile::Standard) {
        bool accepted = false;
        OnOwner([&] {
            accepted = gatherer->Start(transport, servers, 17, 41,
                [this](const P2PStunClient::StunResult& value, uint64_t generation,
                    uint64_t registration) {
                    ++completions;
                    result = value;
                    completed_generation = generation;
                    completed_registration = registration;
                }, profile);
        });
        return accepted;
    }
    bool Receive(const Udp::endpoint& sender, const std::vector<uint8_t>& packet,
        uint64_t generation = 17, uint64_t registration = 41) {
        bool consumed = false;
        OnOwner([&] {
            consumed = gatherer->HandleDatagram(sender, packet.data(),
                static_cast<int>(packet.size()), generation, registration);
        });
        return consumed;
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(shared_transport_response_requires_current_sender_transaction_and_registration) {
    Fixture fixture;
    BOOST_REQUIRE(fixture.Start());
    BOOST_REQUIRE(fixture.transport->sent.size() == 1);
    const auto valid = Response(fixture.transport->sent.front().bytes);
    auto invalid = valid;
    invalid[8] ^= 1;
    BOOST_CHECK(fixture.Receive(Endpoint(1), invalid));
    BOOST_CHECK(fixture.Receive(Endpoint(2), valid));
    BOOST_CHECK(fixture.Receive(Endpoint(1), valid, 16, 41));
    BOOST_CHECK(fixture.Receive(Endpoint(1), valid, 17, 40));
    auto trailing = valid;
    trailing.push_back(0);
    BOOST_CHECK(fixture.Receive(Endpoint(1), trailing));
    std::vector<uint8_t> oversized(513, 0);
    std::copy(valid.begin(), valid.end(), oversized.begin());
    BOOST_CHECK(fixture.Receive(Endpoint(1), oversized));
    BOOST_CHECK(fixture.gatherer->IsRunning());
    BOOST_TEST(fixture.completions == 0u);

    BOOST_CHECK(fixture.Receive(Endpoint(1), valid));
    BOOST_TEST(fixture.completions == 1u);
    BOOST_CHECK(fixture.result.success);
    BOOST_CHECK(fixture.result.mapped_endpoint == Endpoint(99, 54321));
    BOOST_TEST(fixture.completed_generation == 17u);
    BOOST_TEST(fixture.completed_registration == 41u);
    BOOST_TEST(fixture.transport->start_calls == 0u);
    BOOST_TEST(fixture.transport->close_calls == 0u);
    BOOST_CHECK(!fixture.gatherer->IsRunning());
    BOOST_CHECK(fixture.Receive(Endpoint(1), valid));
    BOOST_TEST(fixture.completions == 1u);
}

BOOST_AUTO_TEST_CASE(retry_reuses_exact_request_at_500ms_and_expires_at_1000ms) {
    Fixture fixture;
    BOOST_REQUIRE(fixture.Start());
    fixture.RunFor(550);
    BOOST_REQUIRE(fixture.transport->sent.size() == 2);
    BOOST_TEST(fixture.transport->sent[0].bytes.size() == 20u);
    BOOST_CHECK(fixture.transport->sent[0].bytes == fixture.transport->sent[1].bytes);
    const auto retry_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        fixture.transport->sent[1].at - fixture.transport->sent[0].at).count();
    BOOST_CHECK_GE(retry_ms, P2PStunGatherer::RetryDelayMs);
    BOOST_TEST(fixture.completions == 0u);
    fixture.RunFor(600);
    BOOST_TEST(fixture.completions == 1u);
    BOOST_CHECK(!fixture.result.success);
    BOOST_TEST(fixture.transport->sent.size() == 2u);
    BOOST_TEST(fixture.transport->close_calls == 0u);
}

BOOST_AUTO_TEST_CASE(tailnode_retries_exact_40_bytes_and_keeps_profile_on_next_server) {
    Fixture fixture;
    BOOST_REQUIRE(fixture.Start({Endpoint(1), Endpoint(2)}, P2PStunClient::RequestProfile::Tailnode));
    fixture.RunFor(1600);
    BOOST_REQUIRE(fixture.transport->sent.size() == 4u);
    for (const auto& sent : fixture.transport->sent) {
        BOOST_REQUIRE(sent.bytes.size() == 40u);
        BOOST_TEST(sent.bytes[3] == 20u);
        BOOST_CHECK(std::memcmp(sent.bytes.data() + 24, "tailnode", 8) == 0);
        BOOST_TEST(sent.bytes[32] == 0x80u);
        BOOST_TEST(sent.bytes[33] == 0x28u);
    }
    BOOST_CHECK(fixture.transport->sent[0].bytes == fixture.transport->sent[1].bytes);
    BOOST_CHECK(fixture.transport->sent[2].bytes == fixture.transport->sent[3].bytes);
    BOOST_CHECK(fixture.transport->sent[0].bytes != fixture.transport->sent[2].bytes);
    BOOST_CHECK(fixture.Receive(Endpoint(1), Response(fixture.transport->sent[0].bytes)));
    BOOST_TEST(fixture.completions == 0u);
    const auto valid = Response(fixture.transport->sent[2].bytes);
    BOOST_CHECK(fixture.Receive(Endpoint(2), valid, 16, 41));
    BOOST_CHECK(fixture.Receive(Endpoint(2), valid, 17, 40));
    BOOST_TEST(fixture.completions == 0u);
    BOOST_CHECK(fixture.Receive(Endpoint(2), valid));
    BOOST_TEST(fixture.completions == 1u);
    BOOST_CHECK(fixture.result.success);
    BOOST_TEST(fixture.transport->start_calls == 0u);
    BOOST_TEST(fixture.transport->close_calls == 0u);
}

BOOST_AUTO_TEST_CASE(invalid_request_profile_is_rejected_without_sending) {
    Fixture fixture;
    BOOST_CHECK(!fixture.Start({Endpoint(1)}, static_cast<P2PStunClient::RequestProfile>(99)));
    BOOST_TEST(fixture.transport->sent.size() == 0u);
    BOOST_CHECK(!fixture.gatherer->IsRunning());
}

BOOST_AUTO_TEST_CASE(at_most_three_distinct_servers_and_two_sends_per_server) {
    Fixture fixture;
    BOOST_REQUIRE(fixture.Start({{}, Endpoint(1), Endpoint(1), Endpoint(2), Endpoint(3), Endpoint(4)}));
    fixture.RunFor(3200);
    BOOST_REQUIRE(fixture.transport->sent.size() == 6);
    for (unsigned i = 0; i < 3; ++i) {
        const auto& first = fixture.transport->sent[i * 2];
        const auto& second = fixture.transport->sent[i * 2 + 1];
        BOOST_CHECK(first.endpoint == Endpoint(i + 1));
        BOOST_CHECK(first.bytes == second.bytes);
        if (i > 0) {
            BOOST_CHECK(first.bytes != fixture.transport->sent[(i - 1) * 2].bytes);
        }
    }
    BOOST_TEST(fixture.completions == 1u);
    BOOST_CHECK(!fixture.result.success);
    BOOST_CHECK(!fixture.gatherer->IsRunning());
}

BOOST_AUTO_TEST_CASE(stale_response_from_previous_server_cannot_finish_next_transaction) {
    Fixture fixture;
    BOOST_REQUIRE(fixture.Start({Endpoint(1), Endpoint(2)}));
    const auto stale = Response(fixture.transport->sent.front().bytes);
    fixture.RunFor(1100);
    BOOST_REQUIRE(fixture.transport->sent.size() == 3);
    BOOST_CHECK(fixture.Receive(Endpoint(1), stale));
    BOOST_CHECK(fixture.Receive(Endpoint(2), stale));
    BOOST_TEST(fixture.completions == 0u);
    BOOST_CHECK(fixture.Receive(Endpoint(2), Response(fixture.transport->sent.back().bytes)));
    BOOST_TEST(fixture.completions == 1u);
    BOOST_CHECK(fixture.result.success);
}

BOOST_AUTO_TEST_CASE(cancel_suppresses_retry_and_already_queued_completion_without_closing_transport) {
    Fixture pending;
    BOOST_REQUIRE(pending.Start());
    std::thread stop([&] { pending.gatherer->Cancel(); });
    stop.join();
    pending.RunFor(1100);
    BOOST_TEST(pending.transport->sent.size() == 1u);
    BOOST_TEST(pending.completions == 0u);
    BOOST_TEST(pending.transport->close_calls == 0u);
    BOOST_CHECK(!pending.gatherer->IsRunning());

    Fixture completed;
    BOOST_REQUIRE(completed.Start());
    const auto valid = Response(completed.transport->sent.front().bytes);
    completed.OnOwner([&] {
        BOOST_CHECK(completed.gatherer->HandleDatagram(Endpoint(1),
            valid.data(), static_cast<int>(valid.size()), 17, 41));
        completed.gatherer->Cancel();
        completed.gatherer->Cancel();
    });
    BOOST_TEST(completed.completions == 0u);
    BOOST_TEST(completed.transport->close_calls == 0u);
    BOOST_CHECK(!completed.Start());
}

BOOST_AUTO_TEST_CASE(reentrant_provider_response_finishes_safely_and_only_once) {
    Fixture fixture;
    fixture.transport->on_send = [&](const FakeTransport::Sent& sent) {
        const auto reply = Response(sent.bytes);
        BOOST_CHECK(fixture.gatherer->HandleDatagram(sent.endpoint,
            reply.data(), static_cast<int>(reply.size()), 17, 41));
    };
    BOOST_REQUIRE(fixture.Start());
    BOOST_TEST(fixture.completions == 1u);
    BOOST_CHECK(fixture.result.success);
    BOOST_TEST(fixture.transport->sent.size() == 1u);
    fixture.RunFor(1100);
    BOOST_TEST(fixture.transport->sent.size() == 1u);
}

BOOST_AUTO_TEST_CASE(start_is_single_shot_and_requires_owner_executor_and_started_transport) {
    Fixture fixture;
    BOOST_CHECK(!fixture.gatherer->Start(fixture.transport, {Endpoint(1)}, 17, 41,
        [](const P2PStunClient::StunResult&, uint64_t, uint64_t) {}));
    BOOST_TEST(fixture.transport->sent.size() == 0u);
    BOOST_REQUIRE(fixture.Start());
    BOOST_CHECK(!fixture.Start());
    const std::vector<uint8_t> data{2, 5, 0, 0};
    BOOST_CHECK(!fixture.Receive(Endpoint(1), data));
    fixture.transport->Close();
    fixture.RunFor(600);
    BOOST_TEST(fixture.completions == 1u);
    BOOST_CHECK(!fixture.result.success);
    BOOST_TEST(fixture.transport->sent.size() == 1u);
}

BOOST_AUTO_TEST_CASE(unbound_transport_and_invalid_servers_never_send_or_complete) {
    Fixture fixture;
    fixture.transport->local_endpoint = {};
    BOOST_CHECK(!fixture.Start());
    fixture.transport->local_endpoint = Endpoint(10, 40000);
    BOOST_CHECK(!fixture.Start({{}, Endpoint(1, 0),
        {boost::asio::ip::address_v4(0xe0000001u), 3478},
        {boost::asio::ip::address_v4::broadcast(), 3478},
        {boost::asio::ip::address_v6::loopback(), 3478}}));
    fixture.OnOwner([&] {
        const P2PStunGatherer::Completion completion =
            [](const P2PStunClient::StunResult&, uint64_t, uint64_t) {};
        BOOST_CHECK(!fixture.gatherer->Start(fixture.transport, {Endpoint(1)}, 0, 41, completion));
        BOOST_CHECK(!fixture.gatherer->Start(fixture.transport, {Endpoint(1)}, 17, 0, completion));
        BOOST_CHECK(!fixture.gatherer->Start(fixture.transport, {Endpoint(1)}, 17, 41, {}));
    });
    BOOST_TEST(fixture.transport->sent.size() == 0u);
    BOOST_TEST(fixture.completions == 0u);
    BOOST_REQUIRE(fixture.Start());
    fixture.gatherer->Cancel();
}

BOOST_AUTO_TEST_CASE(demultiplexing_never_consumes_v2_packets_with_cookie_prefix_offer_hash) {
    Fixture fixture;
    BOOST_REQUIRE(fixture.Start());
    std::vector<uint8_t> packet(158, 0);
    packet[0] = 2;
    packet[1] = 1;
    packet[4] = 0x21;
    packet[5] = 0x12;
    packet[6] = 0xa4;
    packet[7] = 0x42;
    BOOST_CHECK(!P2PStunClient::IsStunDatagram(packet.data(), static_cast<int>(packet.size())));
    BOOST_CHECK(!fixture.Receive(Endpoint(1), packet));
    packet[1] = 5;
    BOOST_CHECK(!fixture.Receive(Endpoint(1), packet));
    fixture.gatherer->Cancel();
}

BOOST_AUTO_TEST_CASE(parser_rejects_duplicate_truncated_attributes_and_invalid_mapped_endpoints) {
    std::vector<uint8_t> request(20);
    std::array<uint8_t, 12> transaction{};
    BOOST_REQUIRE(P2PStunClient::BuildRequest(request.data(),
        static_cast<int>(request.size()), transaction.data()) == 20);
    const auto valid = Response(request);
    const auto rejected = [&](const std::vector<uint8_t>& message) {
        auto mapped = Endpoint(77, 40000);
        BOOST_CHECK(!P2PStunClient::ParseResponse(message.data(),
            static_cast<int>(message.size()), transaction.data(), mapped));
        BOOST_CHECK(mapped == Endpoint(77, 40000));
    };
    auto duplicate = valid;
    duplicate.insert(duplicate.end(), valid.begin() + 20, valid.end());
    Write16(duplicate.data() + 2, 24);
    rejected(duplicate);
    auto malformed_after_mapped = valid;
    malformed_after_mapped.resize(40, 0);
    Write16(malformed_after_mapped.data() + 2, 20);
    Write16(malformed_after_mapped.data() + 32, 0x8022);
    Write16(malformed_after_mapped.data() + 34, 5);
    rejected(malformed_after_mapped);
    auto wrong_type = valid;
    Write16(wrong_type.data(), 0x0111);
    rejected(wrong_type);
    auto nonzero_reserved = valid;
    nonzero_reserved[24] = 1;
    rejected(nonzero_reserved);
    rejected(Response(request, Endpoint(99, 0)));
    rejected(Response(request, {boost::asio::ip::address_v4::any(), 2000}));
    rejected(Response(request, {boost::asio::ip::address_v4(0xe0000001u), 2000}));
    rejected(Response(request, {boost::asio::ip::address_v4::broadcast(), 2000}));
    auto trailing = valid;
    trailing.push_back(0);
    rejected(trailing);
}

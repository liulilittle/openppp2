#define BOOST_TEST_MODULE p2p_native_socket_stun_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PDatagramTransport.h>
#include <ppp/p2p/P2PSocketProtector.h>
#include <ppp/p2p/P2PStunClient.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <thread>
#include <vector>

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

class RecordingProtector final : public ISocketProtector {
public:
    bool IsReady() const noexcept override { return ready; }
    bool Protect(int fd) noexcept override {
        ++calls;
        valid_descriptor = fd >= 0;
        sockaddr_storage address{};
        socklen_t size = sizeof(address);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) != 0) {
            unbound = false;
        } else if (address.ss_family == AF_INET) {
            unbound = unbound && reinterpret_cast<sockaddr_in*>(&address)->sin_port == 0;
        } else if (address.ss_family == AF_INET6) {
            unbound = unbound && reinterpret_cast<sockaddr_in6*>(&address)->sin6_port == 0;
        }
        return allow;
    }
    bool ready = true;
    bool allow = true;
    std::atomic<unsigned> calls{0};
    bool valid_descriptor = false;
    bool unbound = true;
};

std::vector<uint8_t> BindingResponse(const uint8_t* request, const Udp::endpoint& mapped) {
    std::vector<uint8_t> response(32, 0);
    response[0] = 1;
    response[1] = 1;
    response[3] = 12;
    std::copy(request + 4, request + 20, response.begin() + 4);
    response[21] = 0x20;
    response[23] = 8;
    response[25] = 1;
    const auto port = mapped.port() ^ 0x2112u;
    response[26] = static_cast<uint8_t>(port >> 8);
    response[27] = static_cast<uint8_t>(port);
    const auto address = mapped.address().to_v4().to_uint() ^ 0x2112a442u;
    for (int i = 0; i < 4; ++i) {
        response[28 + i] = static_cast<uint8_t>(address >> (24 - i * 8));
    }
    return response;
}

class LoopbackResponder {
public:
    explicit LoopbackResponder(boost::asio::io_context& io)
        : socket(io, Udp::endpoint(boost::asio::ip::address_v4::loopback(), 0)) {}

    Udp::endpoint Endpoint() const { return socket.local_endpoint(); }

    void Receive() {
        socket.async_receive_from(boost::asio::buffer(buffer), sender,
            [this](const boost::system::error_code& ec, std::size_t size) {
                if (ec) return;
                observed.push_back(sender);
                requests.emplace_back(buffer.data(), buffer.data() + size);
                if (on_packet) on_packet(sender, requests.back());
                if (socket.is_open()) Receive();
            });
    }
    void Send(const std::vector<uint8_t>& packet, const Udp::endpoint& endpoint) {
        boost::system::error_code ec;
        socket.send_to(boost::asio::buffer(packet), endpoint, 0, ec);
        BOOST_REQUIRE_MESSAGE(!ec, "loopback UDP send failed: " << ec.message());
    }
    void Close() {
        boost::system::error_code ec;
        socket.close(ec);
    }

    Udp::socket socket;
    std::array<uint8_t, 4096> buffer{};
    Udp::endpoint sender;
    std::vector<Udp::endpoint> observed;
    std::vector<std::vector<uint8_t>> requests;
    std::function<void(const Udp::endpoint&, const std::vector<uint8_t>&)> on_packet;
};

struct NativeFixture {
    boost::asio::io_context io;
    P2PStunGatherer::Strand owner{boost::asio::make_strand(io)};
    std::shared_ptr<RecordingProtector> protector = std::make_shared<RecordingProtector>();
    std::shared_ptr<IP2PDatagramTransport> transport =
        CreateNativeSocketP2PDatagramTransportFactory(protector)->Create(io);
    std::shared_ptr<P2PStunGatherer> gatherer = P2PStunGatherer::Create(owner);
    LoopbackResponder responder{io};
    boost::asio::steady_timer watchdog{io};
    bool timed_out = false;
    unsigned errors = 0;
    std::vector<std::vector<uint8_t>> non_stun_received;
    P2PStunClient::StunResult result;
    unsigned completions = 0;

    bool Start() {
        return transport->Start([this](P2PDatagramReceiveStatus status,
            const Udp::endpoint& sender, const uint8_t* packet, int size) {
            if (status != P2PDatagramReceiveStatus::Packet) {
                ++errors;
                return;
            }
            const std::vector<uint8_t> bytes(packet, packet + size);
            if (P2PStunClient::IsStunDatagram(packet, size)) {
                boost::asio::post(owner, [this, sender, bytes] {
                    BOOST_CHECK(gatherer->HandleDatagram(sender, bytes.data(),
                        static_cast<int>(bytes.size()), 7, 19));
                });
            }
            else {
                non_stun_received.push_back(bytes);
                if (non_stun_received.size() == 2) Stop();
            }
        });
    }
    void Gather(const std::function<void()>& on_complete = {}) {
        boost::asio::post(owner, [this, on_complete] {
            BOOST_REQUIRE(gatherer->Start(transport, {responder.Endpoint()}, 7, 19,
                [this, on_complete](const P2PStunClient::StunResult& value,
                    uint64_t generation, uint64_t registration) {
                    BOOST_TEST(generation == 7u);
                    BOOST_TEST(registration == 19u);
                    BOOST_CHECK(owner.running_in_this_thread());
                    ++completions;
                    result = value;
                    if (on_complete) on_complete();
                }));
        });
    }
    void Run(unsigned milliseconds = 2500) {
        watchdog.expires_after(std::chrono::milliseconds(milliseconds));
        watchdog.async_wait([this](const boost::system::error_code& ec) {
            if (!ec) { timed_out = true; Stop(); }
        });
        responder.Receive();
        io.run();
    }
    void Stop() {
        gatherer->Cancel();
        transport->Close();
        responder.Close();
        watchdog.cancel();
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(route_discovery_is_protected_before_connect_and_fails_closed) {
    boost::asio::io_context io;
    auto protector = std::make_shared<RecordingProtector>();
    const Udp::endpoint destination(boost::asio::ip::address_v4::loopback(), 9);
    BOOST_CHECK(GetProtectedP2PRouteAddress(io, protector, destination).is_loopback());
    BOOST_CHECK(protector->unbound);
    protector->allow = false;
    BOOST_CHECK(GetProtectedP2PRouteAddress(io, protector, destination).is_unspecified());
    auto transport = CreateNativeSocketP2PDatagramTransportFactory(protector)->Create(io);
    protector->allow = true;
    BOOST_REQUIRE(transport->Start([](P2PDatagramReceiveStatus, const Udp::endpoint&, const uint8_t*, int) {}));
    BOOST_CHECK(protector->unbound);
    transport->Close();
}

BOOST_AUTO_TEST_CASE(stun_probe_and_data_share_one_socket_protected_before_first_send) {
    NativeFixture fixture;
    BOOST_REQUIRE(fixture.Start());
    const auto local_port = fixture.transport->LocalEndpoint().port();
    BOOST_REQUIRE(local_port != 0);
    BOOST_TEST(fixture.protector->calls.load() >= 1u);
    BOOST_CHECK(fixture.protector->valid_descriptor);
    const std::vector<uint8_t> probe{2, 1, 11, 12};
    const std::vector<uint8_t> data{2, 5, 21, 22, 23};
    fixture.responder.on_packet = [&](const Udp::endpoint& sender, const auto& packet) {
        BOOST_TEST(fixture.protector->calls.load() >= 1u);
        BOOST_TEST(sender.port() == local_port);
        if (P2PStunClient::IsStunDatagram(packet.data(), static_cast<int>(packet.size()))) {
            fixture.responder.Send(BindingResponse(packet.data(), sender), sender);
        }
        else {
            fixture.responder.Send(packet, sender);
        }
    };
    fixture.Gather([&] {
        BOOST_REQUIRE(fixture.result.success);
        BOOST_TEST(fixture.result.mapped_endpoint.port() == local_port);
        BOOST_CHECK(fixture.transport->SendTo(probe.data(), static_cast<int>(probe.size()),
            fixture.responder.Endpoint()));
        BOOST_CHECK(fixture.transport->SendTo(data.data(), static_cast<int>(data.size()),
            fixture.responder.Endpoint()));
    });
    fixture.Run();
    BOOST_CHECK(!fixture.timed_out);
    BOOST_TEST(fixture.completions == 1u);
    BOOST_REQUIRE(fixture.responder.observed.size() == 3);
    BOOST_CHECK(fixture.responder.observed[0] == fixture.responder.observed[1]);
    BOOST_CHECK(fixture.responder.observed[1] == fixture.responder.observed[2]);
    BOOST_REQUIRE(fixture.non_stun_received.size() == 2);
    BOOST_CHECK(fixture.non_stun_received[0] == probe);
    BOOST_CHECK(fixture.non_stun_received[1] == data);
    BOOST_TEST(fixture.errors == 0u);
    BOOST_CHECK(!fixture.transport->IsReady());
}

BOOST_AUTO_TEST_CASE(lost_first_stun_request_retries_identical_bytes_on_same_socket) {
    NativeFixture fixture;
    BOOST_REQUIRE(fixture.Start());
    fixture.responder.on_packet = [&](const Udp::endpoint& sender, const auto& packet) {
        if (fixture.responder.requests.size() == 2) {
            fixture.responder.Send(BindingResponse(packet.data(), sender), sender);
        }
    };
    fixture.Gather([&] { fixture.Stop(); });
    fixture.Run();
    BOOST_CHECK(!fixture.timed_out);
    BOOST_CHECK(fixture.result.success);
    BOOST_TEST(fixture.completions == 1u);
    BOOST_REQUIRE(fixture.responder.requests.size() == 2);
    BOOST_CHECK(fixture.responder.requests[0] == fixture.responder.requests[1]);
    BOOST_CHECK(fixture.responder.observed[0] == fixture.responder.observed[1]);
    BOOST_TEST(fixture.protector->calls.load() >= 1u);
}

BOOST_AUTO_TEST_CASE(protection_failure_and_close_fail_closed) {
    boost::asio::io_context io;
    auto protector = std::make_shared<RecordingProtector>();
    protector->allow = false;
    auto factory = CreateNativeSocketP2PDatagramTransportFactory(protector);
    BOOST_REQUIRE(factory);
    auto transport = factory->Create(io);
    unsigned callbacks = 0;
    BOOST_CHECK(!transport->Start([&](P2PDatagramReceiveStatus,
        const Udp::endpoint&, const uint8_t*, int) { ++callbacks; }));
    BOOST_TEST(protector->calls.load() == 1u);
    BOOST_CHECK(!transport->IsReady());
    BOOST_TEST(transport->LocalEndpoint().port() == 0u);
    const std::array<uint8_t, 2> packet{{2, 1}};
    BOOST_CHECK(!transport->SendTo(packet.data(), static_cast<int>(packet.size()),
        {boost::asio::ip::address_v4::loopback(), 40000}));
    transport->Close();
    transport->Close();
    io.run();
    BOOST_TEST(callbacks == 0u);
}

BOOST_AUTO_TEST_CASE(unready_protector_and_invalid_destinations_cannot_send) {
    boost::asio::io_context io;
    auto protector = std::make_shared<RecordingProtector>();
    protector->ready = false;
    auto transport = CreateNativeSocketP2PDatagramTransportFactory(protector)->Create(io);
    BOOST_CHECK(!transport->IsReady());
    BOOST_CHECK(!transport->Start([](P2PDatagramReceiveStatus,
        const Udp::endpoint&, const uint8_t*, int) {}));
    BOOST_TEST(protector->calls.load() == 0u);
    BOOST_TEST(transport->LocalEndpoint().port() == 0u);

    protector = std::make_shared<RecordingProtector>();
    transport = CreateNativeSocketP2PDatagramTransportFactory(protector)->Create(io);
    BOOST_REQUIRE(transport->Start([](P2PDatagramReceiveStatus,
        const Udp::endpoint&, const uint8_t*, int) {}));
    const std::array<uint8_t, 2> packet{{2, 1}};
    BOOST_CHECK(!transport->SendTo(packet.data(), static_cast<int>(packet.size()),
        {boost::asio::ip::address_v4::loopback(), 0}));
    BOOST_CHECK(!transport->SendTo(packet.data(), static_cast<int>(packet.size()),
        {boost::asio::ip::address_v4::any(), 3478}));
    BOOST_CHECK(!transport->SendTo(packet.data(), static_cast<int>(packet.size()),
        {boost::asio::ip::address_v6::loopback(), 3478}));
    const std::vector<uint8_t> oversized(2049, 0);
    BOOST_CHECK(!transport->SendTo(oversized.data(), static_cast<int>(oversized.size()),
        {boost::asio::ip::address_v4::loopback(), 3478}));
    transport->Close();
    io.run();
}

BOOST_AUTO_TEST_CASE(cancelled_gather_discards_late_real_response_and_preserves_transport) {
    NativeFixture fixture;
    BOOST_REQUIRE(fixture.Start());
    fixture.responder.on_packet = [&](const Udp::endpoint& sender, const auto& packet) {
        fixture.gatherer->Cancel();
        BOOST_CHECK(fixture.transport->IsReady());
        fixture.responder.Send(BindingResponse(packet.data(), sender), sender);
        fixture.responder.Send({2, 5, 1}, sender);
        fixture.responder.Send({2, 5, 2}, sender);
    };
    fixture.Gather();
    fixture.Run(1500);
    BOOST_CHECK(!fixture.timed_out);
    BOOST_TEST(fixture.completions == 0u);
    BOOST_TEST(fixture.responder.requests.size() == 1u);
    BOOST_TEST(fixture.non_stun_received.size() == 2u);
}

BOOST_AUTO_TEST_CASE(shared_receive_chain_survives_oversized_remote_datagram) {
    NativeFixture fixture;
    BOOST_REQUIRE(fixture.Start());
    const Udp::endpoint local(boost::asio::ip::address_v4::loopback(),
        fixture.transport->LocalEndpoint().port());
    fixture.responder.Send(std::vector<uint8_t>(P2P_MAX_PACKET_SIZE + 1, 0xff), local);
    fixture.responder.Send(std::vector<uint8_t>(4096, 0xff), local);
    fixture.responder.Send({2, 5, 1}, local);
    fixture.responder.Send({2, 5, 2}, local);
    fixture.Run(1000);
    BOOST_CHECK(!fixture.timed_out);
    BOOST_TEST(fixture.errors == 0u);
    BOOST_REQUIRE(fixture.non_stun_received.size() == 2);
    BOOST_CHECK(fixture.non_stun_received[0] == std::vector<uint8_t>({2, 5, 1}));
    BOOST_CHECK(fixture.non_stun_received[1] == std::vector<uint8_t>({2, 5, 2}));
}

BOOST_AUTO_TEST_CASE(maximum_datagram_remains_complete_and_close_before_start_is_final) {
    NativeFixture fixture;
    BOOST_REQUIRE(fixture.Start());
    const Udp::endpoint local(boost::asio::ip::address_v4::loopback(),
        fixture.transport->LocalEndpoint().port());
    const std::vector<uint8_t> maximum(P2P_MAX_PACKET_SIZE, 0xab);
    fixture.responder.Send(maximum, local);
    fixture.responder.Send({2, 5, 1}, local);
    fixture.Run(1000);
    BOOST_CHECK(!fixture.timed_out);
    BOOST_REQUIRE(fixture.non_stun_received.size() == 2);
    BOOST_CHECK(fixture.non_stun_received[0] == maximum);
    BOOST_TEST(fixture.errors == 0u);

    auto closed = CreateNativeSocketP2PDatagramTransportFactory(fixture.protector)
        ->Create(fixture.io);
    closed->Close();
    BOOST_CHECK(!closed->Start([](P2PDatagramReceiveStatus,
        const Udp::endpoint&, const uint8_t*, int) {}));
    BOOST_CHECK(!closed->IsReady());
    BOOST_TEST(closed->LocalEndpoint().port() == 0u);
}

BOOST_AUTO_TEST_CASE(concurrent_native_receive_send_and_close_are_serialized) {
    boost::asio::io_context io;
    auto protector = std::make_shared<RecordingProtector>();
    auto transport = CreateNativeSocketP2PDatagramTransportFactory(protector)->Create(io);
    Udp::socket peer(io, {boost::asio::ip::address_v4::loopback(), 0});
    const auto peer_endpoint = peer.local_endpoint();
    std::atomic<unsigned> received{0};
    BOOST_REQUIRE(transport->Start([&](P2PDatagramReceiveStatus status,
        const Udp::endpoint&, const uint8_t*, int) {
        if (status == P2PDatagramReceiveStatus::Packet) ++received;
    }));
    const Udp::endpoint local(boost::asio::ip::address_v4::loopback(),
        transport->LocalEndpoint().port());
    auto work = boost::asio::make_work_guard(io);
    std::thread first([&] { io.run(); });
    std::thread second([&] { io.run(); });
    const std::array<uint8_t, 4> packet{{2, 5, 1, 2}};
    std::thread sender([&] {
        for (unsigned i = 0; i < 200; ++i) {
            transport->SendTo(packet.data(), static_cast<int>(packet.size()), peer_endpoint);
        }
    });
    for (unsigned i = 0; i < 100; ++i) {
        boost::system::error_code ec;
        peer.send_to(boost::asio::buffer(packet), local, 0, ec);
    }
    std::thread closer([&] { transport->Close(); });
    sender.join();
    closer.join();
    transport->Close();
    work.reset();
    first.join();
    second.join();
    BOOST_CHECK(!transport->IsReady());
    BOOST_TEST(transport->LocalEndpoint().port() == 0u);
    BOOST_CHECK(!transport->SendTo(packet.data(), static_cast<int>(packet.size()), peer_endpoint));
}

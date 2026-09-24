#define BOOST_TEST_MODULE ios_p2p_datagram_transport_test
#include <boost/test/included/unit_test.hpp>

#include <ios/IosP2PDatagramTransport.h>

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>

using namespace ppp::p2p;

namespace {

struct FakeProvider {
    openppp2_ios_p2p_receive_fn receive = nullptr;
    void* receive_context = nullptr;
    int create_calls = 0;
    int start_calls = 0;
    int send_calls = 0;
    int close_calls = 0;
    std::array<uint8_t, 16> destination{};
    int destination_size = 0;
    uint16_t destination_port = 0;
    std::mutex send_mutex;
    std::condition_variable send_condition;
    bool block_send = false;
    bool send_entered = false;
    bool allow_send = false;
};

int FakeReady(void*) {
    return 1;
}

void* FakeCreate(
        openppp2_ios_p2p_receive_fn receive,
        void* receive_context,
        void* user_data) {
    auto* provider = static_cast<FakeProvider*>(user_data);
    ++provider->create_calls;
    provider->receive = receive;
    provider->receive_context = receive_context;
    return provider;
}

int FakeStart(void* handle) {
    ++static_cast<FakeProvider*>(handle)->start_calls;
    return 1;
}

int FakeSend(
        void* handle,
        const uint8_t* address,
        int address_size,
        uint16_t port,
        const void*,
        int packet_size) {
    auto* provider = static_cast<FakeProvider*>(handle);
    ++provider->send_calls;
    if (provider->block_send) {
        std::unique_lock<std::mutex> lock(provider->send_mutex);
        provider->send_entered = true;
        provider->send_condition.notify_all();
        provider->send_condition.wait(lock,
            [&]() noexcept { return provider->allow_send; });
    }
    provider->destination_size = address_size;
    provider->destination_port = port;
    std::memcpy(provider->destination.data(), address,
        static_cast<std::size_t>(address_size));
    return packet_size > 0 ? 1 : 0;
}

void FakeClose(void* handle) {
    ++static_cast<FakeProvider*>(handle)->close_calls;
}

openppp2_ios_p2p_datagram_provider MakeCallbacks() {
    return {FakeReady, FakeCreate, FakeStart, FakeSend, FakeClose};
}

} // namespace

BOOST_AUTO_TEST_CASE(provider_bridge_forwards_endpoints_packets_and_close_once) {
    boost::asio::io_context context;
    FakeProvider provider;
    auto factory = CreateIosProviderP2PDatagramTransportFactory(
        MakeCallbacks(), &provider);
    BOOST_REQUIRE(factory);

    auto transport = factory->Create(context);
    BOOST_REQUIRE(transport);
    BOOST_TEST(transport->IsReady());

    int receive_calls = 0;
    boost::asio::ip::udp::endpoint received_sender;
    std::array<uint8_t, 3> received_packet{};
    BOOST_REQUIRE(transport->Start(
        [&](P2PDatagramReceiveStatus status,
            const boost::asio::ip::udp::endpoint& sender,
            const uint8_t* packet,
            int packet_size) {
            BOOST_TEST(static_cast<int>(status) ==
                static_cast<int>(P2PDatagramReceiveStatus::Packet));
            ++receive_calls;
            received_sender = sender;
            BOOST_REQUIRE_EQUAL(packet_size, 3);
            std::memcpy(received_packet.data(), packet, 3);
        }));

    const uint8_t outbound[] = {1, 2, 3};
    const auto destination = boost::asio::ip::udp::endpoint(
        boost::asio::ip::make_address("203.0.113.9"), 45000);
    BOOST_REQUIRE(transport->SendTo(outbound, 3, destination));
    BOOST_TEST(provider.create_calls == 1);
    BOOST_TEST(provider.start_calls == 1);
    BOOST_TEST(provider.send_calls == 1);
    BOOST_TEST(provider.destination_size == 4);
    BOOST_TEST(provider.destination_port == 45000);
    BOOST_TEST(provider.destination[0] == 203);

    const uint8_t sender[] = {198, 51, 100, 7};
    const uint8_t inbound[] = {7, 8, 9};
    provider.receive(provider.receive_context, 0,
        sender, 4, 46000, inbound, 3);
    context.run();
    BOOST_TEST(receive_calls == 1);
    BOOST_TEST(received_sender.address().to_string() == "198.51.100.7");
    BOOST_TEST(received_sender.port() == 46000);
    BOOST_TEST(received_packet[2] == 9);

    transport->Close();
    transport->Close();
    BOOST_TEST(provider.close_calls == 1);

    context.restart();
    provider.receive(provider.receive_context, 0,
        sender, 4, 46000, inbound, 3);
    context.run();
    BOOST_TEST(receive_calls == 1);
}

BOOST_AUTO_TEST_CASE(incomplete_provider_contract_fails_closed) {
    boost::asio::io_context context;
    FakeProvider provider;
    auto callbacks = MakeCallbacks();
    callbacks.send = nullptr;

    auto factory = CreateIosProviderP2PDatagramTransportFactory(
        callbacks, &provider);
    BOOST_TEST(!factory);
}

BOOST_AUTO_TEST_CASE(queued_receive_is_safe_after_transport_destruction) {
    boost::asio::io_context context;
    FakeProvider provider;
    auto factory = CreateIosProviderP2PDatagramTransportFactory(
        MakeCallbacks(), &provider);
    auto transport = factory->Create(context);
    int receive_calls = 0;
    BOOST_REQUIRE(transport->Start(
        [&](P2PDatagramReceiveStatus,
            const boost::asio::ip::udp::endpoint&,
            const uint8_t*, int) {
            ++receive_calls;
        }));

    const uint8_t sender[] = {198, 51, 100, 8};
    const uint8_t inbound[] = {4, 5, 6};
    provider.receive(provider.receive_context, 0,
        sender, 4, 47000, inbound, 3);

    transport->Close();
    transport.reset();
    context.run();

    BOOST_TEST(receive_calls == 0);
    BOOST_TEST(provider.close_calls == 1);
}

BOOST_AUTO_TEST_CASE(close_waits_for_in_flight_provider_send) {
    boost::asio::io_context context;
    FakeProvider provider;
    provider.block_send = true;
    auto factory = CreateIosProviderP2PDatagramTransportFactory(
        MakeCallbacks(), &provider);
    auto transport = factory->Create(context);
    BOOST_REQUIRE(transport->Start(
        [](P2PDatagramReceiveStatus,
           const boost::asio::ip::udp::endpoint&,
           const uint8_t*, int) {}));

    const uint8_t outbound[] = {1, 2, 3};
    const auto destination = boost::asio::ip::udp::endpoint(
        boost::asio::ip::make_address("203.0.113.10"), 48000);
    bool send_result = false;
    std::thread sender([&]() {
        send_result = transport->SendTo(outbound, 3, destination);
    });
    {
        std::unique_lock<std::mutex> lock(provider.send_mutex);
        provider.send_condition.wait(lock,
            [&]() noexcept { return provider.send_entered; });
    }

    std::mutex close_mutex;
    std::condition_variable close_condition;
    bool close_finished = false;
    std::thread closer([&]() {
        transport->Close();
        {
            std::lock_guard<std::mutex> lock(close_mutex);
            close_finished = true;
        }
        close_condition.notify_all();
    });
    {
        std::unique_lock<std::mutex> lock(close_mutex);
        close_condition.wait_for(lock, std::chrono::milliseconds(100),
            [&]() noexcept { return close_finished; });
        BOOST_TEST(!close_finished);
    }

    {
        std::lock_guard<std::mutex> lock(provider.send_mutex);
        provider.allow_send = true;
    }
    provider.send_condition.notify_all();
    sender.join();
    closer.join();

    BOOST_TEST(send_result);
    BOOST_TEST(provider.close_calls == 1);
}

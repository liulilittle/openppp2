#define BOOST_TEST_MODULE dns_udp_relay_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/dns/DnsUdpRelay.h>
#include <ppp/app/client/dns/DnsRelayOperation.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace client_dns = ppp::app::client::dns;

namespace {

boost::asio::ip::udp::endpoint MakeEndpoint(const char* address, uint16_t port) {
    boost::system::error_code ec;
    return boost::asio::ip::udp::endpoint(
        boost::asio::ip::make_address(address, ec), port);
}

}  // namespace

BOOST_AUTO_TEST_CASE(accepts_matching_source_and_transaction_id) {
    const auto server = MakeEndpoint("1.1.1.1", 53);
    const auto received = MakeEndpoint("1.1.1.1", 53);
    const ppp::Byte query[12] = { 0x12, 0x34, 0x01, 0x00 };
    const ppp::Byte response[12] = { 0x12, 0x34, 0x81, 0x80 };

    BOOST_TEST(client_dns::DnsUdpRelay::ShouldAcceptRelayResponse(
        received, server, query, sizeof(query), response, sizeof(response)));
}

BOOST_AUTO_TEST_CASE(rejects_mismatched_source_endpoint) {
    const auto server = MakeEndpoint("1.1.1.1", 53);
    const auto received = MakeEndpoint("8.8.8.8", 53);
    const ppp::Byte query[12] = { 0x12, 0x34, 0x01, 0x00 };
    const ppp::Byte response[12] = { 0x12, 0x34, 0x81, 0x80 };

    BOOST_TEST(!client_dns::DnsUdpRelay::ShouldAcceptRelayResponse(
        received, server, query, sizeof(query), response, sizeof(response)));
}

BOOST_AUTO_TEST_CASE(rejects_mismatched_transaction_id) {
    const auto server = MakeEndpoint("9.9.9.9", 53);
    const auto received = MakeEndpoint("9.9.9.9", 53);
    const ppp::Byte query[12] = { 0x12, 0x34, 0x01, 0x00 };
    const ppp::Byte response[12] = { 0x12, 0x35, 0x81, 0x80 };

    BOOST_TEST(!client_dns::DnsUdpRelay::ShouldAcceptRelayResponse(
        received, server, query, sizeof(query), response, sizeof(response)));
}

BOOST_AUTO_TEST_CASE(rejects_wrong_source_port) {
    const auto server = MakeEndpoint("1.1.1.1", 53);
    const auto received = MakeEndpoint("1.1.1.1", 5353);
    const ppp::Byte query[12] = { 0xab, 0xcd, 0x01, 0x00 };
    const ppp::Byte response[12] = { 0xab, 0xcd, 0x81, 0x80 };

    BOOST_TEST(!client_dns::DnsUdpRelay::ShouldAcceptRelayResponse(
        received, server, query, sizeof(query), response, sizeof(response)));
}

BOOST_AUTO_TEST_CASE(spawn_rejects_invalid_context_or_session) {
    client_dns::DnsQueryContext context;
    BOOST_TEST(!client_dns::DnsUdpRelay::CanSpawn(context, nullptr));
}

BOOST_AUTO_TEST_CASE(response_timeout_and_teardown_have_one_winner) {
    std::atomic<int> cleanup{0};
    std::atomic<int> responses{0};
    std::atomic<int> fallbacks{0};
    auto operation = std::make_shared<client_dns::DnsRelayOperation>(
        [&]() { ++cleanup; }, [&]() { ++fallbacks; }, []() { return true; });

    std::mutex mutex;
    std::condition_variable ready_cv;
    std::condition_variable start_cv;
    int ready = 0;
    bool start = false;
    auto wait_for_start = [&]() {
        std::unique_lock<std::mutex> lock(mutex);
        ++ready;
        ready_cv.notify_one();
        start_cv.wait(lock, [&]() { return start; });
    };

    std::thread response([&]() {
        wait_for_start();
        operation->CompleteResponse([&]() { ++responses; });
    });
    std::thread timeout([&]() {
        wait_for_start();
        operation->CompleteFallback();
    });
    std::thread teardown([&]() {
        wait_for_start();
        operation->CompleteFallback();
    });
    {
        std::unique_lock<std::mutex> lock(mutex);
        ready_cv.wait(lock, [&]() { return ready == 3; });
        start = true;
    }
    start_cv.notify_all();
    response.join();
    timeout.join();
    teardown.join();

    BOOST_TEST(cleanup.load() == 1);
    BOOST_TEST(responses.load() + fallbacks.load() == 1);
}

BOOST_AUTO_TEST_CASE(setup_rollback_rejects_late_callback) {
    int cleanup = 0;
    int responses = 0;
    int fallbacks = 0;
    auto operation = std::make_shared<client_dns::DnsRelayOperation>(
        [&]() { ++cleanup; }, [&]() { ++fallbacks; }, []() { return true; });

    BOOST_TEST(operation->CompleteFallback());
    BOOST_TEST(!operation->CompleteResponse([&]() { ++responses; }));
    BOOST_TEST(!operation->CompleteFallback());
    BOOST_TEST(cleanup == 1);
    BOOST_TEST(fallbacks == 1);
    BOOST_TEST(responses == 0);
}

BOOST_AUTO_TEST_CASE(completed_operation_has_no_self_capture_cycle) {
    std::weak_ptr<client_dns::DnsRelayOperation> weak;
    std::function<void()> late_callback;
    {
        auto operation = std::make_shared<client_dns::DnsRelayOperation>(
            []() {}, []() {}, []() { return true; });
        weak = operation;
        late_callback = [operation]() { operation->CompleteFallback(); };
        operation->CompleteFallback();
    }

    BOOST_TEST(!weak.expired());
    late_callback = {};
    BOOST_TEST(weak.expired());
}

BOOST_AUTO_TEST_CASE(output_rechecks_session_after_cleanup) {
    bool active = true;
    int outputs = 0;
    client_dns::DnsRelayOperation operation(
        [&]() { active = false; }, []() {}, [&]() { return active; });

    BOOST_TEST(operation.CompleteResponse([&]() { ++outputs; }));
    BOOST_TEST(outputs == 0);
}

BOOST_AUTO_TEST_CASE(operation_tokens_are_monotonic_and_handles_are_stable) {
    client_dns::DnsRelayOperation first([]() {}, []() {}, []() { return true; });
    client_dns::DnsRelayOperation second([]() {}, []() {}, []() { return true; });
    void* first_handle = first.RegistryHandle();

    BOOST_TEST(second.Token() > first.Token());
    BOOST_TEST(first_handle == first.RegistryHandle());
    BOOST_TEST(first_handle != second.RegistryHandle());
}

BOOST_AUTO_TEST_CASE(weak_timeout_callback_does_not_retain_operation) {
    std::weak_ptr<client_dns::DnsRelayOperation> weak;
    std::function<void()> timeout_callback;
    {
        auto operation = std::make_shared<client_dns::DnsRelayOperation>(
            []() {}, []() {}, []() { return true; });
        weak = operation;
        timeout_callback = [weak]() {
            const auto active = weak.lock();
            if (active) {
                active->CompleteFallback();
            }
        };
    }

    BOOST_TEST(weak.expired());
    timeout_callback();
}

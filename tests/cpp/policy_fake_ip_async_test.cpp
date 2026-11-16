#include <ppp/app/client/dns/PolicyFakeIpAsync.h>

#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>

using namespace ppp::app::client::dns;
namespace fs = std::filesystem;

namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

void Run() {
    const auto directory = fs::temp_directory_path() /
        ("openppp2-fake-async-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    auto store = std::make_shared<DurableFakeIpStore>();
    std::mutex gate_mutex;
    std::condition_variable gate;
    bool first_write_entered = false;
    bool release_first_write = false;
    std::atomic_bool block_once{true};
    DurableFakeIpStore::Options options;
    options.allow_stage = [&](DurableFakeIpStore::Stage stage) {
        if (stage == DurableFakeIpStore::Stage::JournalAppend && block_once.exchange(false)) {
            std::unique_lock<std::mutex> lock(gate_mutex);
            first_write_entered = true;
            gate.notify_all();
            gate.wait(lock, [&] { return release_first_write; });
        }
        return true;
    };
    Require(store->Open(directory.string(), "async-test", "198.18.0.0/29", options), "store open failed");

    auto io = std::make_shared<boost::asio::io_context>();
    auto work = boost::asio::make_work_guard(*io);
    std::mutex result_mutex;
    std::condition_variable result;
    bool first_delivered = false;
    bool late_delivered = false;
    bool first_durable_before_output = false;
    std::atomic_int pending_count{0};
    std::thread::id io_thread;
    std::thread runner([&] { io_thread = std::this_thread::get_id(); io->run(); });

    auto first_active = std::make_shared<std::atomic_bool>(true);
    Require(PolicyFakeIpAsync::Allocate(store, io, "first.example", [first_active] {
        return first_active->load();
    }, [&](bool ok, uint32_t address) {
        std::string hostname;
        first_durable_before_output = ok && store->LookupHostname(address, hostname) && hostname == "first.example";
        std::lock_guard<std::mutex> lock(result_mutex);
        first_delivered = std::this_thread::get_id() == io_thread;
        result.notify_all();
    }, [&pending_count](std::ptrdiff_t delta) {
        pending_count.fetch_add(static_cast<int>(delta));
    }), "first allocation was not queued");

    {
        std::unique_lock<std::mutex> lock(gate_mutex);
        Require(gate.wait_for(lock, std::chrono::seconds(5), [&] { return first_write_entered; }), "disk write did not reach injected gate");
    }
    auto late_active = std::make_shared<std::atomic_bool>(true);
    Require(PolicyFakeIpAsync::Allocate(store, io, "late.example", [late_active] {
        return late_active->load();
    }, [&](bool, uint32_t) {
        std::lock_guard<std::mutex> lock(result_mutex);
        late_delivered = true;
        result.notify_all();
    }, [&pending_count](std::ptrdiff_t delta) {
        pending_count.fetch_add(static_cast<int>(delta));
    }), "late allocation was not queued");
    late_active->store(false);
    {
        std::lock_guard<std::mutex> lock(gate_mutex);
        release_first_write = true;
    }
    gate.notify_all();
    {
        std::unique_lock<std::mutex> lock(result_mutex);
        Require(result.wait_for(lock, std::chrono::seconds(5), [&] { return first_delivered; }), "durable completion was not delivered");
    }
    Require(first_durable_before_output, "allocation callback ran before the mapping became durable");
    Require(!late_delivered, "inactive request produced a late DNS output callback");
    uint32_t late_address = 0;
    Require(!store->LookupAddress("late.example", late_address), "canceled queued request wrote a mapping");
    const auto pending_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (pending_count.load() != 0 && std::chrono::steady_clock::now() < pending_deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    Require(pending_count.load() == 0, "pending observer did not return to zero");

    first_active->store(false);
    work.reset();
    runner.join();
    store->Close();
    std::error_code ec;
    fs::remove_all(directory, ec);
}

void RunNoDeliveryAfterClose(bool deactivate_request) {
    const auto directory = fs::temp_directory_path() /
        ("openppp2-fake-async-close-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    auto store = std::make_shared<DurableFakeIpStore>();
    std::mutex gate_mutex;
    std::condition_variable gate;
    bool write_entered = false;
    bool release_write = false;
    DurableFakeIpStore::Options options;
    options.allow_stage = [&](DurableFakeIpStore::Stage stage) {
        if (stage == DurableFakeIpStore::Stage::JournalAppend) {
            std::unique_lock<std::mutex> lock(gate_mutex);
            write_entered = true;
            gate.notify_all();
            gate.wait(lock, [&] { return release_write; });
        }
        return true;
    };
    Require(store->Open(directory.string(), "async-stopped-test", "198.18.0.0/29", options),
        "stopped-context store open failed");

    auto io = std::make_shared<boost::asio::io_context>();
    io->stop();
    auto probe = std::make_shared<int>(1);
    std::weak_ptr<int> callback_probe = probe;
    auto request_active = std::make_shared<std::atomic_bool>(true);
    std::atomic_int pending_count{0};
    Require(PolicyFakeIpAsync::Allocate(store, io, "durable-after-stop.example", [request_active] {
        return request_active->load();
    },
        [probe](bool, uint32_t) {}, [&pending_count](std::ptrdiff_t delta) {
            pending_count.fetch_add(static_cast<int>(delta));
        }), "stopped-context allocation was not queued");
    probe.reset();
    {
        std::unique_lock<std::mutex> lock(gate_mutex);
        Require(gate.wait_for(lock, std::chrono::seconds(5), [&] { return write_entered; }),
            "stopped-context write did not reach injected gate");
        if (deactivate_request) request_active->store(false);
        release_write = true;
    }
    gate.notify_all();

    uint32_t address = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!store->LookupAddress("durable-after-stop.example", address) &&
        std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    Require(address != 0, "stopped-context allocation did not become durable");
    Require(pending_count.load() == 0, "stopped-context pending gauge did not return to zero");
    const auto release_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!callback_probe.expired() && std::chrono::steady_clock::now() < release_deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    Require(callback_probe.expired(), "stopped context retained the output callback");

    io.reset();
    store->Close();
    std::error_code ec;
    fs::remove_all(directory, ec);
}
}

int main() {
    try { Run(); RunNoDeliveryAfterClose(false); RunNoDeliveryAfterClose(true); }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    return 0;
}

// Offline Windows regression: no adapter, socket, route or PPP application.
#include <ppp/app/client/xtcp/XtcpRuntime.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <thread>

int main() {
    if (_putenv_s("OPENPPP2_XTCP_SHARDS", "2") != 0 ||
        _putenv_s("OPENPPP2_XTCP_CC", "kcc") != 0 ||
        _putenv_s("OPENPPP2_XTCP_PERF_JSON", "") != 0) {
        return 1;
    }
    using ppp::app::client::xtcp::XtcpRuntime;
    for (int iteration = 0; iteration < 16; ++iteration) {
        auto context = std::make_shared<boost::asio::io_context>();
        auto lifetime = std::make_shared<int>(0);
        std::weak_ptr<int> released = lifetime;
        auto runtime = std::make_unique<XtcpRuntime>(context,
            [lifetime](std::shared_ptr<std::uint8_t>&&, int,
                std::optional<ppp::tap::TxGsoMetadata>) noexcept { return true; },
            XtcpRuntime::ListenerEndpointHandler{},
            XtcpRuntime::ExternalAcceptHandler{}, XtcpRuntime::ExternalCancelHandler{});
        lifetime.reset();
        if (!runtime->Start()) {
            std::fprintf(stderr, "FAIL: start at iteration %d\n", iteration);
            return 1;
        }
        runtime->MarkReady();
        runtime->Stop();
        if ((iteration & 1) == 0) {
            // Also exercise disposal after teardown has had time to drain:
            // the destructor's second Stop must not post to an exited pool.
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            runtime->Stop();
        }
        runtime.reset();
        // Stop posts teardown to the two owning strands. Cancellation handlers
        // must drain and release Impl, including when the last owner is a worker.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!released.expired() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (!released.expired()) {
            std::fprintf(stderr, "FAIL: runtime retained after stop at iteration %d\n", iteration);
            return 1;
        }
    }
    std::puts("PASS: Windows XTCP two-shard stop releases runtime (16 iterations)");
    return 0;
}

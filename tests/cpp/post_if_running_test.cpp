#include <ppp/coroutines/asio/post_if_running.h>

#include <atomic>
#include <iostream>
#include <stdexcept>

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

}

int main() {
    try {
        namespace pca = ppp::coroutines::asio;

        // Running context: handler is scheduled and runs.
        {
            boost::asio::io_context context;
            std::atomic<int> ran{0};
            Require(!pca::ExecutorStopped(context.get_executor()), "fresh context must not be stopped");
            Require(pca::PostIfRunning(context.get_executor(), [&ran]() noexcept { ran++; }), "post on running context must succeed");
            Require(pca::DispatchIfRunning(context.get_executor(), [&ran]() noexcept { ran++; }) , "dispatch on running context must succeed");
            context.run();
            Require(ran == 2, "both handlers must run on a running context");
        }

        // Stopped context: refused immediately, handler never queued (no wait that could hang).
        {
            boost::asio::io_context context;
            std::atomic<int> ran{0};
            context.stop();
            Require(pca::ExecutorStopped(context.get_executor()), "stopped context must be reported");
            Require(!pca::PostIfRunning(context.get_executor(), [&ran]() noexcept { ran++; }), "post on stopped context must fail");
            Require(!pca::DispatchIfRunning(context.get_executor(), [&ran]() noexcept { ran++; }), "dispatch on stopped context must fail");
            context.restart();
            context.poll();
            Require(ran == 0, "refused handler must never be queued");
        }

        // Strand and type-erased socket/timer executors resolve to the same context.
        {
            boost::asio::io_context context;
            boost::asio::strand<boost::asio::io_context::executor_type> strand(context.get_executor());
            boost::asio::ip::tcp::socket socket(context);
            boost::asio::steady_timer timer(strand);
            Require(!pca::ExecutorStopped(strand) && !pca::ExecutorStopped(socket.get_executor()) && !pca::ExecutorStopped(timer.get_executor()), "running");
            context.stop();
            Require(pca::ExecutorStopped(strand), "stopped strand must be reported");
            Require(pca::ExecutorStopped(socket.get_executor()), "stopped socket executor must be reported");
            Require(pca::ExecutorStopped(timer.get_executor()), "stopped timer executor must be reported");
            Require(!pca::PostIfRunning(socket.get_executor(), []() noexcept {}), "post via socket executor must fail when stopped");
        }

        std::cout << "post_if_running_test passed" << std::endl;
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "post_if_running_test failed: " << e.what() << std::endl;
        return 1;
    }
}

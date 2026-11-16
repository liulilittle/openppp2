#define BOOST_TEST_MODULE yield_context_multi_iocontext_test
#include <boost/test/included/unit_test.hpp>
#include <ppp/coroutines/YieldContext.h>
#include <atomic>
#include <memory>
#include <thread>
#include <vector>

BOOST_AUTO_TEST_CASE(worker_one_and_n_keep_shard_execution_context) {
    for (int workers : {1, 4}) {
        std::vector<std::unique_ptr<boost::asio::io_context>> shards;
        std::vector<std::thread> threads;
        std::atomic<int> done{0}, errors{0};
        for (int i = 0; i < workers; ++i) {
            shards.emplace_back(new boost::asio::io_context);
            auto* shard = shards.back().get();
            for (int c = 0; c < 8; ++c) {
                BOOST_REQUIRE(ppp::coroutines::YieldContext::Spawn(*shard,
                    [&, shard](ppp::coroutines::YieldContext& y) {
                        const auto owner = std::this_thread::get_id();
                        for (int k = 0; k < 300; ++k) {
                            auto a = y.Arm();
                            boost::asio::post(*shard, [a] { a.R(); });
                            if (!y.Suspend(a) || &y.GetContext() != shard ||
                                std::this_thread::get_id() != owner) ++errors;
                        }
                        ++done;
                    }));
            }
        }
        for (auto& shard : shards) threads.emplace_back([ctx = shard.get()] { ctx->run(); });
        for (auto& thread : threads) thread.join();
        BOOST_TEST(done.load() == workers * 8);
        BOOST_TEST(errors.load() == 0);
    }
}

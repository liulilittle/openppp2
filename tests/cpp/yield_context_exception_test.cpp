#define BOOST_TEST_MODULE yield_context_exception_test
#include <boost/test/included/unit_test.hpp>
#include <ppp/coroutines/YieldContext.h>
#include <stdexcept>

BOOST_AUTO_TEST_CASE(handler_exceptions_unwind_and_reclaim_after_suspend) {
    boost::asio::io_context context;
    int destroyed = 0;
    int resumed = 0;
    struct Scope { int& n; ~Scope() { ++n; } };
    for (int kind = 0; kind < 2; ++kind) {
        BOOST_REQUIRE(ppp::coroutines::YieldContext::Spawn(context,
            [&, kind](ppp::coroutines::YieldContext& y) {
                Scope scope{destroyed};
                auto a = y.Arm();
                boost::asio::post(context, [a] { a.R(); });
                if (!y.Suspend(a)) std::abort();
                ++resumed;
                if (kind == 0) throw std::runtime_error("test exception");
                throw 7;
            }));
    }
    context.run();
    BOOST_TEST(resumed == 2);
    BOOST_TEST(destroyed == 2);
    // A fresh coroutine still runs after both exceptional completion paths.
    context.restart();
    BOOST_REQUIRE(ppp::coroutines::YieldContext::Spawn(context,
        [&](ppp::coroutines::YieldContext&) { ++resumed; }));
    context.run();
    BOOST_TEST(resumed == 3);
}

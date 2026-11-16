#define BOOST_TEST_MODULE yield_context_stack_test
#include <boost/test/included/unit_test.hpp>
#include <ppp/coroutines/YieldContext.h>
#include <array>

BOOST_AUTO_TEST_CASE(failed_post_can_retry_same_anchor) {
    boost::asio::io_context context;
    ppp::coroutines::YieldContext::Anchor anchor;
    bool completed = false;
    BOOST_REQUIRE(ppp::coroutines::YieldContext::Spawn(context,
        [&](ppp::coroutines::YieldContext& y) {
            anchor = y.Arm();
            if (!y.Suspend(anchor)) std::abort();
            completed = true;
        }));
    context.run();
    BOOST_TEST(!anchor.R()); // stopped context rejects the post
    context.restart();
    BOOST_REQUIRE(anchor.R());
    BOOST_TEST(!anchor.R());
    context.run();
    BOOST_TEST(completed);
    BOOST_TEST(!anchor.R());
}
#if defined(__unix__)
#include <csignal>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(__unix__)
BOOST_AUTO_TEST_CASE(explicit_allocator_overload_preserves_large_stack) {
    const pid_t child = fork();
    BOOST_REQUIRE(child >= 0);
    if (child == 0) {
        rlimit limit{0, 0};
        setrlimit(RLIMIT_CORE, &limit);
        boost::asio::io_context context;
        bool checked = false;
        if (!ppp::coroutines::YieldContext::Spawn(nullptr, context,
            [&](ppp::coroutines::YieldContext&) {
                volatile unsigned char data[512 * 1024];
                for (std::size_t i = 0; i < sizeof(data); ++i) data[i] = static_cast<unsigned char>(i);
                checked = data[sizeof(data) - 1] == 255;
            }, 4 * 1024 * 1024)) _exit(2);
        context.run();
        _exit(checked ? 0 : 3);
    }
    int status = 0;
    BOOST_REQUIRE(waitpid(child, &status, 0) == child);
    BOOST_REQUIRE(WIFEXITED(status));
    BOOST_TEST(WEXITSTATUS(status) == 0);
}
#endif

BOOST_AUTO_TEST_CASE(stack_contents_survive_suspend_and_complete) {
    boost::asio::io_context context;
    int checked = 0;
    BOOST_REQUIRE(ppp::coroutines::YieldContext::Spawn(context,
        [&](ppp::coroutines::YieldContext& y) {
            volatile unsigned char data[24576];
            for (std::size_t i = 0; i < sizeof(data); ++i) data[i] = static_cast<unsigned char>(i);
            for (int n = 0; n < 100; ++n) {
                auto a = y.Arm();
                boost::asio::post(context, [a] { a.R(); });
                if (!y.Suspend(a)) std::abort();
                for (std::size_t i = 0; i < sizeof(data); ++i)
                    if (data[i] != static_cast<unsigned char>(i)) std::abort();
                ++checked;
            }
        }));
    context.run();
    BOOST_TEST(checked == 100);
}

#if defined(PPP_COROCC_GUARD_STACK) && defined(__unix__)
BOOST_AUTO_TEST_CASE(guard_page_faults_in_child_process) {
    const pid_t child = fork();
    BOOST_REQUIRE(child >= 0);
    if (child == 0) {
        rlimit limit{0, 0};
        setrlimit(RLIMIT_CORE, &limit);
        std::signal(SIGSEGV, SIG_DFL);
        std::signal(SIGBUS, SIG_DFL);
        auto stack = ppp::coroutines::backend::AllocateStack(128 * 1024);
        if (!stack) _exit(2);
        // The byte immediately below the usable range is the protected page.
        volatile unsigned char* low = stack.get();
        low[-1] = 1;
        _exit(3);
    }
    int status = 0;
    BOOST_REQUIRE(waitpid(child, &status, 0) == child);
    BOOST_REQUIRE(WIFSIGNALED(status));
    BOOST_TEST((WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS));
}
#endif

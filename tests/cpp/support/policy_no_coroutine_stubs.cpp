#include <ppp/coroutines/YieldContext.h>
#include <cstdlib>

namespace ppp::coroutines {
// Legacy manager fixtures must never schedule native socket or DNS work.
bool YieldContext::Spawn(ppp::threading::BufferswapAllocator*, boost::asio::io_context&,
    boost::asio::strand<boost::asio::io_context::executor_type>*, SpawnHander&&, int) noexcept {
    std::abort();
}
}

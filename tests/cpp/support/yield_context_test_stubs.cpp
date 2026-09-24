// Link-only stubs for yield_context_test.
//
// YieldContext always runs with a null BufferswapAllocator in this test, so the
// allocator entry points are never called; they are referenced anyway by inline
// template code (MakeByteArray / New / Release).  ErrorHandler::SetLastErrorCode
// timestamps entries with Executors::GetTickCount(), whose full implementation
// would drag the executor/vmux dependency graph into this test binary.

#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/threading/Executors.h>

namespace ppp {
namespace threading {

    void* BufferswapAllocator::Alloc(uint32_t) noexcept {
        return nullptr;
    }

    bool BufferswapAllocator::Free(const void*) noexcept {
        return false;
    }

    uint64_t Executors::GetTickCount() noexcept {
        return 0;
    }

}  // namespace threading
}  // namespace ppp

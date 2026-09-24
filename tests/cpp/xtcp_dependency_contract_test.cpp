#include <xtcp/core/mempool.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include <xtcp/xtcp.h>

#include <cstdio>
#include <cstring>

namespace {
int failures = 0;

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) {                                                  \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #condition);                                        \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

void TestVersionContract() {
    const char* version = xtcp::Version();
    CHECK(nullptr != version);
    CHECK(0 == std::strcmp(XTCP_VERSION, version));
}

void TestMempoolLifecycle() {
    xtcp::core::Mempool pool(64, 2);
    CHECK(64 == pool.BlockSize());
    CHECK(2 == pool.Capacity());
    CHECK(2 == pool.FreeCount());

    void* first = pool.Alloc();
    void* second = pool.Alloc();
    CHECK(nullptr != first);
    CHECK(nullptr != second);
    CHECK(first != second);
    CHECK(nullptr == pool.Alloc());
    CHECK(0 == pool.FreeCount());

    pool.Free(first);
    CHECK(1 == pool.FreeCount());
    CHECK(first == pool.Alloc());
    pool.Free(first);
    pool.Free(second);
    CHECK(2 == pool.FreeCount());
}

void TestStackLifecycle() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend;
        xtcp::XtcpStack stack(&backend);
        CHECK(0 == stack.ConnectionCount());
        CHECK(xtcp::ndi::kCapNone == backend.Caps());
    }
    xtcp::buf::ShutdownPools();
}
}  // namespace

int main() {
    TestVersionContract();
    TestMempoolLifecycle();
    TestStackLifecycle();

    if (0 != failures) {
        std::fprintf(stderr, "xtcp_dependency_contract_test: %d failure(s)\n", failures);
        return 1;
    }
    std::puts("xtcp_dependency_contract_test: passed");
    return 0;
}

// H1 并发正确性护栏 —— 多线程 Alloc→写唯一 tag→读回验证→Free。
// 若分配器锁失效导致两线程拿到重叠内存，tag 会被覆盖 → 检出 corruption。
// 配合 ASan(-DENABLE_ASAN=ON) 跑可额外检测 data race / heap 越界。
// 改 BufferswapAllocator 锁的前后都必须 clean pass（回归护栏）。
#include <ppp/threading/BufferswapAllocator.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

using ppp::threading::BufferswapAllocator;

int main() {
    auto alloc = std::make_shared<BufferswapAllocator>(
        ppp::string("/tmp/ppp_stress_pool"), static_cast<uint64_t>(256) * 1024 * 1024);
    if (!alloc->IsVaild()) {
        printf("FAIL: allocator invalid (mmap/buddy init failed)\n");
        return 1;
    }

    std::atomic<int> corrupt{0};
    std::atomic<long> allocs{0};
    const int nthreads = 8;
    const int iters = 30000;

    std::vector<std::thread> ts;
    for (int t = 0; t < nthreads; ++t) {
        ts.emplace_back([&, t] {
            const unsigned char tag = static_cast<unsigned char>(t + 1);
            for (int i = 0; i < iters; ++i) {
                const int sz = 64 + (i % 8) * 128;
                unsigned char* p = static_cast<unsigned char*>(alloc->Alloc(static_cast<uint32_t>(sz)));
                if (p == nullptr) {
                    continue;
                }
                std::memset(p, tag, static_cast<size_t>(sz));
                // 读回验证：本线程写入的 tag 未被其它线程覆盖（重叠分配会破坏它）。
                for (int k = 0; k < sz; ++k) {
                    if (p[k] != tag) { corrupt.fetch_add(1); break; }
                }
                alloc->Free(p);
                allocs.fetch_add(1);
            }
        });
    }
    for (auto& th : ts) {
        th.join();
    }

    printf("%s (threads=%d allocs=%ld corrupt=%d)\n",
           corrupt.load() == 0 ? "PASS (no corruption)" : "FAIL (corruption!)",
           nthreads, allocs.load(), corrupt.load());
    return corrupt.load() == 0 ? 0 : 1;
}

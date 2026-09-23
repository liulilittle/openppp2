// BM1a 专用：内存池被斩断，加密类 MakeByteArray 模板在编译期引用 Alloc/Free，
// 但 BM1a 传 nullptr 走 make_shared_alloc 分支，运行时不触达这里。空实现即可。
// (BM2 用真实 BufferswapAllocator.cpp，绝不与本文件同时链接。)
#include <ppp/stdafx.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace threading {
        void* BufferswapAllocator::Alloc(uint32_t /*allocated_size*/) noexcept { return NULLPTR; }
        bool  BufferswapAllocator::Free(const void* /*allocated_memory*/) noexcept { return false; }
    }
}

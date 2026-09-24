#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/threading/BufferblockAllocator.h>
#include <ppp/Random.h>
#include <ppp/Int128.h>
#include <ppp/io/File.h>
#include <ppp/cryptography/EVP.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file BufferswapAllocator.cpp
 * @brief Implements block-partitioned virtual memory allocation and release.
 */

namespace ppp
{
    namespace threading
    {
        /**
         * @brief Initializes block allocators until the requested memory is covered.
         * @param path Root path template for non-Windows mapped files.
         * @param memory_size Total target memory size in bytes.
         */
        BufferswapAllocator::BufferswapAllocator(const ppp::string& path, uint64_t memory_size) noexcept
            : block_count_(0)
            , memory_size_(0)
        {
#if defined(_WIN32)
            if (memory_size > 0)
            {
#else
            if (memory_size > 0 && path.size() > 0)
            {
                ppp::string bufferblock_rootpath = ppp::io::File::GetFullPath(ppp::io::File::RewritePath(path.data()).data());
#endif
                /**
                 * @brief Splits requested capacity into cyclic chunks capped at 1GB.
                 * @details Keeps each block within practical limits for 32-bit targets.
                 */
                uint32_t bufferblock_sequenceno = 0;
                uint64_t residual_memory_size = memory_size;
                while (residual_memory_size > 0)
                {
                    uint64_t block_memory_size = residual_memory_size;
                    if (block_memory_size >= MAX_MEMORY_BLOCK_SIZE)
                    {
                        block_memory_size = MAX_MEMORY_BLOCK_SIZE;
                        residual_memory_size -= MAX_MEMORY_BLOCK_SIZE;
                    }
                    else
                    {
                        block_memory_size = residual_memory_size;
                        residual_memory_size = 0;
                    }

                    /**
                     * @brief Builds a per-block identifier/path for platform-specific backing.
                     * @details Windows uses kernel virtual memory names; non-Windows uses mapped files.
                     */
                    Random rand(++bufferblock_sequenceno);
                    Int128 guid;
                    rand.SetSeed(((int*)&guid)[0] = rand.Next());
                    rand.SetSeed(((int*)&guid)[1] = rand.Next());
                    rand.SetSeed(((int*)&guid)[2] = rand.Next());
                    rand.SetSeed(((int*)&guid)[3] = rand.Next());
#if defined(_WIN32)
                    ppp::string bufferblock_path = ppp::auxiliary::StringAuxiliary::Int128ToGuidString(guid);
#else
                    ppp::string bufferblock_path = bufferblock_rootpath;
                    bufferblock_path = Replace<ppp::string>(bufferblock_path, "{}", ppp::auxiliary::StringAuxiliary::Int128ToGuidString(guid));
                    bufferblock_path = ppp::io::File::RewritePath(bufferblock_path.data());
                    bufferblock_path = ppp::io::File::GetFullPath(bufferblock_path.data());
#endif

                    /** @brief Requests allocation of one backing virtual memory block. */
                    std::shared_ptr<BufferblockAllocator> bufffer_block = make_shared_object<BufferblockAllocator>(bufferblock_path, block_memory_size);
                    if (NULLPTR == bufffer_block)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                        break;
                    }

                    if (!bufffer_block->IsVaild())
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryPoolCreateFailed);
                        break;
                    }

                    blocks_.emplace_back(bufffer_block);
                    block_count_++;
                    memory_size_ += bufffer_block->GetMemorySize();
                }
            }
        }

        /**
         * @brief Disposes all managed blocks and clears internal state.
         */
        BufferswapAllocator::~BufferswapAllocator() noexcept
        {
            BufferblockAllocatorList blocks;
            do
            {
                SynchronizedObjectScope scope(syncobj_);
                blocks = std::move(blocks_);
                blocks_.clear();
            } while (false);

            for (BufferblockAllocatorPtr& i : blocks)
            {
                i->Dispose();
            }
        }

        /**
         * @brief Allocates memory by scanning managed blocks in round-robin style.
         * @param allocated_size Requested byte count.
         * @return Allocated pointer, or null when no block can satisfy the request.
         */
        void* BufferswapAllocator::Alloc(uint32_t allocated_size) noexcept
        {
            if (allocated_size == 0)
            {
                return NULLPTR;
            }

            // H1: 去掉 swap 层全局锁——各 BufferblockAllocator 已用自身 syncobj_ 保护其 buddy；
            // blocks_ 构造后固定(不再轮转)，故此处对 blocks_ 只读遍历，多线程可并发进入 block 层，
            // 消除原本"swap 锁 + block 锁"双重锁里多余的那一层。
            for (BufferblockAllocatorPtr& allocator : blocks_)
            {
                void* memory = allocator->Alloc(allocated_size);
                if (NULLPTR != memory)
                {
                    return memory;
                }
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryPoolExhausted);
            return NULLPTR;
        }

        /**
         * @brief Frees memory by delegating to the block that owns the pointer.
         * @param allocated_memory Pointer to release.
         * @return true when a block accepted the pointer; otherwise false.
         */
        bool BufferswapAllocator::Free(const void* allocated_memory) noexcept
        {
            if (NULLPTR == allocated_memory)
            {
                return false;
            }

            // H1: 去 swap 锁，只读遍历(blocks_ 构造后固定)；block->Free 内部已有 block 层锁。
            for (auto&& block : blocks_)
            {
                if (block->Free(allocated_memory))
                {
                    return true;
                }
            }

            return false;
        }

        /**
         * @brief Checks whether this allocator currently has at least one block.
         * @return true when usable blocks exist; otherwise false.
         */
        bool BufferswapAllocator::IsVaild() noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
            auto tail = blocks_.begin();
            auto endl = blocks_.end();
            return tail != endl;
        }

        /**
         * @brief Finds the block containing a specific allocated pointer.
         * @param allocated_memory Pointer to test.
         * @return Owning block allocator, or null if not found.
         */
        std::shared_ptr<BufferblockAllocator> BufferswapAllocator::IsInBlock(const void* allocated_memory) noexcept
        {
            if (NULLPTR == allocated_memory)
            {
                return NULLPTR;
            }

            SynchronizedObjectScope scope(syncobj_);
            for (auto&& block : blocks_)
            {
                if (block->IsInBlock(allocated_memory))
                {
                    return block;
                }
            }

            return NULLPTR;
        }

        /**
         * @brief Returns the configured page size of the first available block.
         * @return Page size in bytes, or 0 when no blocks are available.
         */
        uint32_t BufferswapAllocator::GetPageSize() noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
            for (auto&& block : blocks_)
            {
                return block->GetPageSize();
            }

            return 0;
        }

        /**
         * @brief Returns the total memory size assembled from all blocks.
         * @return Total managed size in bytes.
         */
        uint64_t BufferswapAllocator::GetMemorySize() noexcept
        {
            return memory_size_;
        }

        /**
         * @brief Aggregates currently available bytes across all blocks.
         * @return Total free size in bytes.
         */
        uint64_t BufferswapAllocator::GetAvailableSize() noexcept
        {
            uint64_t memory_size = 0;
            SynchronizedObjectScope scope(syncobj_);

            for (auto&& block : blocks_)
            {
                memory_size += block->GetAvailableSize();
            }

            return memory_size;
        }
    }
}

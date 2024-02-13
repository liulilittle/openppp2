#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/threading/BufferblockAllocator.h>
#include <ppp/Random.h>
#include <ppp/Int128.h>
#include <ppp/io/File.h>
#include <ppp/cryptography/EVP.h>
#include <ppp/auxiliary/StringAuxiliary.h>

namespace ppp
{
    namespace threading
    {
        BufferswapAllocator::BufferswapAllocator(const ppp::string& path, bool physical_memory) noexcept
            : BufferswapAllocator(path, path.empty() ? 0 : MAX_MEMORY_BLOCK_SIZE, physical_memory)
        {

        }

        BufferswapAllocator::BufferswapAllocator(const ppp::string& path, uint64_t memory_size, bool physical_memory) noexcept
            : block_count_(0)
            , memory_size_(0)
            , physical_memory_(physical_memory)
        {
            if (path.size() > 0 && memory_size > 0)
            {
                ppp::string bufferblock_rootpath = ppp::io::File::GetFullPath(ppp::io::File::RewritePath(path.data()).data());
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

                    Random rand(++bufferblock_sequenceno);
                    Int128 guid;
                    rand.SetSeed(((int*)&guid)[0] = rand.Next());
                    rand.SetSeed(((int*)&guid)[1] = rand.Next());
                    rand.SetSeed(((int*)&guid)[2] = rand.Next());
                    rand.SetSeed(((int*)&guid)[3] = rand.Next());

                    ppp::string bufferblock_path = bufferblock_rootpath;
                    bufferblock_path = Replace<ppp::string>(bufferblock_path, "{}", ppp::auxiliary::StringAuxiliary::Int128ToGuidString(guid));
                    bufferblock_path = ppp::io::File::RewritePath(bufferblock_path.data());
                    bufferblock_path = ppp::io::File::GetFullPath(bufferblock_path.data());

                    std::shared_ptr<BufferblockAllocator> bufffer_block = make_shared_object<BufferblockAllocator>(bufferblock_path, block_memory_size);
                    if (NULL == bufffer_block)
                    {
                        break;
                    }

                    if (!bufffer_block->IsVaild())
                    {
                        break;
                    }

                    blocks_.emplace_back(bufffer_block);
                    block_count_++;
                    memory_size_ += bufffer_block->GetMemorySize();
                }
            }
        }

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

        void* BufferswapAllocator::Alloc(uint32_t allocated_size) noexcept
        {
            if (allocated_size == 0)
            {
                return NULL;
            }

            int block_length = 0;
            SynchronizedObjectScope scope(syncobj_);
            BufferblockAllocatorList::iterator tail = blocks_.begin();
            BufferblockAllocatorList::iterator endl = blocks_.end();
            while (tail != endl)
            {
                BufferblockAllocatorPtr& allocator = *tail;
                void* memory = allocator->Alloc(allocated_size);
                if (NULL != memory)
                {
                    return memory;
                }
                elif(block_length++ >= block_count_)
                {
                    return NULL;
                }
                else 
                {
                    blocks_.emplace_back(allocator);
                    blocks_.erase(tail);
                    tail = blocks_.begin(); // The following expression is not recommended: tail = std::list.erase(...);
                }
            }
            return NULL;
        }

        bool BufferswapAllocator::Free(const void* allocated_memory) noexcept
        {
            if (NULL == allocated_memory)
            {
                return false;
            }

            SynchronizedObjectScope scope(syncobj_);
            for (auto&& block : blocks_)
            {
                if (block->Free(allocated_memory))
                {
                    return true;
                }
            }
            return false;
        }

        bool BufferswapAllocator::IsVaild() noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
            auto tail = blocks_.begin();
            auto endl = blocks_.end();
            return tail != endl;
        }

        bool BufferswapAllocator::IsPhysicalMemory() noexcept
        {
            return physical_memory_;
        }

        std::shared_ptr<BufferblockAllocator> BufferswapAllocator::IsInBlock(const void* allocated_memory) noexcept
        {
            if (NULL == allocated_memory)
            {
                return NULL;
            }

            SynchronizedObjectScope scope(syncobj_);
            for (auto&& block : blocks_)
            {
                if (block->IsInBlock(allocated_memory))
                {
                    return block;
                }
            }
            return NULL;
        }

        uint32_t BufferswapAllocator::GetPageSize() noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
            for (auto&& block : blocks_)
            {
                return block->GetPageSize();
            }
            return 0;
        }

        uint64_t BufferswapAllocator::GetMemorySize() noexcept
        {
            return memory_size_;
        }

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
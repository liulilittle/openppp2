#include <ppp/stdafx.h>
#include <ppp/io/File.h>
#include <ppp/threading/BufferblockAllocator.h>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

#include <common/memory/buddy_allocator.h>

namespace ppp
{
    namespace threading
    {
        BufferblockAllocator::BufferblockAllocator(const ppp::string& path) noexcept
            : BufferblockAllocator(path, 0)
        {

        }

        BufferblockAllocator::BufferblockAllocator(const ppp::string& path, uint32_t memory_size) noexcept
            : BufferblockAllocator(path, memory_size, PPP_MEMORY_ALIGNMENT_SIZE)
        {

        }

        BufferblockAllocator::BufferblockAllocator(const ppp::string& path, uint32_t memory_size, uint32_t page_size) noexcept
            : path_(path)
            , page_size_(0)
            , buddy_(NULL)
            , memory_start_(NULL)
            , memory_maxof_(NULL)
        {
            // The page size cannot be less than 16 bytes, otherwise the page size of the operating system is obtained.
            if (page_size < PPP_MEMORY_ALIGNMENT_SIZE)
            {
                page_size = GetMemoryPageSize();
            }

            // At least ensure that a minimum of 16MB and above is allocated to the file mapped to the memory space size.
            memory_size = std::max<uint32_t>(1 << 24, memory_size);
            memory_size = (uint32_t)Malign<int64_t>(memory_size, (page_size_ = page_size)); // For byte size alignment by page size, the memory size of the request file map must be a power of two.

            // An attempt is made to open a file mapping, but success is not guaranteed.
            void* buddy_arena = NULL;
            if (memory_size > 0)
            {
#if defined(_WIN32)
                // Windows directly calls the system interface to allocate virtual memory, no longer through the MMF technology to 
                // Allocate virtual memory, MMF technology to allocate virtual memory, exit the program will be stuck for a long time.
                memory_start_ = (char*)VirtualAlloc(NULL, memory_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (NULL != memory_start_)
                {
                    buddy_arena = memory_start_;
                    memory_maxof_ = (char*)buddy_arena + memory_size;
                }
#else
                // On non-windows platforms, virtual memory is allocated through system VirtualAlloc fucntion.   
                // MacOS directly uses shm, which has certain platform compatibility limitations.   
                // In order to ensure that the code does not appear too many platform branches, 
                // Linux/MacOS platforms use mmf technology to allocate virtual memory.
                if (path.size() > 0)
                {
                    std::shared_ptr<boost::interprocess::file_mapping> bip_mapping_file;
                    std::shared_ptr<boost::interprocess::mapped_region> bip_mapped_region;
                    try
                    {
                        do
                        {
                            // If the file specified in the path exists, the file is deleted.
                            // The failure to delete the original file indicates that the permission is insufficient or the file is occupied by another process.
                            ppp::io::File::Delete(path.data());

                            // Opens or creates a mappable memory file that requests the memory size.
                            ppp::io::File::Create(path.data(), memory_size);

                            // Creates or opens a file map and maps the file to the process's address space.
                            boost::interprocess::file_mapping mapping_file(path.data(), boost::interprocess::read_write);
                            boost::interprocess::mapped_region mapped_region(mapping_file, boost::interprocess::read_write);

                            // Swap the currently open file map and map area objects into the managed resource variables held by the object.
                            bip_mapping_file = make_shared_object<boost::interprocess::file_mapping>();
                            bip_mapped_region = make_shared_object<boost::interprocess::mapped_region>();
                            if (NULL != bip_mapping_file && NULL != bip_mapped_region)
                            {
                                bip_mapping_file->swap(mapping_file);
                                bip_mapped_region->swap(mapped_region);
                            }
                        } while (false);
                    }
                    catch (const boost::interprocess::interprocess_exception&)
                    {
                        ppp::io::File::Delete(path.data());
                    }

                    // When the file map is open and mapped to the memory address space of the process.
                    if (NULL != bip_mapping_file && NULL != bip_mapped_region)
                    {
                        bip_mapping_file_ = bip_mapping_file;
                        bip_mapped_region_ = bip_mapped_region;
                        buddy_arena = bip_mapped_region->get_address();
                    }
                }
#endif
            }

            if (NULL != buddy_arena)
            {
                /* You need space for arena and builtin metadata */
                struct buddy* buddy = buddy_embed((unsigned char*)buddy_arena, memory_size);
                if (NULL != buddy)
                {
                    buddy_ = buddy; /* buddy_init(buddy_metadata, buddy_arena, arena_size); */
                }

                /* Sets the header and tail Pointers that the file maps to memory. */
                memory_start_ = (char*)buddy_arena;
                memory_maxof_ = (char*)buddy_arena + memory_size;
            }

#if !defined(_WIN32)
            /* After mapping a file into virtual memory, attempting to immediately delete the file created by the mapping. */
            ppp::io::File::Delete(path.data());
#endif
        }

        BufferblockAllocator::~BufferblockAllocator() noexcept
        {
            Dispose();
        }

        void BufferblockAllocator::Dispose() noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
#if defined(_WIN32)
            if (VirtualFree(memory_start_, 0, MEM_RELEASE))
            {
                memory_start_ = NULL;
                memory_maxof_ = NULL;
            }
#else
            bip_mapped_region_ = NULL;
            bip_mapping_file_ = NULL;
#endif
            buddy_ = NULL;
            memory_start_ = NULL;
            memory_maxof_ = NULL;

#if !defined(_WIN32)
            ppp::io::File::Delete(path_.data());
#endif
        }

        bool BufferblockAllocator::IsVaild() noexcept
        {
            return NULL != buddy_;
        }

        bool BufferblockAllocator::IsInBlock(const void* allocated_memory) noexcept
        {
            if (NULL == buddy_ || NULL == allocated_memory)
            {
                return false;
            }

            if (allocated_memory >= memory_start_ && allocated_memory < memory_maxof_)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        ppp::string BufferblockAllocator::GetPath() noexcept
        {
            return path_;
        }

        uint32_t BufferblockAllocator::GetPageSize() noexcept
        {
            return page_size_;
        }

        uint32_t BufferblockAllocator::GetMemorySize() noexcept
        {
            return (uint32_t)((char*)memory_maxof_ - (char*)memory_start_);
        }

        uint32_t BufferblockAllocator::GetAvailableSize() noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
            struct buddy* buddy = reinterpret_cast<struct buddy*>(buddy_);
            if (NULL == buddy)
            {
                return 0;
            }

            return buddy_arena_free_size(buddy);
        }

        bool BufferblockAllocator::Free(const void* allocated_memory) noexcept
        {
            if (NULL == allocated_memory)
            {
                return false;
            }

            if (allocated_memory < memory_start_ || allocated_memory >= memory_maxof_)
            {
                return false;
            }

            SynchronizedObjectScope scope(syncobj_);
            struct buddy* buddy = reinterpret_cast<struct buddy*>(buddy_);
            if (NULL == buddy)
            {
                return false;
            }

            /* Free using the buddy allocator */
            buddy_free(buddy, constantof(allocated_memory));
            return true;
        }

        void* BufferblockAllocator::Alloc(uint32_t allocated_size) noexcept
        {
            if (allocated_size == 0)
            {
                return NULL;
            }

            SynchronizedObjectScope scope(syncobj_);
            struct buddy* buddy = reinterpret_cast<struct buddy*>(buddy_);
            if (NULL == buddy)
            {
                return NULL;
            }
            else
            {
                allocated_size = Malign(allocated_size, page_size_);
            }

            /* Allocate using the buddy allocator */
            void* data = buddy_malloc(buddy, allocated_size);
            return data;
        }
    }
}
#pragma once

#include <ppp/stdafx.h>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

namespace ppp
{
    namespace threading
    {
        class BufferblockAllocator final : public std::enable_shared_from_this<BufferblockAllocator>
        {
            typedef std::mutex                                      SynchronizedObject;
            typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;

        public:
            BufferblockAllocator(const ppp::string& path) noexcept;
            BufferblockAllocator(const ppp::string& path, uint32_t memory_size) noexcept;
            BufferblockAllocator(const ppp::string& path, uint32_t memory_size, uint32_t page_size) noexcept;
            ~BufferblockAllocator() noexcept;

        public:
            ppp::string                                             GetPath() noexcept;
            bool                                                    IsVaild() noexcept;
            bool                                                    IsInBlock(const void* allocated_memory) noexcept;
            uint32_t                                                GetPageSize() noexcept;
            uint32_t                                                GetMemorySize() noexcept;
            uint32_t                                                GetAvailableSize() noexcept;
            void*                                                   Alloc(uint32_t allocated_size) noexcept;
            bool                                                    Free(const void* allocated_memory) noexcept;
            void                                                    Dispose() noexcept;

        public:
            template <typename T>
            std::shared_ptr<T>                                      MakeArray(int length) noexcept {
                static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

                if (length < 1) {
                    return NULL;
                }

                T* p = (T*)Alloc(length * sizeof(T));
                return std::shared_ptr<T>(p,
                    [self = shared_from_this(), this](void* allocated_memory) noexcept {
                        Free(allocated_memory);
                    });
            }
        
            template <typename T, typename... A>     
            std::shared_ptr<T>                                      MakeObject(A&&... args) noexcept {
                static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

                void* memory = Alloc(sizeof(T));
                if (NULL == memory) {
                    return NULL;
                }
                
                memset(memory, 0, sizeof(T));
                return std::shared_ptr<T>(new (memory) T(std::forward<A&&>(args)...),
                    [self = shared_from_this(), this](T* p) noexcept {
                        p->~T();
                        Free(p);
                    });
            }

        private:
            SynchronizedObject                                      syncobj_;
            ppp::string                                             path_;
            uint32_t                                                page_size_    = 0;
            void*                                                   buddy_        = NULL;
            void*                                                   memory_start_ = NULL;
            void*                                                   memory_maxof_ = NULL;
#if !defined(_WIN32)
            std::shared_ptr<boost::interprocess::file_mapping>      bip_mapping_file_;
            std::shared_ptr<boost::interprocess::mapped_region>     bip_mapped_region_;
#endif
        };
    }
}
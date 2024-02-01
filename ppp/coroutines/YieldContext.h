#pragma once

#include <ppp/stdafx.h>
#include <boost/coroutine/detail/coroutine_context.hpp>
#include <boost/context/detail/fcontext.hpp>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp
{
    namespace coroutines
    {
        class YieldContext final
        {
        public:
            typedef ppp::function<void(YieldContext&)>          SpawnHander;

        public:
            void                                                Resume() noexcept;
            void                                                Suspend() noexcept;
            void                                                Y() noexcept                   { Suspend(); }
            boost::asio::io_context&                            GetContext() const noexcept    { return context_; }
            YieldContext*                                       GetPtr() const noexcept        { return const_cast<YieldContext*>(this);}

        public:
            operator                                            bool() const noexcept          { return NULL != GetPtr(); }
            operator                                            YieldContext*() const noexcept { return GetPtr(); }

        public:
            static bool                                         Spawn(boost::asio::io_context& context, SpawnHander&& spawn) noexcept;
            static bool                                         Spawn(boost::asio::io_context& context, SpawnHander&& spawn, int stack_size) noexcept;

        public:
            static bool                                         Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, SpawnHander&& spawn) noexcept;
            static bool                                         Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, SpawnHander&& spawn, int stack_size) noexcept;

        private:
            void                                                Invoke() noexcept;
            static void                                         Handle(boost::context::detail::transfer_t t) noexcept;
            static void                                         Switch(boost::context::detail::transfer_t t, YieldContext* y) noexcept;

        private:
            template <typename T, typename... A>
            static T*                                           New(ppp::threading::BufferswapAllocator* allocator, A&&... args) noexcept
            {
                if (NULL == allocator)
                {
                    T* p = (T*)Malloc(sizeof(T));
                    if (NULL == p)
                    {
                        return NULL;
                    }

                    return new (p) T(allocator, std::forward<A&&>(args)...);
                }
                else
                {
                    T* p = (T*)allocator->Alloc(sizeof(T));
                    if (NULL == p)
                    {
                        allocator = NULL;
                        return New<T>(allocator, std::forward<A&&>(args)...);
                    }

                    return new (p) T(allocator, std::forward<A&&>(args)...);
                }
            }

            template <typename T>
            static bool                                         Release(T* p) noexcept
            {
                if (NULL == p)
                {
                    return false;
                }

                ppp::threading::BufferswapAllocator* const allocator = p->allocator_;
                p->~T();

                if (NULL == allocator)
                {
                    Mfree(p);
                }
                else
                {
                    allocator->Free(p);
                }

                return true;
            }

        private:
            YieldContext() = delete;
            YieldContext(YieldContext&&) = delete;
            YieldContext(const YieldContext&) = delete;
            YieldContext(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, SpawnHander&& spawn, int stack_size) noexcept;
            ~YieldContext() noexcept;

        private:
            boost::context::detail::fcontext_t                  callee_;
            boost::context::detail::fcontext_t                  caller_;
            SpawnHander                                         h_;
            boost::asio::io_context&                            context_;
            int                                                 stack_size_;
            std::shared_ptr<Byte>                               stack_;
            ppp::threading::BufferswapAllocator*                allocator_;
        };
    }
}
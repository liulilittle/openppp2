#pragma once

#include <ppp/stdafx.h>
#include <boost/coroutine/detail/coroutine_context.hpp>
#include <boost/context/detail/fcontext.hpp>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp
{
    namespace coroutines
    {
        class YieldContext final
        {
        public:
            typedef ppp::function<void(YieldContext&)>                          SpawnHander;

        public:
            bool                                                                Resume() noexcept;
            bool                                                                Suspend() noexcept;
            YieldContext*                                                       GetPtr() const noexcept        { return constantof(this);}
            boost::asio::io_context&                                            GetContext() const noexcept    { return context_; }
            boost::asio::strand<boost::asio::io_context::executor_type>*        GetStrand() const noexcept     { return strand_; }

        public:
            bool                                                                S() noexcept { return s_.load() != 0; }
            bool                                                                Y() noexcept { return Suspend(); }
            bool                                                                R() noexcept;

        public:
            operator                                                            bool() const noexcept          { return NULL != GetPtr(); }
            operator                                                            YieldContext*() const noexcept { return GetPtr();         }

        public:
            static bool                                                         Spawn(boost::asio::io_context& context, SpawnHander&& spawn) noexcept
            {
                return YieldContext::Spawn(context, std::move(spawn), PPP_COROUTINE_STACK_SIZE);
            }
            static bool                                                         Spawn(boost::asio::io_context& context, SpawnHander&& spawn, int stack_size) noexcept
            {
                ppp::threading::BufferswapAllocator* allocator = NULL;
                return YieldContext::Spawn(allocator, context, std::move(spawn), stack_size);
            }
            static bool                                                         Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, SpawnHander&& spawn) noexcept
            {
                return YieldContext::Spawn(allocator, context, std::move(spawn), PPP_COROUTINE_STACK_SIZE);
            }
            static bool                                                         Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, SpawnHander&& spawn, int stack_size) noexcept
            {
                boost::asio::strand<boost::asio::io_context::executor_type>* strand = NULL;
                return YieldContext::Spawn(allocator, context, strand, std::move(spawn), PPP_COROUTINE_STACK_SIZE);
            }
            static bool                                                         Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, boost::asio::strand<boost::asio::io_context::executor_type>* strand, SpawnHander&& spawn)
            {
                return YieldContext::Spawn(allocator, context, strand, std::move(spawn), PPP_COROUTINE_STACK_SIZE);
            }
            static bool                                                         Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, boost::asio::strand<boost::asio::io_context::executor_type>* strand, SpawnHander&& spawn, int stack_size) noexcept;

        private:
            void                                                                Invoke() noexcept;
            static void                                                         Handle(boost::context::detail::transfer_t t) noexcept(false);
            bool                                                                Switch() noexcept(false);
            static bool                                                         Switch(const boost::context::detail::transfer_t& t, YieldContext* y) noexcept;

        private:
            template <typename T, typename... A>
            static T*                                                           New(ppp::threading::BufferswapAllocator* allocator, A&&... args) noexcept
            {
                if (NULL == allocator)
                {
                    void* memory = Malloc(sizeof(T));
                    if (NULL == memory)
                    {
                        return NULL;
                    }

                    memset(memory, 0, sizeof(T)); /* -Wdynamic-class-memaccess */
                    return new (memory) T(allocator, std::forward<A&&>(args)...);
                }
                else
                {
                    void* memory = allocator->Alloc(sizeof(T));
                    if (NULL == memory)
                    {
                        allocator = NULL;
                        return New<T>(allocator, std::forward<A&&>(args)...);
                    }

                    memset(memory, 0, sizeof(T)); /* -Wdynamic-class-memaccess */
                    return new (memory) T(allocator, std::forward<A&&>(args)...);
                }
            }

            template <typename T>
            static bool                                                         Release(T* p) noexcept
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

            static boost::context::detail::transfer_t                           Jump(boost::context::detail::fcontext_t context, void* state) noexcept;

        private:
            YieldContext() = delete;
            YieldContext(YieldContext&&) = delete;
            YieldContext(const YieldContext&) = delete;
            YieldContext(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, boost::asio::strand<boost::asio::io_context::executor_type>* strand, SpawnHander&& spawn, int stack_size) noexcept;
            ~YieldContext() noexcept;

        private:
            std::atomic<int>                                                    s_          = 0;
            std::atomic<boost::context::detail::fcontext_t>                     callee_     = NULL;
            std::atomic<boost::context::detail::fcontext_t>                     caller_     = NULL;
            SpawnHander                                                         h_;
            boost::asio::io_context&                                            context_;
            boost::asio::strand<boost::asio::io_context::executor_type>*        strand_;
            int                                                                 stack_size_ = 0;
            std::shared_ptr<Byte>                                               stack_;
            ppp::threading::BufferswapAllocator*                                allocator_  = NULL;
        };
    }
}
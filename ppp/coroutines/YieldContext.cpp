#include <ppp/coroutines/YieldContext.h>

namespace ppp
{
    namespace coroutines
    {
        YieldContext::YieldContext(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, SpawnHander&& spawn, int stack_size) noexcept
            : callee_(NULL)
            , caller_(NULL)
            , h_(std::move(spawn))
            , context_(context)
            , stack_size_(stack_size)
            , allocator_(allocator)
        {
            if (NULL != allocator)
            {
                Byte* stack = (Byte*)allocator->Alloc(stack_size);
                if (NULL != stack)
                {
                    stack_ = std::shared_ptr<Byte>(stack, 
                        std::bind(&ppp::threading::BufferswapAllocator::Free, allocator, std::placeholders::_1));
                }
            }

            /* boost::context::stack_traits::minimum_size(); */
            if (NULL == stack_)
            {
                stack_ = make_shared_alloc<Byte>(stack_size);
            }
        }

        YieldContext::~YieldContext() noexcept
        {
            YieldContext* y = this;
            y->h_ = NULL;
        }

        void YieldContext::Suspend() noexcept
        {
            YieldContext* y = this;
            y->caller_ = boost::context::detail::jump_fcontext(y->caller_, y).fctx;
        }

        void YieldContext::Resume() noexcept
        {
            YieldContext* y = this;
            Switch(boost::context::detail::jump_fcontext(y->callee_, y), y);
        }

        void YieldContext::Invoke() noexcept
        {
            YieldContext* y = this;
            Byte* stack = stack_.get();
            if (stack)
            {
                boost::context::detail::fcontext_t callee =
                    boost::context::detail::make_fcontext(stack + stack_size_, stack_size_, &YieldContext::Handle);
                Switch(boost::context::detail::jump_fcontext(callee, y), y);
            }
            else
            {
                YieldContext::Release(y);
            }
        }

        void YieldContext::Switch(boost::context::detail::transfer_t t, YieldContext* y) noexcept
        {
            if (t.data)
            {
                y->callee_ = t.fctx;
            }
            else
            {
                YieldContext::Release(y);
            }
        }

        void YieldContext::Handle(boost::context::detail::transfer_t t) noexcept
        {
            YieldContext* y = (YieldContext*)t.data;
            if (y)
            {
                SpawnHander h = std::move(y->h_);
                y->h_ = NULL;
                y->caller_ = t.fctx;
                
                if (h)
                {
                    h(*y);
                }
            }

            boost::context::detail::jump_fcontext(y->caller_, NULL);
        }

        bool YieldContext::Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, SpawnHander&& spawn) noexcept
        {
            return Spawn(allocator, context, std::move(spawn), PPP_COROUTINE_STACK_SIZE);
        }

        bool YieldContext::Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, SpawnHander&& spawn, int stack_size) noexcept
        {
            if (NULL == spawn)
            {
                return false;
            }

            int pagesize = GetMemoryPageSize();
            stack_size = std::max<int>(stack_size, pagesize);

            // If done on the thread that owns the context, it is executed immediately.
            // Otherwise, the delivery event is delivered to the actor queue of the context, 
            // And the host thread of the context drives it when the next event is triggered.
            YieldContext* y = New<YieldContext>(allocator, context, std::move(spawn), stack_size);
            if (NULL == y)
            {
                return false;
            }

            context.post(std::bind(&YieldContext::Invoke, y));
            return true;
        }

        bool YieldContext::Spawn(boost::asio::io_context& context, SpawnHander&& spawn) noexcept
        {
            ppp::threading::BufferswapAllocator* allocator = NULL;
            return YieldContext::Spawn(allocator, context, std::move(spawn));
        }

        bool YieldContext::Spawn(boost::asio::io_context& context, SpawnHander&& spawn, int stack_size) noexcept
        {
            ppp::threading::BufferswapAllocator* allocator = NULL;
            return YieldContext::Spawn(allocator, context, std::move(spawn), stack_size);
        }
    }
}
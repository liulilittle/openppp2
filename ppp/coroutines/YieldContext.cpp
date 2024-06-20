#include <ppp/coroutines/YieldContext.h>

namespace ppp
{
    namespace coroutines
    {
        YieldContext::YieldContext(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, boost::asio::strand<boost::asio::io_context::executor_type>* strand, SpawnHander&& spawn, int stack_size) noexcept
            : s_(0)
            , callee_(NULL)
            , caller_(NULL)
            , h_(std::move(spawn))
            , context_(context)
            , strand_(strand)
            , stack_size_(stack_size)
            , allocator_(allocator)
        {
            if (allocator)
            {
                Byte* stack = (Byte*)allocator->Alloc(stack_size);
                if (stack)
                {
                    stack_ = std::shared_ptr<Byte>(stack, /* std::bind(&ppp::threading::BufferswapAllocator::Free, allocator, std::placeholders::_1)); */
                        [allocator](Byte* p) noexcept 
                        {
                            allocator->Free(p);
                        });
                }
            }

            /* boost::context::stack_traits::minimum_size(); */
            if (!stack_)
            {
                stack_ = make_shared_alloc<Byte>(stack_size);
            }
        }

        YieldContext::~YieldContext() noexcept
        {
            YieldContext* y = this;
            y->h_          = NULL;
            y->stack_      = NULL;
            y->stack_size_ = 0;
            y->strand_     = NULL;
            y->allocator_  = NULL;
        }

        bool YieldContext::Suspend() noexcept
        {
            int L = 0;
            if (s_.compare_exchange_strong(L, 1))
            {
                YieldContext* y = this;
                y->caller_ = boost::context::detail::jump_fcontext(y->caller_, y).fctx;

                L = -1;
                return y->s_.compare_exchange_strong(L, 0);
            }
            else
            {
                return false;
            }
        }

        bool YieldContext::Resume() noexcept
        {
            int L = 2;
            if (s_.compare_exchange_strong(L, -1))
            {
                YieldContext* y = this;
                return Switch(boost::context::detail::jump_fcontext(y->callee_, y), y);
            }
            else
            {
                return false;
            }
        }

        void YieldContext::Invoke() noexcept
        {
            YieldContext* y = this;
            if (Byte* stack = stack_.get(); stack)
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

        bool YieldContext::Switch()
        {
            int L = 1;
            if (s_.compare_exchange_strong(L, 2))
            {
                return true;
            }
            
            throw std::runtime_error("The internal atomic state used for the yield_context switch was corrupted..");
        }

        bool YieldContext::Switch(boost::context::detail::transfer_t t, YieldContext* y) noexcept
        {
            if (t.data)
            {
                y->callee_ = t.fctx;
                return y->Switch();
            }
            else
            {
                YieldContext::Release(y);
                return true;
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
                    h = NULL;
                }

                y->Resume();
                boost::context::detail::jump_fcontext(y->caller_, NULL);
            }
        }
 
        bool YieldContext::Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, boost::asio::strand<boost::asio::io_context::executor_type>* strand, SpawnHander&& spawn, int stack_size) noexcept
        {
            if (!spawn)
            {
                return false;
            }

            int pagesize = GetMemoryPageSize();
            stack_size = std::max<int>(stack_size, pagesize);

            // If done on the thread that owns the context, it is executed immediately.
            // Otherwise, the delivery event is delivered to the actor queue of the context, 
            // And the host thread of the context drives it when the next event is triggered.
            YieldContext* y = New<YieldContext>(allocator, context, strand, std::move(spawn), stack_size);
            if (!y)
            {
                return false;
            }

            // By default the C/C++ compiler optimizes the context delegate event call, and strand is usually multi-core driven if it occurs.
            auto invoked =
                [y]() noexcept 
                {
                    y->Invoke();
                };

            if (strand)
            {
                boost::asio::post(*strand, invoked);
            }
            else
            {
                context.post(invoked);
            }

            return true;
        }

        bool YieldContext::R() noexcept
        {
            YieldContext* y = this;
            auto invoked =
                [y]() noexcept
                {
                    if (!y->Resume())
                    {
                        y->R();
                    }
                };

            boost::asio::io_context* context = &y->context_;
            return ppp::threading::Executors::Post(context, y->strand_, invoked);
        }
    }
}
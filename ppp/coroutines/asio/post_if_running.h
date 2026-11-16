#pragma once

#include <utility>

#include <boost/asio.hpp>

namespace ppp {
    namespace coroutines {
        namespace asio {
            /**
             * @brief Returns true when the io_context behind the executor has been stopped.
             * @details A stopped io_context never runs posted handlers, so a coroutine
             *          that suspends waiting for such a handler would leak with its stack.
             */
            inline bool                                                         ExecutorStopped(const boost::asio::io_context::executor_type& ex) noexcept {
                return ex.context().stopped();
            }

            template <class Executor>
            inline bool                                                         ExecutorStopped(const boost::asio::strand<Executor>& ex) noexcept {
                return ExecutorStopped(ex.get_inner_executor());
            }

            inline bool                                                         ExecutorStopped(const boost::asio::any_io_executor& ex) noexcept {
                // Polymorphic executor: unwrap the known io_context-based targets;
                // any other target is treated as running.
                if (const boost::asio::io_context::executor_type* inner = ex.target<boost::asio::io_context::executor_type>()) {
                    return ExecutorStopped(*inner);
                }

                if (const boost::asio::strand<boost::asio::io_context::executor_type>* strand = ex.target<boost::asio::strand<boost::asio::io_context::executor_type>>()) {
                    return ExecutorStopped(*strand);
                }

                return false;
            }

            /**
             * @brief `boost::asio::post` that refuses to schedule on a stopped context.
             * @return false (handler not scheduled) when stopped; callers must then skip Suspend.
             */
            template <class Executor, class Handler>
            inline bool                                                         PostIfRunning(const Executor& ex, Handler&& handler) noexcept {
                if (ExecutorStopped(ex)) {
                    return false;
                }

                boost::asio::post(ex, std::forward<Handler>(handler));
                return true;
            }

            /** @brief `boost::asio::dispatch` counterpart of @ref PostIfRunning. */
            template <class Executor, class Handler>
            inline bool                                                         DispatchIfRunning(const Executor& ex, Handler&& handler) noexcept {
                if (ExecutorStopped(ex)) {
                    return false;
                }

                boost::asio::dispatch(ex, std::forward<Handler>(handler));
                return true;
            }
        }
    }
}

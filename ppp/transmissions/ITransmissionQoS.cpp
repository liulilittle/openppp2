#include <ppp/transmissions/ITransmissionQoS.h>
#include <ppp/threading/Executors.h>

using ppp::threading::Executors;
using ppp::coroutines::YieldContext;

namespace ppp {
    namespace transmissions {
        static int ITransmissionQoS_ResumeAllContexts(ppp::list<YieldContext*>& contexts) noexcept {
            int events = 0;
            for (YieldContext* y : contexts) {
                y->R();
                events++;
            }
            
            return events;
        }

        ITransmissionQoS::ITransmissionQoS(const std::shared_ptr<boost::asio::io_context>& context, Int64 bandwidth) noexcept
            : disposed_(false)
            , context_(context)
            , bandwidth_(0)
            , last_(0)
            , traffic_(0) {
            SetBandwidth(bandwidth);
        }

        ITransmissionQoS::~ITransmissionQoS() noexcept {
            Finalize();
        }

        void ITransmissionQoS::Finalize() noexcept {
            ppp::list<YieldContext*> contexts; 
            for (;;) {
                SynchronizedObjectScope scope(syncobj_);
                disposed_ = true;
                last_ = 0;
                traffic_ = 0;
                contexts = std::move(contexts_);
                contexts_.clear();
                break;
            }

            ITransmissionQoS_ResumeAllContexts(contexts);
        }

        void ITransmissionQoS::Dispose() noexcept {
            std::shared_ptr<ITransmissionQoS> self = GetReference();
            std::shared_ptr<boost::asio::io_context> context = GetContext();
            context->post(
                [self, this, context]() noexcept {
                    Finalize();
                });
        }

        void ITransmissionQoS::Update(UInt64 tick) noexcept {
            std::shared_ptr<ITransmissionQoS> self = GetReference();
            std::shared_ptr<boost::asio::io_context> context = GetContext();
            context->post(
                [self, this, context, tick]() noexcept {
                    ppp::list<YieldContext*> contexts; 
                    for (;;) {
                        SynchronizedObjectScope scope(syncobj_);
                        if (UInt64 now = tick / 1000; now != last_) {
                            last_ = now;
                            traffic_ = 0;

                            contexts = std::move(contexts_);
                            contexts_.clear();
                        }

                        break;
                    }

                    return ITransmissionQoS_ResumeAllContexts(contexts);
                });
        }

#if defined(_WIN32)
#pragma optimize("", off)
#pragma optimize("gsyb2", on) /* /O1 = /Og /Os /Oy /Ob2 /GF /Gy */
#else
// TRANSMISSIONO1 compiler macros are defined to perform O1 optimizations, 
// Otherwise gcc compiler version If <= 7.5.X, 
// The O1 optimization will also be applied, 
// And the other cases will not be optimized, 
// Because this will cause the program to crash, 
// Which is a fatal BUG caused by the gcc compiler optimization. 
// Higher-version compilers should not optimize the code for gcc compiling this section.
#if defined(__clang__)
#pragma clang optimize off
#else
#pragma GCC push_options
#if defined(TRANSMISSION_O1) || (__GNUC__ < 7) || (__GNUC__ == 7 && __GNUC_MINOR__ <= 5) /* __GNUC_PATCHLEVEL__ */
#pragma GCC optimize("O1")
#else
#pragma GCC optimize("O0")
#endif
#endif
#endif
        std::shared_ptr<Byte> ITransmissionQoS::ReadBytes(YieldContext& y, int length, const ReadBytesAsynchronousCallback& cb) noexcept {
            if (length < 1) {
                return NULL;
            }

            if (NULL == cb) {
                return NULL;
            }

            YieldContext* co = y.GetPtr();
            if (NULL == co) {
                return NULL;
            }

            bool bawait = false; 
            for (;;) { // co_await
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return NULL;
                }

                bawait = IsPeek();
                if (bawait) {
                    contexts_.emplace_back(co);
                }

                break;
            }

            if (bawait) {
                bool suspend = y.Suspend();
                if (!suspend) {
                    return NULL;
                }
            }

            std::shared_ptr<Byte> packet = cb(y, &length);
            if (length > 0) {
                if (packet) {
                    traffic_ += length;
                }
            }

            return packet;
        }
#if defined(_WIN32)
#pragma optimize("", on)
#else
#if defined(__clang__)
#pragma clang optimize on
#else
#pragma GCC pop_options
#endif
#endif
    }
}
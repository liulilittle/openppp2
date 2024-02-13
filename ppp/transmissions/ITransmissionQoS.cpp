#include <ppp/transmissions/ITransmissionQoS.h>
#include <ppp/threading/Executors.h>

using ppp::threading::Executors;
using ppp::coroutines::YieldContext;

namespace ppp {
    namespace transmissions {
        static int ITransmissionQoS_ResumeAllContexts(ppp::list<YieldContext*>& contexts) noexcept {
            int events = 0;
            for (YieldContext* y : contexts) {
                boost::asio::io_context& context = y->GetContext();
                context.post(std::bind(&YieldContext::Resume, y));
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
            ppp::list<YieldContext*> contexts; {
                SynchronizedObjectScope scope(syncobj_);
                disposed_ = true;
                last_ = 0;
                traffic_ = 0;
                contexts = std::move(contexts_);
                contexts_.clear();
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
                    ppp::list<YieldContext*> contexts; {
                        SynchronizedObjectScope scope(syncobj_);
                        if (UInt64 now = tick / 1000; now != last_) {
                            last_ = now;
                            traffic_ = 0;

                            contexts = std::move(contexts_);
                            contexts_.clear();
                        }
                    }

                    return ITransmissionQoS_ResumeAllContexts(contexts);
                });
        }

        std::shared_ptr<Byte> ITransmissionQoS::ReadBytes(YieldContext& y, int length, const ReadBytesAsynchronousCallbackPtr& cb) noexcept {
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

            bool bawait = false; { // co_await
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return NULL;
                }

                bawait = IsPeek();
                if (bawait) {
                    contexts_.emplace_back(co);
                }
            }

            if (bawait) {
                y.Suspend();
            }

            std::shared_ptr<Byte> packet = (*cb)(y, length);
            if (packet) {
                traffic_ += length;
            }
            return packet;
        }
    }
}
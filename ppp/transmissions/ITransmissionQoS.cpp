#include <ppp/transmissions/ITransmissionQoS.h>
#include <ppp/threading/Executors.h>

using ppp::threading::Executors;
using ppp::coroutines::YieldContext;

namespace ppp {
    namespace transmissions {
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

        static int ITransmissionQoS_ResumeAllContexts(ppp::list<YieldContext*>& contexts) noexcept {
            int events = 0;
            for (YieldContext* y : contexts) {
                y->R();
                events++;
            }

            return events;
        }

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
            boost::asio::post(*context, 
                [self, this, context]() noexcept {
                    Finalize();
                });
        }

        void ITransmissionQoS::Update(UInt64 tick) noexcept {
            std::shared_ptr<ITransmissionQoS> self = GetReference();
            std::shared_ptr<boost::asio::io_context> context = GetContext();
            boost::asio::post(*context, 
                [self, this, context, tick]() noexcept {
                    ppp::list<YieldContext*> contexts; 
                    for (SynchronizedObjectScope scope(syncobj_);;) {
                        UInt64 now = tick / 1000; 
                        if (now != last_) {
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
    }
}
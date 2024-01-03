#include <ppp/transmissions/ITransmissionQoS.h>
#include <ppp/threading/Executors.h>

using ppp::threading::Executors;
using ppp::coroutines::YieldContext;

namespace ppp {
    namespace transmissions {
        static int ITransmissionQoS_ResumeAllContexts(ppp::list<YieldContext*>& contexts) noexcept {
            int events = 0;
            for (YieldContext* y : contexts) {
                if (NULL != y) {
                    auto& context = y->GetContext();
                    context.dispatch(std::bind(&YieldContext::Resume, y));
                    events++;
                }
            }
            return events;
        }

        ITransmissionQoS::ITransmissionQoS(UInt32 bandwidth) noexcept
            : disposed_(false)
            , bandwidth_(bandwidth)
            , last_(0)
            , traffic_(0) {

        }

        ITransmissionQoS::~ITransmissionQoS() noexcept {
            ppp::list<YieldContext*> contexts; {
                Finalize(contexts);
                ITransmissionQoS_ResumeAllContexts(contexts);
            }
        }

        void ITransmissionQoS::Finalize(ppp::list<YieldContext*>& contexts) noexcept {
            disposed_ = true;
            last_ = 0;
            traffic_ = 0;
            contexts = std::move(contexts_);
            contexts_.clear();
        }

        std::shared_ptr<ITransmissionQoS> ITransmissionQoS::GetReference() noexcept {
            return this->shared_from_this();
        }

        UInt32 ITransmissionQoS::GetBandwidth() noexcept {
            return bandwidth_;
        }

        void ITransmissionQoS::SetBandwidth(int bandwidth) noexcept {
            bandwidth_ = bandwidth < 1 ? 0 : bandwidth; /* ReLU */
        }

        int ITransmissionQoS::Update() noexcept {
            ppp::list<YieldContext*> contexts; {
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return -1;
                }

                UInt32 now = Executors::GetTickCount() / 1000;
                if (now != last_) {
                    last_ = now;
                    traffic_ = 0;
                    contexts = std::move(contexts_);
                    contexts_.clear();
                }
            }

            return ITransmissionQoS_ResumeAllContexts(contexts);
        }

        void ITransmissionQoS::Dispose() noexcept {
            ppp::list<YieldContext*> contexts; {
                SynchronizedObjectScope scope(syncobj_);
                Finalize(contexts);
            }

            ITransmissionQoS_ResumeAllContexts(contexts);
        }

        bool ITransmissionQoS::IsPeek() noexcept {
            // The unit "bps" stands for bits per second, where "b" represents bits.
            // Therefore, 1 Kbps can be correctly expressed in English as "one kilobit per second," 
            // Where "K" stands for kilo - (representing a factor of 1, 000).
            UInt32 bandwidth = bandwidth_;
            if (bandwidth < 1) {
                return false;
            }

            UInt64 traffic = traffic_ >> 7;
            return traffic >= bandwidth;
        }

        std::shared_ptr<Byte> ITransmissionQoS::ReadBytes(YieldContext& y, int length, const ReadBytesAsynchronousCallbackPtr& cb) noexcept {
            if (length < 1) {
                return NULL;
            }

            if (NULL == cb) {
                return NULL;
            }

            if (!y) {
                return NULL;
            }

            bool bawait = false; { // co_await
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return NULL;
                }

                bawait = IsPeek();
                if (bawait) {
                    contexts_.emplace_back(y.GetPtr());
                }
            }

            if (bawait) {
                y.Suspend();
                if (disposed_) {
                    return NULL;
                }
            }

            std::shared_ptr<Byte> packet = (*cb)(y, length);
            if (packet) {
                traffic_ += length;
            }
            return packet;
        }
    }
}
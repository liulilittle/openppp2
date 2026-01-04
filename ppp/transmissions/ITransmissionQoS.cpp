#include <ppp/transmissions/ITransmissionQoS.h>
#include <ppp/threading/Executors.h>

using ppp::threading::Executors;
using ppp::coroutines::YieldContext;

namespace ppp {
    namespace transmissions {
        using BeginReadAsynchronousCallback = ITransmissionQoS::BeginReadAsynchronousCallback;

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

        static int ITransmissionQoS_ResumeAllReads(ppp::list<BeginReadAsynchronousCallback>& s) noexcept {
            int events = 0;
            for (const BeginReadAsynchronousCallback& f : s) {
                f();
                events++;
            }

            return events;
        }

        std::shared_ptr<Byte> ITransmissionQoS::ReadBytes(YieldContext& y, int length, const ReadBytesAsynchronousCallback& cb) noexcept {
            if (length < 1) {
                return NULLPTR;
            }

            if (NULLPTR == cb) {
                return NULLPTR;
            }

            YieldContext* co = y.GetPtr();
            if (NULLPTR == co) {
                return NULLPTR;
            }

            bool bawait = false; 
            for (;;) { // co_await
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return NULLPTR;
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
                    return NULLPTR;
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

        bool ITransmissionQoS::EndRead(int bytes_transferred) noexcept {
            if (bytes_transferred < 1) {
                return false;
            }
            else {
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return false;
                }
            }

            traffic_ += bytes_transferred;
            return true;
        }

        bool ITransmissionQoS::BeginRead(const BeginReadAsynchronousCallback& cb) noexcept {
            if (cb) {
                bool bawait = false; 
                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_) {
                        return false;
                    }

                    bawait = IsPeek();
                    if (bawait) {
                        reads_.emplace_back(cb);
                    }

                    break;
                }

                if (!bawait) {
                    cb();
                }

                return true;
            }

            return false;
        }

        void ITransmissionQoS::Finalize() noexcept {
            ppp::list<BeginReadAsynchronousCallback> reads;
            ppp::list<YieldContext*> contexts; 

            for (;;) {
                SynchronizedObjectScope scope(syncobj_);
                disposed_ = true;
                last_     = 0;
                traffic_  = 0;

                reads     = std::move(reads_);
                reads_.clear();

                contexts  = std::move(contexts_);
                contexts_.clear();
                break;
            }

            ITransmissionQoS_ResumeAllReads(reads);
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

                    ppp::list<BeginReadAsynchronousCallback> reads;
                    ppp::list<YieldContext*> contexts; 

                    for (SynchronizedObjectScope scope(syncobj_);;) {
                        UInt64 now   = tick / 1000; 
                        if (now != last_) {
                            last_    = now;
                            traffic_ = 0;

                            reads    = std::move(reads_);
                            reads_.clear();

                            contexts = std::move(contexts_);
                            contexts_.clear();
                        }

                        break;
                    }

                    ITransmissionQoS_ResumeAllReads(reads);
                    ITransmissionQoS_ResumeAllContexts(contexts);
                });
        }
    }
}
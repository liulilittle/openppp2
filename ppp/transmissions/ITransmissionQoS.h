#pragma once

#include <ppp/stdafx.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace transmissions {
        class ITransmissionQoS : public std::enable_shared_from_this<ITransmissionQoS> {
        public:
            typedef std::mutex                                      SynchronizedObject;
            typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;
            typedef ppp::coroutines::YieldContext                   YieldContext;
            typedef std::shared_ptr<Byte>                           ByteArrayPtr;
            typedef ppp::function<ByteArrayPtr(YieldContext&, int)> ReadBytesAsynchronousCallback;
            typedef std::shared_ptr<ReadBytesAsynchronousCallback>  ReadBytesAsynchronousCallbackPtr;

        public:
            ITransmissionQoS(UInt32 bandwidth) noexcept;
            virtual ~ITransmissionQoS() noexcept;

        public:
            std::shared_ptr<ITransmissionQoS>                       GetReference() noexcept;
            UInt32                                                  GetBandwidth() noexcept;
            void                                                    SetBandwidth(int bandwidth) noexcept;
            bool                                                    IsPeek() noexcept;

        public:
            virtual int                                             Update() noexcept;
            virtual void                                            Dispose() noexcept;
            virtual std::shared_ptr<Byte>                           ReadBytes(YieldContext& y, int length, const ReadBytesAsynchronousCallbackPtr& cb) noexcept;

        public:
            template <class Reference, class Transmission>
            static std::shared_ptr<Byte>                            DoReadBytes(
                YieldContext&                                       y,
                const int                                           length,
                const Reference                                     self,
                Transmission&                                       transmission,
                const std::shared_ptr<ITransmissionQoS>             qos) noexcept {
                if (length < 1) {
                    return NULL;
                }

                if (NULL != qos) {
                    auto cb = make_shared_object<ReadBytesAsynchronousCallback>(
                        [self, &transmission, qos](YieldContext& y, int length) noexcept {
                            return transmission.ReadBytes(y, length);
                        });
                    return qos->ReadBytes(y, length, cb);
                }
                else {
                    return transmission.ReadBytes(y, length);
                }
            }

        private:
            void                                                    Finalize(ppp::list<YieldContext*>& contexts) noexcept;

        private:
            bool                                                    disposed_;
            SynchronizedObject                                      syncobj_;
            UInt32                                                  bandwidth_;
            UInt32                                                  last_;
            std::atomic<UInt64>                                     traffic_;
            ppp::list<YieldContext*>                                contexts_;
        };
    }
}
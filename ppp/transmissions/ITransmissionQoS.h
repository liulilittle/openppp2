#pragma once

#include <ppp/stdafx.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace transmissions {
        class ITransmissionQoS : public std::enable_shared_from_this<ITransmissionQoS> {
        public:
            typedef std::mutex                                          SynchronizedObject;
            typedef std::lock_guard<SynchronizedObject>                 SynchronizedObjectScope;
            typedef ppp::coroutines::YieldContext                       YieldContext;
            typedef std::shared_ptr<Byte>                               ByteArrayPtr;
            typedef ppp::function<ByteArrayPtr(YieldContext&, int*)>    ReadBytesAsynchronousCallback;

        public:
            ITransmissionQoS(const std::shared_ptr<boost::asio::io_context>& context, Int64 bandwidth) noexcept;
            virtual ~ITransmissionQoS() noexcept;

        public:
            std::shared_ptr<boost::asio::io_context>                    GetContext()                  noexcept { return context_; }
            std::shared_ptr<ITransmissionQoS>                           GetReference()                noexcept { return shared_from_this(); }
            Int64                                                       GetBandwidth()                noexcept { return bandwidth_; }
            void                                                        SetBandwidth(Int64 bandwidth) noexcept { bandwidth_ = bandwidth < 1 ? 0 : bandwidth; /* ReLU */ }
            bool                                                        IsPeek()                      noexcept {
                // The unit "bps" stands for bits per second, where "b" represents bits.
                // Therefore, 1 Kbps can be correctly expressed in English as "one kilobit per second," 
                // Where "K" stands for kilo - (representing a factor of 1, 000).
                Int64 bandwidth = bandwidth_;
                if (bandwidth < 1) {
                    return false;
                }

                UInt64 traffic = traffic_ >> 7;
                return traffic >= (UInt64)bandwidth;
            }

        public:
            virtual void                                                Update(UInt64 tick) noexcept;
            virtual void                                                Dispose() noexcept;
            virtual std::shared_ptr<Byte>                               ReadBytes(YieldContext& y, int length, const ReadBytesAsynchronousCallback& cb) noexcept;

        public: 
            template <class Reference, class Transmission>  
            static std::shared_ptr<Byte>                                DoReadBytes(
                YieldContext&                                           y,
                const int                                               length,
                const Reference                                         self,
                Transmission&                                           transmission,
                const std::shared_ptr<ITransmissionQoS>                 qos) noexcept {
                if (length < 1) {
                    return NULL;
                }

                std::shared_ptr<Byte> packet;
                if (NULL != qos) {
                    packet = qos->ReadBytes(y, length, 
                        [self, &transmission, qos](YieldContext& y, int* length) noexcept {
                            return transmission.ReadBytes(y, *length);
                        });
                }
                else {
                    packet = transmission.ReadBytes(y, length);
                }

                if (NULL != packet) {
                    return packet;
                }

                transmission.Dispose();
                return NULL;
            }

        private:
            void                                                        Finalize() noexcept;

        private:    
            bool                                                        disposed_  = false;
            SynchronizedObject                                          syncobj_;
            std::shared_ptr<boost::asio::io_context>                    context_;
            Int64                                                       bandwidth_ = 0;
            UInt64                                                      last_      = 0;
            std::atomic<UInt64>                                         traffic_   = 0;
            ppp::list<YieldContext*>                                    contexts_;
        };
    }
}
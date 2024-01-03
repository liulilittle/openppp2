#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace transmissions {
        // The number of bytes successfully transmitted/received by the transport layer.
        class ITransmissionStatistics {
        public:
            std::atomic<uint64_t>                               IncomingTraffic;
            std::atomic<uint64_t>                               OutgoingTraffic;

        public:
            ITransmissionStatistics() noexcept { Clear(); }
            
        public:
            virtual std::shared_ptr<ITransmissionStatistics>    Clone() noexcept {
                std::shared_ptr<ITransmissionStatistics> statistics = make_shared_object<ITransmissionStatistics>();
                if (NULL != statistics) {
                    statistics->Copy(*this);
                }
                return statistics;
            }
            virtual ITransmissionStatistics&                    Clear() noexcept {
                IncomingTraffic = 0;
                OutgoingTraffic = 0;
                return *this;
            }
            virtual ITransmissionStatistics&                    Copy(const ITransmissionStatistics& other) noexcept {
                IncomingTraffic.exchange(other.IncomingTraffic);
                OutgoingTraffic.exchange(other.OutgoingTraffic);
                return *this;
            }
        };
    }
}
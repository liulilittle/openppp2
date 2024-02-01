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
            virtual uint64_t                                    AddIncomingTraffic(uint64_t incoming_traffic) noexcept {
                IncomingTraffic += incoming_traffic;
                return IncomingTraffic;
            }
            virtual uint64_t                                    AddOutgoingTraffic(uint64_t outcoming_traffic) noexcept {
                OutgoingTraffic += outcoming_traffic;
                return OutgoingTraffic;
            }

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
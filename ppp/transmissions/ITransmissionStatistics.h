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

        public:
            static bool                                         GetTransmissionStatistics(
                const std::shared_ptr<ppp::transmissions::ITransmissionStatistics>&                         left,
                ppp::transmissions::ITransmissionStatistics&                                                reft,
                uint64_t&                                                                                   incoming_traffic, 
                uint64_t&                                                                                   outgoing_traffic, 
                std::shared_ptr<ppp::transmissions::ITransmissionStatistics>&                               statistics_snapshot) noexcept {
                // Copy a transport layer network traffic statistics snapshot, not directly using the atomic object pointed to, 
                // But copying its value to the function stack, which is adopted for multithreaded parallel arithmetic security evaluation.
                statistics_snapshot = left->Clone();
                if (NULL == statistics_snapshot)
                {
                    return false;
                }

                // Converts an object pointer to the reference type of its object.
                ppp::transmissions::ITransmissionStatistics& statistics = *statistics_snapshot;

                // Gets the size of incoming traffic bytes within the current OnTick execution clock period.
                if (statistics.IncomingTraffic >= reft.IncomingTraffic)
                {
                    incoming_traffic = statistics.IncomingTraffic - reft.IncomingTraffic;
                }
                else
                {
                    Int128 traffic = (Int128(UINT64_MAX) + statistics.IncomingTraffic.load()) + 1;
                    incoming_traffic = (uint64_t)(traffic - reft.IncomingTraffic.load());
                }

                // Gets the size of outgoing traffic bytes within the current OnTick execution clock period.
                if (statistics.OutgoingTraffic >= reft.OutgoingTraffic)
                {
                    outgoing_traffic = statistics.OutgoingTraffic - reft.OutgoingTraffic;
                }
                else
                {
                    Int128 traffic = (Int128(UINT64_MAX) + statistics.OutgoingTraffic.load()) + 1;
                    outgoing_traffic = (uint64_t)(traffic - reft.OutgoingTraffic.load());
                }

                // Copy a snapshot of the network transport layer traffic statistics stored on the function stack to the last traffic statistics field hosted by the app.
                reft.Copy(statistics);
                return true;
            }
        };
    }
}
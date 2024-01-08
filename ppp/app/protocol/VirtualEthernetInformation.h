#pragma once

#include <ppp/auxiliary/JsonAuxiliary.h>

namespace ppp {
    namespace app {
        namespace protocol {
#pragma pack(push, 1)
            struct VirtualEthernetInformation {
            public:
                UInt32 BandwidthQoS;    // Maximum Quality of Service (QoS) bandwidth throughput speed per second, 0 for unlimited, 1 for 1 Kbps.
                UInt64 IncomingTraffic; // The remaining network traffic allowance that can be allowed for incoming clients, 0 is unlimited.
                UInt64 OutgoingTraffic; // The remaining network traffic allowance that can be allowed for outgoing clients, 0 is unlimited.
                UInt32 ExpiredTime;     // The time duration during which clients are expired time from using PPP (Point-to-Point Protocol) VPN services, 0 for no restrictions, measured in seconds.

            public:
                VirtualEthernetInformation() noexcept;

            public:
                void                                                Clear() noexcept;
                void                                                ToJson(Json::Value& json) noexcept;
                ppp::string                                         ToJson() noexcept;
                static std::shared_ptr<VirtualEthernetInformation>  FromJson(const ppp::string& json) noexcept;
                static std::shared_ptr<VirtualEthernetInformation>  FromJson(const Json::Value& json) noexcept;
            };
#pragma pack(pop)
        }
    }
}
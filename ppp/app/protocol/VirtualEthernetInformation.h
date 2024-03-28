#pragma once

#include <ppp/auxiliary/JsonAuxiliary.h>

namespace ppp {
    namespace app {
        namespace protocol {
#pragma pack(push, 1)
            struct VirtualEthernetInformation {
            public:
                UInt32 BandwidthQoS    = 0; // Maximum Quality of Service (QoS) bandwidth throughput speed per second, 0 for unlimited, 1 for 1 Kbps.
                UInt64 IncomingTraffic = 0; // The remaining network traffic allowance that can be allowed for incoming clients, 0 is unlimited.
                UInt64 OutgoingTraffic = 0; // The remaining network traffic allowance that can be allowed for outgoing clients, 0 is unlimited.
                UInt32 ExpiredTime     = 0; // The time duration during which clients are expired time from using PPP (Point-to-Point Protocol) VPN services, 0 for no restrictions, measured in seconds.

            public:
                VirtualEthernetInformation() noexcept;

            public:
                void                                                Clear() noexcept;
                void                                                ToJson(Json::Value& json) noexcept;
                ppp::string                                         ToJson() noexcept;
                ppp::string                                         ToString() noexcept;

            public:
                bool                                                Valid() noexcept                                          { return Valid((UInt32)(GetTickCount() / 1000)); }
                bool                                                Valid(UInt32 now) noexcept                                { return Valid(this, now); }
                static bool                                         Valid(VirtualEthernetInformation* i, UInt32 now) noexcept { return (i->IncomingTraffic > 0 && i->OutgoingTraffic > 0) && (i->ExpiredTime != 0 && i->ExpiredTime > now); }

            public:
                static std::shared_ptr<VirtualEthernetInformation>  FromJson(const ppp::string& json) noexcept;
                static std::shared_ptr<VirtualEthernetInformation>  FromJson(const Json::Value& json) noexcept;
            };
#pragma pack(pop)
        }
    }
}
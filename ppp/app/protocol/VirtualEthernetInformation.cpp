#include <ppp/app/protocol/VirtualEthernetInformation.h>

using ppp::auxiliary::JsonAuxiliary;

namespace ppp {
    namespace app {
        namespace protocol {
            VirtualEthernetInformation::VirtualEthernetInformation() noexcept {
                Clear();
            }

            ppp::string VirtualEthernetInformation::ToJson() noexcept {
                Json::Value json;
                ToJson(json);
                return JsonAuxiliary::ToString(json);
            }

            void VirtualEthernetInformation::ToJson(Json::Value& json) noexcept {
                json["BandwidthQoS"] = this->BandwidthQoS;
                json["IncomingTraffic"] = stl::to_string<ppp::string>(this->IncomingTraffic);
                json["OutgoingTraffic"] = stl::to_string<ppp::string>(this->OutgoingTraffic);
                json["ForbiddenTime"] = this->ForbiddenTime;
            }

            std::shared_ptr<VirtualEthernetInformation> VirtualEthernetInformation::FromJson(const Json::Value& json) noexcept {
                if (!json.isObject()) {
                    return NULL;
                }

                std::shared_ptr<VirtualEthernetInformation> infomartion = make_shared_object<VirtualEthernetInformation>();
                infomartion->BandwidthQoS    = JsonAuxiliary::AsValue<long long>(json["BandwidthQoS"]);
                infomartion->IncomingTraffic = JsonAuxiliary::AsValue<unsigned long long>(json["IncomingTraffic"]);
                infomartion->OutgoingTraffic = JsonAuxiliary::AsValue<unsigned long long>(json["OutgoingTraffic"]);
                infomartion->ForbiddenTime   = JsonAuxiliary::AsValue<long long>(json["ForbiddenTime"]);
                return infomartion;
            }

            std::shared_ptr<VirtualEthernetInformation> VirtualEthernetInformation::FromJson(const ppp::string& json) noexcept {
                return FromJson(JsonAuxiliary::FromString(json));
            }

            void VirtualEthernetInformation::Clear() noexcept {
                this->BandwidthQoS    = 0;
                this->IncomingTraffic = 0;
                this->OutgoingTraffic = 0;
                this->ForbiddenTime   = 0;
            }
        }
    }
}
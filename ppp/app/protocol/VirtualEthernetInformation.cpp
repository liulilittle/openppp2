#include <ppp/app/protocol/VirtualEthernetInformation.h>

using ppp::auxiliary::JsonAuxiliary;

namespace ppp {
    namespace app {
        namespace protocol {
            VirtualEthernetInformation::VirtualEthernetInformation() noexcept {
                Clear();
            }

            static ppp::string STATIC_TO_STRRING(VirtualEthernetInformation& information, bool styled) noexcept {
                Json::Value json;
                information.ToJson(json);

                if (styled) {
                    return JsonAuxiliary::ToStyledString(json);
                }
                else {
                    return JsonAuxiliary::ToString(json);
                }
            }

            ppp::string VirtualEthernetInformation::ToString() noexcept {
                return STATIC_TO_STRRING(*this, true);
            }

            ppp::string VirtualEthernetInformation::ToJson() noexcept {
                return STATIC_TO_STRRING(*this, false);
            }

            void VirtualEthernetInformation::ToJson(Json::Value& json) noexcept {
                json["BandwidthQoS"]    = this->BandwidthQoS;
                json["ExpiredTime"]     = this->ExpiredTime;
                json["IncomingTraffic"] = stl::to_string<ppp::string>(this->IncomingTraffic);
                json["OutgoingTraffic"] = stl::to_string<ppp::string>(this->OutgoingTraffic);
            }

            std::shared_ptr<VirtualEthernetInformation> VirtualEthernetInformation::FromJson(const Json::Value& json) noexcept {
                if (!json.isObject()) {
                    return NULL;
                }

                std::shared_ptr<VirtualEthernetInformation> infomartion = make_shared_object<VirtualEthernetInformation>();
                if (NULL == infomartion) {
                    return NULL;
                }

                infomartion->ExpiredTime     = JsonAuxiliary::AsValue<long long>(json["ExpiredTime"]);
                infomartion->BandwidthQoS    = JsonAuxiliary::AsValue<long long>(json["BandwidthQoS"]);
                infomartion->IncomingTraffic = JsonAuxiliary::AsValue<unsigned long long>(json["IncomingTraffic"]);
                infomartion->OutgoingTraffic = JsonAuxiliary::AsValue<unsigned long long>(json["OutgoingTraffic"]);
                return infomartion;
            }

            std::shared_ptr<VirtualEthernetInformation> VirtualEthernetInformation::FromJson(const ppp::string& json) noexcept {
                Json::Value config = JsonAuxiliary::FromString(json);
                return FromJson(config);
            }

            void VirtualEthernetInformation::Clear() noexcept {
                this->ExpiredTime     = 0;
                this->BandwidthQoS    = 0;
                this->IncomingTraffic = 0;
                this->OutgoingTraffic = 0;
            }
        }
    }
}
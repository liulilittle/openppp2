/**
 * @file VirtualEthernetInformation.cpp
 * @brief Implements serialization and parsing for virtual ethernet information models.
 * @license GPL-3.0
 */

#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/net/Ipep.h>

#include <cstring>
#include <limits>

using ppp::auxiliary::JsonAuxiliary;

namespace {
    static bool IsCanonicalLowerHex(const ppp::string& value, std::size_t length) noexcept {
        if (value.size() != length) {
            return false;
        }
        for (char ch : value) {
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    static bool ParseJsonUInt32(const Json::Value& json, std::uint32_t& value) noexcept {
        if (json.type() == Json::intValue) {
            const Json::Int64 parsed = json.asInt64();
            if (parsed < 0 || static_cast<Json::UInt64>(parsed) >
                std::numeric_limits<std::uint32_t>::max()) {
                return false;
            }
            value = static_cast<std::uint32_t>(parsed);
            return true;
        }
        if (json.type() == Json::uintValue) {
            const Json::UInt64 parsed = json.asUInt64();
            if (parsed > std::numeric_limits<std::uint32_t>::max()) {
                return false;
            }
            value = static_cast<std::uint32_t>(parsed);
            return true;
        }
        return false;
    }

    static bool ParseCanonicalUInt64(const Json::Value& json, std::uint64_t& value) noexcept {
        if (!json.isString()) {
            return false;
        }
        const ppp::string text = json.asString();
        if (text.empty() || (text.size() > 1 && text.front() == '0')) {
            return false;
        }

        std::uint64_t parsed = 0;
        for (char ch : text) {
            if (ch < '0' || ch > '9') {
                return false;
            }
            const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');
            if (parsed > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
                return false;
            }
            parsed = parsed * 10 + digit;
        }
        value = parsed;
        return true;
    }

    static bool IsBoundedReasonToken(const ppp::string& reason) noexcept {
        if (reason.size() > ppp::app::protocol::SessionResumeControl::MaximumReasonLength) {
            return false;
        }
        for (char ch : reason) {
            if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-')) {
                return false;
            }
        }
        return true;
    }

    static bool IsTransportAuthMethodToken(const ppp::string& value) noexcept {
        if (value.empty() ||
            value.size() > ppp::app::protocol::TransportAuthControl::MaximumMethodLength) {
            return false;
        }
        for (char ch : value) {
            if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-')) {
                return false;
            }
        }
        return true;
    }

    static bool IsTransportAuthKeyId(const ppp::string& value) noexcept {
        if (value.empty() ||
            value.size() > ppp::app::protocol::TransportAuthControl::MaximumKeyIdLength ||
            !((value.front() >= 'a' && value.front() <= 'z') ||
                (value.front() >= '0' && value.front() <= '9'))) {
            return false;
        }
        for (char ch : value) {
            if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
                ch == '.' || ch == '_' || ch == '-')) {
                return false;
            }
        }
        return true;
    }

    static bool IsTransportAuthToken(const ppp::string& value) noexcept {
        return value.size() <=
            ppp::app::protocol::TransportAuthControl::MaximumTokenSize &&
            IsCanonicalLowerHex(value,
                ppp::app::protocol::TransportAuthControl::TokenHexLength);
    }

    static bool IsTransportAuthMessage(const ppp::string& value) noexcept {
        if (value.empty() || (value.size() & 1) != 0 ||
            value.size() / 2 > ppp::app::protocol::TransportAuthControl::MaximumMessageBytes) {
            return false;
        }
        for (char ch : value) {
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    static bool IsTransportAuthReason(const ppp::string& value) noexcept {
        if (value.empty() ||
            value.size() > ppp::app::protocol::TransportAuthControl::MaximumReasonLength) {
            return false;
        }
        for (char ch : value) {
            if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-')) {
                return false;
            }
        }
        return true;
    }

    static ppp::string P2PIPv4ToString(uint32_t ip) noexcept {
        if (ip == 0) {
            return ppp::string();
        }
        return ppp::net::IPEndPoint::ToAddressString(ip);
    }

    static uint32_t P2PStringToIPv4(const ppp::string& value) noexcept {
        if (value.empty()) {
            return 0;
        }

        boost::system::error_code ec;
        boost::asio::ip::address address = StringToAddress(value, ec);
        if (ec || !address.is_v4()) {
            return 0;
        }
        return htonl(address.to_v4().to_uint());
    }
}

namespace ppp {
    namespace app {
        namespace protocol {
            VirtualEthernetInformation::VirtualEthernetInformation() noexcept {
                Clear();
            }

            /**
             * @brief Converts a virtual ethernet information object into JSON text.
             * @param information Source information object.
             * @param styled True for pretty-printed JSON; false for compact JSON.
             * @return Serialized JSON string.
             */
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

            /** @brief Serializes this object into formatted JSON text. */
            ppp::string VirtualEthernetInformation::ToString() noexcept {
                return STATIC_TO_STRRING(*this, true);
            }

            /** @brief Serializes this object into compact JSON text. */
            ppp::string VirtualEthernetInformation::ToJson() noexcept {
                return STATIC_TO_STRRING(*this, false);
            }

            /** @brief Writes this object fields into a JSON value. */
            void VirtualEthernetInformation::ToJson(Json::Value& json) noexcept {
                json["BandwidthQoS"]    = stl::to_string<ppp::string>(this->BandwidthQoS);
                json["ExpiredTime"]     = this->ExpiredTime;
                json["IncomingTraffic"] = stl::to_string<ppp::string>(this->IncomingTraffic);
                json["OutgoingTraffic"] = stl::to_string<ppp::string>(this->OutgoingTraffic);
            }

            /** @brief Builds an information object from a JSON value object. */
            std::shared_ptr<VirtualEthernetInformation> VirtualEthernetInformation::FromJson(const Json::Value& json) noexcept {
                if (!json.isObject()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VEthernetInformationFromJsonInvalidObject);
                    return NULLPTR;
                }

                std::shared_ptr<VirtualEthernetInformation> infomartion = make_shared_object<VirtualEthernetInformation>();
                if (NULLPTR == infomartion) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionCreateFailed);
                    return NULLPTR;
                }

                infomartion->ExpiredTime     = JsonAuxiliary::AsValue<long long>(json["ExpiredTime"]);
                infomartion->BandwidthQoS    = JsonAuxiliary::AsValue<long long>(json["BandwidthQoS"]);
                infomartion->IncomingTraffic = JsonAuxiliary::AsValue<unsigned long long>(json["IncomingTraffic"]);
                infomartion->OutgoingTraffic = JsonAuxiliary::AsValue<unsigned long long>(json["OutgoingTraffic"]);
                return infomartion;
            }

            /** @brief Builds an information object from JSON text. */
            std::shared_ptr<VirtualEthernetInformation> VirtualEthernetInformation::FromJson(const ppp::string& json) noexcept {
                if (json.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VEthernetInformationFromJsonTextEmpty);
                    return NULLPTR;
                }

                Json::Value config = JsonAuxiliary::FromString(json);
                return FromJson(config);
            }

            /** @brief Resets all information fields to defaults. */
            void VirtualEthernetInformation::Clear() noexcept {
                this->ExpiredTime     = 0;
                this->BandwidthQoS    = 0;
                this->IncomingTraffic = 0;
                this->OutgoingTraffic = 0;
            }

            /** @brief Resets all IPv6 extension fields to defaults. */
            void VirtualEthernetInformationExtensions::Clear() noexcept {
                AssignedIPv6Mode = IPv6Mode_None;
                AssignedIPv6AddressPrefixLength = 0;
                AssignedIPv6Flags = 0;
                AssignedIPv6Address = boost::asio::ip::address();
                AssignedIPv6Gateway = boost::asio::ip::address();
                AssignedIPv6RoutePrefix = boost::asio::ip::address();
                AssignedIPv6RoutePrefixLength = 0;
                AssignedIPv6Dns1 = boost::asio::ip::address();
                AssignedIPv6Dns2 = boost::asio::ip::address();
                IPv6StatusCode = IPv6Status_None;
                RequestedIPv6Address = boost::asio::ip::address();
                IPv6StatusMessage.clear();
                ClientExitIP = boost::asio::ip::address();
                ClientIPv4Req.Clear();
                ClientIPv4Assign.Clear();
                P2P.Clear();
                TransportAuth.Clear();
                SessionResume.Clear();
                PeerRouteAnnounce.Clear();
                PeerRouteTable.Clear();
            }

            /** @brief Returns whether any IPv6 extension field is currently populated. */
            bool VirtualEthernetInformationExtensions::HasAny() const noexcept {
                return AssignedIPv6Mode != IPv6Mode_None ||
                    AssignedIPv6AddressPrefixLength != 0 ||
                    AssignedIPv6Flags != 0 ||
                    AssignedIPv6Address.is_v6() ||
                    AssignedIPv6Gateway.is_v6() ||
                    AssignedIPv6RoutePrefix.is_v6() ||
                    AssignedIPv6RoutePrefixLength != 0 ||
                    AssignedIPv6Dns1.is_v6() ||
                    AssignedIPv6Dns2.is_v6() ||
                    RequestedIPv6Address.is_v6() ||
                    IPv6StatusCode != IPv6Status_None ||
                    !IPv6StatusMessage.empty() ||
                    !ClientExitIP.is_unspecified() ||
                    ClientIPv4Req.HasAny() ||
                    ClientIPv4Assign.HasAny() ||
                    P2P.HasAny() ||
                    TransportAuth.HasAny() ||
                    SessionResume.HasAny() ||
                    PeerRouteAnnounce.HasAny() ||
                    PeerRouteTable.HasAny();
            }

            /** @brief Writes IPv6 extension fields to a JSON object. */
            void VirtualEthernetInformationExtensions::ToJson(Json::Value& json) const noexcept {
                json["AssignedIPv6Mode"] = AssignedIPv6Mode;
                json["AssignedIPv6AddressPrefixLength"] = AssignedIPv6AddressPrefixLength;
                json["AssignedIPv6Flags"] = AssignedIPv6Flags;
                json["AssignedIPv6RoutePrefixLength"] = AssignedIPv6RoutePrefixLength;
                json["IPv6StatusCode"] = IPv6StatusCode;

                if (AssignedIPv6Address.is_v6()) {
                    std::string value = AssignedIPv6Address.to_string();
                    json["AssignedIPv6Address"] = Json::Value(value.c_str());
                }

                if (AssignedIPv6Gateway.is_v6()) {
                    std::string value = AssignedIPv6Gateway.to_string();
                    json["AssignedIPv6Gateway"] = Json::Value(value.c_str());
                }

                if (AssignedIPv6RoutePrefix.is_v6()) {
                    std::string value = AssignedIPv6RoutePrefix.to_string();
                    json["AssignedIPv6RoutePrefix"] = Json::Value(value.c_str());
                }

                if (RequestedIPv6Address.is_v6()) {
                    std::string value = RequestedIPv6Address.to_string();
                    json["RequestedIPv6Address"] = Json::Value(value.c_str());
                }

                if (AssignedIPv6Dns1.is_v6()) {
                    std::string value = AssignedIPv6Dns1.to_string();
                    json["AssignedIPv6Dns1"] = Json::Value(value.c_str());
                }

                if (AssignedIPv6Dns2.is_v6()) {
                    std::string value = AssignedIPv6Dns2.to_string();
                    json["AssignedIPv6Dns2"] = Json::Value(value.c_str());
                }

                if (!IPv6StatusMessage.empty()) {
                    json["IPv6StatusMessage"] = Json::Value(IPv6StatusMessage.c_str());
                }

                if (!ClientExitIP.is_unspecified()) {
                    std::string value = ClientExitIP.to_string();
                    json["ClientExitIP"] = Json::Value(value.c_str());
                }

                if (ClientIPv4Req.HasAny()) {
                    Json::Value ipv4_req;
                    ClientIPv4Req.ToJson(ipv4_req);
                    json["client-ipv4-request"] = ipv4_req;
                }

                if (ClientIPv4Assign.HasAny()) {
                    Json::Value ipv4_assign;
                    ClientIPv4Assign.ToJson(ipv4_assign);
                    json["client-ipv4"] = ipv4_assign;
                }

                if (P2P.HasAny()) {
                    Json::Value p2p;
                    P2P.ToJson(p2p);
                    json["p2p"] = p2p;
                }

                if (TransportAuth.Valid()) {
                    Json::Value transport_auth;
                    TransportAuth.ToJson(transport_auth);
                    json["transport-auth"] = transport_auth;
                }

                if (SessionResume.Valid()) {
                    Json::Value session_resume;
                    SessionResume.ToJson(session_resume);
                    json["session-resume"] = session_resume;
                }

                if (PeerRouteAnnounce.HasAny()) {
                    Json::Value announce;
                    PeerRouteAnnounce.ToJson(announce);
                    json["peer-route-announce"] = announce;
                }

                if (PeerRouteTable.HasAny()) {
                    Json::Value table;
                    PeerRouteTable.ToJson(table);
                    json["peer-route-table"] = table;
                }
            }

            /** @brief Serializes IPv6 extension fields into compact JSON text. */
            ppp::string VirtualEthernetInformationExtensions::ToJson() const noexcept {
                Json::Value json;
                ToJson(json);
                return JsonAuxiliary::ToString(json);
            }

            /** @brief Parses IPv6 extensions from JSON text into the target value. */
            bool VirtualEthernetInformationExtensions::FromJson(VirtualEthernetInformationExtensions& value, const ppp::string& json) noexcept {
                if (json.empty()) {
                    value.Clear();
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VEthernetInformationExtensionsFromJsonTextEmpty);
                    return false;
                }

                return FromJson(value, JsonAuxiliary::FromString(json));
            }

            /** @brief Parses IPv6 extensions from a JSON object into the target value. */
            bool VirtualEthernetInformationExtensions::FromJson(VirtualEthernetInformationExtensions& value, const Json::Value& json) noexcept {
                value.Clear();
                if (!json.isObject()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                    return false;
                }

                value.AssignedIPv6Mode = static_cast<Byte>(JsonAuxiliary::AsInt64(json["AssignedIPv6Mode"], 0));
                if (value.AssignedIPv6Mode != IPv6Mode_None &&
                    value.AssignedIPv6Mode != IPv6Mode_Nat66 &&
                    value.AssignedIPv6Mode != IPv6Mode_Gua) {
                    value.AssignedIPv6Mode = IPv6Mode_None;
                }
                value.AssignedIPv6AddressPrefixLength = static_cast<Byte>(JsonAuxiliary::AsInt64(json["AssignedIPv6AddressPrefixLength"], JsonAuxiliary::AsInt64(json["AssignedIPv6PrefixLength"], 0)));
                value.AssignedIPv6Flags = static_cast<Byte>(JsonAuxiliary::AsInt64(json["AssignedIPv6Flags"], 0));
                value.AssignedIPv6RoutePrefixLength = static_cast<Byte>(JsonAuxiliary::AsInt64(json["AssignedIPv6RoutePrefixLength"], 0));
                value.IPv6StatusCode = static_cast<Byte>(JsonAuxiliary::AsInt64(json["IPv6StatusCode"], 0));

                /**
                 * @brief Parse IPv6 address fields with strict validation.
                 *
                 * Each candidate string is converted into a boost address and accepted
                 * only when conversion succeeds and the address family is IPv6.
                 */
                boost::system::error_code ec;
                boost::asio::ip::address address = StringToAddress(JsonAuxiliary::AsString(json["AssignedIPv6Address"]), ec);
                if (!ec && address.is_v6()) {
                    value.AssignedIPv6Address = address;
                }

                ec.clear();
                address = StringToAddress(JsonAuxiliary::AsString(json["AssignedIPv6Gateway"]), ec);
                if (!ec && address.is_v6()) {
                    value.AssignedIPv6Gateway = address;
                }

                ec.clear();
                address = StringToAddress(JsonAuxiliary::AsString(json["AssignedIPv6RoutePrefix"]), ec);
                if (!ec && address.is_v6()) {
                    value.AssignedIPv6RoutePrefix = address;
                }

                ec.clear();
                address = StringToAddress(JsonAuxiliary::AsString(json["RequestedIPv6Address"]), ec);
                if (!ec && address.is_v6()) {
                    value.RequestedIPv6Address = address;
                }

                ec.clear();
                address = StringToAddress(JsonAuxiliary::AsString(json["AssignedIPv6Dns1"]), ec);
                if (!ec && address.is_v6()) {
                    value.AssignedIPv6Dns1 = address;
                }

                ec.clear();
                address = StringToAddress(JsonAuxiliary::AsString(json["AssignedIPv6Dns2"]), ec);
                if (!ec && address.is_v6()) {
                    value.AssignedIPv6Dns2 = address;
                }

                value.IPv6StatusMessage = JsonAuxiliary::AsString(json["IPv6StatusMessage"]);

                // Parse ClientExitIP: accepts both IPv4 and IPv6 addresses.
                // This field is populated by the server from the client's remote
                // endpoint and read by the client for ECS exit-IP fallback.
                ec.clear();
                address = StringToAddress(JsonAuxiliary::AsString(json["ClientExitIP"]), ec);
                if (!ec && !address.is_unspecified()) {
                    value.ClientExitIP = address;
                }

                // Parse "client-ipv4-request": IPv4 address request from client to server.
                if (json.isMember("client-ipv4-request") && json["client-ipv4-request"].isObject()) {
                    ClientIPv4Request::FromJson(value.ClientIPv4Req, json["client-ipv4-request"]);
                }

                // Parse "client-ipv4": IPv4 assignment response from server to client.
                if (json.isMember("client-ipv4") && json["client-ipv4"].isObject()) {
                    ClientIPv4Assignment::FromJson(value.ClientIPv4Assign, json["client-ipv4"]);
                }

                if (json.isMember("p2p") && json["p2p"].isObject()) {
                    P2PControlMessage::FromJson(value.P2P, json["p2p"]);
                }

                if (json.isMember("transport-auth") &&
                    !TransportAuthControl::FromJson(value.TransportAuth, json["transport-auth"])) {
                    return false;
                }

                if (json.isMember("session-resume") &&
                    !SessionResumeControl::FromJson(value.SessionResume, json["session-resume"])) {
                    return false;
                }

                if (json.isMember("peer-route-announce") && json["peer-route-announce"].isObject()) {
                    PeerRouteAnnounceMessage::FromJson(value.PeerRouteAnnounce, json["peer-route-announce"]);
                }

                if (json.isMember("peer-route-table") && json["peer-route-table"].isObject()) {
                    PeerRouteTableMessage::FromJson(value.PeerRouteTable, json["peer-route-table"]);
                }

                return true;
            }

            // ---- P2P control ----

            void P2PEndpointCandidate::Clear() noexcept {
                endpoint.clear();
                source.clear();
            }

            bool P2PEndpointCandidate::HasAny() const noexcept {
                return !endpoint.empty();
            }

            void P2PEndpointCandidate::ToJson(Json::Value& json) const noexcept {
                if (!endpoint.empty()) {
                    json["endpoint"] = Json::Value(endpoint.c_str());
                }
                if (!source.empty()) {
                    json["source"] = Json::Value(source.c_str());
                }
            }

            bool P2PEndpointCandidate::FromJson(P2PEndpointCandidate& value, const Json::Value& json) noexcept {
                value.Clear();
                if (!json.isObject()) {
                    return false;
                }

                value.endpoint = JsonAuxiliary::AsString(json["endpoint"]);
                value.source = JsonAuxiliary::AsString(json["source"]);
                return value.HasAny();
            }

            void P2PControlMessage::Clear() noexcept {
                enabled = false;
                mode.clear();
                action.clear();
                virtual_ip = 0;
                peer_virtual_ip = 0;
                token.clear();
                authenticated_offer_v1.clear();
                reason.clear();
                candidates.clear();
            }

            bool P2PControlMessage::HasAny() const noexcept {
                return enabled ||
                    !mode.empty() ||
                    !action.empty() ||
                    virtual_ip != 0 ||
                    peer_virtual_ip != 0 ||
                    !token.empty() ||
                    !authenticated_offer_v1.empty() ||
                    !reason.empty() ||
                    !candidates.empty();
            }

            void P2PControlMessage::ToJson(Json::Value& json) const noexcept {
                json["enabled"] = enabled;
                if (!mode.empty()) {
                    json["mode"] = Json::Value(mode.c_str());
                }
                if (!action.empty()) {
                    json["action"] = Json::Value(action.c_str());
                }
                ppp::string vip = P2PIPv4ToString(virtual_ip);
                if (!vip.empty()) {
                    json["virtual-ip"] = Json::Value(vip.c_str());
                }
                ppp::string peer_vip = P2PIPv4ToString(peer_virtual_ip);
                if (!peer_vip.empty()) {
                    json["peer-virtual-ip"] = Json::Value(peer_vip.c_str());
                }
                if (!token.empty()) {
                    json["token"] = Json::Value(token.c_str());
                }
                if (!authenticated_offer_v1.empty()) {
                    json["authenticated-offer-v1"] =
                        Json::Value(authenticated_offer_v1.c_str());
                }
                if (!reason.empty()) {
                    json["reason"] = Json::Value(reason.c_str());
                }
                if (!candidates.empty()) {
                    Json::Value arr(Json::arrayValue);
                    for (const P2PEndpointCandidate& candidate : candidates) {
                        if (!candidate.HasAny()) {
                            continue;
                        }
                        Json::Value item;
                        candidate.ToJson(item);
                        arr.append(item);
                    }
                    json["candidates"] = arr;
                }
            }

            ppp::string P2PControlMessage::ToJson() const noexcept {
                Json::Value json;
                ToJson(json);
                return JsonAuxiliary::ToString(json);
            }

            bool P2PControlMessage::FromJson(P2PControlMessage& value, const Json::Value& json) noexcept {
                value.Clear();
                if (!json.isObject()) {
                    return false;
                }

                value.enabled = JsonAuxiliary::AsValue<bool>(json["enabled"]);
                value.mode = JsonAuxiliary::AsString(json["mode"]);
                value.action = JsonAuxiliary::AsString(json["action"]);
                value.virtual_ip = P2PStringToIPv4(JsonAuxiliary::AsString(json["virtual-ip"]));
                value.peer_virtual_ip = P2PStringToIPv4(JsonAuxiliary::AsString(json["peer-virtual-ip"]));
                value.token = JsonAuxiliary::AsString(json["token"]);
                value.authenticated_offer_v1 =
                    JsonAuxiliary::AsString(json["authenticated-offer-v1"]);
                value.reason = JsonAuxiliary::AsString(json["reason"]);

                const Json::Value& candidates_json = json["candidates"];
                if (candidates_json.isArray()) {
                    for (Json::ArrayIndex i = 0; i < candidates_json.size(); i++) {
                        P2PEndpointCandidate candidate;
                        if (P2PEndpointCandidate::FromJson(candidate, candidates_json[i])) {
                            value.candidates.emplace_back(std::move(candidate));
                        }
                    }
                }

                return value.HasAny();
            }

            // ---- Transport authentication control ----

            void TransportAuthControl::Clear() noexcept {
                version = ProtocolVersion;
                action = Action::None;
                method.clear();
                methods.clear();
                key_id.clear();
                token.clear();
                sequence = 0;
                message.clear();
                proof.clear();
                reason.clear();
            }

            bool TransportAuthControl::HasAny() const noexcept {
                return action != Action::None || !token.empty();
            }

            bool TransportAuthControl::Valid() const noexcept {
                if (version != ProtocolVersion || action == Action::None) {
                    return false;
                }

                bool methods_valid = !methods.empty() && methods.size() <= MaximumMethods;
                for (std::size_t i = 0; methods_valid && i < methods.size(); ++i) {
                    if (!IsTransportAuthMethodToken(methods[i])) {
                        methods_valid = false;
                        break;
                    }
                    for (std::size_t j = 0; j < i; ++j) {
                        if (methods[j] == methods[i]) {
                            methods_valid = false;
                            break;
                        }
                    }
                }

                const bool method_valid = IsTransportAuthMethodToken(method);
                const bool key_id_valid = IsTransportAuthKeyId(key_id);
                const bool token_valid = IsTransportAuthToken(token);
                const bool message_valid = IsTransportAuthMessage(message);
                switch (action) {
                    case Action::Advertise: {
                        if (!methods_valid || !token_valid || !proof.empty() || !reason.empty()) {
                            return false;
                        }
                        const bool capability_only = method.empty() && key_id.empty() &&
                            sequence == 0 && message.empty();
                        bool method_advertised = false;
                        for (const ppp::string& advertised : methods) {
                            method_advertised = method_advertised || advertised == method;
                        }
                        const bool initiator_message = method_valid && method_advertised &&
                            key_id_valid && sequence == 1 && message_valid;
                        return capability_only || initiator_message;
                    }
                    case Action::Select:
                        return methods.empty() && method_valid && key_id_valid && token_valid &&
                            sequence == 2 && message_valid && proof.empty() && reason.empty();
                    case Action::Success:
                        return methods.empty() && method_valid && key_id_valid && token_valid &&
                            sequence == 0 && message.empty() && reason.empty() &&
                            (proof.empty() || IsCanonicalLowerHex(proof, 64));
                    case Action::Reject:
                        return methods.empty() && method.empty() && key_id.empty() &&
                            (token.empty() || token_valid) && sequence == 0 && message.empty() &&
                            proof.empty() && IsTransportAuthReason(reason);
                    default:
                        return false;
                }
            }

            const char* TransportAuthControl::ActionToString(Action action) noexcept {
                switch (action) {
                    case Action::Advertise: return "advertise";
                    case Action::Select: return "select";
                    case Action::Success: return "success";
                    case Action::Reject: return "reject";
                    default: return "";
                }
            }

            bool TransportAuthControl::ActionFromString(
                const ppp::string& text, Action& action) noexcept {
                if (text == "advertise") action = Action::Advertise;
                else if (text == "select") action = Action::Select;
                else if (text == "success") action = Action::Success;
                else if (text == "reject") action = Action::Reject;
                else {
                    action = Action::None;
                    return false;
                }
                return true;
            }

            void TransportAuthControl::ToJson(Json::Value& json) const noexcept {
                if (!Valid()) {
                    return;
                }

                json["version"] = Json::UInt(version);
                json["action"] = Json::Value(ActionToString(action));
                if (!method.empty()) {
                    json["method"] = Json::Value(method.c_str());
                }
                if (!methods.empty()) {
                    Json::Value array(Json::arrayValue);
                    for (const ppp::string& advertised : methods) {
                        array.append(Json::Value(advertised.c_str()));
                    }
                    json["methods"] = array;
                }
                if (!key_id.empty()) {
                    json["key-id"] = Json::Value(key_id.c_str());
                }
                if (!token.empty()) {
                    json["token"] = Json::Value(token.c_str());
                }
                if (sequence != 0) {
                    json["sequence"] = Json::UInt(sequence);
                }
                if (!message.empty()) {
                    json["message"] = Json::Value(message.c_str());
                }
                if (!proof.empty()) {
                    json["proof"] = Json::Value(proof.c_str());
                }
                if (!reason.empty()) {
                    json["reason"] = Json::Value(reason.c_str());
                }
            }

            ppp::string TransportAuthControl::ToJson() const noexcept {
                Json::Value json;
                ToJson(json);
                return JsonAuxiliary::ToString(json);
            }

            bool TransportAuthControl::FromJson(
                TransportAuthControl& value, const ppp::string& json) noexcept {
                value.Clear();
                if (json.empty()) {
                    return false;
                }
                return FromJson(value, JsonAuxiliary::FromString(json));
            }

            bool TransportAuthControl::FromJson(
                TransportAuthControl& value, const Json::Value& json) noexcept {
                value.Clear();
                if (!json.isObject()) {
                    return false;
                }

                for (const auto& name : json.getMemberNames()) {
                    if (name != "version" && name != "action" && name != "method" &&
                        name != "methods" && name != "key-id" && name != "token" &&
                        name != "sequence" && name != "message" && name != "proof" &&
                        name != "reason") {
                        return false;
                    }
                }

                const bool has_version = json.isMember("version");
                const bool has_action = json.isMember("action");
                const bool has_method = json.isMember("method");
                const bool has_methods = json.isMember("methods");
                const bool has_key_id = json.isMember("key-id");
                const bool has_token = json.isMember("token");
                const bool has_sequence = json.isMember("sequence");
                const bool has_message = json.isMember("message");
                const bool has_proof = json.isMember("proof");
                const bool has_reason = json.isMember("reason");

                TransportAuthControl parsed;
                std::uint32_t parsed_version = 0;
                if (!has_version || !ParseJsonUInt32(json["version"], parsed_version) ||
                    parsed_version != ProtocolVersion || !has_action ||
                    !json["action"].isString() ||
                    !ActionFromString(json["action"].asString(), parsed.action)) {
                    return false;
                }

                if (has_method) {
                    if (!json["method"].isString()) {
                        return false;
                    }
                    parsed.method = json["method"].asString();
                    if (!IsTransportAuthMethodToken(parsed.method)) {
                        return false;
                    }
                }
                if (has_methods) {
                    const Json::Value& advertised = json["methods"];
                    if (!advertised.isArray() || advertised.empty() ||
                        advertised.size() > MaximumMethods) {
                        return false;
                    }
                    for (Json::ArrayIndex i = 0; i < advertised.size(); ++i) {
                        if (!advertised[i].isString()) {
                            return false;
                        }
                        const ppp::string candidate = advertised[i].asString();
                        if (!IsTransportAuthMethodToken(candidate)) {
                            return false;
                        }
                        for (const ppp::string& existing : parsed.methods) {
                            if (existing == candidate) {
                                return false;
                            }
                        }
                        parsed.methods.emplace_back(candidate);
                    }
                }
                if (has_key_id) {
                    if (!json["key-id"].isString()) {
                        return false;
                    }
                    parsed.key_id = json["key-id"].asString();
                    if (!IsTransportAuthKeyId(parsed.key_id)) {
                        return false;
                    }
                }
                if (has_token) {
                    if (!json["token"].isString()) {
                        return false;
                    }
                    parsed.token = json["token"].asString();
                    if (!IsTransportAuthToken(parsed.token)) {
                        return false;
                    }
                }
                if (has_sequence &&
                    !ParseJsonUInt32(json["sequence"], parsed.sequence)) {
                    return false;
                }
                if (has_message) {
                    if (!json["message"].isString()) {
                        return false;
                    }
                    parsed.message = json["message"].asString();
                    if (!IsTransportAuthMessage(parsed.message)) {
                        return false;
                    }
                }
                if (has_proof) {
                    if (!json["proof"].isString()) {
                        return false;
                    }
                    parsed.proof = json["proof"].asString();
                    if (!IsCanonicalLowerHex(parsed.proof, 64)) {
                        return false;
                    }
                }
                if (has_reason) {
                    if (!json["reason"].isString()) {
                        return false;
                    }
                    parsed.reason = json["reason"].asString();
                    if (!IsTransportAuthReason(parsed.reason)) {
                        return false;
                    }
                }

                bool fields_valid = false;
                switch (parsed.action) {
                    case Action::Advertise: {
                        const bool capability_only = has_methods && !has_method && !has_key_id &&
                            has_token && !has_sequence && !has_message && !has_proof && !has_reason;
                        const bool initiator_message = has_methods && has_method && has_key_id &&
                            has_token && has_sequence && parsed.sequence == 1 && has_message &&
                            !has_proof && !has_reason;
                        fields_valid = capability_only || initiator_message;
                        break;
                    }
                    case Action::Select:
                        fields_valid = !has_methods && has_method && has_key_id && has_token &&
                            has_sequence && parsed.sequence == 2 && has_message &&
                            !has_proof && !has_reason;
                        break;
                    case Action::Success:
                        fields_valid = !has_methods && has_method && has_key_id && has_token &&
                            !has_sequence && !has_message && !has_reason;
                        break;
                    case Action::Reject:
                        fields_valid = !has_methods && !has_method && !has_key_id &&
                            !has_sequence && !has_message && !has_proof && has_reason;
                        break;
                    default:
                        break;
                }

                if (!fields_valid || !parsed.Valid()) {
                    return false;
                }
                value = std::move(parsed);
                return true;
            }

            // ---- Session resume control ----

            void SessionResumeControl::Clear() noexcept {
                version = ProtocolVersion;
                action = Action::None;
                capabilities = 0;
                session_id.clear();
                generation = 0;
                client_nonce.clear();
                server_nonce.clear();
                candidate_binding.clear();
                proof.clear();
                reason.clear();
            }

            bool SessionResumeControl::HasAny() const noexcept {
                return action != Action::None;
            }

            bool SessionResumeControl::Valid() const noexcept {
                if (version != ProtocolVersion || !HasAny() ||
                    !IsBoundedReasonToken(reason)) {
                    return false;
                }

                const bool identity = capabilities == CapabilityV1 &&
                    IsCanonicalLowerHex(session_id, 32);
                const bool client_nonce_valid = IsCanonicalLowerHex(client_nonce, 64);
                const bool server_nonce_valid = IsCanonicalLowerHex(server_nonce, 64);
                switch (action) {
                    case Action::Offer:
                        return identity && generation == 0 && client_nonce.empty() &&
                            server_nonce_valid && candidate_binding.empty() &&
                            proof.empty() && reason.empty();
                    case Action::Accepted:
                        return identity && generation == 0 && client_nonce_valid &&
                            server_nonce_valid && candidate_binding.empty() &&
                            IsCanonicalLowerHex(proof, 64) && reason.empty();
                    case Action::ResumeRequest:
                    case Action::GenerationSync:
                        return identity && client_nonce_valid && server_nonce.empty() &&
                            IsCanonicalLowerHex(candidate_binding, 64) &&
                            IsCanonicalLowerHex(proof, 64) && reason.empty();
                    case Action::ResumeAccept:
                    case Action::ResumeConfirm:
                    case Action::ResumeCommitted:
                        return identity && client_nonce_valid && server_nonce_valid &&
                            IsCanonicalLowerHex(candidate_binding, 64) &&
                            IsCanonicalLowerHex(proof, 64) && reason.empty();
                    case Action::Reject: {
                        if (reason.empty()) {
                            return false;
                        }
                        const bool bare = capabilities == 0 && session_id.empty() &&
                            generation == 0 && client_nonce.empty() && server_nonce.empty() &&
                            candidate_binding.empty() && proof.empty();
                        const bool authenticated = identity && client_nonce_valid &&
                            server_nonce_valid && IsCanonicalLowerHex(candidate_binding, 64) &&
                            IsCanonicalLowerHex(proof, 64);
                        return bare || authenticated;
                    }
                    default:
                        return false;
                }
            }

            const char* SessionResumeControl::ActionToString(Action action) noexcept {
                switch (action) {
                    case Action::Offer: return "offer";
                    case Action::Accepted: return "accepted";
                    case Action::ResumeRequest: return "resume-request";
                    case Action::GenerationSync: return "generation-sync";
                    case Action::ResumeAccept: return "resume-accept";
                    case Action::ResumeConfirm: return "resume-confirm";
                    case Action::ResumeCommitted: return "resume-committed";
                    case Action::Reject: return "reject";
                    default: return "";
                }
            }

            bool SessionResumeControl::ActionFromString(const ppp::string& text, Action& action) noexcept {
                if (text == "offer") action = Action::Offer;
                else if (text == "accepted") action = Action::Accepted;
                else if (text == "resume-request") action = Action::ResumeRequest;
                else if (text == "generation-sync") action = Action::GenerationSync;
                else if (text == "resume-accept") action = Action::ResumeAccept;
                else if (text == "resume-confirm") action = Action::ResumeConfirm;
                else if (text == "resume-committed") action = Action::ResumeCommitted;
                else if (text == "reject") action = Action::Reject;
                else {
                    action = Action::None;
                    return false;
                }
                return true;
            }

            void SessionResumeControl::ToJson(Json::Value& json) const noexcept {
                if (!Valid()) {
                    return;
                }

                json["version"] = Json::UInt(version);
                json["action"] = Json::Value(ActionToString(action));
                if (capabilities != 0) {
                    json["capabilities"] = Json::UInt(capabilities);
                }
                if (!session_id.empty()) {
                    json["session-id"] = Json::Value(session_id.c_str());
                }

                const bool resume_action = action == Action::ResumeRequest ||
                    action == Action::GenerationSync || action == Action::ResumeAccept ||
                    action == Action::ResumeConfirm || action == Action::ResumeCommitted;
                const bool authenticated_reject = action == Action::Reject &&
                    (capabilities != 0 || !session_id.empty() || !client_nonce.empty() ||
                        !server_nonce.empty() || !candidate_binding.empty() || !proof.empty());
                if (resume_action || authenticated_reject) {
                    json["generation"] = Json::Value(
                        stl::to_string<ppp::string>(generation).c_str());
                }
                if (!client_nonce.empty()) {
                    json["client-nonce"] = Json::Value(client_nonce.c_str());
                }
                if (!server_nonce.empty()) {
                    json["server-nonce"] = Json::Value(server_nonce.c_str());
                }
                if (!candidate_binding.empty()) {
                    json["candidate-binding"] = Json::Value(candidate_binding.c_str());
                }
                if (!proof.empty()) {
                    json["proof"] = Json::Value(proof.c_str());
                }
                if (!reason.empty()) {
                    json["reason"] = Json::Value(reason.c_str());
                }
            }

            ppp::string SessionResumeControl::ToJson() const noexcept {
                Json::Value json;
                ToJson(json);
                return JsonAuxiliary::ToString(json);
            }

            bool SessionResumeControl::FromJson(
                SessionResumeControl& value, const ppp::string& json) noexcept {
                value.Clear();
                if (json.empty()) {
                    return false;
                }
                return FromJson(value, JsonAuxiliary::FromString(json));
            }

            bool SessionResumeControl::FromJson(
                SessionResumeControl& value, const Json::Value& json) noexcept {
                value.Clear();
                if (!json.isObject()) {
                    return false;
                }

                const bool has_version = json.isMember("version");
                const bool has_action = json.isMember("action");
                const bool has_capabilities = json.isMember("capabilities");
                const bool has_session_id = json.isMember("session-id");
                const bool has_generation = json.isMember("generation");
                const bool has_client_nonce = json.isMember("client-nonce");
                const bool has_server_nonce = json.isMember("server-nonce");
                const bool has_candidate_binding = json.isMember("candidate-binding");
                const bool has_proof = json.isMember("proof");
                const bool has_reason = json.isMember("reason");

                SessionResumeControl parsed;
                std::uint32_t parsed_version = 0;
                if (!has_version || !ParseJsonUInt32(json["version"], parsed_version) ||
                    parsed_version != ProtocolVersion ||
                    !has_action || !json["action"].isString() ||
                    !ActionFromString(json["action"].asString(), parsed.action)) {
                    return false;
                }

                if (has_capabilities) {
                    if (!ParseJsonUInt32(json["capabilities"], parsed.capabilities) ||
                        (parsed.capabilities & ~CapabilityV1) != 0) {
                        return false;
                    }
                }
                if (has_session_id) {
                    if (!json["session-id"].isString()) {
                        return false;
                    }
                    parsed.session_id = json["session-id"].asString();
                    if (!IsCanonicalLowerHex(parsed.session_id, 32)) {
                        return false;
                    }
                }
                if (has_generation && !ParseCanonicalUInt64(json["generation"], parsed.generation)) {
                    return false;
                }

                const auto parse_hex = [&json](const char* name, bool present,
                    ppp::string& output) noexcept -> bool {
                    if (!present) {
                        return true;
                    }
                    if (!json[name].isString()) {
                        return false;
                    }
                    output = json[name].asString();
                    return IsCanonicalLowerHex(output, 64);
                };
                if (!parse_hex("client-nonce", has_client_nonce, parsed.client_nonce) ||
                    !parse_hex("server-nonce", has_server_nonce, parsed.server_nonce) ||
                    !parse_hex("candidate-binding", has_candidate_binding, parsed.candidate_binding) ||
                    !parse_hex("proof", has_proof, parsed.proof)) {
                    return false;
                }
                if (has_reason) {
                    if (!json["reason"].isString()) {
                        return false;
                    }
                    parsed.reason = json["reason"].asString();
                    if (!IsBoundedReasonToken(parsed.reason)) {
                        return false;
                    }
                }

                const bool base = has_capabilities && parsed.capabilities == CapabilityV1 &&
                    has_session_id;
                bool valid = false;
                switch (parsed.action) {
                    case Action::Offer:
                        valid = base && !has_client_nonce && !has_generation &&
                            has_server_nonce && !has_candidate_binding && !has_proof &&
                            parsed.reason.empty();
                        break;
                    case Action::Accepted:
                        valid = base && has_client_nonce && has_server_nonce && has_proof &&
                            !has_generation && !has_candidate_binding && parsed.reason.empty();
                        break;
                    case Action::ResumeRequest:
                    case Action::GenerationSync:
                        valid = base && has_generation && has_client_nonce &&
                            !has_server_nonce && has_candidate_binding && has_proof &&
                            parsed.reason.empty();
                        break;
                    case Action::ResumeAccept:
                    case Action::ResumeConfirm:
                    case Action::ResumeCommitted:
                        valid = base && has_generation && has_client_nonce &&
                            has_server_nonce && has_candidate_binding && has_proof &&
                            parsed.reason.empty();
                        break;
                    case Action::Reject: {
                        const bool any_authentication_field = has_capabilities || has_session_id ||
                            has_generation || has_client_nonce || has_server_nonce ||
                            has_candidate_binding || has_proof;
                        const bool complete_authentication_fields = base && has_generation &&
                            has_client_nonce && has_server_nonce && has_candidate_binding && has_proof;
                        valid = has_reason && !parsed.reason.empty() &&
                            (!any_authentication_field || complete_authentication_fields);
                        break;
                    }
                    default:
                        break;
                }

                if (!valid || !parsed.Valid()) {
                    return false;
                }
                value = std::move(parsed);
                return true;
            }

            // ---- ClientIPv4Request ----

            void ClientIPv4Request::Clear() noexcept {
                enabled = false;
                mode.clear();
                address.clear();
                gateway.clear();
                mask.clear();
            }

            bool ClientIPv4Request::HasAny() const noexcept {
                return enabled ||
                    !mode.empty() ||
                    !address.empty() ||
                    !gateway.empty() ||
                    !mask.empty();
            }

            void ClientIPv4Request::ToJson(Json::Value& json) const noexcept {
                if (!enabled && !HasAny()) {
                    return;
                }
                json["enabled"] = enabled;
                if (!mode.empty()) {
                    json["mode"] = Json::Value(mode.c_str());
                }
                if (!address.empty()) {
                    json["address"] = Json::Value(address.c_str());
                }
                if (!gateway.empty()) {
                    json["gateway"] = Json::Value(gateway.c_str());
                }
                if (!mask.empty()) {
                    json["mask"] = Json::Value(mask.c_str());
                }
            }

            ppp::string ClientIPv4Request::ToJson() const noexcept {
                Json::Value json;
                ToJson(json);
                return JsonAuxiliary::ToString(json);
            }

            bool ClientIPv4Request::FromJson(ClientIPv4Request& value, const ppp::string& json) noexcept {
                if (json.empty()) {
                    value.Clear();
                    return false;
                }
                return FromJson(value, JsonAuxiliary::FromString(json));
            }

            bool ClientIPv4Request::FromJson(ClientIPv4Request& value, const Json::Value& json) noexcept {
                value.Clear();
                if (!json.isObject()) {
                    return false;
                }

                value.enabled = true;
                value.mode    = JsonAuxiliary::AsString(json["mode"]);
                value.address = JsonAuxiliary::AsString(json["address"]);
                value.gateway = JsonAuxiliary::AsString(json["gateway"]);
                value.mask    = JsonAuxiliary::AsString(json["mask"]);
                return true;
            }

            // ---- ClientIPv4Assignment ----

            void ClientIPv4Assignment::Clear() noexcept {
                enabled = false;
                accepted = false;
                conflict = false;
                mode.clear();
                reason.clear();
                requested_address.clear();
                address.clear();
                gateway.clear();
                mask.clear();
            }

            bool ClientIPv4Assignment::HasAny() const noexcept {
                return enabled ||
                    accepted ||
                    conflict ||
                    !mode.empty() ||
                    !reason.empty() ||
                    !requested_address.empty() ||
                    !address.empty() ||
                    !gateway.empty() ||
                    !mask.empty();
            }

            void ClientIPv4Assignment::ToJson(Json::Value& json) const noexcept {
                json["enabled"]  = enabled;
                json["accepted"] = accepted;
                json["conflict"] = conflict;
                if (!mode.empty()) {
                    json["mode"] = Json::Value(mode.c_str());
                }
                if (!reason.empty()) {
                    json["reason"] = Json::Value(reason.c_str());
                }
                if (!requested_address.empty()) {
                    json["requested-address"] = Json::Value(requested_address.c_str());
                }
                if (!address.empty()) {
                    json["address"] = Json::Value(address.c_str());
                }
                if (!gateway.empty()) {
                    json["gateway"] = Json::Value(gateway.c_str());
                }
                if (!mask.empty()) {
                    json["mask"] = Json::Value(mask.c_str());
                }
            }

            ppp::string ClientIPv4Assignment::ToJson() const noexcept {
                Json::Value json;
                ToJson(json);
                return JsonAuxiliary::ToString(json);
            }

            bool ClientIPv4Assignment::FromJson(ClientIPv4Assignment& value, const ppp::string& json) noexcept {
                if (json.empty()) {
                    value.Clear();
                    return false;
                }
                return FromJson(value, JsonAuxiliary::FromString(json));
            }

            bool ClientIPv4Assignment::FromJson(ClientIPv4Assignment& value, const Json::Value& json) noexcept {
                value.Clear();
                if (!json.isObject()) {
                    return false;
                }

                value.enabled           = JsonAuxiliary::AsValue<bool>(json["enabled"]);
                value.accepted          = JsonAuxiliary::AsValue<bool>(json["accepted"]);
                value.conflict          = JsonAuxiliary::AsValue<bool>(json["conflict"]);
                value.mode              = JsonAuxiliary::AsString(json["mode"]);
                value.reason            = JsonAuxiliary::AsString(json["reason"]);
                value.requested_address = JsonAuxiliary::AsString(json["requested-address"]);
                value.address           = JsonAuxiliary::AsString(json["address"]);
                value.gateway           = JsonAuxiliary::AsString(json["gateway"]);
                value.mask              = JsonAuxiliary::AsString(json["mask"]);
                return true;
            }
        }
    }
}

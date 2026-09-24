/**
 * @file VirtualEthernetInformation.h
 * @brief Declares quota and IPv6 extension data models for virtual ethernet sessions.
 * @license GPL-3.0
 */

#pragma once

#include <ppp/stdafx.h>
#include <ppp/app/protocol/PeerPrefixRoute.h>
#include <ppp/auxiliary/JsonAuxiliary.h>
#include <ppp/net/IPEndPoint.h>

namespace ppp {
    namespace app {
        namespace protocol {
#pragma pack(push, 1)
            /**
             * @brief Contains traffic quota and expiration metadata for a virtual ethernet session.
             */
            struct
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed))
#endif
            VirtualEthernetInformation
            {
            public:
                /** @brief Maximum QoS throughput in Kbps units; 0 means unlimited. */
                Int64  BandwidthQoS    = 0; // Maximum Quality of Service (QoS) bandwidth throughput speed per second, 0 for unlimited, 1 for 1 Kbps.
                /** @brief Remaining inbound traffic allowance; 0 means exhausted or invalid. */
                UInt64 IncomingTraffic = 0; // The remaining network traffic allowance that can be allowed for incoming clients.
                /** @brief Remaining outbound traffic allowance; 0 means exhausted or invalid. */
                UInt64 OutgoingTraffic = 0; // The remaining network traffic allowance that can be allowed for outgoing clients.
                /** @brief Expiration timestamp in seconds since epoch; 0 means unset or invalid. */
                UInt32 ExpiredTime     = 0; // The time duration during which clients are expired time from using PPP (Point-to-Point Protocol) VPN services, measured in seconds.

            public:
                /** @brief Constructs an information object with cleared defaults. */
                VirtualEthernetInformation() noexcept;

            public:
                /** @brief Resets all quota and expiration fields. */
                void                                                Clear() noexcept;
                /** @brief Serializes this object into a JSON value container. */
                void                                                ToJson(Json::Value& json) noexcept;
                /** @brief Serializes this object into compact JSON text. */
                ppp::string                                         ToJson() noexcept;
                /** @brief Serializes this object into formatted JSON text. */
                ppp::string                                         ToString() noexcept;
                /**
                 * @brief Checks validity against current wall-clock time.
                 *
                 * Uses time(NULL) (Unix epoch seconds) instead of
                 * GetTickCount()/1000 because ExpiredTime is a Unix timestamp
                 * issued by the server.  The monotonic clock used by
                 * GetTickCount() carries no fixed relationship to Unix time
                 * and must not be used here.
                 */
                 bool                                                Valid() noexcept                                          { return Valid((UInt32)time(NULLPTR)); }
                /** @brief Checks validity against a provided timestamp. */
                bool                                                Valid(UInt32 now) noexcept                                { return Valid(this, now); }
                /** @brief Validates quotas and expiration values for a data instance. */
                static bool                                         Valid(VirtualEthernetInformation* i, UInt32 now) noexcept {
                    if (NULLPTR == i) {
                        return false;
                    }

                    return (i->IncomingTraffic > 0 && i->OutgoingTraffic > 0) &&
                        (i->ExpiredTime != 0 && i->ExpiredTime > now);
                }

            public:
                /** @brief Deserializes an information object from JSON text. */
                static std::shared_ptr<VirtualEthernetInformation>  FromJson(const ppp::string& json) noexcept;
                /** @brief Deserializes an information object from a JSON value. */
                static std::shared_ptr<VirtualEthernetInformation>  FromJson(const Json::Value& json) noexcept;
            };
#pragma pack(pop)

            /**
             * @brief IPv4 address request from client to server.
             *
             * Sent by the client during handshake to indicate whether it
             * wants automatic IPv4 assignment ("auto") or has a manual
             * preference ("manual") with a specific address/gateway/mask.
             *
             * Wire-format JSON (kebab-case):
             * @code
             * {
             *   "client-ipv4-request": {
             *     "mode": "auto",
             *     "address": "10.0.0.2",
             *     "gateway": "10.0.0.1",
             *     "mask": "255.255.255.252"
             *   }
             * }
             * @endcode
             *
             * Backward compatibility: when the @c client-ipv4-request key is
             * absent from the handshake JSON, @c enabled remains false.
             */
            struct ClientIPv4Request {
                bool        enabled = false;  ///< True when the client sends this request.
                ppp::string mode;             ///< "auto" or "manual".
                ppp::string address;          ///< Requested IPv4 address (manual mode only).
                ppp::string gateway;          ///< Requested gateway (manual mode only).
                ppp::string mask;             ///< Requested subnet mask (manual mode only).

                /** @brief Resets all fields to defaults. */
                void                                                Clear() noexcept;
                /** @brief Returns true when any field is populated beyond defaults. */
                bool                                                HasAny() const noexcept;
                /** @brief Serializes into a JSON value object. */
                void                                                ToJson(Json::Value& json) const noexcept;
                /** @brief Serializes into compact JSON text. */
                ppp::string                                         ToJson() const noexcept;
                /** @brief Deserializes from JSON text. */
                static bool                                         FromJson(ClientIPv4Request& value, const ppp::string& json) noexcept;
                /** @brief Deserializes from a JSON value object. */
                static bool                                         FromJson(ClientIPv4Request& value, const Json::Value& json) noexcept;
            };

            /**
             * @brief IPv4 address assignment response from server to client.
             *
             * Returned by the server in the handshake response to indicate
             * the outcome of the IPv4 address allocation.  The client must
             * use the @c address / @c gateway / @c mask from this response
             * when @c accepted is true.
             *
             * Wire-format JSON (kebab-case):
             * @code
             * {
             *   "client-ipv4": {
             *     "enabled": true,
             *     "accepted": true,
             *     "conflict": false,
             *     "mode": "auto",
             *     "address": "10.0.0.2",
             *     "gateway": "10.0.0.1",
             *     "mask": "255.255.255.0"
             *   }
             * }
             * @endcode
             *
             * Backward compatibility: when the @c client-ipv4 key is absent,
             * @c enabled defaults to false and the client preserves legacy
             * IPv4 behavior.
             */
            struct ClientIPv4Assignment {
                bool        enabled = false;   ///< True when server processed an IPv4 request.
                bool        accepted = false;  ///< True when the assigned address is accepted.
                bool        conflict = false;  ///< True when the requested address conflicted.
                ppp::string mode;              ///< "auto" or "manual".
                ppp::string reason;            ///< "conflict", "pool-exhausted", "pool-unavailable", or empty.
                ppp::string requested_address; ///< Original address requested by the client (kebab-case: "requested-address").
                ppp::string address;           ///< Assigned IPv4 address.
                ppp::string gateway;           ///< Assigned gateway.
                ppp::string mask;              ///< Assigned subnet mask.

                /** @brief Resets all fields to defaults. */
                void                                                Clear() noexcept;
                /** @brief Returns true when any field is populated beyond defaults. */
                bool                                                HasAny() const noexcept;
                /** @brief Serializes into a JSON value object. */
                void                                                ToJson(Json::Value& json) const noexcept;
                /** @brief Serializes into compact JSON text. */
                ppp::string                                         ToJson() const noexcept;
                /** @brief Deserializes from JSON text. */
                static bool                                         FromJson(ClientIPv4Assignment& value, const ppp::string& json) noexcept;
                /** @brief Deserializes from a JSON value object. */
                static bool                                         FromJson(ClientIPv4Assignment& value, const Json::Value& json) noexcept;
            };

            /**
             * @brief One endpoint candidate advertised by the P2P coordinator.
             */
            struct P2PEndpointCandidate {
                ppp::string endpoint;   ///< Candidate endpoint in host:port form.
                ppp::string source;     ///< Candidate source, e.g. "observed" or "stun".

                void                                                Clear() noexcept;
                bool                                                HasAny() const noexcept;
                void                                                ToJson(Json::Value& json) const noexcept;
                static bool                                         FromJson(P2PEndpointCandidate& value, const Json::Value& json) noexcept;
            };

            /**
             * @brief Server-coordinated P2P control message carried in the INFO extension JSON.
             *
             * The message is intentionally control-plane only. Data packets still use the
             * existing NAT relay path until a direct UDP channel consumes these hints.
             */
            struct P2PControlMessage {
                bool                                                enabled = false;     ///< Sender has P2P enabled.
                ppp::string                                         mode;                ///< "relay" or "direct-preferred".
                ppp::string                                         action;              ///< "register", "offer", "reject", or "status".
                uint32_t                                            virtual_ip = 0;      ///< Sender virtual IPv4 in network byte order.
                uint32_t                                            peer_virtual_ip = 0; ///< Peer virtual IPv4 in network byte order.
                ppp::string                                         token;               ///< Short-lived coordinator token.
                ppp::string                                         authenticated_offer_v1; ///< Hex-encoded authenticated relay offer for this recipient.
                ppp::string                                         reason;              ///< Rejection or status reason.
                ppp::vector<P2PEndpointCandidate>                   candidates;          ///< Candidate endpoints for the peer.

                void                                                Clear() noexcept;
                bool                                                HasAny() const noexcept;
                void                                                ToJson(Json::Value& json) const noexcept;
                ppp::string                                         ToJson() const noexcept;
                static bool                                         FromJson(P2PControlMessage& value, const Json::Value& json) noexcept;
            };

            /** @brief Fixed v1 transport authentication control actions. */
            enum class TransportAuthAction : std::uint8_t {
                None = 0,
                Advertise = 1,
                Select = 2,
                Success = 3,
                Reject = 4,
            };

            /**
             * @brief Strict v1 carrier-authentication negotiation carried as trailing INFO JSON.
             *
             * An advertisement always carries the ordered method set and may also carry the
             * complete initiator message tuple. Selection carries the responder message tuple.
             * A success with a proof is the proving form; omitting proof is the server
             * acknowledgement form. Every non-reject action carries the same 16-byte attempt
             * token, encoded as 32 canonical lowercase hexadecimal characters. A reject may
             * omit the token when the attempt is not known.
             */
            struct TransportAuthControl {
                static constexpr std::uint8_t                        ProtocolVersion = 1;
                static constexpr std::size_t                         MaximumMethods = 4;
                static constexpr std::size_t                         MaximumMethodLength = 32;
                static constexpr std::size_t                         MaximumKeyIdLength = 63;
                static constexpr std::size_t                         MaximumTokenSize = 255;
                static constexpr std::size_t                         TokenHexLength = 32;
                static constexpr std::size_t                         MaximumMessageBytes = 128;
                static constexpr std::size_t                         MaximumReasonLength = 64;
                using Action = TransportAuthAction;

                std::uint8_t                                        version = ProtocolVersion;
                Action                                              action = Action::None;
                ppp::string                                         method;
                ppp::vector<ppp::string>                            methods;
                ppp::string                                         key_id;
                ppp::string                                         token;
                std::uint32_t                                       sequence = 0;
                ppp::string                                         message;
                ppp::string                                         proof;
                ppp::string                                         reason;

                void                                                Clear() noexcept;
                bool                                                HasAny() const noexcept;
                bool                                                Valid() const noexcept;
                void                                                ToJson(Json::Value& json) const noexcept;
                ppp::string                                         ToJson() const noexcept;
                static const char*                                  ActionToString(Action action) noexcept;
                static bool                                         ActionFromString(const ppp::string& text, Action& action) noexcept;
                static bool                                         FromJson(TransportAuthControl& value, const ppp::string& json) noexcept;
                static bool                                         FromJson(TransportAuthControl& value, const Json::Value& json) noexcept;
            };

            /** @brief Fixed v1 action codes used by JSON controls and authenticated transcripts. */
            enum class SessionResumeAction : std::uint8_t {
                None = 0,
                Offer = 1,
                Accepted = 2,
                ResumeRequest = 3,
                GenerationSync = 4,
                ResumeAccept = 5,
                ResumeConfirm = 6,
                ResumeCommitted = 7,
                Reject = 8,
            };

            /**
             * @brief Strictly versioned L3 roaming control carried as trailing INFO JSON.
             *
             * Byte strings use canonical lowercase hexadecimal. Generation is stored as
             * uint64_t in memory and serialized as a decimal string on the wire.
             */
            struct SessionResumeControl {
                static constexpr std::uint8_t                        ProtocolVersion = 1;
                static constexpr std::uint32_t                       CapabilityV1 = 1u << 0;
                static constexpr std::size_t                         MaximumReasonLength = 64;
                using Action = SessionResumeAction;

                std::uint8_t                                        version = ProtocolVersion;
                Action                                              action = Action::None;
                std::uint32_t                                       capabilities = 0;
                ppp::string                                         session_id;
                std::uint64_t                                       generation = 0;
                ppp::string                                         client_nonce;
                ppp::string                                         server_nonce;
                ppp::string                                         candidate_binding;
                ppp::string                                         proof;
                ppp::string                                         reason;

                void                                                Clear() noexcept;
                bool                                                HasAny() const noexcept;
                bool                                                Valid() const noexcept;
                void                                                ToJson(Json::Value& json) const noexcept;
                ppp::string                                         ToJson() const noexcept;
                static const char*                                  ActionToString(Action action) noexcept;
                static bool                                         ActionFromString(const ppp::string& text, Action& action) noexcept;
                static bool                                         FromJson(SessionResumeControl& value, const ppp::string& json) noexcept;
                static bool                                         FromJson(SessionResumeControl& value, const Json::Value& json) noexcept;
            };

            /**
             * @brief Holds optional IPv6 assignment and status extensions for a session.
             */
            struct VirtualEthernetInformationExtensions {
                /** @brief IPv6 allocation mode indicators.
                 *
                 * Determines how the server assigns an IPv6 address to the client.
                 */
                enum IPv6Mode {
                    IPv6Mode_None                                      = 0,   ///< IPv6 is not assigned; client uses IPv4 only.
                    IPv6Mode_Nat66                                     = 1,   ///< NAT66 transparent translation of a ULA prefix.
                    IPv6Mode_Gua                                       = 2,   ///< Globally Unique Address assigned via prefix delegation.
                };

                /** @brief Bit flags for IPv6 behavior controls.
                 *
                 * Multiple flags may be OR-combined to enable distinct IPv6 behaviors
                 * on the assigned prefix.
                 */
                enum IPv6Flags {
                    IPv6Flag_None                                      = 0,        ///< No special IPv6 behavior flags are set.
                    IPv6Flag_NeighborProxy                             = 1 << 0,   ///< Enable NDP neighbor proxy for the assigned prefix.
                };

                /** @brief Selected IPv6 mode for this session. */
                Byte                                                AssignedIPv6Mode = IPv6Mode_None;
                /** @brief Prefix length for assigned IPv6 address. */
                Byte                                                AssignedIPv6AddressPrefixLength = 0;
                /** @brief IPv6 feature flags for this assignment. */
                Byte                                                AssignedIPv6Flags = 0;
                /** @brief Assigned client IPv6 address. */
                boost::asio::ip::address                            AssignedIPv6Address;
                /** @brief Assigned IPv6 gateway address. */
                boost::asio::ip::address                            AssignedIPv6Gateway;
                /** @brief Assigned routed IPv6 prefix address. */
                boost::asio::ip::address                            AssignedIPv6RoutePrefix;
                /** @brief Prefix length of routed IPv6 prefix. */
                Byte                                                AssignedIPv6RoutePrefixLength = 0;
                /** @brief Primary assigned IPv6 DNS server. */
                boost::asio::ip::address                            AssignedIPv6Dns1;
                /** @brief Secondary assigned IPv6 DNS server. */
                boost::asio::ip::address                            AssignedIPv6Dns2;
                /** @brief IPv6 provisioning status code. */
                Byte                                                IPv6StatusCode = 0;
                /** @brief IPv6 address requested by the client. */
                boost::asio::ip::address                            RequestedIPv6Address;
                /** @brief Human-readable IPv6 status message. */
                ppp::string                                         IPv6StatusMessage;
                /**
                 * @brief Client exit IP observed by the server.
                 *
                 * Populated by the server from `transmission->GetRemoteEndPoint()`
                 * during session establishment.  The client reads this value as
                 * priority-2 source for EDNS Client Subnet (ECS) override IP.
                 * Accepts both IPv4 and IPv6.
                 */
                boost::asio::ip::address                            ClientExitIP;

                /** @brief Client IPv4 address request sent to the server.
                 *
                 * Populated by the client during handshake to request either
                 * automatic ("auto") or manual ("manual") IPv4 assignment.
                 * Transmitted inside the INFORMATION envelope as JSON key
                 * "client-ipv4-request".  Absent when the client does not
                 * request an IPv4 address from the server.
                 */
                ClientIPv4Request                                   ClientIPv4Req;

                /** @brief Server IPv4 assignment response for the client.
                 *
                 * Returned by the server in the INFORMATION envelope so
                 * the client can determine the outcome of its IPv4 request.
                 * Transmitted as JSON key "client-ipv4".  Absent when the
                 * server did not process an IPv4 request.
                 */
                ClientIPv4Assignment                                ClientIPv4Assign;

                /** @brief Optional P2P control-plane message. */
                P2PControlMessage                                   P2P;

                /** @brief Optional carrier authentication negotiation control. */
                TransportAuthControl                                TransportAuth;

                /** @brief Optional authenticated L3 roaming control. */
                SessionResumeControl                                SessionResume;

                /** @brief Client prefix announcement for site-to-site gateway routing. */
                PeerRouteAnnounceMessage                            PeerRouteAnnounce;

                /** @brief Server prefix routing snapshot for clients. */
                PeerRouteTableMessage                               PeerRouteTable;

                /** @brief Detailed IPv6 provisioning outcomes.
                 *
                 * Returned by the server in the INFO envelope so the client can
                 * determine whether its IPv6 address request was honoured and, if
                 * not, the exact reason for the failure.
                 */
                enum IPv6Status {
                    IPv6Status_None                                 = 0,   ///< No IPv6 provisioning was attempted.
                    IPv6Status_Applied                              = 1,   ///< Client's requested IPv6 address was accepted and applied.
                    IPv6Status_ServerAssigned                       = 2,   ///< Server picked and assigned an IPv6 address (client had no preference).
                    IPv6Status_ClientRequested                      = 3,   ///< Server accepted the client's explicit IPv6 address request.
                    IPv6Status_UnsupportedClient                    = 4,   ///< Client does not support IPv6; provisioning skipped.
                    IPv6Status_Rejected                             = 5,   ///< Server rejected the client's IPv6 request by policy.
                    IPv6Status_Failed                               = 6,   ///< IPv6 provisioning attempted but failed due to an internal error.
                };

                /** @brief Resets all extension fields to defaults. */
                void                                                Clear() noexcept;
                /** @brief Returns true when any extension field is populated. */
                bool                                                HasAny() const noexcept;
                /** @brief Serializes extensions into a JSON value object. */
                void                                                ToJson(Json::Value& json) const noexcept;
                /** @brief Serializes extensions into compact JSON text. */
                ppp::string                                         ToJson() const noexcept;
                /** @brief Deserializes extensions from JSON text. */
                static bool                                         FromJson(VirtualEthernetInformationExtensions& value, const ppp::string& json) noexcept;
                /** @brief Deserializes extensions from a JSON value object. */
                static bool                                         FromJson(VirtualEthernetInformationExtensions& value, const Json::Value& json) noexcept;
            };

        }
    }
}

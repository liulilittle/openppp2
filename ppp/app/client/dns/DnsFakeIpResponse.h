#pragma once

/**
 * @file DnsFakeIpResponse.h
 * @brief Synthetic DNS responses for fake-ip mode.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                class DnsFakeIpResponse final {
                public:
                    enum class AQueryStatus {
                        Supported,
                        Invalid,
                        Unsupported
                    };

                    /** @brief Returns false for reverse/local/special names. */
                    static bool ShouldUseFakeIp(const ppp::string& hostname_lower) noexcept;

                    /** @brief Builds a DNS A response with @p fake_ip_host (host order). */
                    static ppp::vector<Byte> BuildARecordResponse(
                        const Byte* query_packet,
                        int query_length,
                        uint32_t fake_ip_host) noexcept;

                    /** @brief Validates a policy-v2 A query, including its optional EDNS OPT. */
                    static AQueryStatus InspectAQueryV2(
                        const Byte* query_packet,
                        int query_length) noexcept;

                    /** @brief Builds a structurally re-encoded policy-v2 A response. */
                    static ppp::vector<Byte> BuildARecordResponseV2(
                        const Byte* query_packet,
                        int query_length,
                        uint32_t fake_ip_host) noexcept;

                    /** @brief Extracts the first A-record from a DNS response (network byte order). */
                    static uint32_t ParseFirstARecordNetwork(
                        const Byte* response,
                        int response_length) noexcept;
                };

            }
        }
    }
}

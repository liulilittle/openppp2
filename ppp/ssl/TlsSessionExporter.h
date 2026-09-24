#pragma once

#include <cstddef>
#include <cstdint>

struct ssl_st;

namespace ppp::ssl {
    bool IsTlsSessionExporterAvailable(::ssl_st* ssl) noexcept;

    bool IsAuthenticatedTlsSessionExporterAvailable(
        bool application_handshake_complete,
        ::ssl_st* ssl) noexcept;

    bool ExportTlsSessionKey(
        ::ssl_st* ssl,
        const char* label,
        const std::uint8_t* context,
        std::size_t context_length,
        std::uint8_t* output,
        std::size_t output_length) noexcept;

    bool ExportAuthenticatedTlsSessionKey(
        bool application_handshake_complete,
        ::ssl_st* ssl,
        const char* label,
        const std::uint8_t* context,
        std::size_t context_length,
        std::uint8_t* output,
        std::size_t output_length) noexcept;
}

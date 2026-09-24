#include <ppp/ssl/TlsSessionExporter.h>

#include <openssl/ssl.h>

#include <cstring>

namespace ppp::ssl {
    bool IsTlsSessionExporterAvailable(::ssl_st* ssl) noexcept {
        return ssl != nullptr && SSL_is_init_finished(ssl) == 1 && SSL_get_session(ssl) != nullptr;
    }

    bool IsAuthenticatedTlsSessionExporterAvailable(
        bool application_handshake_complete,
        ::ssl_st* ssl) noexcept {
        return application_handshake_complete && IsTlsSessionExporterAvailable(ssl);
    }

    bool ExportTlsSessionKey(
        ::ssl_st* ssl,
        const char* label,
        const std::uint8_t* context,
        std::size_t context_length,
        std::uint8_t* output,
        std::size_t output_length) noexcept {
        if (!IsTlsSessionExporterAvailable(ssl) || label == nullptr || label[0] == '\0' ||
            ((context == nullptr) != (context_length == 0)) ||
            output == nullptr || output_length == 0) {
            return false;
        }

        return SSL_export_keying_material(
            ssl,
            output,
            output_length,
            label,
            std::strlen(label),
            context,
            context_length,
            context_length == 0 ? 0 : 1) == 1;
    }

    bool ExportAuthenticatedTlsSessionKey(
        bool application_handshake_complete,
        ::ssl_st* ssl,
        const char* label,
        const std::uint8_t* context,
        std::size_t context_length,
        std::uint8_t* output,
        std::size_t output_length) noexcept {
        if (!IsAuthenticatedTlsSessionExporterAvailable(application_handshake_complete, ssl)) {
            return false;
        }

        return ExportTlsSessionKey(
            ssl, label, context, context_length, output, output_length);
    }
}

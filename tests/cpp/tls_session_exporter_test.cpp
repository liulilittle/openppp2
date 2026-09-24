#define BOOST_TEST_MODULE tls_session_exporter_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/ssl/TlsSessionExporter.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <array>
#include <memory>
#include <string>

namespace {
using SslContextPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SslPtr = std::unique_ptr<SSL, decltype(&SSL_free)>;

struct TlsPair {
    SslContextPtr client_context{nullptr, SSL_CTX_free};
    SslContextPtr server_context{nullptr, SSL_CTX_free};
    SslPtr client{nullptr, SSL_free};
    SslPtr server{nullptr, SSL_free};
};

TlsPair MakeTlsPair() {
    TlsPair pair;
    pair.client_context.reset(SSL_CTX_new(TLS_method()));
    pair.server_context.reset(SSL_CTX_new(TLS_method()));
    BOOST_REQUIRE(pair.client_context);
    BOOST_REQUIRE(pair.server_context);

    BOOST_REQUIRE_EQUAL(
        SSL_CTX_use_certificate_file(pair.server_context.get(), OPENPPP2_TEST_CERTIFICATE, SSL_FILETYPE_PEM),
        1);
    BOOST_REQUIRE_EQUAL(
        SSL_CTX_use_PrivateKey_file(pair.server_context.get(), OPENPPP2_TEST_PRIVATE_KEY, SSL_FILETYPE_PEM),
        1);
    BOOST_REQUIRE_EQUAL(SSL_CTX_check_private_key(pair.server_context.get()), 1);
    SSL_CTX_set_verify(pair.client_context.get(), SSL_VERIFY_NONE, nullptr);

    pair.client.reset(SSL_new(pair.client_context.get()));
    pair.server.reset(SSL_new(pair.server_context.get()));
    BOOST_REQUIRE(pair.client);
    BOOST_REQUIRE(pair.server);

    BIO* client_bio = nullptr;
    BIO* server_bio = nullptr;
    BOOST_REQUIRE_EQUAL(BIO_new_bio_pair(&client_bio, 0, &server_bio, 0), 1);
    SSL_set_bio(pair.client.get(), client_bio, client_bio);
    SSL_set_bio(pair.server.get(), server_bio, server_bio);
    SSL_set_connect_state(pair.client.get());
    SSL_set_accept_state(pair.server.get());
    return pair;
}

void CompleteHandshake(TlsPair& pair) {
    bool client_done = false;
    bool server_done = false;
    for (int attempts = 0; attempts < 1000 && (!client_done || !server_done); ++attempts) {
        if (!client_done) {
            const int result = SSL_do_handshake(pair.client.get());
            client_done = result == 1;
            if (!client_done) {
                const int error = SSL_get_error(pair.client.get(), result);
                BOOST_REQUIRE(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
            }
        }
        if (!server_done) {
            const int result = SSL_do_handshake(pair.server.get());
            server_done = result == 1;
            if (!server_done) {
                const int error = SSL_get_error(pair.server.get(), result);
                BOOST_REQUIRE(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
            }
        }
    }
    BOOST_REQUIRE(client_done);
    BOOST_REQUIRE(server_done);
}
}

BOOST_AUTO_TEST_CASE(exporter_is_unavailable_before_tls_handshake) {
    auto pair = MakeTlsPair();
    BOOST_TEST(!ppp::ssl::IsTlsSessionExporterAvailable(pair.client.get()));
    BOOST_TEST(!ppp::ssl::IsTlsSessionExporterAvailable(pair.server.get()));
}

BOOST_AUTO_TEST_CASE(peers_export_identical_session_bound_material) {
    auto pair = MakeTlsPair();
    CompleteHandshake(pair);
    const std::array<std::uint8_t, 5> context{{1, 3, 5, 7, 9}};
    std::array<std::uint8_t, 32> client_output{};
    std::array<std::uint8_t, 32> server_output{};

    BOOST_REQUIRE(ppp::ssl::IsTlsSessionExporterAvailable(pair.client.get()));
    BOOST_REQUIRE(ppp::ssl::IsTlsSessionExporterAvailable(pair.server.get()));
    BOOST_REQUIRE(ppp::ssl::ExportTlsSessionKey(pair.client.get(), "EXPORTER-OpenPPP2-P2P-v1",
        context.data(), context.size(), client_output.data(), client_output.size()));
    BOOST_REQUIRE(ppp::ssl::ExportTlsSessionKey(pair.server.get(), "EXPORTER-OpenPPP2-P2P-v1",
        context.data(), context.size(), server_output.data(), server_output.size()));
    BOOST_TEST(client_output == server_output);
}

BOOST_AUTO_TEST_CASE(exporter_context_is_domain_separated) {
    auto pair = MakeTlsPair();
    CompleteHandshake(pair);
    const std::array<std::uint8_t, 2> first_context{{0x10, 0x20}};
    const std::array<std::uint8_t, 2> second_context{{0x10, 0x21}};
    std::array<std::uint8_t, 32> first{};
    std::array<std::uint8_t, 32> second{};

    BOOST_REQUIRE(ppp::ssl::ExportTlsSessionKey(pair.client.get(), "EXPORTER-OpenPPP2-P2P-v1",
        first_context.data(), first_context.size(), first.data(), first.size()));
    BOOST_REQUIRE(ppp::ssl::ExportTlsSessionKey(pair.client.get(), "EXPORTER-OpenPPP2-P2P-v1",
        second_context.data(), second_context.size(), second.data(), second.size()));
    BOOST_TEST(first != second);
}

BOOST_AUTO_TEST_CASE(authenticated_exporter_requires_application_handshake) {
    auto pair = MakeTlsPair();
    CompleteHandshake(pair);
    const std::array<std::uint8_t, 3> context{{4, 5, 6}};
    std::array<std::uint8_t, 32> output{};

    BOOST_TEST(!ppp::ssl::IsAuthenticatedTlsSessionExporterAvailable(false, pair.client.get()));
    BOOST_TEST(!ppp::ssl::ExportAuthenticatedTlsSessionKey(false, pair.client.get(),
        "EXPORTER-OpenPPP2-P2P-v1", context.data(), context.size(), output.data(), output.size()));
    BOOST_TEST(ppp::ssl::IsAuthenticatedTlsSessionExporterAvailable(true, pair.client.get()));
    BOOST_TEST(ppp::ssl::ExportAuthenticatedTlsSessionKey(true, pair.client.get(),
        "EXPORTER-OpenPPP2-P2P-v1", context.data(), context.size(), output.data(), output.size()));
}

BOOST_AUTO_TEST_CASE(invalid_arguments_fail_closed) {
    auto pair = MakeTlsPair();
    CompleteHandshake(pair);
    std::array<std::uint8_t, 32> output{};
    const std::array<std::uint8_t, 1> context{{1}};

    BOOST_TEST(!ppp::ssl::ExportTlsSessionKey(nullptr, "label", nullptr, 0, output.data(), output.size()));
    BOOST_TEST(!ppp::ssl::ExportTlsSessionKey(pair.client.get(), nullptr, nullptr, 0, output.data(), output.size()));
    BOOST_TEST(!ppp::ssl::ExportTlsSessionKey(pair.client.get(), "", nullptr, 0, output.data(), output.size()));
    BOOST_TEST(!ppp::ssl::ExportTlsSessionKey(pair.client.get(), "label", nullptr, context.size(), output.data(), output.size()));
    BOOST_TEST(!ppp::ssl::ExportTlsSessionKey(pair.client.get(), "label", context.data(), 0, output.data(), output.size()));
    BOOST_TEST(!ppp::ssl::ExportTlsSessionKey(pair.client.get(), "label", context.data(), context.size(), nullptr, output.size()));
    BOOST_TEST(!ppp::ssl::ExportTlsSessionKey(pair.client.get(), "label", context.data(), context.size(), output.data(), 0));
}

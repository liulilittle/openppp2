#pragma once

/**
 * @file WebSocket.h
 * @brief Generic Beast websocket handshake helper for client/server flows.
 */

#include <ppp/stdafx.h>
#include <ppp/IDisposable.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/YieldContext.h>
#include <sstream>

namespace ppp {
    namespace net {
        namespace asio {
                namespace templates {
                namespace websocket {
                    /** @brief Beast dynamic HTTP body type used during websocket handshake. */
                    typedef boost::beast::http::dynamic_body                    dynamic_body;
                    /** @brief HTTP request type used to read upgrade requests on server side. */
                    typedef boost::beast::http::request<dynamic_body>           http_request;

                    /**
                     * @brief Validates whether a requested URL path matches the configured websocket root.
                     * @param root Expected root path.
                     * @param sw Request target from HTTP upgrade request.
                     * @return True when the request path is accepted.
                     */
                    bool                                                        CheckRequestPath(ppp::string& root, const boost::beast::string_view& sw) noexcept;
                    /**
                     * @brief Extracts untrusted claimed IP text from proxy headers, for diagnostics only.
                     * @param req HTTP upgrade request.
                     * @return Parsed client address string, or empty string if unavailable.
                     */
                    ppp::string                                                 GetAddressString(http_request& req) noexcept;
                }

                /**
                 * @brief Generic websocket handshake runner for both client and server roles.
                 * @tparam T Beast websocket stream type.
                 */
                template <class T>
                class WebSocket : public IDisposable {
                public:
                    typedef ppp::net::IPEndPoint                                IPEndPoint;
                    typedef ppp::coroutines::YieldContext                       YieldContext;
                    typedef ppp::net::asio::templates::websocket::dynamic_body  dynamic_body;
                    typedef ppp::net::asio::templates::websocket::http_request  http_request;

                public:
                    /**
                     * @brief Constructs a handshake helper bound to an existing websocket stream.
                     * @param websocket Underlying websocket stream.
                     * @param binary Whether websocket frames use binary mode.
                     * @param host Host used for client handshake.
                     * @param path Expected websocket path.
                     */
                    WebSocket(
                        T&                                                      websocket,
                        bool                                                    binary,
                        const ppp::string&                                      host,
                        const ppp::string&                                      path) noexcept
                        : host_(host)
                        , path_(path)
                        , websocket_(websocket) {
                        websocket_.binary(binary);
                    }
                    virtual ~WebSocket()                                        noexcept = default;

                protected:
                    /** @brief Stores remote address text extracted from request headers. */
                    virtual void                                                SetAddressString(const ppp::string& address) noexcept = 0;
                    /** @brief Customizes outbound client handshake request headers. */
                    virtual void                                                Decorator(boost::beast::websocket::request_type& req) noexcept {}
                    /** @brief Customizes outbound server handshake response headers. */
                    virtual void                                                Decorator(boost::beast::websocket::response_type& res) noexcept {
                        res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
                    }

                public:
                    /**
                     * @brief Executes websocket handshake as client or server.
                     * @param handshaked_client True for client-side handshake, false for server-side upgrade handling.
                     * @param y Coroutine yield context used by async operations.
                     * @return True when handshake succeeds.
                     */
                    bool                                                        Run(bool handshaked_client, YieldContext& y) noexcept {
                        if (host_.empty() || path_.empty()) {
                            return false;
                        }

                        bool ok = false;
                        const std::shared_ptr<Reference> reference = GetReference();
                        if (handshaked_client) {
                            // Declare a container to hold the request.
                            websocket_.set_option(boost::beast::websocket::stream_base::decorator(
                                [this](boost::beast::websocket::request_type& req) noexcept {
                                    Decorator(req);
                                }));
                    
                            // Handshake with the websocket server.
                            const YieldContext::Anchor anchor = y.Arm();
                            if (!anchor) {
                                return false;
                            }

                            websocket_.async_handshake(host_, path_,
                                [reference, this, &ok, anchor](const boost::system::error_code& ec) noexcept {
                                    ok = ec == boost::system::errc::success;
                                    anchor.R();
                                });
                            y.Suspend(anchor);
                        }
                        else {
                            // This buffer is used for reading and must be persisted.
                            std::shared_ptr<boost::beast::flat_buffer> buffer = make_shared_object<boost::beast::flat_buffer>();
                            if (NULLPTR == buffer) {
                                return false;
                            }

                            // Declare a container to hold the response.
                            std::shared_ptr<http_request> req = make_shared_object<http_request>();
                            if (NULLPTR == req) {
                                return false;
                            }

                            // Receive the HTTP response.
                            const YieldContext::Anchor read_anchor = y.Arm();
                            if (!read_anchor) {
                                return false;
                            }

                            boost::beast::http::async_read(websocket_.next_layer(), *buffer, *req,
                                [reference, this, buffer, req, &ok, read_anchor](boost::system::error_code ec, std::size_t sz) noexcept {
                                    ok = ec == boost::system::errc::success;
                                    read_anchor.R();
                                });
                            y.Suspend(read_anchor);

                            // Receive the HTTP response is do OK.
                            if (ok) {
                                /**
                                 * @brief Server-side upgrade acceptance flow.
                                 *
                                 * Verifies the request path, emits a 404 response when rejected,
                                 * and on success completes async_accept then records proxied client IP.
                                 */
                                // Set suggested timeout settings for the websocket.
                                websocket_.set_option(
                                    boost::beast::websocket::stream_base::timeout::suggested(
                                        boost::beast::role_type::server));

                                // Set a decorator to change the Server of the handshake.
                                websocket_.set_option(boost::beast::websocket::stream_base::decorator(
                                    [this](boost::beast::websocket::response_type& res) noexcept {
                                        Decorator(res);
                                    }));

                                // The websocket async-accept is completed.
                                ok = ppp::net::asio::templates::websocket::CheckRequestPath(path_, req->target());
                                if (ok) {
                                    const YieldContext::Anchor accept_anchor = y.Arm();
                                    if (!accept_anchor) {
                                        return false;
                                    }

                                    // Replay the validated HTTP request together with over-read frames.
                                    // Beast's buffered accept retains bytes beyond the HTTP upgrade.
                                    std::ostringstream serialized;
                                    serialized << *req;
                                    auto prefill = std::make_shared<std::string>(serialized.str());
                                    prefill->append(boost::beast::buffers_to_string(buffer->data()));
                                    auto accepted = [reference, this, req, prefill, &ok, accept_anchor](const boost::system::error_code& ec) noexcept {
                                            ok = ec == boost::system::errc::success;
                                            accept_anchor.R();
                                        };
                                    if (buffer->size() == 0) {
                                        websocket_.async_accept(*req, std::move(accepted));
                                    }
                                    else {
                                        websocket_.async_accept(boost::asio::buffer(*prefill), std::move(accepted));
                                    }
                                    y.Suspend(accept_anchor);
                                }
                                else {
                                    // Path check failed, send HTTP 404 response.
                                    boost::beast::http::response<boost::beast::http::string_body> response(boost::beast::http::status::not_found/*404*/, req->version());
                                    response.set(boost::beast::http::field::content_type, "text/plain");
                                    Decorator(response);

                                    // If the Decorator callback is executed but the upper-level program does not set a server, then by default, set a server name.
                                    if (!response.count(boost::beast::http::field::server)) {
                                        response.set(boost::beast::http::field::server, boost::beast::string_view(BOOST_BEAST_VERSION_STRING));
                                    }

                                    // If the Decorator callback is executed but the upper-level program does not set a response content, then by default, set a response content of "404 Not Found".
                                    std::string& response_body = response.body();
                                    if (response_body.empty()) {
                                        response_body = "404 Not Found";
                                    }

                                    // Encapsulate the HTTP protocol packet into binary and then send the protocol packet to the HTTP client.
                                    response.prepare_payload();

                                    // Reject the HTTP client's request with a 404 Not Found response.
                                    const YieldContext::Anchor reject_anchor = y.Arm();
                                    if (!reject_anchor) {
                                        return false;
                                    }

                                    boost::beast::http::async_write(websocket_.next_layer(), response,
                                        [this, reject_anchor](const boost::system::error_code& ec, std::size_t) {
                                            reject_anchor.R();
                                        });
                                    y.Suspend(reject_anchor);
                                }

                                // Extract the Remote IP EndPoint from an HTTP request.
                                if (ok) {
                                    SetAddressString(ppp::net::asio::templates::websocket::GetAddressString(*req));
                                }
                            }
                        }
                        return ok;
                    }

                private:
                    ppp::string                                                 host_;
                    ppp::string                                                 path_;
                    T&                                                          websocket_;
                };
            }
        }
    }
}

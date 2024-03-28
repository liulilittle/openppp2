#pragma once

#include <ppp/stdafx.h>
#include <ppp/IDisposable.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace net {
        namespace asio {
            namespace templates {
                namespace websocket {
                    typedef boost::beast::http::dynamic_body                    dynamic_body;
                    typedef boost::beast::http::request<dynamic_body>           http_request;

                    bool                                                        CheckRequestPath(ppp::string& root, const boost::beast::string_view& sw) noexcept;
                    ppp::string                                                 GetAddressString(http_request& req) noexcept;
                }

                template <class T>
                class WebSocket : public IDisposable {
                public:
                    typedef ppp::net::IPEndPoint                                IPEndPoint;
                    typedef ppp::coroutines::YieldContext                       YieldContext;
                    typedef ppp::net::asio::templates::websocket::dynamic_body  dynamic_body;
                    typedef ppp::net::asio::templates::websocket::http_request  http_request;

                public:
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
                    virtual ~WebSocket() noexcept = default;

                protected:
                    virtual void                                                SetAddressString(const ppp::string& address) noexcept = 0;
                    virtual void                                                Decorator(boost::beast::websocket::request_type& req) noexcept {}
                    virtual void                                                Decorator(boost::beast::websocket::response_type& res) noexcept {
                        res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
                    }

                public:
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
                            websocket_.async_handshake(host_, path_,
                                [reference, this, &ok, &y](const boost::system::error_code& ec) noexcept {
                                    auto& context = y.GetContext();
                                    ok = ec == boost::system::errc::success;
                                    context.dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, y.GetPtr()));
                                });
                            y.Suspend();
                        }
                        else {
                            // This buffer is used for reading and must be persisted.
                            std::shared_ptr<boost::beast::flat_buffer> buffer = make_shared_object<boost::beast::flat_buffer>();
                            if (NULL == buffer) {
                                return false;
                            }

                            // Declare a container to hold the response.
                            std::shared_ptr<http_request> req = make_shared_object<http_request>();
                            if (NULL == req) {
                                return false;
                            }

                            // Receive the HTTP response.
                            boost::beast::http::async_read(websocket_.next_layer(), *buffer, *req,
                                [reference, this, buffer, req, &ok, &y](boost::system::error_code ec, std::size_t sz) noexcept {
                                    auto& context = y.GetContext();
                                    ok = ec == boost::system::errc::success;
                                    context.dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, y.GetPtr()));
                                });
                            y.Suspend();

                            // Receive the HTTP response is do OK.
                            if (ok) {
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
                                    websocket_.async_accept(*req,
                                        [reference, this, req, &ok, &y](const boost::system::error_code& ec) noexcept {
                                            auto& context = y.GetContext();
                                            ok = ec == boost::system::errc::success;
                                            context.dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, y.GetPtr()));
                                        });
                                    y.Suspend();
                                }
                                else {
                                    // Path check failed, send HTTP 404 response
                                    boost::beast::http::response<boost::beast::http::string_body> response(boost::beast::http::status::not_found, req->version());
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
                                    boost::beast::http::async_write(websocket_.next_layer(), response,
                                        [this, &y](const boost::system::error_code& ec, std::size_t) {
                                            auto& context = y.GetContext();
                                            context.dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, y.GetPtr()));
                                        });
                                    y.Suspend();
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
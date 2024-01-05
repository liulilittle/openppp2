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

                template<class T>
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

                public:
                    bool                                                        Run(bool handshaked_client, YieldContext& y) noexcept {
                        if (host_.empty() || path_.empty()) {
                            return false;
                        }

                        bool ok = false;
                        YieldContext* p = y.GetPtr();
                        const std::shared_ptr<Reference> reference = GetReference();
                        if (handshaked_client) {
                            websocket_.async_handshake(host_, path_,
                                [reference, this, &ok, p](const boost::system::error_code& ec) noexcept {
                                    ok = ec == boost::system::errc::success;
                                    p->GetContext().dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, p));
                                });
                            y.Suspend();
                        }
                        else {
                            // This buffer is used for reading and must be persisted.
                            std::shared_ptr<boost::beast::flat_buffer> buffer = make_shared_object<boost::beast::flat_buffer>();

                            // Declare a container to hold the response.
                            std::shared_ptr<http_request> req = make_shared_object<http_request>();

                            // Receive the HTTP response.
                            boost::beast::http::async_read(websocket_.next_layer(), *buffer, *req,
                                [reference, this, buffer, req, &ok, p](boost::system::error_code ec, std::size_t sz) noexcept {
                                    ok = ec == boost::system::errc::success;
                                    p->GetContext().dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, p));
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
                                    [](boost::beast::websocket::response_type& res) noexcept {
                                        res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
                                    }));

                                // The websocket async-accept is completed.
                                ok = ppp::net::asio::templates::websocket::CheckRequestPath(path_, req->target());
                                if (ok) {
                                    websocket_.async_accept(*req,
                                        [reference, this, req, &ok, p](const boost::system::error_code& ec) noexcept {
                                            ok = ec == boost::system::errc::success;
                                            p->GetContext().dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, p));
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
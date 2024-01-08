#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/SocketAcceptor.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITransmission.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace http {
                class VEthernetHttpProxyConnection;

                class VEthernetHttpProxySwitcher : public std::enable_shared_from_this<VEthernetHttpProxySwitcher> {
                    typedef std::shared_ptr<VEthernetHttpProxyConnection>               VEthernetHttpProxyConnectionPtr;
                    typedef ppp::unordered_map<void*, VEthernetHttpProxyConnectionPtr>  VEthernetHttpProxyConnectionTable;

                    friend class VEthernetHttpProxyConnection;

                public:
                    VEthernetHttpProxySwitcher(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;
                    virtual ~VEthernetHttpProxySwitcher() noexcept;

                public:
                    std::shared_ptr<boost::asio::io_context>                            GetContext() noexcept;
                    std::shared_ptr<ppp::configurations::AppConfiguration>              GetConfiguration() noexcept;
                    std::shared_ptr<VEthernetExchanger>                                 GetExchanger() noexcept;
                    std::shared_ptr<ppp::threading::BufferswapAllocator>                GetBufferAllocator() noexcept;
                    boost::asio::ip::tcp::endpoint                                      GetLocalEndPoint() noexcept;
                    virtual bool                                                        Open() noexcept;
                    virtual void                                                        Dispose() noexcept;

                protected:
                    virtual void                                                        Update(UInt64 now) noexcept;
                    virtual std::shared_ptr<VEthernetHttpProxyConnection>               NewConnection(const std::shared_ptr<boost::asio::io_context>& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;

                private:
                    void                                                                Finalize() noexcept;
                    bool                                                                CreateAlwaysTimeout() noexcept;
                    bool                                                                ProcessAcceptSocket(const std::shared_ptr<boost::asio::io_context>& context, int sockfd) noexcept;
                    void                                                                ReleaseConnection(VEthernetHttpProxyConnection* connection) noexcept;
                    std::shared_ptr<boost::asio::ip::tcp::socket>                       NewSocket(const std::shared_ptr<boost::asio::io_context>& context, int sockfd) noexcept;

                private:
                    bool                                                                disposed_;
                    std::shared_ptr<VEthernetExchanger>                                 exchanger_;
                    std::shared_ptr<ppp::net::SocketAcceptor>                           acceptor_;
                    std::shared_ptr<boost::asio::io_context>                            context_;
                    std::shared_ptr<ppp::configurations::AppConfiguration>              configuration_;
                    std::shared_ptr<ppp::threading::Timer>                              timeout_;
                    VEthernetHttpProxyConnectionTable                                   connections_;
                };
            }
        }
    }
}
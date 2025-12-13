#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/SocketAcceptor.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace proxys {
                class VEthernetLocalProxyConnection;

                class VEthernetLocalProxySwitcher : public std::enable_shared_from_this<VEthernetLocalProxySwitcher> {
                    friend class                                                        VEthernetLocalProxyConnection;

                private:
                    typedef std::shared_ptr<VEthernetLocalProxyConnection>              VEthernetLocalProxyConnectionPtr;
                    typedef ppp::unordered_map<void*, VEthernetLocalProxyConnectionPtr> VEthernetLocalProxyConnectionTable;
                    typedef std::mutex                                                  SynchronizedObject;
                    typedef std::lock_guard<SynchronizedObject>                         SynchronizedObjectScope;

                public:
                    VEthernetLocalProxySwitcher(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;
                    virtual ~VEthernetLocalProxySwitcher() noexcept;

                public:
                    std::shared_ptr<boost::asio::io_context>&                           GetContext()         noexcept { return context_; }
                    std::shared_ptr<ppp::configurations::AppConfiguration>&             GetConfiguration()   noexcept { return configuration_; }
                    std::shared_ptr<VEthernetExchanger>&                                GetExchanger()       noexcept { return exchanger_; }
                    std::shared_ptr<ppp::threading::BufferswapAllocator>                GetBufferAllocator() noexcept;
                    boost::asio::ip::tcp::endpoint                                      GetLocalEndPoint()   noexcept;
                    virtual bool                                                        Open()               noexcept;
                    virtual void                                                        Dispose()            noexcept;

                protected:
                    virtual boost::asio::ip::address                                    MyLocalEndPoint(int& bind_port) noexcept = 0;
                    virtual void                                                        Update(UInt64 now) noexcept;
                    virtual std::shared_ptr<VEthernetLocalProxyConnection>              NewConnection(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept = 0;

                private:
                    void                                                                Finalize() noexcept;
                    bool                                                                CreateAlwaysTimeout() noexcept;
                    bool                                                                ProcessAcceptSocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, int sockfd) noexcept;
                    void                                                                ReleaseConnection(VEthernetLocalProxyConnection* connection) noexcept;
                    bool                                                                AddConnection(const std::shared_ptr<VEthernetLocalProxyConnection>& connection) noexcept;
                    bool                                                                RemoveConnection(VEthernetLocalProxyConnection* connection) noexcept;
                    std::shared_ptr<boost::asio::ip::tcp::socket>                       NewSocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, int sockfd) noexcept;

                private:
                    SynchronizedObject                                                  syncobj_;
                    bool                                                                disposed_ = false;
                    std::shared_ptr<VEthernetExchanger>                                 exchanger_;
                    std::shared_ptr<ppp::net::SocketAcceptor>                           acceptor_;
                    std::shared_ptr<boost::asio::io_context>                            context_;
                    std::shared_ptr<ppp::configurations::AppConfiguration>              configuration_;
                    std::shared_ptr<ppp::threading::Timer>                              timeout_;
                    VEthernetLocalProxyConnectionTable                                  connections_;
                };
            }
        }
    }
}
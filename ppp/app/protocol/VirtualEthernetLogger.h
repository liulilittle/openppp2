#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace app {
        namespace protocol {
            class VirtualEthernetLogger : public std::enable_shared_from_this<VirtualEthernetLogger> {
            public:
                VirtualEthernetLogger(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& log_path) noexcept;
                virtual ~VirtualEthernetLogger() noexcept;

            public:
                std::shared_ptr<ppp::threading::BufferswapAllocator>            BufferAllocator;

            public:
                std::shared_ptr<boost::asio::io_context>                        GetContext() noexcept;
                ppp::string                                                     GetPath() noexcept;
                std::shared_ptr<VirtualEthernetLogger>                          GetReference() noexcept;
                bool                                                            Valid() noexcept;
                virtual void                                                    Dispose() noexcept;

            public:
                bool                                                            Vpn(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission) noexcept;
                bool                                                            Dns(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const ppp::string& hostDomain) noexcept;
                bool                                                            Arp(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, uint32_t ip, uint32_t mask) noexcept;
                bool                                                            Arp(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::address& ip, const boost::asio::ip::address& mask) noexcept;
                bool                                                            Port(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::udp::endpoint& inEP, const boost::asio::ip::udp::endpoint& natEP) noexcept;
                bool                                                            Connect(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::tcp::endpoint& natEP, const boost::asio::ip::tcp::endpoint& dstEP, const ppp::string& hostDomain) noexcept;

            public:
                bool                                                            MPEntry(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::tcp::endpoint& publicEP, bool protocol_tcp_or_udp) noexcept;
                bool                                                            MPConnect(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::tcp::endpoint& publicEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept;
                
            public:
                bool                                                            Write(const void* s, int length, const ppp::function<void(bool)>& cb) noexcept;
                virtual bool                                                    Write(const std::shared_ptr<Byte>& s, int length, const ppp::function<void(bool)>& cb) noexcept;

            private:
                void                                                            Finalize() noexcept;

            private:
#if defined(_WIN32)
                std::atomic<FILE*>                                              log_file_ = NULL;
#else
                std::shared_ptr<boost::asio::posix::stream_descriptor>          log_file_;
#endif
                ppp::string                                                     log_path_;
                std::shared_ptr<boost::asio::io_context>                        log_context_;
            };
        }
    }
}
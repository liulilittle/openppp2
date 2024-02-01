#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/DateTime.h>
#include <ppp/io/File.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Executors.h>
#include <ppp/auxiliary/StringAuxiliary.h>

namespace ppp {
    namespace app {
        namespace protocol {
            VirtualEthernetLogger::VirtualEthernetLogger(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& log_path) noexcept
                : log_file_(NULL)
                , log_context_(context) {
                if (NULL != context && log_path.size() > 0) {
                    ppp::string file_path = ppp::io::File::GetFullPath(ppp::io::File::RewritePath(log_path.data()).data());
                    ppp::string file_dirs = ppp::io::File::GetParentPath(file_path.data());
                    if (file_dirs.size() > 0) {
                        if (ppp::io::File::CreateDirectories(file_dirs.data())) {
                            ppp::string file_name = ppp::io::File::GetFileName(file_path.data());
                            if (file_name.size() > 0) {
#ifdef _WIN32
                                log_file_ = fopen(file_path.data(), "ab+");
#else
                                int fd = open(file_path.data(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
                                if (fd != -1) { // https://android.googlesource.com/platform/bionic/+/b23f193/libc/unistd/lseek64.c
                                    bool seek64 = lseek64(fd, 0, SEEK_END) != -1;
                                    if (!seek64) {
                                        seek64 = lseek(fd, 0, SEEK_END) != -1;
                                        if (!seek64) {
                                            close(fd);
                                        }
                                    }
                                    
                                    if (seek64) {
                                        auto log_file = make_shared_object<boost::asio::posix::stream_descriptor>(*context, fd);;
                                        if (NULL == log_file) {
                                            close(fd);
                                        }
                                        else {
                                            log_file_ = std::move(log_file);
                                        }
                                    }
                                }
#endif
                            }
                        }
                    }
                }
            }

            VirtualEthernetLogger::~VirtualEthernetLogger() noexcept {
                Finalize();
            }

            std::shared_ptr<boost::asio::io_context> VirtualEthernetLogger::GetContext() noexcept {
                return log_context_;
            }

            ppp::string VirtualEthernetLogger::GetPath() noexcept {
                return log_path_;
            }

            bool VirtualEthernetLogger::Valid() noexcept {
#ifdef _WIN32
                return NULL != log_file_.load();
#else
                std::shared_ptr<boost::asio::posix::stream_descriptor> log = log_file_;
                if (NULL == log) {
                    return false;
                }

                return log->is_open();
#endif
            }

            std::shared_ptr<VirtualEthernetLogger> VirtualEthernetLogger::GetReference() noexcept {
                return shared_from_this();
            }

            void VirtualEthernetLogger::Dispose() noexcept {
                std::shared_ptr<VirtualEthernetLogger> self = GetReference();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                context->post(
                    [self, this]() noexcept {
                        Finalize();
                    });
            }

            void VirtualEthernetLogger::Finalize() noexcept {
#ifdef _WIN32
                FILE* log = log_file_.exchange(NULL);
                if (NULL != log) {
                    fflush(log);
                    fclose(log);
                }
#else
                std::shared_ptr<boost::asio::posix::stream_descriptor> log = std::move(log_file_);
                if (NULL != log) {
                    log_file_.reset();
                    ppp::net::Socket::Closestream(log);
                }
#endif
            }

            bool VirtualEthernetLogger::Write(const void* s, int length, const ppp::function<void(bool)>& cb) noexcept {
                if (NULL == s || length < 1) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = BufferAllocator;
                std::shared_ptr<Byte> buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, length);
                if (NULL == buffer) {
                    return false;
                }

                memcpy(buffer.get(), s, length);
                return Write(buffer, length, cb);
            }

            bool VirtualEthernetLogger::Write(const std::shared_ptr<Byte>& s, int length, const ppp::function<void(bool)>& cb) noexcept {
                if (NULL == s || length < 1) {
                    return false;
                }

#ifdef _WIN32
                std::shared_ptr<VirtualEthernetLogger> self = shared_from_this();
                log_context_->post(
                    [self, this, s, length, cb]() noexcept {
                        bool ok = false;
                        FILE* log = log_file_.load();
                        if (NULL != log) {
                            fwrite(s.get(), 1, length, log);
                            fflush(log);
                        }

                        if (cb) {
                            cb(ok);
                        }
                    });
#else
                std::shared_ptr<boost::asio::posix::stream_descriptor> log = log_file_;
                if (NULL == log || !log->is_open()) {
                    return false;
                }

                std::shared_ptr<VirtualEthernetLogger> self = shared_from_this();
                boost::asio::async_write(*log, boost::asio::buffer(s.get(), length),
                    [s, cb](boost::system::error_code ec, std::size_t sz) noexcept {
                        if (cb) {
                            bool ok = ec == boost::system::errc::success;
                            cb(ok);
                        }
                    });
#endif
                return true;
            }

            static ppp::string LOGGER_NOW() noexcept {
                ppp::string s = "[";
                s += ppp::threading::Executors::Now().ToString("yyyy-MM-dd HH:mm:ss");
                s += "]";
                return s;
            }

            static ppp::string LOGGER_GUID(Int128 guid) noexcept {
                ppp::string s = "{";
                s += ToUpper(ppp::auxiliary::StringAuxiliary::Int128ToGuidString(guid));
                s += "}";
                return s;
            }

            bool VirtualEthernetLogger::Connect(Int128 guid, const boost::asio::ip::tcp::endpoint& srcEP, const boost::asio::ip::tcp::endpoint& natEP, const boost::asio::ip::tcp::endpoint& dstEP, const ppp::string& hostDomain) noexcept {
                ppp::string log = LOGGER_NOW() + " ";
                log += LOGGER_GUID(guid) + " ";
                log += "CONNECT SOURCE:";
                log += ppp::net::IPEndPoint::ToEndPoint(srcEP).ToString() + " NAT:";
                log += ppp::net::IPEndPoint::ToEndPoint(natEP).ToString() + " DESTINATION:";
                log += ppp::net::IPEndPoint::ToEndPoint(dstEP).ToString();
                if (hostDomain.size() > 0) {
                    log += " DOMAIN:" + hostDomain + ":";
                    log += stl::to_string<ppp::string>(dstEP.port());
                }

                log += "\r\n";
                return this->Write(log.data(), log.size(), NULL);
            }

            bool VirtualEthernetLogger::Arp(Int128 guid, const boost::asio::ip::tcp::endpoint& srcEP, uint32_t ip, uint32_t mask) noexcept {
                return this->Arp(guid, srcEP, ppp::net::Ipep::ToAddress(ip), ppp::net::Ipep::ToAddress(mask));
            }

            bool VirtualEthernetLogger::Arp(Int128 guid, const boost::asio::ip::tcp::endpoint& srcEP, const boost::asio::ip::address& ip, const boost::asio::ip::address& mask) noexcept {
                ppp::string log = LOGGER_NOW() + " ";
                log += LOGGER_GUID(guid) + " ";
                log += "ARP SOURCE:";
                log += ppp::net::IPEndPoint::ToEndPoint(srcEP).ToString() + " IP:";
                log += ip.to_string() + " ";
                log += " GATEWAY:";
                log += mask.to_string() + "\r\n";

                return this->Write(log.data(), log.size(), NULL);
            }

            bool VirtualEthernetLogger::Vpn(Int128 guid, const boost::asio::ip::tcp::endpoint& srcEP) noexcept {
                ppp::string log = LOGGER_NOW() + " ";
                log += LOGGER_GUID(guid) + " ";
                log += "VPN SOURCE:";
                log += ppp::net::IPEndPoint::ToEndPoint(srcEP).ToString() + "\r\n";

                return this->Write(log.data(), log.size(), NULL);
            }

            bool VirtualEthernetLogger::Dns(Int128 guid, const boost::asio::ip::tcp::endpoint& srcEP, const ppp::string& hostDomain) noexcept {
                ppp::string log = LOGGER_NOW() + " ";
                log += LOGGER_GUID(guid) + " ";
                log += "DNS SOURCE:";
                log += ppp::net::IPEndPoint::ToEndPoint(srcEP).ToString() + " DOMAIN:";
                log += hostDomain + "\r\n";

                return this->Write(log.data(), log.size(), NULL);
            }

            bool VirtualEthernetLogger::Port(Int128 guid, const boost::asio::ip::tcp::endpoint& srcEP, const boost::asio::ip::udp::endpoint& inEP, const boost::asio::ip::udp::endpoint& natEP) noexcept {
                ppp::string log = LOGGER_NOW() + " ";
                log += LOGGER_GUID(guid) + " ";
                log += "PORT SOURCE:";
                log += ppp::net::IPEndPoint::ToEndPoint(srcEP).ToString() + " IN:";
                log += ppp::net::IPEndPoint::ToEndPoint(inEP).ToString() + " NAT:";
                log += ppp::net::IPEndPoint::ToEndPoint(natEP).ToString() + "\r\n";

                return this->Write(log.data(), log.size(), NULL);
            }

            bool VirtualEthernetLogger::MPConnect(Int128 guid, const boost::asio::ip::tcp::endpoint& srcEP, const boost::asio::ip::tcp::endpoint& publicEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
                ppp::string log = LOGGER_NOW() + " ";
                log += LOGGER_GUID(guid) + " ";
                log += "MAPPING PORT CONNECT SOURCE:";
                log += ppp::net::IPEndPoint::ToEndPoint(srcEP).ToString() + " PUBLIC:";
                log += ppp::net::IPEndPoint::ToEndPoint(publicEP).ToString() + " REMOTE:";
                log += ppp::net::IPEndPoint::ToEndPoint(remoteEP).ToString() + "\r\n";

                return this->Write(log.data(), log.size(), NULL);
            }

            bool VirtualEthernetLogger::MPEntry(Int128 guid, const boost::asio::ip::tcp::endpoint& srcEP, const boost::asio::ip::tcp::endpoint& publicEP, bool protocol_tcp_or_udp) noexcept {
                ppp::string log = LOGGER_NOW() + " ";
                log += LOGGER_GUID(guid) + " ";
                log += "MAPPING PORT ENTRY SOURCE:";
                log += ppp::net::IPEndPoint::ToEndPoint(srcEP).ToString() + " PUBLIC:";
                log += ppp::net::IPEndPoint::ToEndPoint(publicEP).ToString() + (ppp::string("/") + (protocol_tcp_or_udp ? "tcp" : "udp") + "\r\n");

                return this->Write(log.data(), log.size(), NULL);
            }
        }
    }
}
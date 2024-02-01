// https://android.googlesource.com/platform/frameworks/base.git/+/android-4.3_r2.1/services/jni/com_android_server_connectivity_Vpn.cpp
// https://android.googlesource.com/platform/system/core/+/master/libnetutils/ifc_utils.c
// https://www.androidos.net.cn/android/6.0.1_r16/xref/bionic/libc/bionic/if_nametoindex.c
// https://android.googlesource.com/platform/frameworks/native/+/master/include/android/multinetwork.h
// https://android.googlesource.com/platform/cts/+/fed9991/tests/tests/net/jni/NativeMultinetworkJni.c

#include <ppp/stdafx.h>
#include <ppp/tap/ITap.h>

#ifdef _WIN32
#include <windows/ppp/tap/TapWindows.h>
#else
#include <linux/ppp/tap/TapLinux.h>
#endif

#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Executors.h>

typedef ppp::net::IPEndPoint IPEndPoint;
typedef ppp::net::Ipep       Ipep;

namespace ppp
{
    namespace tap
    {
        template<typename T>
        static std::shared_ptr<T> WrapStreamFromNativePtr(T* native) noexcept
        {
            if (NULL == native)
            {
                return NULL;
            }

            auto f = [](T* stream) noexcept
            {
                boost::system::error_code ec;
                if (NULL != stream)
                {
                    stream->cancel(ec);
                    stream->close(ec);
                    stream->~T();
                }
            };
            return std::shared_ptr<T>(native, f);
        }

        static std::shared_ptr<boost::asio::posix::stream_descriptor> NewStreamFromHandle(boost::asio::io_context& context, void* handle) noexcept
        {
            if (handle == INVALID_HANDLE_VALUE)
            {
                return NULL;
            }

            void* memory = Malloc(sizeof(boost::asio::posix::stream_descriptor));
            if (NULL == memory)
            {
                return NULL;
            }

            boost::asio::posix::stream_descriptor* stream = NULL;
            try
            {
#ifdef _WIN32
                stream = new (memory) boost::asio::posix::stream_descriptor(context, reinterpret_cast<void*>(handle));
#else
                stream = new (memory) boost::asio::posix::stream_descriptor(context, (int32_t)(int64_t)handle);
#endif
            }
            catch (const std::exception&)
            {
                Mfree(memory);
                memory = NULL;
            }

            return WrapStreamFromNativePtr(stream);
        }

        ITap::ITap(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& id, void* tun, uint32_t ip, uint32_t gw, uint32_t mask, bool hosted_network)
            : IPAddress(ip)
            , GatewayServer(gw)
            , SubmaskAddress(mask)
            , _id(id)
            , _context(context)
            , _opening(false)
            , _hosted_network(hosted_network)
            , _handle(tun)
            , _interface_index(-1)
        {
            if (NULL == _context)
            {
                _context = ppp::threading::Executors::GetDefault();
            }

            if (NULL == _context)
            {
                throw std::runtime_error("Default thread not working.");
            }
            else
            {
                const_cast<uint32_t&>(IPAddress) = ip;
                const_cast<uint32_t&>(GatewayServer) = gw;
                const_cast<uint32_t&>(SubmaskAddress) = mask;
            }

            _stream = NewStreamFromHandle(*_context, tun);
        }

        ITap::~ITap() noexcept
        {
            Finalize();
        }

        bool ITap::IsReady() noexcept
        {
            bool b = NULL != _context && NULL != _stream;
            if (b)
            {
                void* h = _handle;
                if (NULL == h)
                {
                    return false;
                }

                if (h == INVALID_HANDLE_VALUE)
                {
                    return false;
                }
            }
            return b;
        }

        bool ITap::IsOpen() noexcept
        {
            return _opening && IsReady();
        }

        std::shared_ptr<ITap> ITap::From(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& id, void* tun, uint32_t address, uint32_t gw, uint32_t mask, bool hosted_network) noexcept
        {
            if (tun == INVALID_HANDLE_VALUE)
            {
                return NULL;
            }

            IPEndPoint ipEP(address, 0);
            if (IPEndPoint::IsInvalid(ipEP))
            {
                return NULL;
            }

            IPEndPoint maskEP(address, 0);
            if (IPEndPoint::IsInvalid(maskEP))
            {
                return NULL;
            }

            IPEndPoint gwEP(address, 0);
            if (IPEndPoint::IsInvalid(gwEP))
            {
                return NULL;
            }

            std::shared_ptr<ITap> tap;
#ifdef _WIN32
            tap = make_shared_object<ppp::tap::TapWindows>(context, id, tun, address, gw, mask, hosted_network);
            if (NULL == tap)
            {
                return NULL;
            }
            else 
            {
                tap->GetInterfaceIndex() = ppp::tap::TapWindows::GetNetworkInterfaceIndex(id);
            }
#else
            tap = make_shared_object<ppp::tap::TapLinux>(context, id, tun, address, gw, mask, hosted_network);
            if (NULL == tap)
            {
                return NULL;
            }

            if (ppp::string ss; TapLinux::GetInterfaceName(static_cast<int>(reinterpret_cast<std::intptr_t>(tun)), ss)) 
            {
                tap->GetInterfaceIndex() = TapLinux::GetInterfaceIndex(ss.data());
            }
            else 
            {
                tap->GetInterfaceIndex() = TapLinux::GetInterfaceIndex(id.data());
            }
#endif
            return tap;
        }

#ifdef _WIN32
        std::shared_ptr<ITap> ITap::Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t lease_time_in_seconds, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses) noexcept
#else
        std::shared_ptr<ITap> ITap::Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, uint32_t ip, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses) noexcept
#endif
        {
            if (NULL == context)
            {
                return NULL;
            }

            if (dev.empty())
            {
                return NULL;
            }

            IPEndPoint ipEP(ip, IPEndPoint::MinPort);
            if (IPEndPoint::IsInvalid(ipEP))
            {
                return NULL;
            }

            IPEndPoint gwEP(gw, IPEndPoint::MinPort);
            if (IPEndPoint::IsInvalid(gwEP))
            {
                return NULL;
            }

            UInt32 maskCIDR = IPEndPoint::NetmaskToPrefix(mask);
            UInt32 maskIPPX = IPEndPoint::PrefixToNetmask(maskCIDR);
            if (mask != maskIPPX)
            {
                return NULL;
            }

#ifdef _WIN32
            return ppp::tap::TapWindows::Create(context, dev, ip, gw, mask, lease_time_in_seconds, hosted_network, dns_addresses);
#else
            return ppp::tap::TapLinux::Create(context, dev, ip, gw, mask, promisc, hosted_network, dns_addresses);
#endif
        }

#ifdef _WIN32
        std::shared_ptr<ITap> ITap::Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, const ppp::string& ip, const ppp::string& gw, const ppp::string& mask, uint32_t lease_time_in_seconds, bool hosted_network, const ppp::vector<ppp::string>& dns_addresses) noexcept 
        {
            ppp::vector<uint32_t> dns_addresses_stloc;
            Ipep::ToAddresses(dns_addresses, dns_addresses_stloc);

            return ITap::Create(context,
                dev,
                inet_addr(ip.data()),
                inet_addr(gw.data()),
                inet_addr(mask.data()),
                lease_time_in_seconds,
                hosted_network,
                dns_addresses_stloc);
        }
#else
        std::shared_ptr<ITap> ITap::Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, const ppp::string& ip, const ppp::string& gw, const ppp::string& mask, bool promisc, bool hosted_network, const ppp::vector<ppp::string>& dns_addresses) noexcept
        {
            ppp::vector<uint32_t> dns_addresses_stloc;
            Ipep::ToAddresses(dns_addresses, dns_addresses_stloc);

            return ITap::Create(context, 
                dev, 
                inet_addr(ip.data()), 
                inet_addr(gw.data()), 
                inet_addr(mask.data()), 
                promisc,
                hosted_network,
                dns_addresses_stloc);
        }
#endif

        ppp::string ITap::FindAnyDevice() noexcept
        {
#ifdef _WIN32
            return ppp::tap::TapWindows::FindComponentId();
#else
            return BOOST_BEAST_VERSION_STRING;
#endif
        }

        void ITap::Finalize() noexcept
        {
            std::shared_ptr<boost::asio::posix::stream_descriptor> stream = std::move(_stream); 
            PacketInput.reset();

            if (NULL != stream) 
            {
                _stream.reset();
                ppp::net::Socket::Closestream(stream);
            }
        }

        void ITap::Dispose() noexcept
        {
            std::shared_ptr<ITap> self = shared_from_this();
            std::shared_ptr<boost::asio::io_context> context = GetContext();
            context->dispatch(
                [self, this]() noexcept 
                {
                    Finalize();
                });
        }

        bool ITap::Open() noexcept
        {
            bool isReady = IsReady();
            if (!isReady)
            {
                return false;
            }

            if (_opening)
            {
                return false;
            }

            if (!AsynchronousReadPacketLoops())
            {
                return false;
            }

            _opening = true;
            return true;
        }

        bool ITap::AsynchronousReadPacketLoops() noexcept
        {
            std::shared_ptr<boost::asio::posix::stream_descriptor> stream = _stream;
            if (NULL == stream)
            {
                return false;
            }

            bool opened = stream->is_open();
            if (!opened)
            {
                return false;
            }

            std::shared_ptr<ITap> self = shared_from_this();
            stream->async_read_some(boost::asio::buffer(_packet, ITap::Mtu), 
                [self, this, stream](const boost::system::error_code& ec, std::size_t sz) noexcept
                {
                    if (ec == boost::system::errc::operation_canceled)
                    {
                        return;
                    }

                    int len = std::max<int>(ec ? -1 : sz, -1);
                    if (len > 0)
                    {
                        PacketInputEventArgs e{ _packet, len };
                        OnInput(e);
                    }

                    AsynchronousReadPacketLoops();
                });
            return true;
        }

        void ITap::OnInput(PacketInputEventArgs& e) noexcept
        {
            std::shared_ptr<PacketInputEventHandler> eh = PacketInput;
            if (eh)
            {
                (*eh)(this, e);
            }
        }

        class WritePacketToKernelNio final 
        {
        public:
            static bool                                                 Invoke(
                ITap*                                                   my,
                const std::shared_ptr<Byte>&                            packet, 
                int                                                     packet_size) noexcept 
            {
                if (NULL == packet || packet_size < 1)
                {
                    return true;
                }

                std::shared_ptr<boost::asio::posix::stream_descriptor> stream = my->_stream;
                if (NULL == stream)
                {
                    return false;
                }

                bool opened = stream->is_open();
                if (!opened)
                {
                    return false;
                }

                std::shared_ptr<ITap> self = my->shared_from_this();
                my->_context->dispatch(
                    [self, my, stream, packet, packet_size]() noexcept 
                    { 
                        bool opened = stream->is_open();
                        if (!opened)
                        {
                            return false;
                        }

                        auto ac = [self, my, stream, packet](const boost::system::error_code& ec, std::size_t sz) noexcept
                            {
                                if (ec == boost::system::errc::operation_canceled)
                                {
                                    my->Finalize();
                                }
                            };
                        boost::asio::async_write(*stream, boost::asio::buffer(packet.get(), packet_size), ac);
                        return true;
                    }); 
                return true;
            }
        };

        bool ITap::Output(const void* packet, int packet_size) noexcept
        {
            if (NULL == packet || packet_size < 1)
            {
                return true;
            }

            std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = this->BufferAllocator;
            std::shared_ptr<Byte> buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, packet_size);
            if (NULL == buffer)
            {
                return false;
            }

            memcpy(buffer.get(), packet, packet_size);
            return WritePacketToKernelNio::Invoke(this, buffer, packet_size);
        }

        bool ITap::Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept
        {
            return WritePacketToKernelNio::Invoke(this, packet, packet_size);
        }
    }
}
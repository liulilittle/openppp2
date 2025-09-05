#include <windows/ppp/app/client/lsp/PaperAirplaneController.h>
#include <windows/ppp/app/client/lsp/PaperAirplaneConnection.h>
#include <windows/ppp/app/client/lsp/PaperAirplaneLspX.h>
#include <windows/ppp/app/client/lsp/PaperAirplaneLspY.h>
#include <windows/ppp/win32/Win32Native.h>

#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/io/File.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/text/Encoding.h>
#include <ppp/collections/Dictionary.h>

using ppp::io::File;
using ppp::net::Socket;
using ppp::net::IPEndPoint;

namespace ppp
{
    namespace app
    {
        namespace client
        {
            namespace lsp
            {
                PaperAirplaneController::PaperAirplaneController(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept
                    : disposed_(false)
                    , forward_port_(0)
                    , exchanger_(exchanger)
                    , configuration_(exchanger->GetConfiguration())
                    , context_(exchanger->GetContext())
                    , acceptors_{ boost::asio::ip::tcp::acceptor(*context_), boost::asio::ip::tcp::acceptor(*context_) }
                {

                }

                PaperAirplaneController::~PaperAirplaneController() noexcept
                {
                    Finalize();
                }

                void PaperAirplaneController::Finalize() noexcept
                {
                    PaperAirplaneControlBlockPortPtr block_port = std::move(block_port_);
                    block_port_.reset();
                    
                    if (NULL != block_port)
                    {
                        if (block_port->IsAvailable())
                        {
                            block_port->Set(-1, IPEndPoint::MinPort, IPEndPoint::MinPort, IPEndPoint::MinPort);
                        }
                    }

                    for (int i = 0; i < arraysizeof(acceptors_); i++)
                    {
                        boost::asio::ip::tcp::acceptor& acceptor = acceptors_[i];
                        ppp::net::Socket::Closesocket(acceptor);
                    }

                    disposed_ = true;
                }

                void PaperAirplaneController::Dispose() noexcept
                {
                    auto self = shared_from_this();
                    std::shared_ptr<boost::asio::io_context> context = GetContext();
                    boost::asio::post(*context, 
                        [self, this, context]() noexcept
                        {
                            Finalize();
                        });
                }

                bool PaperAirplaneController::OpenAllAcceptors() noexcept
                {
                    AppConfigurationPtr configuration = GetConfiguration();
                    if (NULL == configuration)
                    {
                        return false;
                    }

                    for (int i = 0; i < arraysizeof(acceptors_); i++)
                    {
                        boost::asio::ip::tcp::acceptor& acceptor = acceptors_[i];
                        if (acceptor.is_open())
                        {
                            return false;
                        }
                    }

                    boost::asio::ip::address bind_addresses[arraysizeof(acceptors_)] = { boost::asio::ip::address_v4::loopback(), boost::asio::ip::address_v4::any() };
                    for (int i = 0; i < arraysizeof(acceptors_); i++)
                    {
                        boost::asio::ip::tcp::acceptor& acceptor = acceptors_[i];
                        if (!Socket::OpenAcceptor(acceptor, bind_addresses[i],
                            IPEndPoint::MinPort, configuration->tcp.backlog, configuration->tcp.fast_open, configuration->tcp.turbo))
                        {
                            return false;
                        }

                        Socket::SetWindowSizeIfNotZero(acceptor.native_handle(), configuration->tcp.cwnd, configuration->tcp.rwnd);
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::tcp::endpoint localEP = acceptors_[1].local_endpoint(ec);
                    if (ec)
                    {
                        return false;
                    }

                    forward_port_ = localEP.port();
                    return true;
                }

                bool PaperAirplaneController::OpenControlBlockPort(int interface_index, uint32_t ip, uint32_t mask) noexcept
                {
                    std::shared_ptr<PaperAirplaneControlBlockPort> block_port = make_shared_object<PaperAirplaneControlBlockPort>();
                    if (NULL == block_port)
                    {
                        return false;
                    }

                    bool available = block_port->IsAvailable();
                    if (!available)
                    {
                        return false;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::tcp::endpoint localEP = acceptors_[0].local_endpoint(ec);
                    if (ec)
                    {
                        return false;
                    }

                    bool ok = block_port->Set(interface_index, localEP.port(), ip, mask);
                    if (!ok)
                    {
                        return false;
                    }

                    block_port_ = std::move(block_port);
                    return true;
                }

                bool PaperAirplaneController::Open(int interface_index, uint32_t ip, uint32_t mask) noexcept
                {
                    if (disposed_)
                    {
                        return false;
                    }

                    return OpenAllAcceptors() &&
                        OpenControlBlockPort(interface_index, ip, mask) &&
                        AcceptMasterAcceptor() &&
                        AcceptForwardAcceptor() &&
                        NextAlwaysTickTimer();
                }

                bool PaperAirplaneController::NextAlwaysTickTimer() noexcept
                {
                    if (disposed_)
                    {
                        return false;
                    }

                    return Timeout(1000,
                        [this](Timer*) noexcept
                        {
                            UInt64 now = ppp::threading::Executors::GetTickCount();
                            Update(now);
                            NextAlwaysTickTimer();
                        });
                }

                void PaperAirplaneController::Update(UInt64 now) noexcept
                {
                    UpdateAllForwardEntries(now);
                    ppp::collections::Dictionary::UpdateAllObjects(connections_, now);
                }

                PaperAirplaneController::PaperAirplaneConnectionPtr PaperAirplaneController::NewConnection(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept
                {
                    auto self = shared_from_this();
                    return make_shared_object<PaperAirplaneConnection>(self, context, strand, socket);
                }

                bool PaperAirplaneController::Timeout(int milliseconds, const Timer::TimeoutEventHandler& handler) noexcept
                {
                    if (disposed_)
                    {
                        return false;
                    }

                    if (NULL == handler)
                    {
                        return false;
                    }

                    if (milliseconds < 0)
                    {
                        milliseconds = 0;
                    }

                    struct TimeoutHandler final
                    {
                    public:
                        Timer::TimeoutEventHandler               h;
                        Timer*                                   k;
                        std::shared_ptr<PaperAirplaneController> p;

                    public:
                        void                                     Call(Timer*) noexcept
                        {
                            if (p->disposed_)
                            {
                                return;
                            }

                            auto tail = p->timeouts_.find(k);
                            auto endl = p->timeouts_.end();
                            if (tail == endl)
                            {
                                return;
                            }

                            p->timeouts_.erase(tail);
                            k->Stop();
                            k->Dispose();

                            h(k);
                            h = NULL;
                            k = NULL;
                            p = NULL;
                        }
                    };

                    std::shared_ptr<TimeoutHandler> h = make_shared_object<TimeoutHandler>();
                    if (NULL == h)
                    {
                        return false;
                    }
                    
                    h->k = NULL;
                    h->h = handler;
                    h->p = shared_from_this();
                    
                    std::shared_ptr<Timer> timeout = Timer::Timeout(milliseconds, std::bind(&TimeoutHandler::Call, h, std::placeholders::_1));
                    if (NULL == timeout)
                    {
                        return false;
                    }
                    else
                    {
                        h->k = timeout.get();
                    }

                    bool ok = timeouts_.emplace(timeout.get(), timeout).second;
                    if (!ok)
                    {
                        timeout->Stop();
                        timeout->Dispose();
                    }

                    return ok;
                }

                bool PaperAirplaneController::UpdateAllForwardEntries(UInt64 now) noexcept
                {
                    std::vector<boost::asio::ip::tcp::endpoint> releases;
                    for (auto&& kv : entries_)
                    {
                        PortForwardMappingEntry& i = kv.second;
                        if (now >= (i.last + 1000))
                        {
                            releases.emplace_back(kv.first);
                        }
                    }

                    for (auto&& k : releases)
                    {
                        auto tail = entries_.find(k);
                        auto endl = entries_.end();
                        if (tail != endl)
                        {
                            entries_.erase(tail);
                        }
                    }
                    return true;
                }

                bool PaperAirplaneController::AcceptMasterAcceptor() noexcept
                {
                    auto self = shared_from_this();
                    return ppp::net::Socket::AcceptLoopbackAsync(acceptors_[0], 
                        [self, this](const ppp::net::Socket::AsioContext& conntext, const ppp::net::Socket::AsioTcpSocket& socket) noexcept
                        {
                            if (disposed_)
                            {
                                return false;
                            }

                            return ppp::app::client::lsp::paper_airplane::PacketInput(*socket,
                                [self, this, socket](boost::asio::ip::tcp::endpoint& local, boost::asio::ip::tcp::endpoint& remote) noexcept -> int
                                {
                                    if (disposed_)
                                    {
                                        return 0;
                                    }

                                    PortForwardMappingEntry entry;
                                    entry.last = ppp::threading::Executors::GetTickCount();
                                    entry.natEP = local;
                                    entry.destinationEP = remote;

                                    bool ok = entries_.emplace(local, entry).second;
                                    return ok ? forward_port_ : 0;
                                });
                        });
                }

                bool PaperAirplaneController::AcceptForwardAcceptor() noexcept
                {
                    auto self = shared_from_this();
                    return ppp::net::Socket::AcceptLoopbackSchedulerAsync(acceptors_[1],
                        [self, this](const ppp::net::Socket::AsioContext& context, const ppp::net::Socket::AsioStrandPtr& strand, const ppp::net::Socket::AsioTcpSocket& socket) noexcept
                        {
                            if (disposed_)
                            {
                                return false;
                            }

                            boost::system::error_code ec;
                            boost::asio::ip::tcp::endpoint natEP = socket->remote_endpoint(ec);
                            if (ec)
                            {
                                return false;
                            }
                            else
                            {
                                IPEndPoint ep = IPEndPoint::V6ToV4(IPEndPoint::ToEndPoint(natEP));
                                natEP = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(ep);
                            }

                            auto tail = entries_.find(natEP);
                            auto endl = entries_.end();
                            if (tail == endl)
                            {
                                return false;
                            }

                            if (!ppp::net::Socket::AdjustDefaultSocketOptional(*socket, configuration_->tcp.turbo))
                            {
                                return false;
                            }
                            else 
                            {
                                ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration_->tcp.cwnd, configuration_->tcp.rwnd);
                            }

                            boost::asio::ip::tcp::endpoint remoteEP = tail->second.destinationEP;
                            entries_.erase(tail);

                            return AcceptForwardClient(context, strand, socket, remoteEP);
                        });
                }

                bool PaperAirplaneController::AcceptForwardClient(const ppp::net::Socket::AsioContext& context, const ppp::threading::Executors::StrandPtr& strand, const ppp::net::Socket::AsioTcpSocket& socket, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept
                {
                    using NetworkState = VEthernetExchanger::NetworkState;

                    std::shared_ptr<VEthernetExchanger> exchanger = GetExchanger();
                    if (NULL == exchanger)
                    {
                        return false;
                    }

                    NetworkState network_state = exchanger->GetNetworkState();
                    if (network_state != NetworkState::NetworkState_Established) 
                    {
                        return false;
                    }

                    AppConfigurationPtr configuration = exchanger->GetConfiguration();
                    if (NULL == configuration)
                    {
                        return false;
                    }

                    std::shared_ptr<PaperAirplaneConnection> connection = NewConnection(context, strand, socket);
                    if (NULL == connection)
                    {
                        connection->Dispose();
                        return false;
                    }

                    auto kv = connections_.emplace(connection.get(), connection);
                    if (!kv.second)
                    {
                        connection->Dispose();
                        return false;
                    }

                    auto self = shared_from_this();
                    auto allocator = configuration->GetBufferAllocator();
                    
                    bool bok = ppp::coroutines::YieldContext::Spawn(allocator.get(), *context, strand.get(),
                        [self, this, strand, connection, remoteEP](ppp::coroutines::YieldContext& y) noexcept
                        {
                            bool bok = false;
                            if (!disposed_)
                            {
                                bok = connection->Run(remoteEP.address(), remoteEP.port(), y);
                            }

                            if (!bok)
                            {
                                connection->Dispose();
                            }
                        });

                    if (!bok)
                    {
                        connection->Dispose();
                        connections_.erase(kv.first);
                    }

                    return bok;
                }

                bool PaperAirplaneController::ReleaseConnection(PaperAirplaneConnection* connection) noexcept
                {
                    if (NULL == connection)
                    {
                        return false;
                    }

                    auto self = shared_from_this();
                    std::shared_ptr<boost::asio::io_context> context = GetContext();
                    boost::asio::post(*context, 
                        [self, this, context, connection]() noexcept
                        {
                            auto tail = connections_.find(connection);
                            auto endl = connections_.end();
                            if (tail == endl)
                            {
                                return false;
                            }

                            PaperAirplaneConnectionPtr connection_managed = std::move(tail->second);
                            connections_.erase(tail);

                            if (NULL == connection_managed)
                            {
                                return false;
                            }

                            connection_managed->Dispose();
                            return true;
                        });
                    return true;
                }

                int PaperAirplaneController::Upgrade() noexcept
                {
                    std::vector<ppp::string> dllPaths;
                    std::vector<ppp::string> libPaths;
                    if (!lsp::paper_airplane::IsWow64System())
                    {
                        ppp::string winddir = ppp::win32::Win32Native::GetFolderPathWithWindows();
                        dllPaths.emplace_back(winddir + "/System32/PaperAirplane.dll");
                        libPaths.emplace_back("./Driver/x86/PaperAirplane.dll");
                    }
                    elif(ppp::win32::Win32Native::IsWow64Process())
                    {
                        ppp::string winddir = ppp::win32::Win32Native::GetFolderPathWithWindows();
                        dllPaths.emplace_back(winddir + "/System32/PaperAirplane.dll");
                        dllPaths.emplace_back(winddir + "/SysWow64/PaperAirplane.dll");
                        libPaths.emplace_back("./Driver/x64/PaperAirplane.dll");
                        libPaths.emplace_back("./Driver/x86/PaperAirplane.dll");
                    }
                    else
                    {
                        ppp::string winddir = ppp::win32::Win32Native::GetFolderPathWithWindows();
                        dllPaths.emplace_back(winddir + "/System32/PaperAirplane.dll"); // System32
                        dllPaths.emplace_back(winddir + "/SysNative/PaperAirplane.dll"); // SysWow64
                        libPaths.emplace_back("./Driver/x86/PaperAirplane.dll");
                        libPaths.emplace_back("./Driver/x64/PaperAirplane.dll");
                    }

                    std::vector<ppp::string>* pathss[] = { &dllPaths, &libPaths };
                    for (auto&& paths : pathss)
                    {
                        for (ppp::string& path : *paths)
                        {
                            path = File::GetFullPath(File::RewritePath(path.data()).data());
                        }
                    }

                    bool b = false;
                    size_t n = 0;
                    for (std::size_t i = 0; i < dllPaths.size(); i++)
                    {
                        int libFileSize = 0;
                        std::shared_ptr<Byte> libFileBytes = File::ReadAllBytes(libPaths[i].data(), libFileSize);
                        if (NULL == libFileBytes || libFileSize < 1)
                        {
                            n++;
                            continue;
                        }

                        int dllFileSize = 0;
                        std::shared_ptr<Byte> dllFileBytes = File::ReadAllBytes(dllPaths[i].data(), dllFileSize);
                        if (NULL == dllFileBytes || dllFileSize < 1)
                        {
                            continue;
                        }

                        dllFileSize = std::max<int>(0, dllFileSize);
                        libFileSize = std::max<int>(0, libFileSize);
                        if (libFileSize != dllFileSize)
                        {
                            b = true;
                            break;
                        }

                        int libCompareStatus = memcmp(libFileBytes.get(), dllFileBytes.get(), dllFileSize);
                        if (libCompareStatus != 0)
                        {
                            b = true;
                            break;
                        }
                    }

                    if (b)
                    {
                        b = false;
                        for (std::size_t i = 0; i < dllPaths.size(); i++)
                        {
                            ppp::string& dllFilePath = dllPaths[i];
                            if (!File::Exists(dllFilePath.data()))
                            {
                                continue;
                            }

                            if (!File::Delete(dllFilePath.data()))
                            {
                                b = true;
                                break;
                            }
                        }
                    }

                    return b || n != libPaths.size() ? Uninstall(b) : 1;
                }

                int PaperAirplaneController::Uninstall(bool reboot) noexcept
                {
                    ppp::string sysproxy32_path = File::GetFullPath(File::RewritePath("./Driver/x86/sysproxy32.exe").data());
                    ppp::string sysproxy64_path = File::GetFullPath(File::RewritePath("./Driver/x64/sysproxy64.exe").data());
                    bool sysproxy32_path_is_exists = File::Exists(sysproxy32_path.data());
                    bool sysproxy64_path_is_exists = File::Exists(sysproxy64_path.data());
                    if (!sysproxy32_path_is_exists && !sysproxy64_path_is_exists)
                    {
                        return 1;
                    }

                    bool uninstallOk = false;
                    if (sysproxy32_path_is_exists)
                    {
                        uninstallOk |= ppp::win32::Win32Native::EchoTrim(sysproxy32_path + " uninstall") == "1";
                    }

                    if (sysproxy64_path_is_exists)
                    {
                        uninstallOk |= ppp::win32::Win32Native::EchoTrim(sysproxy64_path + " uninstall") == "1";
                    }

                    if (!uninstallOk)
                    {
                        ppp::win32::Win32Native::Echo(R"(netsh winsock reset)");
                    }

                    if (reboot)
                    {
                        int result = MessageBoxA(NULL, "You need to reboot your system to complete the update of the \"PaperAirplane\" plugin, do you need to restart system now?",
                            ppp::win32::Win32Native::GetConsoleWindowText().data(), MB_ICONWARNING | MB_YESNO);
                        if (result == IDYES)
                        {
                            ppp::win32::Win32Native::Echo(R"(shutdown /r /f /t 0)");
                            return -1;
                        }
                        else
                        {
                            return 1;
                        }
                    }
                    return 0;
                }

                bool PaperAirplaneController::CopyToSystemFolder() noexcept
                {
                    auto copyToSystemFolder = [](int mode, bool x86) noexcept -> bool
                        {
                            constexpr const char* sysdirs[] = { "/SysNative", "/SysWOW64", "/System32" };

                            ppp::string syspath = File::GetFullPath(File::RewritePath((ppp::win32::Win32Native::GetFolderPathWithWindows() + sysdirs[mode]).data()).data());
                            ppp::string dll = File::GetFullPath(File::RewritePath((syspath + "/PaperAirplane.dll").data()).data());
                            if (File::Exists(dll.data()))
                            {
                                return true;
                            }

                            const char* srcdlls = "./Driver/x64/PaperAirplane.dll";
                            if (x86)
                            {
                                srcdlls = "./Driver/x86/PaperAirplane.dll";
                            }

                            ppp::string src = File::GetFullPath(File::RewritePath(srcdlls).data());
                            return CopyFileA(src.data(), dll.data(), FALSE);
                        };

                    if (!lsp::paper_airplane::IsWow64System())
                    {
                        return copyToSystemFolder(2, true);
                    }
                    elif(ppp::win32::Win32Native::IsWow64Process())
                    {
                        return copyToSystemFolder(1, true) && copyToSystemFolder(2, false);
                    }
                    else
                    {
                        return copyToSystemFolder(2, true) && copyToSystemFolder(0, false);
                    }
                }

                int PaperAirplaneController::Install() noexcept
                {
                    int err = Upgrade();
                    if (err < 0)
                    {
                        return -1;
                    }
                    elif(err > 0)
                    {
                        return 1;
                    }

                    while (!CopyToSystemFolder())
                    {
                        int result = MessageBoxA(NULL,
                            "Unable to copy the \"PaperAirplane\" plugin-file to the system disk directory \"System32 and SysWow64\". You are actively rejecting this action. You can ignore this message, but the \"PaperAirplane\" plugin function will be disabled.",
                            ppp::win32::Win32Native::GetConsoleWindowText().data(), MB_ABORTRETRYIGNORE | MB_ICONWARNING);
                        if (result == IDRETRY)
                        {
                            continue;
                        }
                        elif(result == IDIGNORE)
                        {
                            break;
                        }
                        else
                        {
                            return -1;
                        }
                    }

                    for (;;)
                    {
                        bool success = true;
                        if (success && !ppp::app::client::lsp::paper_airplane::IsInstallProvider(true))
                        {
                            ppp::string sysproxy32_path = File::GetFullPath(File::RewritePath("./Driver/x86/sysproxy32.exe").data());
                            success = ppp::win32::Win32Native::EchoTrim(sysproxy32_path + " install") == "1";
                        }

                        if (success && !ppp::app::client::lsp::paper_airplane::IsInstallProvider(false))
                        {
                            ppp::string sysproxy64_path = File::GetFullPath(File::RewritePath("./Driver/x64/sysproxy64.exe").data());
                            success = ppp::win32::Win32Native::EchoTrim(sysproxy64_path + " install") == "1";
                        }

                        if (success)
                        {
                            return 1;
                        }

                        int result = MessageBoxA(NULL,
                            "Unable to install the \"PaperAirplane\" plugin on your computer system, You are actively rejecting this action. You can ignore this message, but the \"PaperAirplane\" plugin function will be disabled.",
                            ppp::win32::Win32Native::GetConsoleWindowText().data(), MB_ABORTRETRYIGNORE | MB_ICONWARNING);
                        if (result == IDRETRY)
                        {
                            continue;
                        }
                        elif(result == IDIGNORE)
                        {
                            return 0;
                        }
                        else
                        {
                            return -1;
                        }
                    }
                    return 0;
                }

                bool PaperAirplaneController::NoLsp() noexcept
                {
                    static constexpr int EXEPATH_MAX = 1 << 10;

                    bool ok = false;
                    char szExePath[EXEPATH_MAX + 1];
                    ppp::string username = ppp::win32::Win32Native::GetLoginUser();

                    ok |= paper_airplane::NoLsp(LR"(C:\Program Files\WindowsApps\MicrosoftCorporationII.WindowsSubsystemForLinux_2.0.9.0_x64__8wekyb3d8bbwe\wsl.exe)");
                    ok |= paper_airplane::NoLsp(LR"(C:\Program Files\WSL\wsl.exe)");
                    ok |= paper_airplane::NoLsp(LR"(C:\Program Files\WSL\wslservice.exe)");

                    snprintf(szExePath, EXEPATH_MAX, R"(C:\Users\%s\AppData\Local\Microsoft\WindowsApps\wsl.exe)", username.data());
                    ok |= paper_airplane::NoLsp(ppp::text::Encoding::ascii_to_wstring(szExePath).data());

                    snprintf(szExePath, EXEPATH_MAX, R"(C:\Users\%s\AppData\Local\Microsoft\WindowsApps\MicrosoftCorporationII.WindowsSubsystemForLinux_8wekyb3d8bbwe\wsl.exe)", username.data());
                    ok |= paper_airplane::NoLsp(ppp::text::Encoding::ascii_to_wstring(szExePath).data());

                    ok |= paper_airplane::NoLsp(LR"(C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.22621.2506_none_62c8e9f54a7fa6e6\wsl.exe)");
                    ok |= paper_airplane::NoLsp(LR"(C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.22621.2506_none_62c8e9f54a7fa6e6\f\wsl.exe)");
                    ok |= paper_airplane::NoLsp(LR"(C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.22621.2506_none_62c8e9f54a7fa6e6\r\wsl.exe)");

                    ok |= paper_airplane::NoLsp(LR"(C:\Windows\System32\wsl.exe)");
                    ok |= paper_airplane::NoLsp(LR"(C:\Windows\System32\vmwp.exe)");
                    ok |= paper_airplane::NoLsp(LR"(C:\Windows\System32\vmcompute.exe)");
                    return ok;
                }
 
                bool PaperAirplaneController::NoLsp(const ppp::string& path) noexcept
                {
                    if (path.empty())
                    {
                        return false;
                    }

                    ppp::string fullpath = File::GetFullPath(File::RewritePath(path.data()).data());
                    if (!File::Exists(fullpath.data()))
                    {
                        return false;
                    }

                    std::wstring fullpath_wstr = ppp::text::Encoding::ascii_to_wstring(std::string(fullpath.data(), fullpath.size()));
                    if (fullpath_wstr.empty())
                    {
                        return false;
                    }

                    return paper_airplane::NoLsp(fullpath_wstr.data());
                }

                bool PaperAirplaneController::Reset() noexcept
                {
                    PaperAirplaneControlBlockPort block_port;
                    if (!block_port.IsAvailable())
                    {
                        return false;
                    }

                    return block_port.Set(-1, IPEndPoint::MinPort, IPEndPoint::AnyAddress, IPEndPoint::AnyAddress);
                }
            }
        }
    }
}
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/Int128.h>
#include <ppp/io/File.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/http/HttpClient.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/vdns.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/diagnostics/Stopwatch.h>
#include <ppp/diagnostics/PreventReturn.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Thread.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetManagedServer.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>

#if defined(_WIN32)
#include <windows/ppp/net/proxies/HttpProxy.h>
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/Win32Native.h>
#include <windows/ppp/win32/network/Firewall.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#else
#include <common/unix/UnixAfx.h>
#if defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#else
#include <linux/ppp/tap/TapLinux.h>
#include <linux/ppp/diagnostics/UnixStackTrace.h>
#endif
#endif

#if defined(CURLINC_CURL)
#include <curl/curl.h>
#endif

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <common/aesni/aes.h>
#include <common/chnroutes2/chnroutes2.h>

using ppp::configurations::AppConfiguration;
using ppp::threading::Executors;
using ppp::threading::Thread;
using ppp::threading::Timer;
using ppp::threading::BufferswapAllocator;
using ppp::diagnostics::Stopwatch;
using ppp::diagnostics::PreventReturn;
using ppp::tap::ITap;
using ppp::net::Ipep;
using ppp::net::IPEndPoint;
using ppp::net::AddressFamily;
using ppp::net::Socket;
using ppp::net::asio::IAsynchronousWriteIoQueue;
using ppp::io::File;
using ppp::io::FileAccess;
using ppp::auxiliary::StringAuxiliary;
using ppp::app::server::VirtualEthernetSwitcher;
using ppp::app::client::VEthernetNetworkSwitcher;
using ppp::app::client::VEthernetExchanger;
using ppp::app::client::proxys::VEthernetLocalProxySwitcher;
using ppp::app::client::proxys::VEthernetHttpProxySwitcher;
using ppp::app::client::proxys::VEthernetSocksProxySwitcher;
using ppp::Int128;

// Custom restart signals are useful only on linux/macos platforms.
#if !defined(_WIN32) && !defined(_ANDROID) && !defined(_IPHONE)  
#define SIGRESTART 64 
#endif

static constexpr int PPP_VIRR_UPDATE_STRETCH  = 300;
static constexpr int PPP_VIRR_UPDATE_INTERVAL = 86400;
static constexpr int PPP_VBGP_UPDATE_INTERVAL = 3600;

struct NetworkInterface final
{
#if defined(_WIN32)
    uint32_t                                        LeaseTimeInSeconds = 0;
    bool                                            SetHttpProxy       = false;
#else
    bool                                            Promisc            = false;
    int                                             Ssmt               = 0;
#if defined(_LINUX)
    bool                                            SsmtMQ             = false;
    bool                                            ProtectNetwork     = false;
#endif
#endif

    bool                                            StaticMode         = false;
    bool                                            Lwip               = false;
    bool                                            VNet               = false;
    bool                                            HostedNetwork      = false;
    bool                                            BlockQUIC          = false;

    uint16_t                                        Mux                = 0;
    uint8_t                                         MuxAcceleration    = 0;

    ppp::string                                     Bypass;
#if defined(_LINUX)
    ppp::string                                     BypassNic;
#endif
    boost::asio::ip::address                        BypassNgw;

    ppp::string                                     ComponentId;
    ppp::string                                     FirewallRules;
    ppp::string                                     DNSRules;
    ppp::string                                     Nic;

    ppp::vector<boost::asio::ip::address>           DnsAddresses;

    boost::asio::ip::address                        Ngw;
    boost::asio::ip::address                        IPAddress;
    boost::asio::ip::address                        GatewayServer;
    boost::asio::ip::address                        SubmaskAddress;
};

struct ConsoleForegroundWindowSize final
{
    int                                             x   = -1;
    int                                             y   = -1;
    bool                                            tty = true;
};

class PrintToConsoleForegroundWindow final 
{
public:
    ConsoleForegroundWindowSize*                    console_window_size    = NULL;
    ppp::string*                                    console_window_content = NULL;
    int*                                            console_window_heights = NULL;

public:
    template <class... A>
    void                                            operator()(const char* format, A&&... args) noexcept 
    {
        // Control the number of lines that need to be printed to the console window to prevent crowding the visible display area 
        // Of the console window, and when the console window size changes, follow the printed content until it is fully printed.
        if (console_window_size->y > *console_window_heights) 
        {
            ppp::string st = PrintToString(console_window_size->x, ' ', format, std::forward<A&&>(args)...);

            (*console_window_heights)++;
            console_window_content->append(st);
        }
    }

private:
    template <class... A>
    ppp::string                                     PrintToString(std::size_t padding_length, char padding_char, const char* format, A&&... args) noexcept 
    {
        char buf[8096];
        int dw = snprintf(buf, sizeof(buf), format, std::forward<A&&>(args)...);

        if (dw >= sizeof(buf))
        {
            dw = sizeof(buf) - 1;
        }
        elif(dw < 0) 
        {
            dw = 0;
        }

        ppp::string result;
        buf[dw] = '\x0';

        result = ppp::PaddingRight<ppp::string>(
            ppp::string(buf, dw), 
            padding_length, padding_char);
            
        if (!console_window_size->tty) 
        {
            result.append("\r\n");
        }

        return result;
    }
};

class PppApplication : public std::enable_shared_from_this<PppApplication>
{
public:
    PppApplication() noexcept;
    virtual ~PppApplication() noexcept;

public:
    int                                             Main(int argc, const char* argv[]) noexcept;
    void                                            Dispose() noexcept;
    void                                            Release() noexcept;

public:
    static std::shared_ptr<PppApplication>          GetDefault() noexcept;
    static bool                                     OnShutdownApplication() noexcept;
    static bool                                     ShutdownApplication(bool restart) noexcept;
    static bool                                     AddShutdownApplicationEventHandler() noexcept;

public:
    std::shared_ptr<AppConfiguration>               GetConfiguration() noexcept;
    std::shared_ptr<VirtualEthernetSwitcher>        GetServer() noexcept;
    std::shared_ptr<VEthernetNetworkSwitcher>       GetClient() noexcept;
    std::shared_ptr<BufferswapAllocator>            GetBufferAllocator() noexcept;

public:
    void                                            PrintHelpInformation() noexcept;
    void                                            PullIPList(const ppp::string& command, bool virr) noexcept;
    int                                             PullIPList(const ppp::string& url, ppp::set<ppp::string>& ips) noexcept;
    bool                                            PullIPList(const ppp::string& url, const ppp::function<void(int, const ppp::set<ppp::string>&)>& cb) noexcept;
    int                                             PreparedArgumentEnvironment(int argc, const char* argv[]) noexcept;

protected:
    virtual bool                                    OnTick(uint64_t now) noexcept;

private:
    std::shared_ptr<AppConfiguration>               LoadConfiguration(int argc, const char* argv[], ppp::string& path) noexcept;
    bool                                            IsModeClientOrServer(int argc, const char* argv[]) noexcept;
    std::shared_ptr<NetworkInterface>               GetNetworkInterface(int argc, const char* argv[]) noexcept;
    boost::asio::ip::address                        GetNetworkAddress(const char* name, int MIN_PREFIX_ADDRESS, int MAX_PREFIX_ADDRESS, int argc, const char* argv[]) noexcept;
    boost::asio::ip::address                        GetNetworkAddress(const char* name, int MIN_PREFIX_ADDRESS, int MAX_PREFIX_ADDRESS, const char* default_address_string, int argc, const char* argv[]) noexcept;
    void                                            GetDnsAddresses(ppp::vector<boost::asio::ip::address>& addresses, int argc, const char* argv[]) noexcept;
    bool                                            PreparedLoopbackEnvironment(const std::shared_ptr<NetworkInterface>& network_interface) noexcept;
    bool                                            PrintEnvironmentInformation() noexcept;

private:
    static bool                                     NextTickAlwaysTimeout(bool next) noexcept;
    void                                            ClearTickAlwaysTimeout() noexcept;

private:
    bool                                            GetTransmissionStatistics(uint64_t& incoming_traffic, uint64_t& outgoing_traffic, std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept;

private:
    ConsoleForegroundWindowSize                     console_window_size_last_;
    std::size_t                                     console_window_buff_size_   = 0;       
    bool                                            client_mode_                = false;
    bool                                            quic_                       = false;
    std::shared_ptr<AppConfiguration>               configuration_;
    std::shared_ptr<VirtualEthernetSwitcher>        server_;
    std::shared_ptr<VEthernetNetworkSwitcher>       client_;
    ppp::string                                     configuration_path_;
    std::shared_ptr<NetworkInterface>               network_interface_;
    std::shared_ptr<Timer>                          timeout_                    = 0;
    Stopwatch                                       stopwatch_;
    PreventReturn                                   prevent_rerun_;
    ppp::transmissions::ITransmissionStatistics     transmission_statistics_;
};
static std::shared_ptr<PppApplication>              DEFAULT_;
static struct {
    bool                                            restart                     = false;
    bool                                            vbgp                        = false;
    uint64_t                                        vbgp_last                   = 0;

    int                                             link_restart                = 0;
    int                                             auto_restart                = 0;

    bool                                            virr                        = false;
    uint64_t                                        virr_next                   = 0;
    ppp::string                                     virr_argument;

    ppp::string                                     bypass;
}                                                   GLOBAL_;

PppApplication::PppApplication() noexcept
{
    // Hide the cursor that is currently flashing on the console.
    ppp::HideConsoleCursor(true);

#if defined(_WIN32)
    // Set the title information for the current user-facing console window!
    SetConsoleTitle(TEXT("PPP PRIVATE NETWORK™ 2"));

    // Set the default matrix size for the console window, valid only on Windows platforms.
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE); 
    if (NULL != hConsole)
    {
        COORD cSize = { 120, ppp::win32::Win32Native::IsWindows11OrLaterVersion() ? 46 : 47 };
        if (SetConsoleScreenBufferSize(hConsole, cSize))
        {
            SMALL_RECT rSize = { 0, 0, cSize.X - 1, cSize.Y - 1 };
            SetConsoleWindowInfo(hConsole, TRUE, &rSize);
        }
    }

    // Hide the close button of the console window to prevent users from illegally forcing the VPN program to close.
    ppp::win32::Win32Native::EnabledConsoleWindowClosedButton(false);
#endif
}

PppApplication::~PppApplication() noexcept
{
    Release();
}

void PppApplication::Release() noexcept 
{
    // Display the cursor that is currently flashing on the console.
    ppp::HideConsoleCursor(false);

#if defined(_WIN32)
    // Display the close button of the console window, otherwise the host console window close button cannot be clicked.
    ppp::win32::Win32Native::EnabledConsoleWindowClosedButton(true);
#endif

    // Turn off the global named mutex lock that prevents programs from running repeatedly!
    prevent_rerun_.Close();
}

bool PppApplication::PullIPList(const ppp::string& url, const ppp::function<void(int, const ppp::set<ppp::string>&)>& cb) noexcept
{
    // Realize automatic asn route pulling, which is similar to the dynamic route allocation of bgp border gateways.
    if (NULL == cb || url.empty()) 
    {
        return false;
    }

    auto self = shared_from_this();
    std::thread(
        [self, this, url, cb]() noexcept 
        {
            ppp::set<ppp::string> ips;
            ppp::SetThreadName("vbgp");

            int events = PullIPList(url, ips);
            cb(events, ips);
        }).detach();
    return true;
}

int PppApplication::PullIPList(const ppp::string& url, ppp::set<ppp::string>& ips) noexcept 
{
    // Realize the collection of route lists captured from Internet resources of the HTTP/HTTPS protocol that comply with the ip route configuration rules.
    using HttpClient = ppp::net::http::HttpClient;

    ppp::string host;
    ppp::string path;
    int port;
    bool https;

    if (!HttpClient::VerifyUri(url, ppp::addressof(host), &port, ppp::addressof(path), &https)) 
    {
        return -1;
    }

    HttpClient http_client((https ? "https://" : "http://") + host, chnroutes2_cacertpath_default());
    
    int http_status_code = -1;
    std::string http_response_body = http_client.Get(path, http_status_code);

    if (http_status_code < 200 || http_status_code >= 300) 
    {
        return -1;
    }

    return chnroutes2_getiplist(ips, ppp::string(), stl::transform<ppp::string>(http_response_body));
}

void PppApplication::PullIPList(const ppp::string& command, bool virr) noexcept
{
    // Notify the customer that the IPlist is being pulled from the APNIC.
    if (!virr)
    {
        fprintf(stdout, "[%s]PULL\r\n", chnroutes2_gettime(chnroutes2_gettime()).data());
    }

    // Gets ip address list and nation parameters passed into the command-line.
    ppp::string path;
    ppp::string nation;
    for (ppp::string command_string = ppp::LTrim(ppp::RTrim(command)); command_string.size() > 0;) 
    {
        std::size_t index = command_string.find('<');
        if (index == std::string::npos) 
        {
            index = command_string.find('/');
            if (index == std::string::npos) 
            {
                path = command_string;
                break;
            }
        }

        path = ppp::RTrim(command_string.substr(0, index));
        nation = ppp::LTrim(command_string.substr(index + 1));
        break;
    }

    // If no path is passed to save the IP list file, the default storage path is automatically obtained.
    if (path.empty()) 
    {
        path = chnroutes2_filepath_default();
    }

    // Rewrite the file path to an absolute path, which ensures that there are no ambiguities.
    path = File::GetFullPath(File::RewritePath(path.data()).data());

    // Getting the latest IPlist routing table information from APNIC.
    bool ok = false;
    if (virr)
    {
        // Asynchronous execution does not block the main thread.
        chnroutes2_getiplist_async(
            [path, nation](const ppp::string& response_text) noexcept 
            {
                auto process =
                    [&]() noexcept 
                    {
                        ppp::set<ppp::string> ips;
                        if (chnroutes2_getiplist(ips, nation, response_text) < 1)
                        {
                            return -1;
                        }
                    
                        // The file path is different. You only need to save the file and do not need to restart the VPN route.
                        if (GLOBAL_.bypass != path)
                        {
                            chnroutes2_saveiplist(path, ips);
                            return 0;
                        }
                    
                        // Check whether the local ip.txt is the same as the iplist captured on the apnic. If not, you need to restart the app.
                        ppp::set<ppp::string> olds;
                        ppp::string iplist = ppp::LTrim(ppp::RTrim(File::ReadAllText(path.data())));
                    
                        // Determine if it is the same as the local bypass file. If it is the same, there is no need to restart the route.
                        chnroutes2_getiplist(olds, ppp::string(), iplist);
                        if (chnroutes2_equals(ips, olds))
                        {
                            return 0;
                        }
                    
                        // Write to file failed, this may be a disk is full or other errors
                        ppp::string news = chnroutes2_toiplist(ips);
                        if (!File::WriteAllBytes(path.data(), news.data(), news.size()))
                        {
                            return -1;
                        }
                        
                        // Post the restart application event.
                        ShutdownApplication(true);
                        return 1;
                    };

                // If the returned value of the processing is less than 0, it indicates that this is caused by an error and needs to be reprocessed after a certain period of time.
                int return_code = process();
                if (return_code < 0)
                {   
                    uint64_t now = Executors::GetTickCount();
                    GLOBAL_.virr_next = now + (PPP_VIRR_UPDATE_STRETCH * 1000);
                }

                return return_code;
            });
    }
    else 
    {
        // synchronized execution will block the main thread.
        ppp::set<ppp::string> ips;
        if (chnroutes2_getiplist(ips, nation) > 0)
        {
            ok = chnroutes2_saveiplist(path, ips);
        }
    }

    // Reports the current status of the IPlist pulled from the APNIC.
    if (!virr)
    {
        if (ok)
        {
            fprintf(stdout, "[%s]OK\r\n", chnroutes2_gettime(chnroutes2_gettime()).data());
        }
        else
        {
            fprintf(stdout, "[%s]FAIL\r\n", chnroutes2_gettime(chnroutes2_gettime()).data());
        }
    }
}

bool PppApplication::PrintEnvironmentInformation() noexcept
{
    // Check if the network interface information for the current app exists and is valid, otherwise return failure.
    std::shared_ptr<NetworkInterface> network_interface = network_interface_;
    if (NULL == network_interface)
    {
        return false;
    }

    // Get the size of the console window.
    ConsoleForegroundWindowSize console_window_size;
    if (isatty(fileno(stdout)) == 0 || !ppp::GetConsoleWindowSize(console_window_size.x, console_window_size.y)) 
    {
        // No need to determine: isatty(STDOUT_FILENO) or isatty(fileno(stdout))
        fseek(stdout, 0, SEEK_SET);
        console_window_size.x = 80; /* Console-default-size: 80*25 */
        console_window_size.y = 80; 
        console_window_size.tty = false;
    }

    // Move the current console cursor position to the initial position and re-render the console output.
    if (console_window_size.tty && !ppp::SetConsoleCursorPosition(0, 0))
    {
        return false;
    }
    
    // Retrieve the current hosting environment, which essentially distinguishes between the debug and release versions, but it doesn't have significant meaning.
    ppp::string hosting_environment;
#if defined(_DEBUG)
    hosting_environment = "development";
#else
    hosting_environment = "production";
#endif

    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;
    hosting_environment = (NULL != client ? "client:" : "server:") + hosting_environment;

    // If the size of the current console window changes, clear the output content of the console window.
    if (console_window_size_last_.x != console_window_size.x || console_window_size_last_.y != console_window_size.y)
    {
        console_window_size_last_ 
            = console_window_size;

        if (console_window_size.tty)
        {
            ppp::ClearConsoleOutputCharacter();
        }
    }

    // Define an anonymous arrow function that prints and newline with a locally variable argument list.
    ppp::string console_window_content;
    if (console_window_buff_size_ > 0)
    {
        console_window_content.reserve(console_window_buff_size_);
    }

    int console_window_heights = 0;
    PrintToConsoleForegroundWindow printfn = { &console_window_size, &console_window_content, &console_window_heights };

    // Get the separator symbol for console tabs.
    ppp::string section_separator;
    section_separator = ppp::PaddingRight(section_separator, console_window_size.x, '-');

    // Printing ready-to-start VPN client or server program log informations.
    printfn("%s", PPP_APPLICATION_NAME);
    printfn("%s", section_separator.data());
    printfn("%s", "Application started. Press Ctrl+C to shut down.");
    printfn("Max Concurrent        : %d", configuration_->concurrent);
    printfn("Process               : %d", ppp::GetCurrentProcessId());

#if defined(__SIMD__)
    if (aesni::aes_cpu_is_support()) 
    {
        printfn("Triplet               : %s:%s[SIMD]", 
            ppp::GetSystemCode(), ppp::GetPlatformCode());
    }
    else 
    {
#endif
        printfn("Triplet               : %s:%s", ppp::GetSystemCode(), ppp::GetPlatformCode());
#if defined(__SIMD__)
    }
#endif

    printfn("Cwd                   : %s", ppp::GetCurrentDirectoryPath().data());
    printfn("Template              : %s", configuration_path_.data());

    // Print some information about the server's Virtual Ethernet switcher.
    std::shared_ptr<VirtualEthernetSwitcher> server = server_;
    if (NULL != server)
    {
        // Displays the link status and link Uri of the VPN back-end management server.
        auto managed_server = server->GetManagedServer(); 
        if (NULL != managed_server)
        {
            const char* link_state = "connecting";
            if (managed_server->LinkIsAvailable()) 
            {
                link_state = "established";
            }
            elif(managed_server->LinkIsReconnecting()) 
            {
                link_state = "reconnecting";
            }

            ppp::string link_url = managed_server->GetUri();
            printfn("Managed Server        : %s @(%s)", link_url.data(), link_state);
        }
    }

    // Print some information about the client's Virtual Ethernet switcher.
    if (NULL != client)
    {
        // Print the address of the remote server currently in use by the client!
        if (ppp::string remote_uri = client->GetRemoteUri(); remote_uri.size() > 0)
        {
            std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger();
            printfn("VPN Server            : %s [%s]", remote_uri.data(), NULL != exchanger && exchanger->StaticEchoAllocated() ? "static" : "dynamic");
        }

        // Print the information related to the http/socks proxy server tab.
        struct 
        {
            const char*                                     proxy;
            std::shared_ptr<VEthernetLocalProxySwitcher>    switcher;
        } proxys[] = 
            { 
                { "Http Proxy            : %s/http", client->GetHttpProxy() }, 
                { "Socks Proxy           : %s/socks", client->GetSocksProxy() }
            };
        for (auto& st : proxys)
        {
            std::shared_ptr<VEthernetLocalProxySwitcher> switcher = st.switcher;
            if (NULL == switcher) 
            {
                continue;
            }
            
            boost::asio::ip::tcp::endpoint localEP = switcher->GetLocalEndPoint();
            boost::asio::ip::address localIP = localEP.address();
            if (localIP.is_unspecified())
            {
                if (auto ni = client->GetUnderlyingNetowrkInterface(); NULL != ni)
                {
                    localIP = ni->IPAddress;
                }
            }

            // Displays the address of the http/socks proxy server for the local virtual loopback.
            ppp::string address_string = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(localIP, localEP.port())).ToString();
            printfn(st.proxy, address_string.data());
        }

#if defined(_WIN32)
        // Displays the open status of the current paper Airplane session layer plugins.
        printfn("P/A Controller        : %s", client->GetPaperAirplaneController() ? "on" : "off");
#endif
    }

    // Print some display information of the current virtual ethernet server!
    if (std::shared_ptr<VirtualEthernetSwitcher> server = server_; NULL != server)
    {
        using NAC = VirtualEthernetSwitcher::NetworkAcceptorCategories;

        // Print the public IP address and interface IP address configured for the current virtual Ethernet server!
        if (std::shared_ptr<AppConfiguration> configuration = configuration_; NULL != configuration)
        {
            printfn("Public IP             : %s", configuration->ip.public_.data());
            printfn("Interface IP          : %s", configuration->ip.interface_.data());
        }

        // Displays the port numbers of various server public service addresses that are currently monitored.
        const char* categories[] = { "ppp+tcp", "ppp+udp", "ppp+ws", "ppp+wss", "cdn+1", "cdn+2" };
        VirtualEthernetSwitcher::NetworkAcceptorCategories categoriess[] = 
        { 
            NAC::NetworkAcceptorCategories_Tcpip, 
            NAC::NetworkAcceptorCategories_Udpip, 
            NAC::NetworkAcceptorCategories_WebSocket, 
            NAC::NetworkAcceptorCategories_WebSocketSSL,
            NAC::NetworkAcceptorCategories_CDN1,
            NAC::NetworkAcceptorCategories_CDN2,
        };
        for (int i = 0, j = 0; i < arraysizeof(categories); i++)
        {
            boost::asio::ip::tcp::endpoint serverEP = server->GetLocalEndPoint(categoriess[i]);
            if (serverEP.port() <= IPEndPoint::MinPort || serverEP.port() > IPEndPoint::MaxPort)
            {
                continue;
            }

            ppp::string tmp = "Service ";
            tmp += stl::to_string<ppp::string>(++j);
            tmp = ppp::PaddingRight(tmp, 22, ' ');
            tmp += ": " + IPEndPoint::ToEndPoint(serverEP).ToString();
            tmp += "/";
            tmp += categories[i];
            printfn("%s", tmp.data());
        }
    }

    // Displays the current host environment type, in effect marking whether it is a released product or a development debug release.
    printfn("Hosting Environment   : %s", hosting_environment.data());

    // To print a blank line as a separator for major categories.
    printfn("");

    // Displays information about the bearer network interface used by the VPN.
    if (NULL != client)
    {
        // Print all display information related to TAP tabs one by one.
        struct
        {
            std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> ni;
            const char*                                                 tab;
            bool                                                        tun;
        } stnis[] = {
            { client->GetTapNetworkInterface(), "TUN", true,  },
            { client->GetUnderlyingNetowrkInterface(), "NIC", false },
        };
        for (auto&& sti : stnis)
        {
            auto ni = sti.ni; 
            if (NULL != ni)
            {
                printfn("%s", sti.tab);
                printfn("%s", section_separator.data());
#if defined(_WIN32)
                printfn("Name                  : %s[%s]", ni->Name.data(), ni->Description.data());
#else
                printfn("Name                  : %s", ni->Name.data());
#endif
                printfn("Index                 : %d", ni->Index);
#if !defined(_MACOS)
                ppp::string component_id = ni->Id;
                if (component_id.size() > 0)
                {
                    printfn("Id                    : %s", component_id.data());
                }
#endif
                printfn("Interface             : %s %s %s",
                    ni->IPAddress.to_string().data(),
                    ni->GatewayServer.to_string().data(),
                    ni->SubmaskAddress.to_string().data());

                if (sti.tun)
                {
                    for (const char* aggligator_status[] = { "none", "unknown", "connecting", "reconnecting", "established" };;)
                    {
                        if (std::shared_ptr<aggligator::aggligator> aggligator = client->GetAggligator(); NULL != aggligator)
                        {
                            int max_channel = 0;
                            int max_servers = 0;
                            aggligator->client_fetch_concurrency(max_servers, max_channel);
                            
                            aggligator::aggligator::link_status link_status = aggligator->status();
                            ppp::string aggligator_status_string = aggligator_status[(int)link_status];
                            aggligator_status_string += ", ";
                            aggligator_status_string += stl::to_string<ppp::string>(max_servers);
                            aggligator_status_string += "-server, ";
                            aggligator_status_string += stl::to_string<ppp::string>(max_channel);
                            aggligator_status_string += "-channel";

                            printfn("Aggligator            : %s", aggligator_status_string.data());
                        }
                        else
                        {
                            printfn("Aggligator            : %s", *aggligator_status);
                        }

                        break;
                    }

                    for (std::shared_ptr<ppp::transmissions::proxys::IForwarding> forwarding = client->GetForwarding();;)
                    {
                        if (NULL != forwarding)
                        {
                            ppp::string proxy_url = forwarding->GetProxyUrl();
                            printfn("Proxy Interlayer      : %s", proxy_url.data());
                        }
                        else 
                        {
                            printfn("Proxy Interlayer      : %s", "none");
                        }

                        break;
                    }

                    printfn("TCP/IP CC             : %s", client->IsLwip() ? "lwip" : "ctcp");
                    printfn("Block QUIC            : %s", client->IsBlockQUIC() ? "blocked" : "unblocked");

                    if (std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger(); NULL != exchanger)
                    {
                        const char* network_states[] = { "connecting", "established", "reconnecting" };
                        ppp::string network_state_string;
                        if (client->IsMuxEnabled())
                        {
                            network_state_string = network_states[(int)exchanger->GetMuxNetworkState()];
                            network_state_string += ", ";
                            network_state_string += stl::to_string<ppp::string>(client->Mux(NULL));
                            network_state_string += "-channel";
                        }
                        else 
                        {
                            network_state_string = "none";
                        }

                        printfn("Mux State             : %s", network_state_string.data());
                        printfn("Link State            : %s", network_states[(int)exchanger->GetNetworkState()]);
                    }
                    else
                    {
                        printfn("Mux State             : %s", "none");
                        printfn("Link State            : %s", "none");
                    }
                }

                for (std::size_t i = 0, l = ni->DnsAddresses.size(); i < l; i++)
                {
                    ppp::string tmp = "DNS Server " + stl::to_string<ppp::string>(i + 1);
                    tmp = ppp::PaddingRight(tmp, 22, ' ');
                    tmp += ": " + ni->DnsAddresses[i].to_string();
                    printfn("%s", tmp.data());
                }

                // To print a blank line as a separator for major categories.
                printfn("");
            }
        }
    }

    // Get statistics on the physical network transport layer of the Virtual Ethernet switcher.
    struct
    {
        uint64_t incoming_traffic;
        uint64_t outgoing_traffic;
        std::shared_ptr<ppp::transmissions::ITransmissionStatistics> statistics_snapshot;
    } TransmissionStatistics;

    if (!GetTransmissionStatistics(TransmissionStatistics.incoming_traffic, TransmissionStatistics.outgoing_traffic, TransmissionStatistics.statistics_snapshot))
    {
        TransmissionStatistics.incoming_traffic = 0;
        TransmissionStatistics.outgoing_traffic = 0;
        TransmissionStatistics.statistics_snapshot = NULL;
    }

    // Implement some information printing on the console window for VPN information.
    printfn("%s", "VPN");
    printfn("%s", section_separator.data());
    printfn("Duration              : %s", stopwatch_.Elapsed().ToString("TT:mm:ss", false).data());
    if (NULL != server) 
    {
        printfn("Sessions              : %s", stl::to_string<ppp::string>(server->GetAllExchangerNumber()).data());
    }

    printfn("TX                    : %s", ppp::StrFormatByteSize(TransmissionStatistics.outgoing_traffic).data());
    printfn("RX                    : %s", ppp::StrFormatByteSize(TransmissionStatistics.incoming_traffic).data());
    if (auto statistics = TransmissionStatistics.statistics_snapshot; statistics)
    {
        printfn("IN                    : %s", ppp::StrFormatByteSize(statistics->IncomingTraffic).data());
        printfn("OUT                   : %s", ppp::StrFormatByteSize(statistics->OutgoingTraffic).data());
    }

    // Dynamically calculates the default buffer size for the console window's string container before the next print operation.
    std::size_t console_window_content_size = console_window_content.size();
    if (console_window_content_size > console_window_buff_size_)
    {
        console_window_buff_size_ = ppp::Malign(console_window_content_size, 1 << 6);
    }

    // Print text to the console window screen, or on Linux to the _tty of the shell-terminal.
    fprintf(stdout, "%s", console_window_content.data());
    return true;
}

bool PppApplication::PreparedLoopbackEnvironment(const std::shared_ptr<NetworkInterface>& network_interface) noexcept
{
    std::shared_ptr<AppConfiguration> configuration = GetConfiguration();
    if (NULL == configuration)
    {
        return false;
    }

    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULL == context)
    {
        return false;
    }
    else
    {
#if defined(_WIN32)
        // The system32 firewall Settings are automatically deployed and set in the os, 
        // Because overlapping io requires its support, otherwise it cannot be used.
        ppp::string executable_path = File::GetFullPath(File::RewritePath(ppp::GetFullExecutionFilePath().data()).data());

        // Compatibility failure: In some LTSB versions of Windows operating systems, the kernel firewall may not be initialized, 
        // Resulting in openppp2 having no way to configure the kernel firewall rules in this scenario.
        ppp::win32::network::Fw::NetFirewallAddApplication(PPP_APPLICATION_NAME, executable_path.data());
        ppp::win32::network::Fw::NetFirewallAddAllApplication(PPP_APPLICATION_NAME, executable_path.data());

        // There are some basic transactions that need to be configured in the operating system before running openppp2 client mode.
        if (client_mode_)
        {
            // If the configuration file specifies that the paper plane needs to be pulled up, 
            // The initialization actions associated with the paper plane are performed.
            if (network_interface->HostedNetwork && configuration->client.paper_airplane.tcp)
            {
                // Try to install or update the paper airplane plugin into the operating system.
                if (ppp::app::client::lsp::PaperAirplaneController::Install() < 0)
                {
                    return false;
                }
            }

            // Prohibit some system programs from loading LSPS /DLLs plug-ins because these programs may cause problems. 
            // The solution is to completely prohibit these programs from loading LSP/s.
            ppp::app::client::lsp::PaperAirplaneController::NoLsp();

            // Reset the paper plane controller Settings because the program may have closed abnormally, 
            // Which may cause the paper plane controller to not close properly.
            ppp::app::client::lsp::PaperAirplaneController::Reset();
        }
#endif
    }

    bool success = false;
    if (client_mode_)
    {
        std::shared_ptr<VEthernetNetworkSwitcher> ethernet = NULL;
        std::shared_ptr<ITap> tap = NULL;
        do
        {
            // Try to open the tun/tap virtual Ethernet device!
#if defined(_WIN32)
            tap = ITap::Create(context,
                network_interface->ComponentId,
                Ipep::ToAddressString<ppp::string>(network_interface->IPAddress),
                Ipep::ToAddressString<ppp::string>(network_interface->GatewayServer),
                Ipep::ToAddressString<ppp::string>(network_interface->SubmaskAddress),
                network_interface->LeaseTimeInSeconds,
                network_interface->HostedNetwork,
                Ipep::AddressesTransformToStrings(network_interface->DnsAddresses));
#else
            tap = ITap::Create(context,
                network_interface->ComponentId,
                Ipep::ToAddressString<ppp::string>(network_interface->IPAddress),
                Ipep::ToAddressString<ppp::string>(network_interface->GatewayServer),
                Ipep::ToAddressString<ppp::string>(network_interface->SubmaskAddress),
                network_interface->Promisc,
                network_interface->HostedNetwork,
                Ipep::AddressesTransformToStrings(network_interface->DnsAddresses));
#endif
            if (NULL == tap)
            {
                fprintf(stdout, "%s\r\n", "Open tun/tap driver failure.");
                break;
            }
            else
            {
                fprintf(stdout, "%s\r\n", "Open tun/tap driver success.");
            }

            // Gets the current buffer allocator and sets it to tun/tap.
            tap->BufferAllocator = configuration->GetBufferAllocator();
            if (!tap->Open())
            {
                fprintf(stdout, "%s\r\n", "Listen tun/tap driver failure.");
                break;
            }
            else
            {
                fprintf(stdout, "%s\r\n", "Listen tun/tap driver success.");
            }

            // Construct the switcher instance after creating the virtual ethernet network switcher object in client mode 
            // And adding the iplist file to load to bypass the vpn route.
            ethernet = ppp::make_shared_object<VEthernetNetworkSwitcher>(context, network_interface->Lwip, network_interface->VNet, configuration->concurrent > 1, configuration);
            if (NULL == ethernet)
            {
                break;
            }

#if !defined(_WIN32)
            // Ssmt technology squeezes the machine performance of the device as much as possible for VPN VEthernet services.
            ethernet->Ssmt(&network_interface->Ssmt);
#if defined(_LINUX)
            ethernet->SsmtMQ(&network_interface->SsmtMQ);
            ethernet->ProtectMode(&network_interface->ProtectNetwork);
#endif
#endif
            ethernet->Mux(&network_interface->Mux);
            ethernet->MuxAcceleration(&network_interface->MuxAcceleration);
            ethernet->StaticMode(&network_interface->StaticMode);
            ethernet->PreferredNgw(network_interface->Ngw);
            ethernet->PreferredNic(network_interface->Nic);
#if defined(_LINUX)
            ethernet->AddLoadIPList(network_interface->Bypass, network_interface->BypassNic, network_interface->BypassNgw, ppp::string());
#else
            ethernet->AddLoadIPList(network_interface->Bypass, network_interface->BypassNgw, ppp::string());
#endif
            for (auto&& route : configuration->client.routes)
            {
                ppp::string path = File::GetFullPath(File::RewritePath(route.path.data()).data());
                if (path.empty()) 
                {
                    continue;
                }

#if defined(_LINUX)
                ethernet->AddLoadIPList(path, route.nic, Ipep::ToAddress(route.ngw), route.vbgp);
#else
                ethernet->AddLoadIPList(path, Ipep::ToAddress(route.ngw), route.vbgp);
#endif
            }

            ethernet->LoadAllDnsRules(network_interface->DNSRules, true);
            if (!ethernet->Open(tap))
            {
                auto ni = ethernet->GetUnderlyingNetowrkInterface();
                if (NULL != ni)
                {
                    fprintf(stdout, "%s\r\n", "Failed to open the vpn client.");
                }
                else
                {
                    fprintf(stdout, "%s\r\n", "No available nic could be found.");
                }
                break;
            }

            success = true;
            client_ = ethernet;
        } while (false);

        // When the creation of a virtual Ethernet switch fails, it is important to close and reclaim any unnecessary managed resources.
        if (!success)
        {
            client_.reset();
            if (NULL != ethernet)
            {
                ethernet->Dispose();
            }

            // Turn off the tun/tap virtual network card driver that has been opened.
            if (NULL != tap)
            {
                tap->Dispose();
            }
        }
    }
    else
    {
        std::shared_ptr<VirtualEthernetSwitcher> ethernet = NULL;
        do
        {
            // Instantiate and open a vpn virtual ethernet network switcher object in server-mode.
            ethernet = ppp::make_shared_object<VirtualEthernetSwitcher>(configuration);
            if (NULL == ethernet)
            {
                break;
            }

            if (!ethernet->Open(network_interface->FirewallRules))
            {
                fprintf(stdout, "%s\r\n", "Failed to open the vpn server.");
                break;
            }

            // Run all externally provided services of the switcher object that have just been instantiated and opened.
            if (!ethernet->Run())
            {
                fprintf(stdout, "%s\r\n", "Listen to vpn server failure.");
                break;
            }

            success = true;
            server_ = ethernet;
        } while (false);

        // When the creation of a virtual Ethernet switch fails, it is important to close and reclaim any unnecessary managed resources.
        if (!success)
        {
            server_.reset();
            if (NULL != ethernet)
            {
                ethernet->Dispose();
            }
        }
    }
    return success;
}

std::shared_ptr<BufferswapAllocator> PppApplication::GetBufferAllocator() noexcept
{
    std::shared_ptr<AppConfiguration> configuration = GetConfiguration();
    if (NULL == configuration)
    {
        return NULL;
    }
    else
    {
        return configuration->GetBufferAllocator();
    }
}

int PppApplication::PreparedArgumentEnvironment(int argc, const char* argv[]) noexcept
{
    // Check whether the network mode is set to flash.
    Socket::SetDefaultFlashTypeOfService(ppp::ToBoolean(ppp::GetCommandArgument("--tun-flash", argc, argv).data()));
    if (ppp::IsInputHelpCommand(argc, argv))
    {
        return -1;
    }

    ppp::string path;
    std::shared_ptr<AppConfiguration> configuration = LoadConfiguration(argc, argv, path);
    if (NULL == configuration)
    {
        return -1;
    }
    else
    {
        // Gets whether client mode or server mode is currently running.
        client_mode_ = IsModeClientOrServer(argc, argv);
    }

    int max_concurrent = configuration->concurrent - 1;
    if (max_concurrent > 0)
    {
        Executors::SetMaxSchedulers(max_concurrent);
        if (!client_mode_)
        {
            Executors::SetMaxThreads(configuration->GetBufferAllocator(), max_concurrent);
        }
    }

    std::shared_ptr<NetworkInterface> network_interface = GetNetworkInterface(argc, argv);
    if (NULL == network_interface)
    {
        return -1;
    }

    configuration_path_ = path;
    configuration_ = configuration;
    network_interface_ = network_interface;
    
    ppp::net::asio::vdns::ttl = configuration->udp.dns.ttl;
    ppp::net::asio::vdns::enabled = configuration->udp.dns.turbo;
    return 0;
}

static ppp::string GetVersionString(int major, int minor, int patch = 0) noexcept
{
    char buf[100];
    *buf = '\x0';

    if (patch != 0) 
    {
        snprintf(buf, sizeof(buf), "%d.%d.%d", major, minor, patch);
    }
    else 
    {
        snprintf(buf, sizeof(buf), "%d.%d", major, minor);
    }

    return buf;
}

static ppp::string GetBoostVersionString() noexcept 
{
    constexpr int version = BOOST_VERSION;

    int minor = (version / 100) % 100;
    int major = version / 100000;
    int patch = version % 100;

    return GetVersionString(major, minor, patch);
}

void PppApplication::PrintHelpInformation() noexcept
{
    ppp::string execution_file_name = ppp::GetExecutionFileName();
    ppp::string cwd = ppp::GetCurrentDirectoryPath();
    
    // Define column widths for perfect alignment
    static constexpr int col_option_width = 40;
    static constexpr int col_description_width = 48;
    static constexpr int col_default_width = 23;
    static constexpr int col_command_width = 38;
    static constexpr int col_command_width_utlity = col_command_width + 2;

    // Print header information
    printf("┌──────────────────────────────────────────────────────────────────────┐\n");
    printf("│                       PPP PRIVATE NETWORK™ 2                         │\n");
    printf("│  Next-generation security network access technology, providing high- │\n");
    printf("│  performance Virtual Ethernet tunneling service.                     │\n");
    printf("└──────────────────────────────────────────────────────────────────────┘\n\n");
    
    printf("Version:      %s\n", PPP_APPLICATION_VERSION);
    printf("Copyright:    (C) 2017 ~ 2055 SupersocksR ORG. All rights reserved.\n");
    printf("Current Dir:  %s\n\n", cwd.data());
    
    printf("USAGE:\n");
    printf("    %s [OPTIONS]\n\n", execution_file_name.data());
    
    // GENERAL OPTIONS
    printf("GENERAL OPTIONS:\n");
    printf("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n");
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "OPTION", 
        col_description_width, "DESCRIPTION", 
        col_default_width, "DEFAULT");
    printf("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--rt=[yes|no]", 
        col_description_width, "Enable real-time mode", 
        col_default_width, "yes");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--mode=[client|server]", 
        col_description_width, "Set running mode", 
        col_default_width, "server");

    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--config=<path>", 
        col_description_width, "Configuration file path", 
        col_default_width, "./appsettings.json");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--dns=<ip-list>", 
        col_description_width, "DNS server addresses", 
        col_default_width, "8.8.8.8,8.8.4.4");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun-flash=[yes|no]", 
        col_description_width, "Enable advanced QoS policy", 
        col_default_width, "disabled");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--auto-restart=<seconds>", 
        col_description_width, "Auto restart interval", 
        col_default_width, "0 (disabled)");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--link-restart=<count>", 
        col_description_width, "Link reconnection attempts", 
        col_default_width, "0");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--block-quic=[yes|no]", 
        col_description_width, "Block QUIC protocol traffic", 
        col_default_width, "no");
    
    printf("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n");
    
    // SERVER-SPECIFIC OPTIONS
    printf("SERVER-SPECIFIC OPTIONS:\n");
    printf("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n");
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "OPTION", 
        col_description_width, "DESCRIPTION", 
        col_default_width, "DEFAULT");
    printf("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--firewall-rules=<file>", 
        col_description_width, "Firewall rules file", 
        col_default_width, "./firewall_rules.txt");
    
    printf("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n");
    
    // CLIENT-SPECIFIC OPTIONS
    printf("CLIENT-SPECIFIC OPTIONS:\n");
    printf("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n");
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "OPTION", 
        col_description_width, "DESCRIPTION", 
        col_default_width, "DEFAULT");
    printf("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--lwip=[yes|no]", 
        col_description_width, "Network protocol stack selection",
        col_default_width, 
#if defined(_WIN32)
        "yes"
#else
        "no"
#endif
    );
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--vbgp=[yes|no]", 
        col_description_width, "Enable virtual BGP routing", 
        col_default_width, "yes");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--nic=<interface>", 
        col_description_width, "Specify physical network interface", 
        col_default_width, "auto-select");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--ngw=<ip>", 
        col_description_width, "Force gateway address", 
        col_default_width, "auto-detect");
    
    ppp::string default_tun_name;
#if defined(_WIN32)
    default_tun_name = "PPP";
#elif defined(_MACOS)
    default_tun_name = "utun0";
#else
    default_tun_name = "ppp";
#endif
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun=<name>", 
        col_description_width, "Virtual adapter name", 
        col_default_width, default_tun_name.c_str());
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun-ip=<ip>", 
        col_description_width, "Virtual adapter IP address", 
        col_default_width, "10.0.0.2");
    
    ppp::string default_tun_gw;
#if defined(_WIN32)
    default_tun_gw = "10.0.0.0";
#else
    default_tun_gw = "10.0.0.1";
#endif
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun-gw=<ip>", 
        col_description_width, "Virtual adapter gateway", 
        col_default_width, default_tun_gw.c_str());
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun-mask=<bits>", 
        col_description_width, "Subnet mask bits", 
        col_default_width, "30");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun-vnet=[yes|no]", 
        col_description_width, "Enable subnet forwarding", 
        col_default_width, "yes");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun-host=[yes|no]", 
        col_description_width, "Prefer host network", 
        col_default_width, "yes");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun-static=[yes|no]", 
        col_description_width, "Enable static tunnel", 
        col_default_width, "no");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun-mux=<connections>", 
        col_description_width, "MUX connection count (0=disabled)", 
        col_default_width, "0");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun-mux-acceleration=<mode>", 
        col_description_width, "MUX acceleration mode (0-3)", 
        col_default_width, "0 (standard)");
    
#if defined(_LINUX) || defined(_MACOS)
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun-promisc=[yes|no]", 
        col_description_width, "Enable promiscuous mode", 
        col_default_width, "yes");
#endif
    
#if defined(_MACOS)
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun-ssmt=<threads>", 
        col_description_width, "SSMT thread optimization", 
        col_default_width, "4");
#elif defined(_LINUX)
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun-ssmt=<N>[/<mode>]", 
        col_description_width, "SSMT threads (N), mode: st or mq (optional)", 
        col_default_width, "0/st");
#endif
    
#if defined(_LINUX)
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun-route=[yes|no]", 
        col_description_width, "Route compatibility", 
        col_default_width, "no");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun-protect=[yes|no]", 
        col_description_width, "Route protection", 
        col_default_width, "yes");
#endif
    
#if defined(_WIN32)
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--tun-lease-time-in-seconds=<sec>", 
        col_description_width, "DHCP lease time", 
        col_default_width, "7200");
#endif
    
    printf("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n");
    
    // ROUTING OPTIONS
    printf("ROUTING OPTIONS:\n");
    printf("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n");
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "OPTION", 
        col_description_width, "DESCRIPTION", 
        col_default_width, "DEFAULT");
    printf("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--bypass=<file>", 
        col_description_width, "Bypass IP list file", 
        col_default_width, "./ip.txt");
    
#if defined(_LINUX)
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--bypass-nic=<interface>", 
        col_description_width, "Interface for bypass list", 
        col_default_width, "auto-select");
#endif
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--bypass-ngw=<ip>", 
        col_description_width, "Gateway for bypass list", 
        col_default_width, "auto-detect");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--virr=[file/country]", 
        col_description_width, "Auto-update and take effect IP-list", 
        col_default_width, "./ip.txt/CN");
    
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--dns-rules=<file>", 
        col_description_width, "DNS rules configuration", 
        col_default_width, "./dns_rules.txt");
    
    printf("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n");
    
    // WINDOWS-SPECIFIC COMMANDS
#if defined(_WIN32)
    printf("WINDOWS-SPECIFIC COMMANDS:\n");
    printf("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┐\n");
    printf("│ %-*s │ %-*s │\n", 
        col_command_width_utlity, "COMMAND", 
        col_description_width, "DESCRIPTION");
    printf("├──────────────────────────────────────────┼──────────────────────────────────────────────────┤\n");
    
    printf("│ %-*s │ %-*s │\n", 
        col_command_width_utlity, "--system-network-reset", 
        col_description_width, "Reset Windows network stack");
    
    printf("│ %-*s │ %-*s │\n", 
        col_command_width_utlity, "--system-network-optimization", 
        col_description_width, "Optimize network performance");
    
    printf("│ %-*s │ %-*s │\n", 
        col_command_width_utlity, "--system-network-preferred-ipv4", 
        col_description_width, "Set IPv4 as preferred protocol");
    
    printf("│ %-*s │ %-*s │\n", 
        col_command_width_utlity, "--system-network-preferred-ipv6", 
        col_description_width, "Set IPv6 as preferred protocol");
    
    printf("│ %-*s │ %-*s │\n", 
        col_command_width_utlity, "--no-lsp <program>", 
        col_description_width, "Disable LSP for specified program");
    
    printf("└──────────────────────────────────────────┴──────────────────────────────────────────────────┘\n\n");
#endif
    
    // UTILITY COMMANDS
    printf("UTILITY COMMANDS:\n");
    printf("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n");
    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "COMMAND", 
        col_description_width, "DESCRIPTION", 
        col_default_width, "DEFAULT");
    printf("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n");

    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--help", 
        col_description_width, "Display this help information", 
        col_default_width, "none");

    printf("│ %-*s │ %-*s │ %-*s │\n", 
        col_option_width, "--pull-iplist [file/country]", 
        col_description_width, "Download country IP list from APNIC", 
        col_default_width, "./ip.txt/CN");

    printf("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n");
    
    // Contact information
    printf("CONTACT:\n");
    printf("    Telegram: https://t.me/supersocksr_group\n\n");
    
    // Dependencies information
    printf("DEPENDENCIES:\n");
    printf("    boost@%s", GetBoostVersionString().c_str());
    
#if defined(__GLIBC__) && defined(__GLIBC_MINOR__)
    printf(", libc@%s", GetVersionString(__GLIBC__, __GLIBC_MINOR__).c_str());
#if defined(__MUSL__)
    printf("/musl");
#else
    printf("/glibc");
#endif
#endif
    
#if defined(LIBCURL_VERSION_MAJOR)
    printf(", curl@%s", GetVersionString(LIBCURL_VERSION_MAJOR, LIBCURL_VERSION_MINOR, LIBCURL_VERSION_PATCH).c_str());
#endif
    
#if defined(OPENSSL_VERSION_MAJOR)
    printf(", openssl@%s", GetVersionString(OPENSSL_VERSION_MAJOR, OPENSSL_VERSION_MINOR, OPENSSL_VERSION_PATCH).c_str());
#else
    printf(", openssl@1.1.1");
#endif
    
#if defined(JEMALLOC_VERSION_MAJOR)
    printf(", jemalloc@%s", GetVersionString(JEMALLOC_VERSION_MAJOR, JEMALLOC_VERSION_MINOR, JEMALLOC_VERSION_BUGFIX).c_str());
#endif
    
    printf("\n");
}

boost::asio::ip::address PppApplication::GetNetworkAddress(const char* name, int MIN_PREFIX_ADDRESS, int MAX_PREFIX_ADDRESS, int argc, const char* argv[]) noexcept
{
    ppp::string address_string = ppp::GetCommandArgument(name, argc, argv);
    if (address_string.empty())
    {
        return boost::asio::ip::address_v4::any();
    }

    address_string = ppp::LTrim<ppp::string>(address_string);
    address_string = ppp::RTrim<ppp::string>(address_string);
    if (address_string.empty())
    {
        return boost::asio::ip::address_v4::any();
    }

    boost::asio::ip::address address;
    if (StringAuxiliary::WhoisIntegerValueString(address_string))
    {
        int prefix = atoll(address_string.data());
        if (prefix < 1 || prefix > MAX_PREFIX_ADDRESS)
        {
            prefix = MAX_PREFIX_ADDRESS;
        }
        elif(MIN_PREFIX_ADDRESS > 0 && prefix < MIN_PREFIX_ADDRESS)
        {
            prefix = MIN_PREFIX_ADDRESS;
        }

        auto prefix_to_netmask = IPEndPoint::PrefixToNetmask(prefix);
        address = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(prefix_to_netmask, 0).address();
    }
    else
    {
        address = Ipep::ToAddress(address_string, true);
    }

    if (IPEndPoint::IsInvalid(address))
    {
        return boost::asio::ip::address_v4::any();
    }

    return address;
}

boost::asio::ip::address PppApplication::GetNetworkAddress(const char* name, int MIN_PREFIX_ADDRESS, int MAX_PREFIX_ADDRESS, const char* default_address_string, int argc, const char* argv[]) noexcept
{
    boost::asio::ip::address address = GetNetworkAddress(name, MIN_PREFIX_ADDRESS, MAX_PREFIX_ADDRESS, argc, argv);
    if (IPEndPoint::IsInvalid(address))
    {
        address = boost::asio::ip::address_v4::any();
    }

    if (IPEndPoint::IsInvalid(address))
    {
        if (NULL == default_address_string)
        {
            default_address_string = "";
        }

        return Ipep::ToAddress(default_address_string, false);
    }
    else
    {
        return address;
    }
}

void PppApplication::GetDnsAddresses(ppp::vector<boost::asio::ip::address>& addresses, int argc, const char* argv[]) noexcept
{
#if defined(_WIN32)
    bool at_least_two = true;
    if (!client_mode_) {
        at_least_two = false;
    }

#else
    bool at_least_two = false;
#endif

    ppp::string dns = ppp::GetCommandArgument("--dns", argc, argv);
    if (Ipep::ToDnsAddresses(dns, addresses, at_least_two) < 1) {
        boost::system::error_code ec;
        addresses.emplace_back(ppp::StringToAddress(PPP_PREFERRED_DNS_SERVER_1, ec));
        addresses.emplace_back(ppp::StringToAddress(PPP_PREFERRED_DNS_SERVER_2, ec));
    }
}

std::shared_ptr<NetworkInterface> PppApplication::GetNetworkInterface(int argc, const char* argv[]) noexcept
{
    std::shared_ptr<NetworkInterface> ni = ppp::make_shared_object<NetworkInterface>();
    if (NULL != ni)
    {
#if defined(_WIN32)
        ni->Lwip = ppp::ToBoolean(ppp::GetCommandArgument("--lwip", argc, argv, "y").data());
#else
        ni->Lwip = ppp::ToBoolean(ppp::GetCommandArgument("--lwip", argc, argv).data());
#endif

        ni->Nic = ppp::RTrim(ppp::LTrim(ppp::GetCommandArgument("--nic", argc, argv)));
        ni->BlockQUIC = ppp::ToBoolean(ppp::GetCommandArgument("--block-quic", argc, argv).data());

        // Get and set the dns domain name server to be used.
        GetDnsAddresses(ni->DnsAddresses, argc, argv);
        if (!ni->DnsAddresses.empty()) {
            auto dns_servers = ppp::net::asio::vdns::servers;
            dns_servers->clear();

            for (const boost::asio::ip::address& dns_server : ni->DnsAddresses) {
                dns_servers->emplace_back(boost::asio::ip::udp::endpoint(dns_server, PPP_DNS_SYS_PORT));
            }
        }

        ni->Ngw = GetNetworkAddress("--ngw", 0, 32, "0.0.0.0", argc, argv);
        ni->IPAddress = GetNetworkAddress("--tun-ip", 0, 32, "10.0.0.2", argc, argv);
        ni->SubmaskAddress = GetNetworkAddress("--tun-mask", 16, 32, "255.255.255.252", argc, argv); // IP-ranges: 0 ~ 65535.

#if defined(_WIN32)
        // Suggested Ethernet card address setting for TAP-Windows(ndis-5/6) driver.
        ni->GatewayServer = GetNetworkAddress("--tun-gw", 0, 32, "10.0.0.0", argc, argv);

        // DHCP-MASQ lease time in seconds.
        ni->LeaseTimeInSeconds = strtoul(ppp::GetCommandArgument("--tun-lease-time-in-seconds", argc, argv).data(), NULL, 10);
        if (ni->LeaseTimeInSeconds < 1)
        {
            ni->LeaseTimeInSeconds = 7200;
        }
#else
        // Suggested Ethernet card address setting for Linux or unix tun/tap driver.
        ni->GatewayServer = GetNetworkAddress("--tun-gw", 0, 32, "10.0.0.1", argc, argv);
#endif

        // Enabled the vEthernet bearer network to take over the Layer L2/L3 vEthernet traffic of the entire operating system.
        ni->IPAddress = Ipep::FixedIPAddress(ni->IPAddress, ni->GatewayServer, ni->SubmaskAddress);
        ni->StaticMode = ppp::ToBoolean(ppp::GetCommandArgument("--tun-static", argc, argv).data());
        ni->HostedNetwork = ppp::ToBoolean(ppp::GetCommandArgument("--tun-host", argc, argv, "y").data());
        ni->VNet = ppp::ToBoolean(ppp::GetCommandArgument("--tun-vnet", argc, argv, "y").data());

#if defined(_LINUX)
        ni->BypassNic = ppp::RTrim(ppp::LTrim(ppp::GetCommandArgument("--bypass-nic", argc, argv)));
#endif
        ni->BypassNgw = GetNetworkAddress("--bypass-ngw", 0, 32, "0.0.0.0", argc, argv);
        ni->Bypass = File::GetFullPath(File::RewritePath(ppp::LTrim(ppp::RTrim(ppp::GetCommandArgument("--bypass", argc, argv, "./ip.txt"))).data()).data());

        ni->DNSRules = ppp::GetCommandArgument("--dns-rules", argc, argv, "./dns-rules.txt");
        ni->FirewallRules = ppp::GetCommandArgument("--firewall-rules", argc, argv, "./firewall-rules.txt");
        ni->Mux = (uint16_t)std::max<int>(0, atoi(ppp::GetCommandArgument("--tun-mux", argc, argv).data()));
        ni->MuxAcceleration = (uint8_t)std::max<int>(0, atoi(ppp::GetCommandArgument("--tun-mux-acceleration", argc, argv).data()));
        if (ni->MuxAcceleration > PPP_MUX_ACCELERATION_MAX) 
        {
            ni->MuxAcceleration = 0;
        }

#if defined(_WIN32)
        ni->SetHttpProxy = ppp::ToBoolean(ppp::GetCommandArgument("--set-http-proxy", argc, argv).data());
        ni->ComponentId = ppp::tap::TapWindows::FindComponentId(ppp::GetCommandArgument("--tun", argc, argv));
#else
        ni->ComponentId = ppp::GetCommandArgument("--tun", argc, argv);

#if defined(_LINUX)
        // Determine whether to set the control mode of the vEthernet route to compatibility mode.
        if (ppp::ToBoolean(ppp::GetCommandArgument("--tun-route", argc, argv).data())) 
        {
            ppp::tap::TapLinux::CompatibleRoute(true);
        }

        // Linux requires network protection services to be turned on, but this may not be compatible on some Linux devices.
        ni->ProtectNetwork = ppp::ToBoolean(ppp::GetCommandArgument("--tun-protect", argc, argv, "y").data());
        ni->Ssmt = 0;
        ni->SsmtMQ = false;

        if (ppp::string ssmt = ppp::GetCommandArgument("--tun-ssmt", argc, argv); !ssmt.empty()) 
        {
            char ssmt_mq_keys[] = { 'm', 'q' };
            for (int j = 0; j < arraysizeof(ssmt_mq_keys); j++) 
            { 
                if (ssmt.find(ssmt_mq_keys[j]) != ppp::string::npos) 
                {
                    ni->SsmtMQ = true;
                    break;
                }
            }

            ni->Ssmt = std::max<int>(0, atoi(ssmt.data()));
        }
#elif defined(_MACOS)
        ni->Ssmt = std::max<int>(0, atoi(ppp::GetCommandArgument("--tun-ssmt", argc, argv).data()));
#endif

#if defined(_MACOS) || defined(_LINUX)
        // MacOS/Linux Virtual Ethernet is set to the promiscuous NIC mode by default.
        ni->Promisc = ppp::ToBoolean(ppp::GetCommandArgument("--tun-promisc", argc, argv, "y").data());
#endif
#endif

        ni->ComponentId = ppp::LTrim<ppp::string>(ni->ComponentId);
        ni->ComponentId = ppp::RTrim<ppp::string>(ni->ComponentId);

        // If no virtual network card name is specified else find the default virtual ethernet network card name.
        if (ni->ComponentId.empty()) 
        {
            ni->ComponentId = ppp::tap::ITap::FindAnyDevice();
        }
    }
    return ni;
}

bool PppApplication::IsModeClientOrServer(int argc, const char* argv[]) noexcept
{
    static constexpr const char* keys[] = { "--mode", "--m", "-mode", "-m" };

    ppp::string mode_string;
    for (const char* key : keys)
    {
        mode_string = ppp::GetCommandArgument(key, argc, argv);
        if (mode_string.size() > 0)
        {
            break;
        }
    }

    if (mode_string.empty())
    {
        mode_string = "server";
    }

    mode_string = ppp::ToLower<ppp::string>(mode_string);
    mode_string = ppp::LTrim<ppp::string>(mode_string);
    mode_string = ppp::RTrim<ppp::string>(mode_string);
    return mode_string.empty() ? false : mode_string[0] == 'c';
}

void PppApplication::Dispose() noexcept
{
    std::shared_ptr<VirtualEthernetSwitcher> server = std::move(server_);
    if (NULL != server)
    {
        server_.reset();
        server->Dispose();
    }

    std::shared_ptr<VEthernetNetworkSwitcher> client = std::move(client_);
    if (NULL != client)
    {
        // Release the local virtual ethernet client switcher.
        client_.reset();
        client->Dispose();

#if defined(_WIN32)
        // Restore the original QUIC support Settings of the current system.
        ppp::net::proxies::HttpProxy::SetSupportExperimentalQuicProtocol(quic_);

        // Clear the proxy configured in the system environment when the VPN client adapter program works.
        if (network_interface_->SetHttpProxy)
        {
            client->ClearHttpProxyToSystemEnv();
        }
#endif
    }

    ClearTickAlwaysTimeout();
}

bool PppApplication::GetTransmissionStatistics(uint64_t& incoming_traffic, uint64_t& outgoing_traffic, std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept
{
    // Initialization requires the initial value of the FAR outgoing parameter.
    statistics_snapshot = NULL;
    incoming_traffic = 0;
    outgoing_traffic = 0;

    // The transport layer network statistics are obtained only when the current client switch or server switch is not released.
    std::shared_ptr<VirtualEthernetSwitcher> server = server_;
    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;
    if ((NULL != server && !server->IsDisposed()) || (NULL != client && !client->IsDisposed()))
    {
        // Obtain transport layer traffic statistics from the client switch or server switch management object.
        std::shared_ptr<ppp::transmissions::ITransmissionStatistics> transmission_statistics;
        if (NULL != client)
        {
            transmission_statistics = client->GetStatistics();
        }
        elif(NULL != server)
        {
            transmission_statistics = server->GetStatistics();
        }

        if (NULL != transmission_statistics)
        {
            return ppp::transmissions::ITransmissionStatistics::GetTransmissionStatistics(transmission_statistics, transmission_statistics_, incoming_traffic, outgoing_traffic, statistics_snapshot);
        }
    }

    return false;
}

bool PppApplication::OnTick(uint64_t now) noexcept
{
    using RouteIPListTablePtr = VEthernetNetworkSwitcher::RouteIPListTablePtr;
    using NetworkState        = VEthernetExchanger::NetworkState;

    // Print the current VPN client or server running status and environment information!
    PrintEnvironmentInformation();

#if defined(_WIN32)
    // Windows platform calls system functions to optimize the size of the working memory used by the program in order to minimize 
    // The use of physical memory resources on low memory desktop platforms.
    ppp::win32::Win32Native::OptimizedProcessWorkingSize();
#endif

    // Process the support flow for setting the auto-restart command line options.
    if (GLOBAL_.auto_restart > 0)
    {
        int64_t elapsed_milliseconds = stopwatch_.ElapsedMilliseconds() / 1000;
        if (elapsed_milliseconds > 0 && elapsed_milliseconds >= GLOBAL_.auto_restart)
        {
            return ShutdownApplication(true);
        }
    }

    // Check whether the current VPN client exists.
    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;
    if (NULL == client) 
    {
        return false;
    }

    // Check whether the current VPN exchanger exists.
    std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger(); 
    if (NULL == exchanger)
    {
        return false;
    }

    // Determine the link status of the current VPN network.
    NetworkState network_state = exchanger->GetNetworkState();
    if (network_state == NetworkState::NetworkState_Established) 
    {
        // If the link restart is set, this is used to fix the issue where the VPN cannot continue to work after the physical network card of the VM is disabled and then enabled.
        if (GLOBAL_.link_restart > 0) 
        {
            // If the number of link reconnections exceeds a certain number, the program needs to be restarted immediately.
            if (exchanger->GetReconnectionCount() >= GLOBAL_.link_restart)
            {
                return ShutdownApplication(true);
            }
        }
    }
    else 
    {
        return false;
    }

    // The automatic iplist option takes effect only when enabled and automatically attempts to synchronize from apnic once every minute.
    if (now >= GLOBAL_.virr_next)
    {
        // Update the last automatic pull time and decide whether to pull the IP list file based on the en1abled options.
        GLOBAL_.virr_next = now + (PPP_VIRR_UPDATE_INTERVAL * 1000);
        if (GLOBAL_.virr)
        {
            PullIPList(GLOBAL_.virr_argument, true);
        }
    }

    // To achieve automatic pulling of the operator routing table, if the operator routing table changes, the routes will be restarted to take effect. This is similar to vBGP.
    if ((now - GLOBAL_.vbgp_last) / 1000 >= PPP_VBGP_UPDATE_INTERVAL)
    {
        GLOBAL_.vbgp_last = now;
        if (RouteIPListTablePtr vbgp = client->GetVbgp(); GLOBAL_.vbgp && NULL != vbgp)
        {
            // Loop the border gateway route list in vBGP, which is similar to bgp receiving route hop broadcasts from different line ASNs
            for (auto&& kv : *vbgp) 
            {
                // The low-version C/C++ compiler of the OS X platform has source code compilation compatibility.  
                // In such scenarios, the temporary local variable auto&& [path, url] cannot be captured.
                const ppp::string& path = kv.first;
                const ppp::string& url = kv.second;
                PullIPList(url, 
                    [path](int count, const ppp::set<ppp::string>& ips) noexcept
                    {
                        if (count < 1)
                        {
                            return -1;
                        }
                        
                        ppp::set<ppp::string> olds;
                        ppp::string iplist = ppp::LTrim(ppp::RTrim(File::ReadAllText(path.data())));

                        chnroutes2_getiplist(olds, ppp::string(), iplist);
                        if (!chnroutes2_equals(ips, olds))
                        {
                            ppp::string news = chnroutes2_toiplist(ips);
                            if (File::WriteAllBytes(path.data(), news.data(), news.size()))
                            {
                                ShutdownApplication(true);
                                return 1;
                            }
                        }
                    
                        return 0;
                    });
            }
        }
    }

    return true;
}

bool PppApplication::NextTickAlwaysTimeout(bool next) noexcept
{
    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULL == context)
    {
        return false;
    }

    std::shared_ptr<PppApplication> app = DEFAULT_;
    if (NULL == app)
    {
        return false;
    }

    std::shared_ptr<VirtualEthernetSwitcher> server = app->server_;
    std::shared_ptr<VEthernetNetworkSwitcher> client = app->client_;
    if (NULL == server && NULL == client)
    {
        return false;
    }

    std::shared_ptr<Timer> timeout = Timer::Timeout(context, 1000, 
        [](Timer*) noexcept
        {
            std::shared_ptr<PppApplication> app = DEFAULT_;
            if (NULL != app)
            {
                app->NextTickAlwaysTimeout(true);
            }
        });
    if (NULL == timeout)
    {
        return false;
    }
    elif(!next)
    {
        ppp::ClearConsoleOutputCharacter();
    }

    app->timeout_ = std::move(timeout);
    app->OnTick(Executors::GetTickCount());
    return true;
}

void PppApplication::ClearTickAlwaysTimeout() noexcept
{
    std::shared_ptr<Timer> timeout = std::move(timeout_);
    if (NULL != timeout)
    {
        timeout_.reset();
        timeout->Dispose();
    }
}

std::shared_ptr<VirtualEthernetSwitcher> PppApplication::GetServer() noexcept
{
    return server_;
}

std::shared_ptr<VEthernetNetworkSwitcher> PppApplication::GetClient() noexcept
{
    return client_;
}

std::shared_ptr<PppApplication> PppApplication::GetDefault() noexcept
{
    return DEFAULT_;
}

std::shared_ptr<AppConfiguration> PppApplication::GetConfiguration() noexcept
{
    return configuration_;
}

std::shared_ptr<AppConfiguration> PppApplication::LoadConfiguration(int argc, const char* argv[], ppp::string& path) noexcept
{
    static constexpr const char* argument_keys[] = { "-c", "--c", "-config", "--config" };

    for (const char* argument_key : argument_keys)
    {
        ppp::string argument_value = ppp::GetCommandArgument(argument_key, argc, argv);
        if (argument_value.empty())
        {
            continue;
        }

        argument_value = File::RewritePath(argument_value.data());
        argument_value = File::GetFullPath(argument_value.data());
        if (argument_value.empty())
        {
            continue;
        }

        if (File::CanAccess(argument_value.data(), FileAccess::Read))
        {
            path = std::move(argument_value);
            break;
        }
    }

    ppp::string configuration_paths[] =
    {
        path,
        "./config.json",
        "./appsettings.json",
    };
    for (ppp::string& configuration_path : configuration_paths)
    {
        configuration_path = File::GetFullPath(File::RewritePath(configuration_path.data()).data());
        if (!File::Exists(configuration_path.data()))
        {
            continue;
        }

        std::shared_ptr<AppConfiguration> configuration = ppp::make_shared_object<AppConfiguration>();
        if (NULL == configuration)
        {
            continue;
        }

        if (!configuration->Load(configuration_path))
        {
            continue;
        }

#if defined(_WIN32)
        if (configuration->vmem.size > 0)
#else
        if (configuration->vmem.path.size() > 0 && configuration->vmem.size > 0)
#endif
        {
            std::shared_ptr<BufferswapAllocator> allocator = ppp::make_shared_object<BufferswapAllocator>(configuration->vmem.path,
                std::max<int64_t>((int64_t)1LL << (int64_t)25LL, (int64_t)configuration->vmem.size << (int64_t)20LL));
            if (NULL != allocator && allocator->IsVaild())
            {
                configuration->SetBufferAllocator(allocator);
            }
        }

        path = configuration_path;
        return configuration;
    }

    path.clear();
    return NULL;
}

bool PppApplication::OnShutdownApplication() noexcept 
{
    return ShutdownApplication(false);
}

bool PppApplication::ShutdownApplication(bool restart) noexcept 
{
    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULL == context)
    {
        return false;
    }
    else
    {
        GLOBAL_.restart |= restart;
        boost::asio::post(*context, 
            [restart, context]() noexcept
            {
                // References to move app application domains.
                std::shared_ptr<PppApplication> APP = std::move(DEFAULT_);
                if (NULL == APP)
                {
                    return false;
                }

                // Output a prompt message that the current app is exiting.
                fprintf(stdout, "%s\r\n", restart ? "Application is restarting..." : "Application is shutting down...");

                // Release app instances.
                DEFAULT_.reset();
                APP->Dispose();

                // It requires a delay of waiting X seconds before exiting all worker threads, so that the application can close links and virtual network card drivers.
                std::shared_ptr<Timer> timeout = Timer::Timeout(context, 1000, 
                    [](Timer*) noexcept
                    {
                        // Exit all the app loops.
                        Executors::Exit();
                    });
                return NULL != timeout;
            });
        return true;
    }
}

bool PppApplication::AddShutdownApplicationEventHandler() noexcept
{
#if defined(_WIN32)
    return ppp::win32::Win32Native::AddShutdownApplicationEventHandler(PppApplication::OnShutdownApplication);
#else
    return ppp::unix__::UnixAfx::AddShutdownApplicationEventHandler(PppApplication::OnShutdownApplication);
#endif
}

#if defined(_WIN32)
static bool Windows_PreparedEthernetEnvironment(const std::shared_ptr<NetworkInterface>& network_interface) noexcept
{
    // If TAP-Windows vEthernet is not installed, you can try deploying the vNIC.
    if (network_interface->ComponentId.empty())
    {
        LOG_INFO("%s", "Installing TAP-Windows driver.");

        // Install the TAP-Windows vNIC in the Windows operating system.
        ppp::string driverPath = File::GetFullPath((ppp::GetApplicationStartupPath() + "\\Driver\\").data());
        if (ppp::tap::TapWindows::InstallDriver(driverPath.data(), ppp::ToUpper<ppp::string>(BOOST_BEAST_VERSION_STRING)))
        {
            network_interface->ComponentId = ppp::tap::ITap::FindAnyDevice();
        }

        // The virtual Ethernet card device was not successfully deployed on your computer.
        if (network_interface->ComponentId.empty())
        {
            LOG_INFO("%s", "Failed to install TAP-Windows driver.");
            return false;
        }
        else
        {
            LOG_INFO("%s", "Success to install TAP-Windows driver.");
        }
    }
    return true;
}

static bool Windows_NoLsp(int argc, const char* argv[]) noexcept
{
    char key[] = "--no-lsp";
    if (!ppp::HasCommandArgument(key, argc, argv))
    {
        return false;
    }

    bool ok = false;
    do
    {
        ppp::string line = ppp::GetCommandArgument(argc, argv);
        if (line.empty())
        {
            break;
        }

        std::size_t index = line.find(key);
        if (index == ppp::string::npos)
        {
            break;
        }

        line = line.substr(index + sizeof(key) - 1);
        if (line.empty())
        {
            break;
        }

        int ch = line[0];
        if (ch != '=' && ch != ' ')
        {
            break;
        }

        line = ppp::RTrim(ppp::LTrim(line.substr(1)));
        if (line.empty())
        {
            break;
        }

        ok = ppp::app::client::lsp::PaperAirplaneController::NoLsp(line);
    } while (false);

    fprintf(stdout, "[%s]%s\r\n", chnroutes2_gettime(chnroutes2_gettime()).data(), ok ? "OK" : "FAIL");
    return true;
}

static bool Windows_PreferredNetwork(int argc, const char* argv[]) noexcept 
{

    bool ok = false;
    if (ppp::HasCommandArgument("--system-network-preferred-ipv4", argc, argv))
    {
        ok = ppp::net::proxies::HttpProxy::PreferredNetwork(true);
    }
    elif(ppp::HasCommandArgument("--system-network-preferred-ipv6", argc, argv))
    {
        ok = ppp::net::proxies::HttpProxy::PreferredNetwork(false);
    }
    elif(ppp::HasCommandArgument("--system-network-reset", argc, argv))
    {
        ok = ppp::win32::network::ResetNetworkEnvironment();
    }
    else
    {
        return false;
    }

    fprintf(stdout, "[%s]%s\r\n", chnroutes2_gettime(chnroutes2_gettime()).data(), ok ? "OK" : "FAIL");
    return true;
}
#endif

int PppApplication::Main(int argc, const char* argv[]) noexcept
{
    // Check whether you are running as user Administrator on Linux as user ROOT and on Windows as user administrator.
    if (!ppp::IsUserAnAdministrator()) // $ROOT is 0.
    {
        fprintf(stdout, "%s\r\n", "Non-administrators are not allowed to run.");
        return -1;
    }

    // Check if the client mode of the VPN is currently running repeatedly!
    ppp::string rerun_name = (client_mode_ ? "client://" : "server://") + configuration_path_;
    if (prevent_rerun_.Exists(rerun_name.data()))
    {
        fprintf(stdout, "%s\r\n", "Repeat runs are not allowed.");
        return -1;
    }

    // Create a global mutex lock object that prevents clients from running repeatedly.
    if (!prevent_rerun_.Open(rerun_name.data()))
    {
        fprintf(stdout, "%s\r\n", "Failed to open the repeat run lock.");
        return -1;
    }

#if defined(_WIN32)
    // Prepare the Ethernet environment only in client mode.
    if (client_mode_)
    {
        // Prepare the environment for the virtual Ethernet network device card.
        if (!Windows_PreparedEthernetEnvironment(network_interface_))
        {
            return -1;
        }
    }

    // Fetch quic enable policy status of the windows operating system.  This is used to restore the changed quic policy status when ppp is closed.
    quic_ = ppp::net::proxies::HttpProxy::IsSupportExperimentalQuicProtocol();
#endif

    // Prepare the handling for the loopback environment of the virtual Ethernet switch.
    if (!PreparedLoopbackEnvironment(network_interface_))
    {
        return -1;
    }

    // Initialize the values of some counters for the app.
    stopwatch_.Restart();
    transmission_statistics_.Clear();

    // Setting control function parameter properties for the client's vEthernet switcher adapter.
    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;
    if (NULL != client)
    {
#if defined(_WIN32)
        // Windows platform manages whether these browsers use the QUIC protocol by setting methods such as Edge/Chrome global policy.
        ppp::net::proxies::HttpProxy::SetSupportExperimentalQuicProtocol(!network_interface_->BlockQUIC);
#endif

        // Set up http-proxy and whether to block QUIC traffic!
        client->BlockQUIC(network_interface_->BlockQUIC);

#if defined(_WIN32)
        // Linux does not support global Settings of the http proxy server on the operating system.   
        // This is because you can only change the /etc/profile configuration file.   
        // If the current user is the user, you can change the ~/.  bashrc configuration files implement.

        // The configuration proxy syntax is approximately:
        // export http_proxy="http://proxy.example.com:8080"
        // export https_proxy="http://proxy.example.com:8080"

        // However, there is a big flaw here, if the _tty terminal window that has been opened cannot take effect, 
        // And the Windows platform can take effect globally is different, so directly cancel the function support 
        // Of setting http proxy on Linux above the operating system.
        if (network_interface_->SetHttpProxy)
        {
            client->SetHttpProxyToSystemEnv();
        }
#endif

        // Only in client mode can the automatic pull option function be run.
        GLOBAL_.virr = ppp::HasCommandArgument("--virr", argc, argv);
        if (GLOBAL_.virr) 
        {
            GLOBAL_.bypass = network_interface_->Bypass;
            GLOBAL_.virr_argument = ppp::GetCommandArgument("--virr", argc, argv);
        }

        // If vbgp is not set up, it is enabled by default; otherwise, the vbgp function is disabled. Enabling the vbgp function will consume performance.
        GLOBAL_.vbgp = ppp::ToBoolean(ppp::GetCommandArgument("--vbgp", argc, argv, "y").data());
    }

    // Auto restart the unit is second, the server mode is supported.
    GLOBAL_.auto_restart = std::max<int>(0, atoi(ppp::GetCommandArgument("--auto-restart", argc, argv).data()));

    // Whether to restart is determined by detecting the number of unlimited reconnections of the link.
    GLOBAL_.link_restart = (uint8_t)std::max<int>(0, atoi(ppp::GetCommandArgument("--link-restart", argc, argv).data()));

    // Open and move to the next tick for the continuous timeout handling function
    return NextTickAlwaysTimeout(false) ? 0 : -1;
}

static int Run(const std::shared_ptr<PppApplication>& APP, int prepared_status, int argc, const char* argv[]) noexcept
{
    // Check whether the cli command to pull the IPList list for a specific locale from the APNIC is executed.
    if (ppp::HasCommandArgument("--pull-iplist", argc, argv))
    {
        APP->PullIPList(ppp::GetCommandArgument("--pull-iplist", argc, argv), false);
        return -1;
    }

#if defined(_WIN32)
    // If the current command is to configure the Windows operating system preferred IPV4 or IPV6 network.
    if (Windows_PreferredNetwork(argc, argv))
    {
        return -1;
    }

    // Set the EXE program of the specified PE file path not to load LSPS. If some EXE programs load LSPS, the network cannot be accessed, for example, WSL.
    if (Windows_NoLsp(argc, argv))
    {
        return -1;
    }

    // The operating system network kernel parameter tuning is optimized once by default only on the Windows platform.
    if (ppp::HasCommandArgument("--system-network-optimization", argc, argv))
    {
        ppp::string datetime = chnroutes2_gettime(chnroutes2_gettime());
        fprintf(stdout, "[%s]%s\r\n", datetime.data(), ppp::win32::Win32Native::OptimizationSystemNetworkSettings() ? "OK" : "FAIL");
        return -1;
    }
#endif

    // Print help information for vpn command line interfaces!
    if (prepared_status != 0)
    {
        APP->PrintHelpInformation();
        return -1;
    }

    // Added shutdown application event handler.
    PppApplication::AddShutdownApplicationEventHandler();

    // Added control signals for restarting applications on Linux/MacOS X platforms only.
#if SIGRESTART
    signal(SIGRESTART, (decltype(SIG_DFL))&PppApplication::ShutdownApplication);
#endif

    return APP->Main(argc, argv);
}

int main(int argc, const char* argv[]) noexcept
{
    // If the balanced mode is enabled, the kernel scheduling priority of the thread is set to the normal thread level; otherwise, 
    // The thread uses the highest priority (approximately equivalent to the real-time thread mode).
    ppp::RT = ppp::ToBoolean(ppp::GetCommandArgument("--rt", argc, argv, "y").data());
    
    // Global static constructor for PPP PRIVATE NETWORK™ 2. (For OS X platform compatibility.)
    ppp::global::cctor();

    // Enable io-uring, it is necessary to check the compatible minimum kernel version.
#if BOOST_ASIO_HAS_IO_URING != 0
    if (!ppp::diagnostics::IfIOUringKernelVersion()) 
    {
        fprintf(stdout, "%s\r\n", "Enable io-uring, the kernel version must be 5.10.0 or higher.");
        return -1;
    }
#endif

    // Instantiate and construct a vpn application object.
    std::shared_ptr<PppApplication> APP = ppp::make_shared_object<PppApplication>();
    DEFAULT_ = APP;

    // Prepare the environment for the current console command line input parameters.
    int prepared_status = APP->PreparedArgumentEnvironment(argc, argv);
    int result_code = Executors::Run(APP->GetBufferAllocator(), 
        [APP, prepared_status](int argc, const char* argv[]) noexcept -> int
        {
            int result_code = Run(APP, prepared_status, argc, argv);
#if defined(_WIN32)
            if (result_code != 0)
            {
                ppp::win32::Win32Native::PauseWindowsConsole();
            }
#endif
            return result_code;
        }, argc, argv);
    
    // Releasing the application's reference, it triggers the finalize, 
    // If the finalize is not performed, then there is an engineering structural problem that requires 
    // A detailed memory and reference correlation analysis to ensure that the established plan can be restored.
    APP->Release();
    APP.reset();
    DEFAULT_.reset();

    // When the Restart application flag is set, you need to restart the current application.
    if (GLOBAL_.restart)
    {
#if defined(_WIN32)
        ppp::string command_line = "\"" + ppp::string(*argv) + "\"";
        for (int i = 1; i < argc; ++i) 
        {
            command_line += " \"" + ppp::string(argv[i]) + "\""; 
        }

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
    
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        if (CreateProcessA(NULL, command_line.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
#else
        execvp(*argv, (char**)argv);
#endif
    }

    return result_code;
}
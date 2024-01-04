#include <ppp/configurations/AppConfiguration.h>
#include <ppp/Int128.h>
#include <ppp/io/File.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/diagnostics/Stopwatch.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Thread.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>

#include <common/chnroutes2/chnroutes2.h>

#ifdef _WIN32
#include <windows/ppp/net/proxies/HttpProxy.h>
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/Win32Event.h>
#include <windows/ppp/win32/Win32Native.h>
#include <windows/ppp/win32/network/Firewall.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#elif _LINUX
#include <linux/ppp/tap/TapLinux.h>
#endif

#ifndef PPP_APPLICATION_VERSION
#define PPP_APPLICATION_VERSION ("1.0.0")
#endif

#ifndef PPP_APPLICATION_NAME
#define PPP_APPLICATION_NAME ("PPP")
#endif

using ppp::configurations::AppConfiguration;
using ppp::threading::Executors;
using ppp::threading::Thread;
using ppp::threading::Timer;
using ppp::threading::BufferswapAllocator;
using ppp::diagnostics::Stopwatch;
using ppp::tap::ITap;
using ppp::net::Ipep;
using ppp::net::IPEndPoint;
using ppp::net::AddressFamily;
using ppp::io::File;
using ppp::io::FileAccess;
using ppp::auxiliary::StringAuxiliary;
using ppp::app::server::VirtualEthernetSwitcher;
using ppp::app::client::VEthernetNetworkSwitcher;
using ppp::app::client::VEthernetExchanger;
using ppp::app::client::http::VEthernetHttpProxySwitcher;
using ppp::Int128;

struct NetworkInterface
{
#ifdef _WIN32
    uint32_t                                        LeaseTimeInSeconds = 0;
    bool                                            SetHttpProxy       = false;
#elif _LINUX
    bool                                            Promisc            = false;
#endif

    bool                                            Lwip               = false;
    bool                                            HostedNetwork      = false;
    bool                                            BlockQUIC          = false;

    ppp::string                                     BypassIplist;
    ppp::string                                     ComponentId;
    boost::asio::ip::address                        IPAddress;
    boost::asio::ip::address                        GatewayServer;
    boost::asio::ip::address                        SubmaskAddress;
    ppp::vector<boost::asio::ip::address>           DnsAddresses;
};

class PppApplication
{
public:
    PppApplication() noexcept;
    virtual ~PppApplication() noexcept;

public:
    int                                             Main(int argc, const char* argv[]) noexcept;
    void                                            Dispose() noexcept;

public:
    static std::shared_ptr<PppApplication>          GetDefault() noexcept;
    static bool                                     AddShutdownApplicationEventHandler() noexcept;

public:
    std::shared_ptr<AppConfiguration>               GetConfiguration() noexcept;
    std::shared_ptr<VirtualEthernetSwitcher>        GetServer() noexcept;
    std::shared_ptr<VEthernetNetworkSwitcher>       GetClient() noexcept;
    std::shared_ptr<BufferswapAllocator>            GetBufferAllocator() noexcept;

public:
    void                                            PrintHelpInformation() noexcept;
    void                                            PullIPList() noexcept;
    int                                             PreparedArgumentEnvironment(int argc, const char* argv[]) noexcept;

protected:
    virtual bool                                    OnTick(uint64_t now) noexcept;

private:
    std::shared_ptr<AppConfiguration>               LoadConfiguration(int argc, const char* argv[]) noexcept;
    bool                                            IsModeClientOrServer(int argc, const char* argv[]) noexcept;
    std::shared_ptr<NetworkInterface>               GetNetworkInterface(int argc, const char* argv[]) noexcept;
    boost::asio::ip::address                        GetNetworkAddress(const char* name, int argc, const char* argv[]) noexcept;
    boost::asio::ip::address                        GetNetworkAddress(const char* name, const char* default_address_string, int argc, const char* argv[]) noexcept;
    void                                            GetDnsAddresses(ppp::vector<boost::asio::ip::address>& addresses, int argc, const char* argv[]) noexcept;
    bool                                            PreparedLoopbackEnvironment(bool client_or_server, const std::shared_ptr<NetworkInterface>& network_interface) noexcept;
    bool                                            PrintEnvironmentInformation() noexcept;

private:
    static bool                                     NextTickAlwaysTimeout() noexcept;
    void                                            ClearTickAlwaysTimeout() noexcept;

private:
    bool                                            GetTransmissionStatistics(uint64_t& incoming_traffic, uint64_t& outgoing_traffic, std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept;

private:
    struct Size
    {
        int                                         x                           = -1;
        int                                         y                           = -1;
    }                                               console_window_size_last_;
    bool                                            quic_                       = false;
    std::shared_ptr<AppConfiguration>               configuration_;
    std::shared_ptr<VirtualEthernetSwitcher>        server_;
    std::shared_ptr<VEthernetNetworkSwitcher>       client_;
    std::shared_ptr<NetworkInterface>               network_interface_;
    std::shared_ptr<Timer>                          timeout_;
    Stopwatch                                       stopwatch_;
    ppp::transmissions::ITransmissionStatistics     transmission_statistics_;
#ifdef _WIN32
    ppp::win32::Win32Event                          prevent_rerun_;
#endif
};
static std::shared_ptr<PppApplication>              PPP_APPLICATION_DEFAULT_APP_DOMAIN;

PppApplication::PppApplication() noexcept
{
    // Hide the cursor that is currently flashing on the console.
    ppp::HideConsoleCursor(true);

#ifdef _WIN32
    // Set the title information for the current user-facing console window!
    SetConsoleTitle(TEXT("PPP PRIVATE NETWORK™ 2"));

    // Set the default matrix size for the console window, valid only on Windows platforms.
    if (HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE); NULL != hConsole)
    {
        COORD cSize = { 120, 40 };
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
    // Display the cursor that is currently flashing on the console.
    ppp::HideConsoleCursor(false);

#ifdef _WIN32
    // Display the close button of the console window, otherwise the host console window close button cannot be clicked.
    ppp::win32::Win32Native::EnabledConsoleWindowClosedButton(true);

    // Turn off the global named mutex lock that prevents programs from running repeatedly!
    prevent_rerun_.Dispose();
#endif
}

void PppApplication::PullIPList() noexcept
{
    // Notify the customer that the IPlist is being pulled from the APNIC.
    time_t last = chnroutes2_gettime();
    fprintf(stdout, "[%s]PULL\r\n", chnroutes2_gettime(last).data());

    // Getting the latest IPlist routing table information from APNIC, synchronized execution will block the main thread.
    bool ok = false;
    ppp::set<ppp::string> ips;
    if (chnroutes2_getiplist(ips) > 0)
    {
        ppp::string path = chnroutes2_filepath_default();
        ok = chnroutes2_saveiplist(path, ips);
    }

    // Reports the current status of the IPlist pulled from the APNIC.
    time_t now = chnroutes2_gettime();
    if (ok)
    {
        fprintf(stdout, "[%s]OK\r\n", chnroutes2_gettime(now).data());
    }
    else
    {
        fprintf(stdout, "[%s]FAIL\r\n", chnroutes2_gettime(now).data());
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

    // Move the current console cursor position to the initial position and re-render the console output.
    if (!ppp::SetConsoleCursorPosition(0, 0))
    {
        return false;
    }
    
    // Setting control function parameter properties for the client's virtual Ethernet switch adapter.
    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;
    if (NULL != client)
    {
#ifdef _WIN32
        // Fetch quic enable policy status of the windows operating system.  This is used to restore the changed quic policy status when ppp is closed.
        quic_ = ppp::net::proxies::HttpProxy::IsSupportExperimentalQuicProtocol();
#endif

        // Set up http-proxy and whether to block QUIC traffic!
        client->BlockQUIC(network_interface->BlockQUIC);

#ifdef _WIN32
        // Linux does not support global Settings of the http proxy server on the operating system.   
        // This is because you can only change the /etc/profile configuration file.   
        // If the current user is the user, you can change the ~/.  bashrc configuration files implement.

        // The configuration proxy syntax is approximately:
        // export http_proxy="http://proxy.example.com:8080"
        // export https_proxy="http://proxy.example.com:8080"

        // However, there is a big flaw here, if the _tty terminal window that has been opened cannot take effect, 
        // And the Windows platform can take effect globally is different, so directly cancel the function support 
        // Of setting http proxy on Linux above the operating system.
        if (network_interface->SetHttpProxy)
        {
            client->SetHttpProxyToSystemEnv();
        }
#endif
    }

    // Retrieve the current hosting environment, which essentially distinguishes between the debug and release versions, but it doesn't have significant meaning.
    ppp::string hosting_environment;
#ifdef _DEBUG
    hosting_environment = "development";
#else
    hosting_environment = "production";
#endif
    hosting_environment = (NULL != client ? "client:" : "server:") + hosting_environment;

    // Get the size of the console window.
    Size console_window_size;
    if (!ppp::GetConsoleWindowSize(console_window_size.x, console_window_size.y)) 
    {
        return false;
    }

    // If the size of the current console window changes, clear the output content of the console window.
    if (console_window_size_last_.x != console_window_size.x || console_window_size_last_.y != console_window_size.y)
    {
        console_window_size_last_ 
            = console_window_size;
        ppp::ClearConsoleOutputCharacter();
    }

    // Define an anonymous arrow function that prints and newline with a locally variable argument list.
    ppp::string console_window_content;
    int console_window_heights = 0;
    auto printfn = [&console_window_size, &console_window_content, &console_window_heights](const char* format, ...) noexcept
        {
            // Control the number of lines that need to be printed to the console window to prevent crowding the visible display area 
            // Of the console window, and when the console window size changes, follow the printed content until it is fully printed.
            if (console_window_size.y > console_window_heights) 
            {
                va_list ap;
                va_start(ap, format);
                console_window_heights++;
                console_window_content += ppp::PrintToString(console_window_size.x, ' ', format, ap);
                va_end(ap);
            }
        };

    // Get the separator symbol for console tabs.
    ppp::string section_separator;
    section_separator = ppp::PaddingRight(section_separator, console_window_size.x, '-');

    // Printing ready-to-start VPN client or server program log informations.
    printfn("%s", PPP_APPLICATION_NAME);
    printfn("%s", section_separator.data());
    printfn("%s", "Application started. Press Ctrl+C to shut down.");
    printfn("Max Concurrent        : %d", Executors::GetMaxConcurrency());
    printfn("Process               : %d", ppp::GetCurrentProcessId());
    printfn("Triplet               : %s:%s", ppp::GetSystemCode(), ppp::GetPlatformCode());
    printfn("Cwd                   : %s", ppp::GetCurrentDirectoryPath().data());

    // Print some information about the client's Virtual Ethernet switcher.
    if (NULL != client)
    {
        // Print the address of the remote server currently in use by the client!
        if (ppp::string remote_uri = client->GetRemoteUri(); remote_uri.size() > 0)
        {
            printfn("VPN Server            : %s", remote_uri.data());
        }

        // Print the information related to the http proxy server tab.
        if (std::shared_ptr<VEthernetHttpProxySwitcher> http_proxy = client->GetHttpProxy(); NULL != http_proxy)
        {
            boost::asio::ip::tcp::endpoint localEP = http_proxy->GetLocalEndPoint();
            boost::asio::ip::address localIP = localEP.address();
            if (localIP.is_unspecified())
            {
                if (auto ni = client->GetUnderlyingNetowrkInterface(); NULL != ni)
                {
                    localIP = ni->IPAddress;
                }
            }

            // Displays the address of the http-proxy server for the local virtual loopback.
            ppp::string address_string = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(localIP, localEP.port())).ToString();
            printfn("Http Proxy            : %s/http", address_string.data());

#ifdef _WIN32
            // Displays the open status of the current paper Airplane session layer plugins.
            printfn("P/A Controller        : %s", client->GetPaperAirplaneController() ? "on" : "off");
#endif
        }
    }

    // Print some display information of the current virtual ethernet server!
    if (std::shared_ptr<VirtualEthernetSwitcher> server = server_; NULL != server)
    {
        // Print the public IP address and interface IP address configured for the current virtual Ethernet server!
        if (std::shared_ptr<AppConfiguration> configuration = configuration_; NULL != configuration)
        {
            printfn("Public IP             : %s", configuration->ip.public_.data());
            printfn("Interface IP          : %s", configuration->ip.interface_.data());
        }

        // Displays the port numbers of various server public service addresses that are currently monitored.
        const char* categories[VirtualEthernetSwitcher::NetworkAcceptorCategories_Max] = { "ppp+tcp", "ppp+ws", "ppp+wss", "cdn+1", "cdn+2" };
        for (int i = VirtualEthernetSwitcher::NetworkAcceptorCategories_Min, j = 0; i < VirtualEthernetSwitcher::NetworkAcceptorCategories_Max; i++)
        {
            boost::asio::ip::tcp::endpoint serverEP = server->GetLocalEndPoint((VirtualEthernetSwitcher::NetworkAcceptorCategories)i);
            if (serverEP.port() <= IPEndPoint::MinPort || serverEP.port() > IPEndPoint::MaxPort)
            {
                continue;
            }

            ppp::string tmp = "Service ";
            tmp += std::to_string(++j);
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
            if (auto ni = sti.ni; NULL != ni)
            {
                printfn("%s", sti.tab);
                printfn("%s", section_separator.data());
#ifdef _WIN32
                printfn("Name                  : %s[%s]", ni->Name.data(), ni->Description.data());
#else
                printfn("Name                  : %s", ni->Name.data());
#endif
                printfn("Index                 : %d", ni->Index);
                printfn("Id                    : %s", ni->Id.data());
                printfn("Interface             : %s %s %s",
                    ni->IPAddress.to_string().data(),
                    ni->GatewayServer.to_string().data(),
                    ni->SubmaskAddress.to_string().data());

                if (sti.tun)
                {
                    printfn("TCP/IP CC             : %s", client->IsLwip() ? "lwip" : "ctcp");
                    printfn("Block QUIC            : %s", client->IsBlockQUIC() ? "blocked" : "unblocked");

                    std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger();
                    if (NULL != exchanger)
                    {
                        const char* network_states[] = { "connecting", "established", "reconnecting" };
                        printfn("Link State            : %s", network_states[(int)exchanger->GetNetworkState()]);
                    }
                }

                for (std::size_t i = 0, l = ni->DnsAddresses.size(); i < l; i++)
                {
                    std::string tmp = "DNS Server " + std::to_string(i + 1);
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
    printfn("Duration              : %s", stopwatch_.Elapsed().ToString("HH:mm:ss").data());
    printfn("TX                    : %s", ppp::StrFormatByteSize(TransmissionStatistics.outgoing_traffic).data());
    printfn("RX                    : %s", ppp::StrFormatByteSize(TransmissionStatistics.incoming_traffic).data());
    if (auto statistics = TransmissionStatistics.statistics_snapshot; statistics)
    {
        printfn("IN                    : %s", ppp::StrFormatByteSize(statistics->IncomingTraffic).data());
        printfn("OUT                   : %s", ppp::StrFormatByteSize(statistics->OutgoingTraffic).data());
    }

    // Print text to the console window screen, or on Linux to the _tty of the shell-terminal.
    fprintf(stdout, "%s", console_window_content.data());
    return true;
}

bool PppApplication::PreparedLoopbackEnvironment(bool client_or_server, const std::shared_ptr<NetworkInterface>& network_interface) noexcept
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
#ifdef _WIN32
        // The system32 firewall Settings are automatically deployed and set in the os, because overlapping io requires its support, otherwise it cannot be used.
        ppp::string executable_path = File::GetFullPath(File::RewritePath(ppp::GetFullExecutionFilePath().data()).data());
        if (!ppp::win32::network::Fw::NetFirewallAddAllApplication(PPP_APPLICATION_NAME, executable_path.data()))
        {
            fprintf(stdout, "%s\r\n", "Failed to add the network firewall rule of the system.");
            return false;
        }
        elif(client_or_server)
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

        // The operating system network kernel parameter tuning is optimized once by default only on the Windows platform.
        ppp::win32::Win32Native::OptimizationSystemNetworkSettings();
#endif
    }

    bool success = false;
    if (client_or_server)
    {
        std::shared_ptr<VEthernetNetworkSwitcher> ethernet = NULL;
        std::shared_ptr<ITap> tap = NULL;
        do
        {
            // Try to open the tun/tap virtual Ethernet device!
#ifdef _WIN32
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
                fprintf(stdout, "%s\r\n", "TUN/TAP vNIC fails to be opened, because the vNIC is not installed in the system or is blocked by antivirus software, or be other apps open driver, or is blocked from loading the vNIC driver by hook kernel functions injected by three parties.");
                break;
            }
            else
            {
                fprintf(stdout, "%s\r\n", "Connecting to the tun/tap vNIC driver succeeded!");
            }

            // Gets the current buffer allocator and sets it to tun/tap.
            tap->BufferAllocator = configuration->GetBufferAllocator();
            if (!tap->Open())
            {
                fprintf(stdout, "%s\r\n", "An unknown and fatal problem occurred while opening the tun/tap driver.");
                break;
            }
            else
            {
                fprintf(stdout, "%s\r\n", "Open tun/tap vNIC deriver read and write succeeded!");
            }

            // Construct the switcher instance after creating the virtual ethernet network switcher object in client mode 
            // And adding the iplist file to load to bypass the vpn route.
            ethernet = ppp::make_shared_object<VEthernetNetworkSwitcher>(context, network_interface->Lwip, configuration);
            ethernet->AddLoadIPList(network_interface->BypassIplist);
            if (!ethernet->Constructor(tap))
            {
                if (auto ni = ethernet->GetUnderlyingNetowrkInterface(); NULL == ni)
                {
                    fprintf(stdout, "%s\r\n", "Can't find for carrying overlapping VPN vEthernet network physical carrying network adapter device, not can be constructed and open VPN client instance.");
                }
                else
                {
                    fprintf(stdout, "%s\r\n", "Failure to construct a client-mode vEthernet device object instance is an unexpected error that should not exist.");
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
            if (!ethernet->Open())
            {
                fprintf(stdout, "%s\r\n", "Try open remote vEthernet switcher instance fails in server-mode, possibly because any public service that can be accessed by users is not turned on..");
                break;
            }

            // Run all externally provided services of the switcher object that have just been instantiated and opened.
            if (!ethernet->Run())
            {
                fprintf(stdout, "%s\r\n", "An unknown and fatal problem occurred while opening the server loopback.");
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
    if (ppp::IsInputHelpCommand(argc, argv))
    {
        return -1;
    }

    std::shared_ptr<AppConfiguration> configuration = LoadConfiguration(argc, argv);
    if (NULL == configuration)
    {
        return -1;
    }
    else
    {
        Executors::SetMaxThreads(configuration->GetBufferAllocator(), configuration->concurrent);
    }

    std::shared_ptr<NetworkInterface> network_interface = GetNetworkInterface(argc, argv);
    if (NULL == network_interface)
    {
        return -1;
    }

    configuration_ = configuration;
    network_interface_ = network_interface;
    return 0;
}

void PppApplication::PrintHelpInformation() noexcept
{
    ppp::string messages = "Copyright (C) 2017 ~ 2024 SupersocksR ORG. All rights reserved.\r\n";
    messages += "Ppp-2(X) %s Version\r\n\r\n";
    messages += "Cwd:\r\n    " + ppp::GetCurrentDirectoryPath() + "\r\n";
    messages += "Usage:\r\n    ./%s \\\r\n";
    messages += "        --mode=[client|server] \\\r\n";
    messages += "        --config=./appsettings.json \\\r\n";
    messages += "        --lwip=[yes|no] \\\r\n";
    messages += "        --tun=[%s] \\\r\n";

#ifdef _WIN32
    messages += "        --tun-ip=10.0.0.2 \\\r\n";
    messages += "        --tun-gw=10.0.0.0 \\\r\n";
    messages += "        --tun-mask=30 \\\r\n";
    messages += "        --tun-host=[yes|no] \\\r\n";
    messages += "        --tun-lease-time-in-seconds=7200 \\\r\n";
#else
    messages += "        --tun-ip=10.0.0.2 \\\r\n";
    messages += "        --tun-gw=10.0.0.1 \\\r\n";
    messages += "        --tun-mask=30 \\\r\n";
    messages += "        --tun-host=[yes|no] \\\r\n";
#ifdef _LINUX
    messages += "        --tun-route=[yes|no] \\\r\n";
    messages += "        --tun-promisc=[yes|no] \\\r\n";
#endif
#endif

    messages += "        --dns=8.8.8.8,8.8.4.4 \\\r\n";
    messages += "        --bypass-iplist=[./ip.txt] \\\r\n";
    messages += "        --block-quic=[yes|no] \\\r\n";
#ifdef _WIN32
    messages += "        --set-http-proxy=[yes|no] \r\n";
#endif

    messages += "Commands:\r\n";
    messages += "        ./%s --help \\\r\n";
    messages += "        ./%s --pull-iplist \\\r\n";
    messages += "Contact us:\r\n";
    messages += "    https://t.me/supersocksr_group \r\n";

    ppp::string execution_file_name = ppp::GetExecutionFileName();
    fprintf(stdout, messages.data(), PPP_APPLICATION_VERSION, execution_file_name.data(), BOOST_BEAST_VERSION_STRING, execution_file_name.data(), execution_file_name.data());

#ifdef _WIN32
    ppp::win32::Win32Native::PauseWindowsConsole();
#endif
}

boost::asio::ip::address PppApplication::GetNetworkAddress(const char* name, int argc, const char* argv[]) noexcept
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
        constexpr const int MAX_PREFIX_ADDRESS = 30;

        int prefix = atoll(address_string.data());
        if (prefix < 1 || prefix > MAX_PREFIX_ADDRESS)
        {
            prefix = MAX_PREFIX_ADDRESS;
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

boost::asio::ip::address PppApplication::GetNetworkAddress(const char* name, const char* default_address_string, int argc, const char* argv[]) noexcept
{
    boost::asio::ip::address address = GetNetworkAddress(name, argc, argv);
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
    static constexpr const char* DEFAULT_DNS_ADDRESSES[] = { "8.8.8.8", "8.8.4.4" };

    Ipep::ToAddresses2(ppp::GetCommandArgument("--dns", argc, argv), addresses);
    for (const char* dns_addresss_string : DEFAULT_DNS_ADDRESSES)
    {
        if (addresses.size() >= arraysizeof(DEFAULT_DNS_ADDRESSES))
        {
            break;
        }

        boost::asio::ip::address dns_address = Ipep::ToAddress(dns_addresss_string, false);
        if (std::find(addresses.begin(), addresses.end(), dns_address) == addresses.end())
        {
            addresses.emplace_back(dns_address);
        }
    }
}

std::shared_ptr<NetworkInterface> PppApplication::GetNetworkInterface(int argc, const char* argv[]) noexcept
{
    std::shared_ptr<NetworkInterface> ni = ppp::make_shared_object<NetworkInterface>();
    if (NULL != ni)
    {
        ni->Lwip = ppp::ToBoolean(ppp::GetCommandArgument("--lwip", argc, argv, "y").data());
        ni->BlockQUIC = ppp::ToBoolean(ppp::GetCommandArgument("--block-quic", argc, argv).data());
        GetDnsAddresses(ni->DnsAddresses, argc, argv);

#ifdef _WIN32
        // Suggested Ethernet card address setting for TAP-Windows(ndis-5/6) driver.
        ni->IPAddress = GetNetworkAddress("--tun-ip", "10.0.0.2", argc, argv);
        ni->GatewayServer = GetNetworkAddress("--tun-gw", "10.0.0.0", argc, argv);
        ni->SubmaskAddress = GetNetworkAddress("--tun-mask", "255.255.255.252", argc, argv);

        // DHCP-MASQ lease time in seconds.
        ni->LeaseTimeInSeconds = strtoul(ppp::GetCommandArgument("--tun-lease-time-in-seconds", argc, argv).data(), NULL, 10);
        if (ni->LeaseTimeInSeconds < 1)
        {
            ni->LeaseTimeInSeconds = 7200;
        }
#else
        // Suggested Ethernet card address setting for Linux or unix tun/tap driver.
        ni->IPAddress = GetNetworkAddress("--tun-ip", "10.0.0.2", argc, argv);
        ni->GatewayServer = GetNetworkAddress("--tun-gw", "10.0.0.1", argc, argv);
        ni->SubmaskAddress = GetNetworkAddress("--tun-mask", "255.255.255.252", argc, argv);
#endif

        // Enabled the vEthernet bearer network to take over the Layer L2/L3 vEthernet traffic of the entire operating system.
        ni->IPAddress = Ipep::FixedIPAddress(ni->IPAddress, ni->GatewayServer, ni->SubmaskAddress);
        ni->HostedNetwork = ppp::ToBoolean(ppp::GetCommandArgument("--tun-host", argc, argv, "y").data());
        ni->BypassIplist = ppp::GetCommandArgument("--bypass-iplist", argc, argv, "./ip.txt");

#ifdef _WIN32
        ni->SetHttpProxy = ppp::ToBoolean(ppp::GetCommandArgument("--set-http-proxy", argc, argv).data());
        ni->ComponentId = ppp::tap::TapWindows::FindComponentId(ppp::GetCommandArgument("--tun", argc, argv));
#else
        ni->ComponentId = ppp::GetCommandArgument("--tun", argc, argv);
#ifdef _LINUX
        // If no virtual network card name is specified else find the default virtual ethernet network card name.
        if (ni->ComponentId.empty()) 
        {
            ni->ComponentId = ppp::tap::TapLinux::FindAnyDevice();
        }

        // Determine whether to set the control mode of the virtual Ethernet route to compatibility mode.
        if (ppp::ToBoolean(ppp::GetCommandArgument("--tun-route", argc, argv).data())) 
        {
            ppp::tap::TapLinux::CompatibleRoute(true);
        }

        // Linux Virtual Ethernet is set to the promiscuous NIC mode by default.
        ni->Promisc = ppp::ToBoolean(ppp::GetCommandArgument("--tun-promisc", argc, argv, "y").data());
#endif
#endif

        ni->ComponentId = ppp::LTrim<ppp::string>(ni->ComponentId);
        ni->ComponentId = ppp::RTrim<ppp::string>(ni->ComponentId);
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

#ifdef _WIN32
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
            // Copy a transport layer network traffic statistics snapshot, not directly using the atomic object pointed to, 
            // But copying its value to the function stack, which is adopted for multithreaded parallel arithmetic security evaluation.
            statistics_snapshot = transmission_statistics->Clone();
            if (NULL == statistics_snapshot)
            {
                return false;
            }

            // Converts an object pointer to the reference type of its object.
            ppp::transmissions::ITransmissionStatistics& statistics = *statistics_snapshot;

            // Gets the size of incoming traffic bytes within the current OnTick execution clock period.
            if (statistics.IncomingTraffic >= transmission_statistics_.IncomingTraffic)
            {
                incoming_traffic = statistics.IncomingTraffic - transmission_statistics_.IncomingTraffic;
            }
            else
            {
                Int128 traffic = (Int128(UINT64_MAX) + statistics.IncomingTraffic.load()) + 1;
                incoming_traffic = (uint64_t)(traffic - transmission_statistics_.IncomingTraffic.load());
            }

            // Gets the size of outgoing traffic bytes within the current OnTick execution clock period.
            if (statistics.OutgoingTraffic >= transmission_statistics_.OutgoingTraffic)
            {
                outgoing_traffic = statistics.OutgoingTraffic - transmission_statistics_.OutgoingTraffic;
            }
            else
            {
                Int128 traffic = (Int128(UINT64_MAX) + statistics.OutgoingTraffic.load()) + 1;
                outgoing_traffic = (uint64_t)(traffic - transmission_statistics_.OutgoingTraffic.load());
            }

            // Copy a snapshot of the network transport layer traffic statistics stored on the function stack to the last traffic statistics field hosted by the app.
            transmission_statistics_.Copy(statistics);
        }
    }

    return true;
}

bool PppApplication::OnTick(uint64_t now) noexcept
{
    // Print the current VPN client or server running status and environment information!
    PrintEnvironmentInformation();

#ifdef _WIN32
    // Windows platform calls system functions to optimize the size of the working memory used by the program in order to minimize 
    // The use of physical memory resources on low memory desktop platforms.
    ppp::win32::Win32Native::OptimizedProcessWorkingSize();
#endif
    return true;
}

bool PppApplication::NextTickAlwaysTimeout() noexcept
{
    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULL == context)
    {
        return false;
    }

    std::shared_ptr<PppApplication> app = PPP_APPLICATION_DEFAULT_APP_DOMAIN;
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

    auto fx = ppp::make_shared_object<Timer::TimeoutEventHandler>(
        []() noexcept
        {
            std::shared_ptr<PppApplication> app = PPP_APPLICATION_DEFAULT_APP_DOMAIN;
            if (NULL != app)
            {
                app->NextTickAlwaysTimeout();
            }
        });

    std::shared_ptr<Timer> timeout = Timer::Timeout(context, 1000, fx);
    if (NULL == timeout)
    {
        return false;
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
        timeout->Dispose();
        timeout.reset();
        timeout_.reset();
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
    return PPP_APPLICATION_DEFAULT_APP_DOMAIN;
}

std::shared_ptr<AppConfiguration> PppApplication::GetConfiguration() noexcept
{
    return configuration_;
}

std::shared_ptr<AppConfiguration> PppApplication::LoadConfiguration(int argc, const char* argv[]) noexcept
{
    static constexpr const char* argument_keys[] = { "-c", "--c", "-config", "--config" };

    ppp::string path;
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
        if (!configuration->Load(configuration_path))
        {
            continue;
        }

        if (configuration->vmem.path.size() > 0 && configuration->vmem.size > 0)
        {
            std::shared_ptr<BufferswapAllocator> allocator = ppp::make_shared_object<BufferswapAllocator>(configuration->vmem.path,
                std::max<int64_t>((int64_t)1LL << (int64_t)25LL, (int64_t)configuration->vmem.size << (int64_t)20LL), true);
            if (allocator->IsVaild())
            {
                configuration->SetBufferAllocator(allocator);
            }
        }
        return configuration;
    }
    return NULL;
}

bool PppApplication::AddShutdownApplicationEventHandler() noexcept
{
    auto f = []() noexcept
    {
        std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
        if (NULL == context)
        {
            return false;
        }
        else
        {
            Executors::Post(context,
                []() noexcept
                {
                    // Output a prompt message that the current app is exiting.
                    fprintf(stdout, "%s\r\n", "Application is shutting down...");

                    // Release app instances.
                    std::shared_ptr<PppApplication> APP = std::move(PPP_APPLICATION_DEFAULT_APP_DOMAIN);
                    if (NULL != APP)
                    {
                        PPP_APPLICATION_DEFAULT_APP_DOMAIN.reset();
                        APP->Dispose();
                    }

                    // Exit all the app loops.
                    Executors::Exit();
                });
            return true;
        }
    };

#ifdef _WIN32
    return ppp::win32::Win32Native::AddShutdownApplicationEventHandler(f);
#else
    return ppp::tap::TapLinux::AddShutdownApplicationEventHandler(f);
#endif
}

#ifdef _WIN32
static bool Windows_PreparedEthernetEnvironment(const std::shared_ptr<NetworkInterface>& network_interface) noexcept
{
    // If TAP-Windows vEthernet is not installed, you can try deploying the vNIC.
    if (network_interface->ComponentId.empty())
    {
        LOG_INFO("%s", "Installing the PPP Virtual Network Card TAP-Windows device driver.");

        // Install the TAP-Windows vNIC in the Windows operating system.
        ppp::string driverPath = File::GetFullPath((ppp::GetApplicationStartupPath() + "\\Driver\\").data());
        if (ppp::tap::TapWindows::InstallDriver(driverPath.data(), ppp::ToUpper<ppp::string>(BOOST_BEAST_VERSION_STRING)))
        {
            network_interface->ComponentId = ppp::tap::TapWindows::FindAnyDevice();
        }

        // The virtual Ethernet card device was not successfully deployed on your computer.
        if (network_interface->ComponentId.empty())
        {
            LOG_INFO("%s", "Unable to install PPP Virtual Network Card TAP-Windows device driver to computer.");
            return false;
        }
        else
        {
            LOG_INFO("%s", "Installed the PPP Virtual Network Card TAP-Windows device driver to computer.");
        }
    }
    return true;
}
#endif

int PppApplication::Main(int argc, const char* argv[]) noexcept
{
    // Gets whether client mode or server mode is currently running.
    bool client_or_server = IsModeClientOrServer(argc, argv);

    // Check whether you are running as user Administrator on Linux as user ROOT and on Windows as user administrator.
    if (!ppp::IsUserAnAdministrator())
    {
        fprintf(stdout, "%s\r\n", "Application is illegal, please immediately shattered and holistic antivirus.");
        return -1;
    }

#ifdef _WIN32
    // Prepare the Ethernet environment only in client mode.
    if (client_or_server)
    {
        // Check if the client mode of the VPN is currently running repeatedly!
        if (prevent_rerun_.Exists(PPP_APPLICATION_NAME))
        {
            fprintf(stdout, "%s\r\n", "PPP client mode cannot be run repeatedly, otherwise PPP will have difficulty in correctly and automatically managing the operating system routes and virtual Ethernet card devices. Running multiple VPN services on one computer at the same time is usually a false proposition!");
            return -1;
        }

        // Create a global mutex lock object that prevents clients from running repeatedly.
        try
        {
            prevent_rerun_.Open(PPP_APPLICATION_NAME, false, false);
        }
        catch (const std::exception& e)
        {
            fprintf(stdout, "%s\r\n", e.what());
            return -1;
        }

        // Prepare the environment for the virtual Ethernet network device card.
        if (!Windows_PreparedEthernetEnvironment(network_interface_))
        {
            return -1;
        }
    }
#endif

    // Prepare the handling for the loopback environment of the virtual Ethernet switch.
    if (!PreparedLoopbackEnvironment(client_or_server, network_interface_))
    {
        return -1;
    }

    // Initialize the values of some counters for the app.
    stopwatch_.Restart();
    transmission_statistics_.Clear();

    // Open and move to the next tick for the continuous timeout handling function
    if (!NextTickAlwaysTimeout())
    {
        return -1;
    }
    return 0;
}

int main(int argc, const char* argv[]) noexcept
{
    // Instantiate and construct a vpn application object.
    std::shared_ptr<PppApplication> APP = ppp::make_shared_object<PppApplication>();
    PPP_APPLICATION_DEFAULT_APP_DOMAIN = APP;

    // Check whether the cli command to pull the IPList list for a specific locale from the APNIC is executed.
    if (ppp::HasCommandArgument("--pull-iplist", argc, argv))
    {
        APP->PullIPList();
        return -1;
    }

    // Prepare the environment for the current console command line input parameters.
    if (APP->PreparedArgumentEnvironment(argc, argv))
    {
        APP->PrintHelpInformation();
        return 0;
    }

    return Executors::Run(APP->GetBufferAllocator(), /* std::bind(&PppApplication::Main, PPP_APPLICATION_DEFAULT_APP_DOMAIN, std::placeholders::_1, std::placeholders::_2); */
        [APP](int argc, const char* argv[]) noexcept -> int
        {
            PppApplication::AddShutdownApplicationEventHandler();
            return APP->Main(argc, argv);
        }, argc, argv);
}
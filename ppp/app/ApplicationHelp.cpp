/**
 * @file ApplicationHelp.cpp
 * @brief Version formatting and command-line help text rendering.
 */

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/PppApplicationInternal.h>

namespace ppp::app {

/**
 * @brief Formats semantic version components into printable string.
 * @param major Major version number.
 * @param minor Minor version number.
 * @param patch Patch version number; omitted when zero.
 * @return Human-readable version string.
 */
static ppp::string GetVersionString(int major, int minor, int patch = 0) noexcept {
    char buf[100];
    *buf = '\x0';

    if (patch != 0) {
        snprintf(buf, sizeof(buf), "%d.%d.%d", major, minor, patch);
    } else {
        snprintf(buf, sizeof(buf), "%d.%d", major, minor);
    }

    return buf;
}

/**
 * @brief Converts Boost compile-time numeric version macro to dotted string.
 * @return Boost library version string.
 */
static ppp::string GetBoostVersionString() noexcept {
    constexpr int version = BOOST_VERSION;

    int minor = (version / 100) % 100;
    int major = version / 100000;
    int patch = version % 100;

    return GetVersionString(major, minor, patch);
}

/**
 * @brief Prints full command-line help, platform options, and dependency versions.
 */
void PppApplication::PrintHelpInformation() noexcept {
    ppp::string execution_file_name = ppp::GetExecutionFileName();
    ppp::string cwd = ppp::GetCurrentDirectoryPath();

    static constexpr int col_option_width = 40;
    static constexpr int col_description_width = 48;
    static constexpr int col_default_width = 23;
    static constexpr int col_command_width = 38;
    static constexpr int col_command_width_utlity = col_command_width + 2;

    ppp::ConsoleWrite("┌──────────────────────────────────────────────────────────────────────┐\n");
    ppp::ConsoleWrite("│                       PPP PRIVATE NETWORK™ 2                         │\n");
    ppp::ConsoleWrite("│  Next-generation security network access technology, providing high- │\n");
    ppp::ConsoleWrite("│  performance Virtual Ethernet tunneling service.                     │\n");
    ppp::ConsoleWrite("└──────────────────────────────────────────────────────────────────────┘\n\n");

    ppp::ConsoleFormat("Version:      %s\n", PPP_APPLICATION_VERSION);
    ppp::ConsoleWrite("Copyright:    (C) 2017 ~ 2055 SupersocksR ORG. All rights reserved.\n");
    ppp::ConsoleFormat("Current Dir:  %s\n\n", cwd.data());

    ppp::ConsoleWrite("USAGE:\n");
    ppp::ConsoleFormat("    %s [OPTIONS]\n\n", execution_file_name.data());

    ppp::ConsoleWrite("GENERAL OPTIONS:\n");
    ppp::ConsoleWrite("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "OPTION", col_description_width, "DESCRIPTION", col_default_width, "DEFAULT");
    ppp::ConsoleWrite("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--rt=[yes|no]", col_description_width, "Enable real-time mode", col_default_width, "yes");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--mode=[client|server|proxy]", col_description_width, "Set running mode", col_default_width, "server");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--proxy-http-port=<port>", col_description_width, "Local HTTP proxy listen port (proxy mode)", col_default_width, "8080");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--proxy-socks-port=<port>", col_description_width, "Local SOCKS5 proxy listen port (proxy mode)", col_default_width, "1080");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--config=<path>", col_description_width, "Configuration file path", col_default_width, "./appsettings.json");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--stats-json=<path|stdout>", col_description_width, "Write local runtime stats as NDJSON", col_default_width, "(disabled)");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--dns=<ip-list>", col_description_width, "DNS server addresses", col_default_width, "8.8.8.8,8.8.4.4");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-flash=[yes|no]", col_description_width, "Enable advanced QoS policy", col_default_width, "no");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--auto-restart=<seconds>", col_description_width, "Auto restart interval", col_default_width, "0 (disabled)");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--link-restart=<count>", col_description_width, "Link reconnection attempts", col_default_width, "0");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--block-quic=[yes|no]", col_description_width, "Block QUIC protocol traffic", col_default_width, "no");
    ppp::ConsoleWrite("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n");

    ppp::ConsoleWrite("SERVER-SPECIFIC OPTIONS:\n");
    ppp::ConsoleWrite("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "OPTION", col_description_width, "DESCRIPTION", col_default_width, "DEFAULT");
    ppp::ConsoleWrite("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--firewall-rules=<file>", col_description_width, "Firewall rules file", col_default_width, "./firewall-rules.txt");
    ppp::ConsoleWrite("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n");

    ppp::ConsoleWrite("CLIENT-SPECIFIC OPTIONS:\n");
    ppp::ConsoleWrite("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "OPTION", col_description_width, "DESCRIPTION", col_default_width, "DEFAULT");
    ppp::ConsoleWrite("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tcp-stack=[native|lwip|xtcp]", col_description_width, "Select TCP stack (xtcp must be built and wired)", col_default_width,
#if defined(_WIN32)
        ppp::tap::TapWindows::IsWintun() ? "native" : "lwip"
#else
        "native"
#endif
    );
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--lwip=[yes|no]", col_description_width, "Legacy compatibility TCP stack selection", col_default_width,
#if defined(_WIN32)
        ppp::tap::TapWindows::IsWintun() ? "no" : "yes"
#else
        "no"
#endif
    );

    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--vbgp=[yes|no]", col_description_width, "Enable virtual BGP routing", col_default_width, "yes");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--nic=<interface>", col_description_width, "Specify physical network interface", col_default_width, "auto-select");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--ngw=<ip>", col_description_width, "Force gateway address", col_default_width, "auto-detect");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun=<name>", col_description_width, "Virtual adapter name", col_default_width, NetworkInterface::GetDefaultTun().c_str());
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-ip=<ip>", col_description_width, "Virtual adapter IP address", col_default_width, "10.0.0.2");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-ipv6=<ip>", col_description_width, "Requested virtual adapter IPv6", col_default_width, "server-assigned");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-gw=<ip>", col_description_width, "Virtual adapter gateway", col_default_width, "10.0.0.1");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-mask=<bits>", col_description_width, "Subnet mask bits", col_default_width, "30");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-vnet=[yes|no]", col_description_width, "Enable subnet forwarding", col_default_width, "yes");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-host=[yes|no]", col_description_width, "Prefer host network", col_default_width, "yes");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-static=[yes|no]", col_description_width, "Enable static tunnel", col_default_width, "no");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-mux=<connections>", col_description_width, "MUX connection count (0=disabled)", col_default_width, "0");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-mux-acceleration=<mode>", col_description_width, "MUX acceleration mode (0-3)", col_default_width, "0 (standard)");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--mux-mode=<compat|flow|balance|stripe>", col_description_width, "MUX scheduler mode", col_default_width, "compat");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--debug-key=<secret>", col_description_width, "Debug shared key for remote mux control", col_default_width, "(disabled)");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--mux-mode-set=<compat|flow>", col_description_width, "Push mux mode to peer (needs --debug-key)", col_default_width, "(off)");

#if defined(_LINUX) || defined(_MACOS)
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-promisc=[yes|no]", col_description_width, "Enable promiscuous mode", col_default_width, "yes");
#endif

#if defined(_MACOS)
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-ssmt=<threads>", col_description_width, "SSMT thread optimization", col_default_width, "0");
#elif defined(_LINUX)
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-ssmt=<N>[/<mode>]", col_description_width, "SSMT threads (N), mode: st or mq; mq opens one Linux tun queue per worker", col_default_width, "0/st");
#endif

#if defined(_LINUX)
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-route=[yes|no]", col_description_width, "Route compatibility", col_default_width, "no");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-protect=[yes|no]", col_description_width, "Route protection", col_default_width, "yes");
#endif

#if defined(_WIN32)
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-lease-time-in-seconds=<sec>", col_description_width, "DHCP lease time", col_default_width, "7200");
#endif

    ppp::ConsoleWrite("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n");

    ppp::ConsoleWrite("ROUTING OPTIONS:\n");
    ppp::ConsoleWrite("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "OPTION", col_description_width, "DESCRIPTION", col_default_width, "DEFAULT");
    ppp::ConsoleWrite("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--bypass=<file1|file2>", col_description_width, "Bypass IP list file", col_default_width, "./ip.txt");

#if defined(_LINUX)
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--bypass-nic=<interface>", col_description_width, "Interface for bypass list", col_default_width, "auto-select");
#endif

    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--bypass-ngw=<ip>", col_description_width, "Gateway for bypass list", col_default_width, "auto-detect");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--virr=[file/country]", col_description_width, "Auto-update and take effect IP-list", col_default_width, "./ip.txt/CN");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--dns-rules=<file>", col_description_width, "DNS rules configuration", col_default_width, "./dns-rules.txt");
    ppp::ConsoleWrite("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n");

#if defined(_WIN32)
    ppp::ConsoleWrite("WINDOWS-SPECIFIC COMMANDS:\n");
    ppp::ConsoleWrite("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┐\n");
    ppp::ConsoleFormat("│ %-*s │ %-*s │\n", col_command_width_utlity, "COMMAND", col_description_width, "DESCRIPTION");
    ppp::ConsoleWrite("├──────────────────────────────────────────┼──────────────────────────────────────────────────┤\n");
    ppp::ConsoleFormat("│ %-*s │ %-*s │\n", col_command_width_utlity, "--system-network-reset", col_description_width, "Reset Windows network stack");
    ppp::ConsoleFormat("│ %-*s │ %-*s │\n", col_command_width_utlity, "--system-network-optimization", col_description_width, "Optimize network performance");
    ppp::ConsoleFormat("│ %-*s │ %-*s │\n", col_command_width_utlity, "--system-network-preferred-ipv4", col_description_width, "Set IPv4 as preferred protocol");
    ppp::ConsoleFormat("│ %-*s │ %-*s │\n", col_command_width_utlity, "--system-network-preferred-ipv6", col_description_width, "Set IPv6 as preferred protocol");
    ppp::ConsoleFormat("│ %-*s │ %-*s │\n", col_command_width_utlity, "--no-lsp <program>", col_description_width, "Disable LSP for specified program");
    ppp::ConsoleWrite("└──────────────────────────────────────────┴──────────────────────────────────────────────────┘\n\n");
#endif

    ppp::ConsoleWrite("UTILITY COMMANDS:\n");
    ppp::ConsoleWrite("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "COMMAND", col_description_width, "DESCRIPTION", col_default_width, "DEFAULT");
    ppp::ConsoleWrite("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--help", col_description_width, "Display this help information", col_default_width, "none");
    ppp::ConsoleFormat("│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--pull-iplist [file/country]", col_description_width, "Download country IP list from APNIC", col_default_width, "./ip.txt/CN");
    ppp::ConsoleWrite("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n");

    ppp::ConsoleWrite("CONTACT:\n");
    ppp::ConsoleWrite("    Telegram: https://t.me/supersocksr_group\n\n");

    ppp::ConsoleWrite("DEPENDENCIES:\n");
    ppp::ConsoleFormat("    boost@%s", GetBoostVersionString().c_str());

#if defined(__GLIBC__) && defined(__GLIBC_MINOR__)
    ppp::ConsoleFormat(", libc@%s", GetVersionString(__GLIBC__, __GLIBC_MINOR__).c_str());
#if defined(__MUSL__)
    ppp::ConsoleWrite("/musl");
#else
    ppp::ConsoleWrite("/glibc");
#endif
#endif

#if defined(LIBCURL_VERSION_MAJOR)
    ppp::ConsoleFormat(", curl@%s", GetVersionString(LIBCURL_VERSION_MAJOR, LIBCURL_VERSION_MINOR, LIBCURL_VERSION_PATCH).c_str());
#endif

#if defined(OPENSSL_VERSION_MAJOR)
    ppp::ConsoleFormat(", openssl@%s", GetVersionString(OPENSSL_VERSION_MAJOR, OPENSSL_VERSION_MINOR, OPENSSL_VERSION_PATCH).c_str());
#else
    ppp::ConsoleWrite(", openssl@1.1.1");
#endif

#if defined(JEMALLOC_VERSION_MAJOR)
    ppp::ConsoleFormat(", jemalloc@%s", GetVersionString(JEMALLOC_VERSION_MAJOR, JEMALLOC_VERSION_MINOR, JEMALLOC_VERSION_BUGFIX).c_str());
#endif

    ppp::ConsoleWrite("\n");
    fflush(stdout);
}

} // namespace ppp::app

/**
 * @file LINUX_IPv6Auxiliary.cpp
 * @brief Linux IPv6 auxiliary routines for server/client route, firewall, and sysctl lifecycle handling.
 *
 * This unit provides IPv6 environment preparation and teardown for Linux PPP workflows,
 * including route management, ip6tables rule orchestration, and sysctl snapshot persistence.
 */
#include <linux/ppp/ipv6/IPv6Auxiliary.h>
#include <linux/ppp/ipv6/SysctlValidation.h>
#include <ppp/ipv6/IPv6Packet.h>
#include <ppp/diagnostics/Error.h>

#include <ppp/net/IPEndPoint.h>
#include <ppp/auxiliary/JsonAuxiliary.h>
#include <ppp/io/File.h>
#include <common/unix/UnixAfx.h>
#include <linux/ppp/tap/TapLinux.h>

namespace {
    static bool IsSafeIPv6ClientAddress(const boost::asio::ip::address_v6& address, int prefix_length, const boost::asio::ip::address_v6* gateway = NULLPTR) noexcept {
        // Reject well-known non-routable or reserved address categories.
        // Link-local (fe80::/10) must be excluded: they are interface-scoped and
        // cannot be safely applied as a globally routable client address.
        if (address.is_unspecified() || address.is_multicast() || address.is_loopback() || address.is_link_local()) {
            return false;
        }

        prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));

        boost::system::error_code network_ec;
        boost::asio::ip::address network_address = StringToAddress(ppp::linux::ipv6::auxiliary::ComputeNetworkAddress(address, prefix_length), network_ec);
        if (!network_ec && prefix_length < ppp::ipv6::IPv6_MAX_PREFIX_LENGTH && address == network_address.to_v6()) {
            return false;
        }

        if (NULLPTR != gateway && !gateway->is_unspecified() && address == *gateway) {
            return false;
        }

        return true;
    }

    static bool IsSafeShellToken(const ppp::string& value) noexcept {
        if (value.empty()) {
            return false;
        }

        for (char ch : value) {
            bool ok =
                (ch >= 'a' && ch <= 'z') ||
                (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9') ||
                ch == ':' || ch == '.' || ch == '_' || ch == '-' || ch == '%' || ch == '/';
            if (!ok) {
                return false;
            }
        }

        return true;
    }

    static bool IsSafeShellRoute(const ppp::string& value) noexcept {
        if (value.empty()) {
            return false;
        }

        for (char ch : value) {
            bool ok =
                (ch >= 'a' && ch <= 'z') ||
                (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9') ||
                ch == ':' || ch == '.' || ch == '_' || ch == '-' || ch == '%' || ch == '/' || ch == ' ';
            if (!ok) {
                return false;
            }
        }

        return true;
    }

    /**
     * @brief SECURITY-GOVERNANCE: Canonical system() wrapper for this translation unit.
     *
     * All command execution in this file MUST route through this function.
     * Callers MUST sanitize every dynamic token via IsSafeShellToken() (or
     * IsSafeSysctlKey/IsSafeSysctlValue for sysctl operations) before
     * interpolating into the command string.  Raw system() calls are
     * prohibited outside this wrapper.
     *
     * @param command Fully-formed shell command to execute.
     * @return The exit status of the command, or -1 if the command is empty.
     */
    static int RunSystemCommand(const ppp::string& command) noexcept {
        if (command.empty()) {
            return -1;
        }
        return system(command.data());
    }

    /** @brief Convenience wrapper: returns true when the command exits with status 0. */
    static bool LinuxExecuteCommand(const ppp::string& command) noexcept {
        return RunSystemCommand(command) == 0;
    }

    /**
     * @brief Gets the on-disk path used to persist IPv6 sysctl snapshots.
     * @return Absolute snapshot file path.
     */
    static ppp::string GetIPv6SysctlSnapshotPath() noexcept {
        return "/tmp/openppp2_ipv6_sysctl_snapshot.json";
    }

    using ppp::linux::ipv6::auxiliary::detail::IsAllowedSysctlSnapshotKey;
    using ppp::linux::ipv6::auxiliary::detail::IsSafeSysctlKey;
    using ppp::linux::ipv6::auxiliary::detail::IsSafeSysctlValue;

    /**
     * @brief Reads a sysctl value by key using `sysctl -n`.
     *
     * SECURITY-GOVERNANCE: This function intentionally uses raw popen() rather than
     * RunSystemCommand() because it needs to capture stdout.  The `key` parameter is
     * validated by IsSafeSysctlKey() which restricts characters to [a-zA-Z0-9._-],
     * preventing shell metacharacter injection.
     *
     * @param key Sysctl key to query (must pass IsSafeSysctlKey).
     * @param value Receives the trimmed sysctl value on success.
     * @return true if the key is valid and a non-empty value is read; otherwise false.
     */
    static bool ReadSysctlValue(const ppp::string& key, ppp::string& value) noexcept {
        value.clear();
        if (!IsSafeSysctlKey(key)) {
            return false;
        }

        char command[512];
        snprintf(command, sizeof(command), "sysctl -n %s 2>/dev/null", key.data());

        FILE* pipe = popen(command, "r");
        if (NULLPTR == pipe) {
            return false;
        }

        char buffer[256];
        ppp::string line;
        if (fgets(buffer, sizeof(buffer), pipe) != NULLPTR) {
            line = buffer;
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) {
                line.pop_back();
            }
        }

        pclose(pipe);
        if (line.empty()) {
            return false;
        }

        value = line;
        return true;
    }

    /**
     * @brief Applies a sysctl key/value pair via `sysctl -w`.
     * @param key Sysctl key to update.
     * @param value Value to assign.
     * @return true when the command succeeds; otherwise false.
     */
    static bool ApplySysctlValue(const ppp::string& key, const ppp::string& value) noexcept {
        if (!IsSafeSysctlKey(key) || !IsAllowedSysctlSnapshotKey(key) || !IsSafeSysctlValue(value)) {
            return false;
        }

        char command[768];
        snprintf(command, sizeof(command), "sysctl -w %s=%s >/dev/null 2>&1", key.data(), value.data());
        return LinuxExecuteCommand(command);
    }

    /**
     * @brief Loads previously captured sysctl values from the snapshot file.
     * @param snapshot Receives validated key/value pairs.
     * @return true if at least one valid entry is loaded; otherwise false.
     */
    static bool LoadSysctlSnapshot(ppp::unordered_map<ppp::string, ppp::string>& snapshot) noexcept {
        snapshot.clear();

        ppp::string path = GetIPv6SysctlSnapshotPath();
        if (!ppp::io::File::Exists(path.data())) {
            return false;
        }

        ppp::string content = ppp::io::File::ReadAllText(path.data());
        if (content.empty()) {
            return false;
        }

        Json::Value root = ppp::auxiliary::JsonAuxiliary::FromString(content);
        if (!root.isObject()) {
            return false;
        }

        Json::Value sysctl = root["sysctl"];
        if (!sysctl.isObject()) {
            return false;
        }

        for (Json::ValueConstIterator it = sysctl.begin(); it != sysctl.end(); ++it) {
            Json::String key_json = it.name();
            ppp::string key(key_json.data(), key_json.size());
            ppp::string value = ppp::auxiliary::JsonAuxiliary::AsString(*it);
            if (!IsSafeSysctlKey(key) || !IsAllowedSysctlSnapshotKey(key) || !IsSafeSysctlValue(value)) {
                continue;
            }
            snapshot[key] = value;
        }

        return !snapshot.empty();
    }

    /**
     * @brief Persists sysctl key/value pairs to the snapshot file in JSON format.
     * @param snapshot Sysctl values to serialize.
     * @return true if the snapshot is written successfully; otherwise false.
     */
    static bool SaveSysctlSnapshot(const ppp::unordered_map<ppp::string, ppp::string>& snapshot) noexcept {
        if (snapshot.empty()) {
            return false;
        }

        Json::Value root(Json::objectValue);
        root["version"] = 1;

        Json::Value sysctl(Json::objectValue);
        for (const auto& kv : snapshot) {
            if (!IsSafeSysctlKey(kv.first) || !IsAllowedSysctlSnapshotKey(kv.first) || !IsSafeSysctlValue(kv.second)) {
                continue;
            }
            sysctl[kv.first] = kv.second;
        }

        if (sysctl.empty()) {
            return false;
        }

        root["sysctl"] = sysctl;
        ppp::string text = ppp::auxiliary::JsonAuxiliary::ToString(root);
        if (text.empty()) {
            return false;
        }

        ppp::string path = GetIPv6SysctlSnapshotPath();
        return ppp::io::File::WriteAllBytes(path.data(), text.data(), static_cast<int>(text.size()));
    }

    /**
     * @brief Restores sysctl values from the persisted snapshot file.
     * @param delete_on_success Whether to delete the snapshot file after a full successful restore.
     * @return true when all restored keys are applied (or no snapshot exists); otherwise false.
     */
    static bool RestoreSysctlFromSnapshotFile(bool delete_on_success) noexcept {
        ppp::string path = GetIPv6SysctlSnapshotPath();
        if (!ppp::io::File::Exists(path.data())) {
            return true;
        }

        ppp::unordered_map<ppp::string, ppp::string> snapshot;
        if (!LoadSysctlSnapshot(snapshot)) {
            return false;
        }

        bool all_ok = true;
        for (const auto& kv : snapshot) {
            if (!ApplySysctlValue(kv.first, kv.second)) {
                all_ok = false;
            }
        }

        if (all_ok && delete_on_success) {
            ppp::string path = GetIPv6SysctlSnapshotPath();
            ppp::io::File::Delete(path.data());
        }
        return all_ok;
    }

    /**
     * @brief Captures current server IPv6-related sysctl values before mutation.
     * @param mode Active IPv6 server mode.
     * @param uplink_name Resolved uplink interface name for mode-specific keys.
     * @param snapshot Receives captured sysctl values.
     * @return true when all required keys are captured; otherwise false.
     */
    static bool CaptureServerSysctlSnapshot(ppp::configurations::AppConfiguration::IPv6Mode mode, const ppp::string& uplink_name, ppp::unordered_map<ppp::string, ppp::string>& snapshot) noexcept {
        snapshot.clear();

        ppp::vector<ppp::string> keys;
        keys.emplace_back("net.ipv6.conf.all.forwarding");
        keys.emplace_back("net.ipv6.conf.default.forwarding");

        if ((mode == ppp::configurations::AppConfiguration::IPv6Mode_Nat66 ||
            mode == ppp::configurations::AppConfiguration::IPv6Mode_Gua) && !uplink_name.empty()) {
            keys.emplace_back("net.ipv6.conf." + uplink_name + ".accept_ra");
        }

        for (const ppp::string& key : keys) {
            ppp::string value;
            if (!ReadSysctlValue(key, value)) {
                return false;
            }
            snapshot[key] = value;
        }

        return !snapshot.empty();
    }

    /**
     * @brief Extracts the interface name from an IPv6 route line.
     * @param route Raw route line (e.g. output from `ip -6 route`).
     * @return Parsed interface name after `dev`, or empty if not found/unsafe.
     */
    static ppp::string ExtractRouteInterface(const ppp::string& route) noexcept {
        static const char token[] = " dev ";

        std::size_t pos = route.find(token);
        if (pos == ppp::string::npos) {
            return ppp::string();
        }

        pos += sizeof(token) - 1;
        std::size_t end = route.find(' ', pos);
        ppp::string interface_name = end == ppp::string::npos ? route.substr(pos) : route.substr(pos, end - pos);
        if (!IsSafeShellToken(interface_name)) {
            return ppp::string();
        }

        return interface_name;
    }

    /**
     * @brief Reads all current IPv6 default routes from the system.
     * @return Route lines returned by `ip -6 route show default`.
     */
    static ppp::vector<ppp::string> ReadDefaultRoutes() noexcept {
        return ppp::unix__::UnixAfx::ExecuteShellCommandLines("ip -6 route show default");
    }

    /** @brief Convenience wrapper: returns the raw exit status (preserves legacy semantics). */
    static int LinuxExecuteCommandWithStatus(const ppp::string& command) noexcept {
        return RunSystemCommand(command);
    }

    static bool SupportsIp6tablesNatTable() noexcept {
        return LinuxExecuteCommandWithStatus("ip6tables -t nat -S >/dev/null 2>&1") == 0;
    }

    static ppp::string BuildIpv6ForwardRules(bool add_rules, const ppp::string& prefix, int prefix_length) noexcept {
        if (prefix.empty()) {
            return ppp::string();
        }

        char command[2048];
        if (add_rules) {
            snprintf(command, sizeof(command),
                "ip6tables -C FORWARD -s %s/%d -j ACCEPT >/dev/null 2>&1 || "
                "ip6tables -A FORWARD -s %s/%d -j ACCEPT >/dev/null 2>&1; "
                "ip6tables -C FORWARD -d %s/%d -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || "
                "ip6tables -A FORWARD -d %s/%d -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1",
                prefix.data(), prefix_length,
                prefix.data(), prefix_length,
                prefix.data(), prefix_length,
                prefix.data(), prefix_length);
        }
        else {
            snprintf(command, sizeof(command),
                "ip6tables -D FORWARD -s %s/%d -j ACCEPT >/dev/null 2>&1; "
                "ip6tables -D FORWARD -d %s/%d -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1",
                prefix.data(), prefix_length,
                prefix.data(), prefix_length);
        }

        return ppp::string(command);
    }

    static ppp::string ResolveIpv6UplinkInterface(const ppp::string& preferred_nic) noexcept {
        if (!preferred_nic.empty() && IsSafeShellToken(preferred_nic)) {
            return preferred_nic;
        }

        auto lines = ppp::unix__::UnixAfx::ExecuteShellCommandLines("ip -6 route show default",
            [](const ppp::string& line) noexcept -> bool {
                return !ExtractRouteInterface(line).empty();
            });

        for (const auto& route : lines) {
            ppp::string interface_name = ExtractRouteInterface(route);
            if (!interface_name.empty()) {
                return interface_name;
            }
        }

        ppp::string interface_name;
        ppp::UInt32 ip = ppp::net::IPEndPoint::AnyAddress;
        ppp::UInt32 gw = ppp::net::IPEndPoint::AnyAddress;
        ppp::UInt32 mask = ppp::net::IPEndPoint::AnyAddress;
        if (ppp::tap::TapLinux::GetPreferredNetworkInterface(interface_name, ip, mask, gw, preferred_nic)) {
            return interface_name;
        }
        return ppp::string();
    }

    static bool ParseIpv6Cidr(const ppp::string& cidr, ppp::string& prefix, int& prefix_length) noexcept {
        prefix.clear();
        prefix_length = 0;
        if (cidr.empty()) {
            return false;
        }

        std::size_t slash = cidr.find('/');
        if (slash == ppp::string::npos) {
            prefix = cidr;
            prefix_length = ppp::ipv6::IPv6_MAX_PREFIX_LENGTH;
            return true;
        }

        prefix = cidr.substr(0, slash);

        /**
         * @brief Validate prefix length using strtol for proper error detection.
         * @note atoi is unsafe as it cannot distinguish between 0 and error.
         */
        const ppp::string plen_str = cidr.substr(slash + 1);
        char* endptr = NULLPTR;
        long parsed = strtol(plen_str.c_str(), &endptr, 10);
        if (NULLPTR == endptr || endptr == plen_str.c_str() || *endptr != '\x0' || parsed < 0 || parsed > 128) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6PrefixInvalid);
            return false;
        }

        prefix_length = static_cast<int>(parsed);
        prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));
        return !prefix.empty();
    }

    static bool NormalizeIpv6Prefix(const ppp::string& cidr, int configured_prefix_length, ppp::string& prefix, int& prefix_length) noexcept {
        if (!ParseIpv6Cidr(cidr, prefix, prefix_length)) {
            return false;
        }

        if (configured_prefix_length > ppp::ipv6::IPv6_MIN_PREFIX_LENGTH && configured_prefix_length <= ppp::ipv6::IPv6_MAX_PREFIX_LENGTH) {
            prefix_length = configured_prefix_length;
        }

        boost::system::error_code ec;
        boost::asio::ip::address address = StringToAddress(prefix, ec);
        if (ec || !address.is_v6()) {
            return false;
        }

        prefix = ppp::linux::ipv6::auxiliary::ComputeNetworkAddress(address.to_v6(), prefix_length);
        return true;
    }


    /**
     * @brief Removes IPv6 forwarding/NAT rules and transit interface state.
     * @param mode Active server IPv6 mode.
     * @param prefix IPv6 prefix used for rule targeting.
     * @param prefix_length Prefix length in bits.
     * @param preferred_nic Preferred uplink interface hint.
     * @param transit_ifname Transit interface to flush.
     */
    static void CleanupServerRules(ppp::configurations::AppConfiguration::IPv6Mode mode, const ppp::string& prefix, int prefix_length, const ppp::string& preferred_nic, const ppp::string& transit_ifname) noexcept {
        ppp::string uplink_name = ResolveIpv6UplinkInterface(preferred_nic);
        if (!uplink_name.empty() && !IsSafeShellToken(uplink_name)) {
            uplink_name.clear();
        }

        char command[4096];
        ppp::string forward_cleanup;
        if (!prefix.empty()) {
            forward_cleanup = BuildIpv6ForwardRules(false, prefix, prefix_length);
        }
        if (mode == ppp::configurations::AppConfiguration::IPv6Mode_Nat66) {
            if (prefix.empty()) {
                // When no prefix is configured, PrepareServerEnvironment only installs the
                // MASQUERADE rule (keyed on uplink interface name).  No FORWARD rules are
                // installed in this path because BuildIpv6ForwardRules requires a non-empty
                // prefix.  Remove only the MASQUERADE rule here.
                if (!uplink_name.empty()) {
                    snprintf(command, sizeof(command), "ip6tables -t nat -D POSTROUTING -o %s -j MASQUERADE >/dev/null 2>&1", uplink_name.data());
                    LinuxExecuteCommand(command);
                }
            }
            elif (uplink_name.empty()) {
                snprintf(command, sizeof(command),
                    "%s; "
                    "ip6tables -t nat -D POSTROUTING -s %s/%d -j MASQUERADE >/dev/null 2>&1",
                    forward_cleanup.data(),
                    prefix.data(), prefix_length);
            }
            else {
                snprintf(command, sizeof(command),
                    "%s; "
                    "ip6tables -t nat -D POSTROUTING -s %s/%d -j MASQUERADE >/dev/null 2>&1; "
                    "ip6tables -t nat -D POSTROUTING -o %s -s %s/%d -j MASQUERADE >/dev/null 2>&1",
                    forward_cleanup.data(),
                    prefix.data(), prefix_length,
                    uplink_name.data(), prefix.data(), prefix_length);
            }
            LinuxExecuteCommand(command);
        }
        elif (mode == ppp::configurations::AppConfiguration::IPv6Mode_Gua) {
            if (!forward_cleanup.empty()) {
                LinuxExecuteCommand(forward_cleanup);
            }
        }

        if (!transit_ifname.empty() && IsSafeShellToken(transit_ifname)) {
            snprintf(command, sizeof(command), "ip -6 route flush dev %s >/dev/null 2>&1; ip -6 addr flush dev %s >/dev/null 2>&1", transit_ifname.data(), transit_ifname.data());
            LinuxExecuteCommand(command);
        }
    }
}

namespace ppp {
    namespace linux {
        namespace ipv6 {
            namespace auxiliary {
                /**
                 * @brief Reads the first available IPv6 default route line.
                 *
                 * SECURITY-GOVERNANCE: Uses popen() with a hardcoded command literal
                 * (no dynamic tokens); no IsSafeShellToken guard is required.
                 *
                 * @return First non-empty default route entry, or empty if unavailable.
                 */
                ppp::string ReadDefaultRoute() noexcept {
                    FILE* pipe = popen("ip -6 route show default", "r");
                    if (NULLPTR == pipe) {
                        return ppp::string();
                    }

                    char buffer[1024];
                    ppp::string route;
                    while (fgets(buffer, sizeof(buffer), pipe) != NULLPTR) {
                        route = buffer;
                        while (!route.empty() && (route.back() == '\n' || route.back() == '\r')) {
                            route.pop_back();
                        }

                        if (!route.empty()) {
                            break;
                        }
                    }
                    pclose(pipe);
                    return route;
                }

                ppp::string ComputeNetworkAddress(const boost::asio::ip::address_v6& address, int prefix_length) noexcept {
                    boost::asio::ip::address_v6::bytes_type bytes = address.to_bytes();
                    prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));

                    int full_bytes = prefix_length / 8;
                    int remainder_bits = prefix_length % 8;
                    if (full_bytes < 16) {
                        if (remainder_bits != 0) {
                            unsigned char mask = static_cast<unsigned char>(0xff << (8 - remainder_bits));
                            bytes[full_bytes] &= mask;
                            full_bytes++;
                        }

                        for (int i = full_bytes; i < 16; ++i) {
                            bytes[i] = 0;
                        }
                    }

                    std::string network = boost::asio::ip::address_v6(bytes).to_string();
                    return ppp::string(network.data(), network.size());
                }

                /**
                 * @brief Applies a full IPv6 default route expression via `ip -6 route replace`.
                 * @param route Route payload to apply.
                 * @return true when the command executes successfully; otherwise false.
                 */
                bool ApplyDefaultRouteCommand(const ppp::string& route) noexcept {
                    if (route.empty() || !IsSafeShellRoute(route)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RouteReplaceFailed);
                    }

                    char command[1600];
                    snprintf(command, sizeof(command), "ip -6 route replace %s > /dev/null 2>&1", route.data());
                    if (RunSystemCommand(command) == 0) {
                        return true;
                    }

                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RouteReplaceFailed);
                }

                /**
                 * @brief Prepares Linux IPv6 server networking state for NAT66 or GUA mode.
                 * @param configuration Runtime application configuration.
                 * @param preferred_nic Preferred uplink interface hint.
                 * @param transit_ifname Transit interface used for route/address flushing.
                 * @return true if environment setup succeeds or mode does not require setup; otherwise false.
                 */
                bool PrepareServerEnvironment(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const ppp::string& preferred_nic, const ppp::string& transit_ifname) noexcept {
                    if (NULLPTR == configuration) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6ServerPrepareFailed);
                    }

                    const auto& ipv6 = configuration->server.ipv6;
                    auto mode = ipv6.mode;
                    if (mode != ppp::configurations::AppConfiguration::IPv6Mode_Nat66 && mode != ppp::configurations::AppConfiguration::IPv6Mode_Gua) {
                        return true;
                    }

                    ppp::string prefix;
                    int prefix_length = 0;
                    bool normalized = NormalizeIpv6Prefix(ipv6.cidr, ipv6.prefix_length, prefix, prefix_length);
                    if (!normalized && mode == ppp::configurations::AppConfiguration::IPv6Mode_Nat66) {
                        prefix = ppp::ipv6::IPV6_DEFAULT_PREFIX;
                        prefix_length = ppp::ipv6::IPv6_DEFAULT_PREFIX_LENGTH;
                    }
                    elif (!normalized) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6PrefixInvalid);
                        return false;
                    }

                    if (!prefix.empty() && !IsSafeShellToken(prefix)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6PrefixInvalid);
                        return false;
                    }

                    if (!RestoreSysctlFromSnapshotFile(true)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ForwardingEnableFailed);
                        return false;
                    }

                    CleanupServerRules(mode, prefix, prefix_length, preferred_nic, transit_ifname);

                    ppp::string uplink_name = ResolveIpv6UplinkInterface(preferred_nic);
                    char ip6tables_command[3072];
                    if (!uplink_name.empty() && !IsSafeShellToken(uplink_name)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                        CleanupServerRules(mode, prefix, prefix_length, preferred_nic, transit_ifname);
                        RestoreSysctlFromSnapshotFile(false);
                        return false;
                    }

                    ppp::unordered_map<ppp::string, ppp::string> sysctl_snapshot;
                    if (!CaptureServerSysctlSnapshot(mode, uplink_name, sysctl_snapshot) || !SaveSysctlSnapshot(sysctl_snapshot)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ForwardingEnableFailed);
                        CleanupServerRules(mode, prefix, prefix_length, preferred_nic, transit_ifname);
                        RestoreSysctlFromSnapshotFile(false);
                        return false;
                    }

                    char sysctl_command[512];
                    snprintf(sysctl_command, sizeof(sysctl_command), "sysctl -w net.ipv6.conf.all.forwarding=1 net.ipv6.conf.default.forwarding=1 > /dev/null 2>&1");
                    if (!LinuxExecuteCommand(sysctl_command)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ForwardingEnableFailed);
                        RestoreSysctlFromSnapshotFile(false);
                        return false;
                    }

                    if (!uplink_name.empty()) {
                        char accept_ra_command[512];
                        snprintf(accept_ra_command, sizeof(accept_ra_command), "sysctl -w net.ipv6.conf.%s.accept_ra=2 > /dev/null 2>&1", uplink_name.data());
                        if (!LinuxExecuteCommand(accept_ra_command)) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ForwardingEnableFailed);
                            CleanupServerRules(mode, prefix, prefix_length, preferred_nic, transit_ifname);
                            RestoreSysctlFromSnapshotFile(false);
                            return false;
                        }
                    }

                    ppp::string forward_rules = BuildIpv6ForwardRules(true, prefix, prefix_length);
                    if (forward_rules.empty()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ForwardRuleApplyFailed);
                        CleanupServerRules(mode, prefix, prefix_length, preferred_nic, transit_ifname);
                        RestoreSysctlFromSnapshotFile(false);
                        return false;
                    }

                    if (mode == ppp::configurations::AppConfiguration::IPv6Mode_Gua) {
                        if (LinuxExecuteCommandWithStatus(forward_rules) == 0) {
                            return true;
                        }

                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ForwardRuleApplyFailed);
                        CleanupServerRules(mode, prefix, prefix_length, preferred_nic, transit_ifname);
                        RestoreSysctlFromSnapshotFile(false);
                        return false;
                    }

                    if (!SupportsIp6tablesNatTable()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6Nat66Unavailable);
                        CleanupServerRules(mode, prefix, prefix_length, preferred_nic, transit_ifname);
                        RestoreSysctlFromSnapshotFile(false);
                        return false;
                    }

                    if (uplink_name.empty()) {
                        snprintf(ip6tables_command, sizeof(ip6tables_command),
                            "%s; "
                            "ip6tables -t nat -C POSTROUTING -s %s/%d -j MASQUERADE >/dev/null 2>&1 || "
                            "ip6tables -t nat -A POSTROUTING -s %s/%d -j MASQUERADE >/dev/null 2>&1",
                            forward_rules.data(),
                            prefix.data(), prefix_length,
                            prefix.data(), prefix_length);
                    }
                    else {
                        snprintf(ip6tables_command, sizeof(ip6tables_command),
                            "%s; "
                            "ip6tables -t nat -C POSTROUTING -o %s -s %s/%d -j MASQUERADE >/dev/null 2>&1 || "
                            "ip6tables -t nat -A POSTROUTING -o %s -s %s/%d -j MASQUERADE >/dev/null 2>&1",
                            forward_rules.data(),
                            uplink_name.data(), prefix.data(), prefix_length,
                            uplink_name.data(), prefix.data(), prefix_length);
                    }

                    if (LinuxExecuteCommandWithStatus(ip6tables_command) == 0) {
                        return true;
                    }

                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ForwardRuleApplyFailed);
                    CleanupServerRules(mode, prefix, prefix_length, preferred_nic, transit_ifname);
                    RestoreSysctlFromSnapshotFile(false);
                    return false;
                }

                /**
                 * @brief Finalizes Linux IPv6 server networking and restores prior sysctl state.
                 * @param configuration Runtime application configuration.
                 * @param preferred_nic Preferred uplink interface hint.
                 * @param transit_ifname Transit interface used for route/address flushing.
                 */
                void FinalizeServerEnvironment(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const ppp::string& preferred_nic, const ppp::string& transit_ifname) noexcept {
                    if (NULLPTR == configuration) {
                        return;
                    }

                    const auto& ipv6 = configuration->server.ipv6;
                    auto mode = ipv6.mode;
                    if (mode != ppp::configurations::AppConfiguration::IPv6Mode_Nat66 && mode != ppp::configurations::AppConfiguration::IPv6Mode_Gua) {
                        return;
                    }

                    ppp::string prefix;
                    int prefix_length = 0;
                    if (!NormalizeIpv6Prefix(ipv6.cidr, ipv6.prefix_length, prefix, prefix_length) && mode == ppp::configurations::AppConfiguration::IPv6Mode_Nat66) {
                        prefix = ppp::ipv6::IPV6_DEFAULT_PREFIX;
                        prefix_length = ppp::ipv6::IPv6_DEFAULT_PREFIX_LENGTH;
                    }

                    if (!prefix.empty() && !IsSafeShellToken(prefix)) {
                        return;
                    }

                    CleanupServerRules(mode, prefix, prefix_length, preferred_nic, transit_ifname);
                    if (!RestoreSysctlFromSnapshotFile(true)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ForwardingEnableFailed);
                    }
                }

                void CaptureClientOriginalState(const ::ppp::ipv6::auxiliary::ClientContext& context, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    state.OriginalDnsConfiguration = ppp::unix__::UnixAfx::GetDnsResolveConfiguration();
                    state.OriginalDefaultRoutes = ReadDefaultRoutes();
                    if (!state.OriginalDefaultRoutes.empty()) {
                        state.OriginalDefaultRoute = state.OriginalDefaultRoutes.front();
                    }
                    else {
                        state.OriginalDefaultRoute.clear();
                    }
                    state.DefaultRouteWasPresent = !state.OriginalDefaultRoute.empty();
                    state.OriginalDefaultRouteInterface = ExtractRouteInterface(state.OriginalDefaultRoute);
                }

                bool ApplyClientAddress(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool gua_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    if (NULLPTR == context.Tap || context.InterfaceName.empty() || context.InterfaceIndex < 0 || !address.is_v6()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                    }

                    if (!IsSafeIPv6ClientAddress(address.to_v6(), prefix_length)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6AddressUnsafe);
                    }

                    ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(context.Tap);
                    if (NULLPTR == linux_tap) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                    }

                    std::string addr_std = address.to_string();
                    ppp::string addr_str(addr_std.data(), addr_std.size());
                    if (!ppp::tap::TapLinux::SetIPv6Address(context.InterfaceName, addr_str, prefix_length)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6ClientAddressApplyFailed);
                    }

                    state.AddressApplied = true;
                    state.Address = addr_str;
                    return true;
                }

                bool ApplyClientDefaultRoute(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& gateway, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    if (NULLPTR == context.Tap || context.InterfaceName.empty()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                        return false;
                    }

                    ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(context.Tap);
                    if (NULLPTR == linux_tap) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                        return false;
                    }

                    ppp::string gateway_string;
                    if (gateway.is_v6()) {
                        gateway_string = gateway.to_string();
                    }
                    elif (!nat_mode) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6GatewayMissing);
                    }

                    bool gateway_neighbor_created = false;
                    if (!gateway_string.empty()) {
                        ppp::tap::TapLinux::NeighborMutationResult neighbor_result =
                            ppp::tap::TapLinux::AddIPv6PermanentNeighbor(context.InterfaceName, gateway_string);
                        if (neighbor_result == ppp::tap::TapLinux::NeighborMutationResult::Failed) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed);
                            return false;
                        }
                        gateway_neighbor_created = neighbor_result == ppp::tap::TapLinux::NeighborMutationResult::Changed;
                    }

                    if (!ppp::tap::TapLinux::AddRoute6(context.InterfaceName, "::", 0, gateway_string)) {
                        if (gateway_neighbor_created &&
                            !ppp::tap::TapLinux::DeleteIPv6PermanentNeighbor(context.InterfaceName, gateway_string)) {
                            state.GatewayNeighborOwned = true;
                            state.DefaultRouteGateway = gateway_string;
                        }
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed);
                        return false;
                    }

                    state.DefaultRouteApplied = true;
                    state.GatewayNeighborOwned = state.GatewayNeighborOwned || gateway_neighbor_created;
                    state.DefaultRouteGateway = gateway_string;
                    return true;
                }

                bool ApplyClientSubnetRoute(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& prefix, int prefix_length, const boost::asio::ip::address& gateway, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    if (!nat_mode) {
                        return true;
                    }

                    if (NULLPTR == context.Tap || context.InterfaceName.empty() || !prefix.is_v6()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                        return false;
                    }

                    ppp::string gateway_string;
                    if (gateway.is_v6()) {
                        gateway_string = gateway.to_string();
                    }
                    elif (!nat_mode) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6GatewayMissing);
                    }

                    std::string prefix_std = prefix.to_string();
                    ppp::string prefix_string(prefix_std.data(), prefix_std.size());
                    prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));
                    if (!ppp::tap::TapLinux::AddRoute6(context.InterfaceName, prefix_string, prefix_length, gateway_string)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed);
                        return false;
                    }

                    state.SubnetRouteApplied = true;
                    state.SubnetRoutePrefix = prefix_string;
                    state.SubnetRoutePrefixLength = prefix_length;
                    state.SubnetRouteGateway = gateway_string;
                    return true;
                }

                bool ApplyClientDns(const ::ppp::ipv6::auxiliary::ClientContext& context, const ppp::vector<ppp::string>& dns_servers, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    if (dns_servers.empty()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6ClientDnsApplyFailed);
                    }

                    ppp::vector<boost::asio::ip::address> dns_addrs;
                    ppp::vector<boost::asio::ip::address> current_addrs;
                    ppp::unix__::UnixAfx::GetDnsAddresses(current_addrs);
                    for (auto& s : dns_servers) {
                        boost::system::error_code ec;
                        auto addr = StringToAddress(s, ec);
                        if (!ec && addr.is_v6()) {
                            dns_addrs.emplace_back(addr);
                        }
                    }

                    if (dns_addrs.empty() || !ppp::unix__::UnixAfx::MergeDnsAddresses(dns_addrs, current_addrs)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6ClientDnsApplyFailed);
                    }

                    state.DnsApplied = true;
                    state.DnsServers = dns_servers;
                    return true;
                }

                void RestoreClientConfiguration(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    if (NULLPTR == context.Tap || context.InterfaceName.empty()) {
                        return;
                    }

                    ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(context.Tap);
                    if (NULLPTR == linux_tap) {
                        return;
                    }

                    if (state.SubnetRouteApplied && !state.SubnetRoutePrefix.empty()) {
                        ppp::tap::TapLinux::DeleteRoute6(context.InterfaceName, state.SubnetRoutePrefix, state.SubnetRoutePrefixLength, state.SubnetRouteGateway);
                    }

                    if (state.DefaultRouteApplied && nat_mode && state.DefaultRouteGateway.empty()) {
                        ppp::tap::TapLinux::DeleteRoute6(context.InterfaceName, "::", 0, ppp::string());
                    }
                    elif (state.DefaultRouteApplied) {
                        ppp::tap::TapLinux::DeleteRoute6(context.InterfaceName, "::", 0, state.DefaultRouteGateway);
                    }

                    bool gateway_neighbor_delete_failed = false;
                    if (state.GatewayNeighborOwned) {
                        bool removed = false;
                        if (!state.DefaultRouteGateway.empty()) {
                            // Retry once because netlink teardown can fail transiently while the
                            // default route removal is still settling in the kernel.
                            for (int attempt = 0; attempt < 2 && !removed; ++attempt) {
                                removed = ppp::tap::TapLinux::DeleteIPv6PermanentNeighbor(
                                    context.InterfaceName, state.DefaultRouteGateway);
                            }
                        }
                        if (removed) {
                            state.GatewayNeighborOwned = false;
                        }
                        else {
                            gateway_neighbor_delete_failed = true;
                        }
                    }

                    if (state.AddressApplied && address.is_v6() && !state.Address.empty()) {
                        ppp::tap::TapLinux::DeleteIPv6Address(context.InterfaceName, state.Address, prefix_length);
                    }

                    if (state.DnsApplied) {
                        ppp::unix__::UnixAfx::SetDnsResolveConfiguration(state.OriginalDnsConfiguration);
                    }

                    if (state.DefaultRouteApplied && state.DefaultRouteWasPresent) {
                        for (const ppp::string& route : state.OriginalDefaultRoutes) {
                            ApplyDefaultRouteCommand(route);
                        }
                    }

                    if (gateway_neighbor_delete_failed) {
                        // The void cross-platform restore API cannot report partial cleanup.
                        // Preserve ownership for a later manager retry and expose diagnostics.
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                    }
                }
            }
        }
    }
}

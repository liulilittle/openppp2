/**
 * @file PppApplication.h
 * @brief Declares the main PPP application lifecycle and runtime orchestration interface.
 *
 * @details `PppApplication` is the process-wide singleton that owns the full application
 *          lifecycle: argument parsing, configuration loading, mode selection (client or
 *          server), executor dispatch, signal handling, and periodic maintenance ticks.
 *
 *          Architecture overview:
 *          - `Run(argc, argv)` is the entry point called from `main()`.  It prepares the
 *            argument environment, loads configuration, resolves the network interface,
 *            creates the executor pool, and blocks until shutdown.
 *          - In **client mode**, `client_` (`VEthernetNetworkSwitcher`) is created.
 *          - In **server mode**, `server_` (`VirtualEthernetSwitcher`) is created.
 *          - `OnTick(now)` is called periodically by the global timeout timer and drives
 *            statistics collection, display refresh, and keepalive.
 *          - `ShutdownApplication(restart)` can be called from signal handlers or console
 *            commands to initiate a clean shutdown (or restart).
 *
 *          Singleton access:
 *          - `GetInstance()` returns a reference to the process-wide instance.
 *          - `GetDefault()` returns a shared_ptr to the same instance.
 *
 *          Thread safety:
 *          - `GetInstance()` and `GetDefault()` are safe to call from any thread.
 *          - All other methods must be called from the main IO thread unless documented
 *            otherwise.
 *
 * @license GPL-3.0
 */

#pragma once

#include <ppp/stdafx.h>
#include <ppp/app/ApplicationMode.h>
#include <ppp/app/runtime/DatapathAcceptanceBoundary.h>
#include <ppp/app/runtime/RuntimeLifecycle.h>
#include <ppp/app/runtime/RuntimeSnapshotJson.h>
#include <ppp/diagnostics/PreventReturn.h>
#include <ppp/diagnostics/Stopwatch.h>
#include <ppp/transmissions/ITransmissionStatistics.h>

namespace ppp {
namespace configurations {
class AppConfiguration;
}

namespace threading {
class BufferswapAllocator;
class Timer;
}

namespace app {
class ConsoleUI;

namespace server {
class VirtualEthernetSwitcher;
}

namespace client {
class VEthernetNetworkSwitcher;
}

struct NetworkInterface;

/**
 * @brief Process-wide application singleton managing the full PPP runtime lifecycle.
 *
 * @details A single `PppApplication` instance exists for the lifetime of the process.
 *          It is responsible for:
 *          - Parsing command-line arguments and loading `AppConfiguration`.
 *          - Selecting client or server mode and creating the appropriate runtime object.
 *          - Resolving the physical network interface used for routing.
 *          - Registering OS signal handlers for graceful shutdown.
 *          - Driving the periodic maintenance tick via an internal timer.
 *          - Providing accessors to the configuration, server, client, and buffer allocator.
 *
 * @note Construct via the default constructor; access the singleton via `GetInstance()`.
 */
class PppApplication : public std::enable_shared_from_this<PppApplication> {
public:
    /**
     * @brief Constructs the application singleton with default-initialized state.
     *
     * @note Called exactly once at process startup.  Do not construct additional instances.
     */
    PppApplication() noexcept;

    /**
     * @brief Destroys the application and releases all owned resources.
     *
     * @details Calls `Dispose()` and `Release()` to ensure the server/client runtime,
     *          configuration, and timer are all cleaned up.
     */
    virtual ~PppApplication() noexcept;

public:
    /**
     * @brief Returns a reference to the process-wide `PppApplication` singleton.
     *
     * @return Reference to the singleton `PppApplication` instance.
     * @note Thread-safe; the singleton is initialized before `main()` enters.
     */
    static PppApplication& GetInstance() noexcept;

    /**
     * @brief Runs application startup, argument preparation, and executor dispatch.
     *
     * @details Sequence:
     *          1. Calls `PreparedArgumentEnvironment()` to validate and pre-process `argv`.
     *          2. Loads configuration via `LoadConfiguration()`.
     *          3. Resolves the network interface via `GetNetworkInterface()`.
     *          4. Creates the executor pool and enters the IO loop.
     *          5. Returns the process exit code when the loop exits.
     *
     * @param argc Command-line argument count.
     * @param argv Command-line argument vector.
     * @return Process exit code; 0 on clean exit, non-zero on error.
     */
    int Run(int argc, char** argv) noexcept;

public:
    /**
     * @brief Application main logic entry point executed inside the executor loop.
     *
     * @details Creates the server or client runtime, opens resources, and starts the
     *          periodic tick timer.  Blocks on the IO context until shutdown is signaled.
     *
     * @param argc Argument count (forwarded from `Run()`).
     * @param argv Argument vector (forwarded from `Run()`).
     * @return Exit code; 0 on success.
     */
    int Main(int argc, const char* argv[]) noexcept;

    /**
     * @brief Disposes the server and client runtime objects.
     *
     * @details Calls `Dispose()` on `server_` and `client_` if they are non-null, then
     *          nulls both pointers.  Safe to call multiple times.
     */
    void Dispose() noexcept;

    /**
     * @brief Releases configuration and clears the network interface reference.
     *
     * @details Called during shutdown after `Dispose()` to release the last shared
     *          references to configuration and network interface objects.
     */
    void Release() noexcept;

public:
    /**
     * @brief Returns a shared_ptr to the process-wide `PppApplication` singleton.
     *
     * @return Shared ownership pointer to the singleton instance.
     */
    static std::shared_ptr<PppApplication> GetDefault() noexcept;

    /**
     * @brief Handles the OS shutdown signal by initiating a clean application exit.
     *
     * @details Registered as the handler for `SIGTERM`/`SIGINT` (and `CTRL_C_EVENT` on
     *          Windows).  Posts a shutdown request to the main IO context.
     *
     * @return True if the shutdown is initiated successfully.
     */
    static bool OnShutdownApplication() noexcept;

    /**
     * @brief Requests application shutdown or restart.
     *
     * @param restart True to restart the process after shutdown; false for clean exit.
     * @return True if the request is posted to the IO context.
     */
    static bool ShutdownApplication(bool restart) noexcept;

    /**
     * @brief Registers OS signal handlers for graceful application shutdown.
     *
     * @details On POSIX systems registers `SIGTERM` and `SIGINT`.
     *          On Windows registers `CTRL_C_EVENT` and `CTRL_BREAK_EVENT`.
     *
     * @return True if all handlers are installed successfully.
     */
    static bool AddShutdownApplicationEventHandler() noexcept;

public:
    /**
     * @brief Returns the loaded application configuration snapshot.
     * @return Shared pointer to the `AppConfiguration`; null before `Run()` completes.
     */
    std::shared_ptr<ppp::configurations::AppConfiguration> GetConfiguration() noexcept;

    /**
     * @brief Returns the server-mode runtime object.
     * @return Shared pointer to `VirtualEthernetSwitcher`; null in client mode or before startup.
     */
    std::shared_ptr<ppp::app::server::VirtualEthernetSwitcher> GetServer() noexcept;

    /**
     * @brief Returns the client-mode runtime object.
     * @return Shared pointer to `VEthernetNetworkSwitcher`; null in server mode or before startup.
     */
    std::shared_ptr<ppp::app::client::VEthernetNetworkSwitcher> GetClient() noexcept;

    /**
     * @brief Returns the global buffer-swap allocator used for IO buffers.
     * @return Shared pointer to `BufferswapAllocator`; null before `Run()` completes.
     */
    std::shared_ptr<ppp::threading::BufferswapAllocator> GetBufferAllocator() noexcept;

    ppp::app::runtime::RuntimeSnapshot GetRuntimeSnapshot() const noexcept;
    std::string GetRuntimeSnapshotJson() const noexcept;
    std::uint64_t SubscribeRuntimeSnapshots(
        ppp::app::runtime::RuntimeLifecycle::Listener listener) noexcept;
    void UnsubscribeRuntimeSnapshots(std::uint64_t token) noexcept;

public:
    /**
     * @brief Prints help and usage information to standard output.
     *
     * @details Displays available command-line flags, configuration options, and examples.
     */
    void PrintHelpInformation() noexcept;

    /**
     * @brief Builds detailed runtime environment lines for console/TUI display.
     *
     * @details
     * Produces a high-detail snapshot (runtime identity, listeners, proxies,
     * NIC details, and traffic counters) that mirrors the legacy
     * `PrintEnvironmentInformation()` content model.
     *
     * @param lines Output vector receiving one formatted line per row.
     */
    void GetEnvironmentInformationLines(ppp::vector<ppp::string>& lines,
        uint64_t incoming_traffic,
        uint64_t outgoing_traffic,
        const std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept;

    /**
     * @brief Pulls and applies an IP list from the given command string or URL.
     *
     * @param command Command string specifying the source (URL or file path).
     * @param virr    True to insert into the virtual routing table; false for the firewall.
     */
    void PullIPList(const ppp::string& command, bool virr) noexcept;

    /**
     * @brief Downloads an IP list from a URL and returns the count of entries loaded.
     *
     * @param url URL of the IP list resource.
     * @param ips Set to populate with parsed IP/CIDR strings.
     * @return Number of entries loaded; 0 or negative on failure.
     */
    int PullIPList(const ppp::string& url, ppp::set<ppp::string>& ips) noexcept;

    /**
     * @brief Asynchronously downloads an IP list and invokes a callback with the result.
     *
     * @param url URL of the IP list resource.
     * @param cb  Callback invoked with the entry count and the populated IP set.
     * @return True if the download is initiated.
     */
    bool PullIPList(const ppp::string& url, const ppp::function<void(int, const ppp::set<ppp::string>&)>& cb) noexcept;

    /**
     * @brief Validates and pre-processes command-line arguments before `Main()` runs.
     *
     * @param argc Argument count.
     * @param argv Argument vector.
     * @return 0 on success; non-zero exit code on invalid arguments.
     */
    int PreparedArgumentEnvironment(int argc, const char* argv[]) noexcept;

protected:
    /**
     * @brief Called on each maintenance tick to update statistics and drive keepalive.
     *
     * @param now Current monotonic tick count in milliseconds.
     * @return True to continue ticking; false to stop the timer.
     */
    virtual bool OnTick(uint64_t now) noexcept;

private:
    /**
     * @brief Loads and parses the application configuration from the file indicated by argv.
     *
     * @param argc     Argument count.
     * @param argv     Argument vector.
     * @param path[out] Resolved path of the configuration file.
     * @return Shared pointer to the loaded `AppConfiguration`; null on failure.
     */
    std::shared_ptr<ppp::configurations::AppConfiguration> LoadConfiguration(int argc, const char* argv[], ppp::string& path) noexcept;

    /**
     * @brief Parses `--mode=client|server|proxy` from argv.
     */
    ApplicationMode ResolveApplicationMode(int argc, const char* argv[]) noexcept {
        return ResolveApplicationModeFromArgv(argc, argv);
    }

    /**
     * @brief Returns true when `--mode=client` or `--mode=proxy` is present in argv.
     */
    bool IsModeClientOrServer(int argc, const char* argv[]) noexcept;

    /**
     * @brief Resolves the physical network interface to use for routing.
     *
     * @param argc Argument count.
     * @param argv Argument vector.
     * @return Shared pointer to the resolved `NetworkInterface`; null on failure.
     */
    std::shared_ptr<NetworkInterface> GetNetworkInterface(int argc, const char* argv[]) noexcept;

    /**
     * @brief Parses an IP address argument by name, clamping the prefix to [MIN, MAX].
     *
     * @param name                 Argument name to look up in argv.
     * @param MIN_PREFIX_ADDRESS   Minimum valid prefix length.
     * @param MAX_PREFIX_ADDRESS   Maximum valid prefix length.
     * @param argc                 Argument count.
     * @param argv                 Argument vector.
     * @return Parsed IP address; unspecified address on failure.
     */
    boost::asio::ip::address GetNetworkAddress(const char* name, int MIN_PREFIX_ADDRESS, int MAX_PREFIX_ADDRESS, int argc, const char* argv[]) noexcept;

    /**
     * @brief Parses an IP address argument by name with a fallback default string.
     *
     * @param name                    Argument name to look up in argv.
     * @param MIN_PREFIX_ADDRESS      Minimum valid prefix length.
     * @param MAX_PREFIX_ADDRESS      Maximum valid prefix length.
     * @param default_address_string  Default address string used when the argument is absent.
     * @param argc                    Argument count.
     * @param argv                    Argument vector.
     * @return Parsed or default IP address.
     */
    boost::asio::ip::address GetNetworkAddress(const char* name, int MIN_PREFIX_ADDRESS, int MAX_PREFIX_ADDRESS, const char* default_address_string, int argc, const char* argv[]) noexcept;

    /**
     * @brief Parses one or more DNS address arguments from argv into the output vector.
     *
     * @param addresses[out] Vector populated with resolved DNS server addresses.
     * @param argc           Argument count.
     * @param argv           Argument vector.
     */
    void GetDnsAddresses(ppp::vector<boost::asio::ip::address>& addresses, int argc, const char* argv[]) noexcept;

    /**
     * @brief Variant that also returns parallel-indexed labels.
     *
     * When @p labels is non-null it is filled with one entry per address. A
     * non-empty label string indicates a human-readable rendering preference
     * (typically a DoH/DoT hostname plus protocol tag); an empty string
     * means the caller should fall back to formatting the IP literal.
     */
    void GetDnsAddresses(ppp::vector<boost::asio::ip::address>& addresses, ppp::vector<ppp::string>* labels, int argc, const char* argv[]) noexcept;

    /**
     * @brief Configures the loopback environment for the resolved network interface.
     *
     * @param network_interface Resolved network interface descriptor.
     * @return True if the loopback environment is set up correctly.
     */
    bool PreparedLoopbackEnvironment(const std::shared_ptr<NetworkInterface>& network_interface) noexcept;

private:
    /**
     * @brief Manages the always-timeout timer state across ticks.
     *
     * @param next True to arm the next tick; false to disarm.
     * @return Previous timer state.
     */
    static bool NextTickAlwaysTimeout(bool next) noexcept;

    /** @brief Cancels and releases the always-timeout maintenance timer. */
    void ClearTickAlwaysTimeout() noexcept;

private:
    /**
     * @brief Reads current transmission statistics from the active runtime.
     *
     * @param incoming_traffic[out]     Total bytes received since startup.
     * @param outgoing_traffic[out]     Total bytes sent since startup.
     * @param statistics_snapshot[out]  Snapshot of the current statistics object.
     * @return True if statistics are available and populated.
     */
    bool GetTransmissionStatistics(uint64_t& incoming_traffic, uint64_t& outgoing_traffic, std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept;

private:
    bool                                                                    client_mode_ = false;         ///< True when running in client or proxy mode.
    bool                                                                    proxy_mode_ = false;          ///< True when running in proxy-only mode.
    ApplicationMode                                                         application_mode_ = ApplicationMode::Server;
    bool                                                                    quic_        = false;         ///< True when QUIC transport is enabled.
    std::shared_ptr<ppp::configurations::AppConfiguration>                  configuration_;               ///< Loaded application configuration.
    std::shared_ptr<ppp::app::server::VirtualEthernetSwitcher>              server_;                      ///< Server runtime (null in client mode).
    std::shared_ptr<ppp::app::client::VEthernetNetworkSwitcher>             client_;                      ///< Client runtime (null in server mode).
    ppp::string                                                             configuration_path_;          ///< Resolved path of the loaded configuration file.
    ppp::string                                                             stats_json_path_;              ///< Optional local NDJSON statistics destination.
    ppp::app::runtime::DatapathAcceptanceBoundary                           acceptance_boundary_;          ///< Optional local stats/ack acceptance gate.
    std::shared_ptr<NetworkInterface>                                       network_interface_;           ///< Physical network interface descriptor.
    std::shared_ptr<ppp::threading::Timer>                                  timeout_ = 0;                 ///< Global maintenance timer.
    ppp::diagnostics::Stopwatch                                             stopwatch_;                   ///< Elapsed-time tracker for uptime display.
    ppp::diagnostics::PreventReturn                                         prevent_rerun_;               ///< Guard that prevents re-entrant execution.
    ppp::transmissions::ITransmissionStatistics                             transmission_statistics_;     ///< Accumulated traffic statistics snapshot.
    ppp::app::runtime::RuntimeLifecycle                                     runtime_lifecycle_;            ///< Authoritative runtime state contract.
};

} // namespace app
} // namespace ppp

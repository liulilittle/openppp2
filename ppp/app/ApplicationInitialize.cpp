/**
 * @file ApplicationInitialize.cpp
 * @brief Startup, teardown, and runtime preflight routines for the PPP application.
 */

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/ApplicationClientBootstrap.h>
#include <ppp/app/ApplicationServerBootstrap.h>
#include <ppp/app/PppApplicationInternal.h>
#include <ppp/p2p/P2PCapabilityGate.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/diagnostics/Error.h>
#if defined(_WIN32)
#include <windows/ppp/app/client/lsp/PaperAirplaneController.h>
#endif

namespace ppp::app {

/**
 * @brief Initializes process-level console state and platform-specific UI settings.
 *
 * @note The terminal cursor visibility is intentionally *not* altered here.
 *       ConsoleUI::Start() owns the cursor state for the duration of the TUI
 *       session and restores it verbatim on Stop().  Touching the cursor at
 *       construction time would corrupt redirected log files (the escape
 *       sequence would be written into the pipe) and race with the TUI's own
 *       save/restore sequence.
 */
PppApplication::PppApplication() noexcept {
#if defined(_WIN32)
    SetConsoleTitle(TEXT("PPP PRIVATE NETWORK™ 2"));

    ppp::win32::Win32Native::EnabledConsoleWindowClosedButton(false);
#endif
}

/**
 * @brief Releases owned runtime resources before object destruction.
 */
PppApplication::~PppApplication() noexcept {
    Release();
}

/**
 * @brief Restores temporary process state and closes singleton guard handles.
 *
 * @note Cursor restoration is handled by ConsoleUI::Stop(); see the note on
 *       the constructor for the rationale.
 */
void PppApplication::Release() noexcept {
#if defined(_WIN32)
    ppp::win32::Win32Native::EnabledConsoleWindowClosedButton(true);
#endif

    prevent_rerun_.Close();
}

/**
 * @brief Prepares tunnel, switcher, and route environment for client/server mode.
 * @param network_interface Resolved tunnel and routing configuration.
 * @return True when all required runtime components are successfully opened.
 */
bool PppApplication::PreparedLoopbackEnvironment(const std::shared_ptr<NetworkInterface>& network_interface) noexcept {
    std::shared_ptr<AppConfiguration> configuration = GetConfiguration();
    if (NULLPTR == configuration) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
        return false;
    }

    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULLPTR == context) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
        return false;
    }

#if defined(_WIN32)
    ppp::string executable_path = File::GetFullPath(File::RewritePath(ppp::GetFullExecutionFilePath().data()).data());
    ppp::win32::network::Fw::NetFirewallAddApplication(PPP_APPLICATION_NAME, executable_path.data());
    ppp::win32::network::Fw::NetFirewallAddAllApplication(PPP_APPLICATION_NAME, executable_path.data());

    if (client_mode_) {
        if (!proxy_mode_ && network_interface->HostedNetwork && configuration->client.paper_airplane.tcp) {
            if (ppp::app::client::lsp::PaperAirplaneController::Install() < 0) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                return false;
            }
        }
        ppp::app::client::lsp::PaperAirplaneController::NoLsp();
        ppp::app::client::lsp::PaperAirplaneController::Reset();
    }
#endif

    bool success = false;
    if (client_mode_) {
        success = PrepareClientLoopbackEnvironment(network_interface, configuration, context, proxy_mode_, client_);
    } else {
        success = PrepareServerLoopbackEnvironment(network_interface, configuration, server_);
    }

    if (!success) {
        if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppPreflightCheckFailed);
        }
    }

    return success;
}

#if defined(_WIN32)
/**
 * @brief Ensures a usable Windows TAP/Wintun component id is available.
 * @param network_interface Network interface settings to update in place.
 * @return True when a component id is resolved or already present.
 */
bool Windows_PreparedEthernetEnvironment(const std::shared_ptr<NetworkInterface>& network_interface) noexcept {
    if (network_interface->ComponentId.empty()) {
        ppp::string driverPath = File::GetFullPath((ppp::GetApplicationStartupPath() + "\\Driver\\").data());
        if (ppp::tap::TapWindows::InstallDriver(driverPath.data(), NetworkInterface::GetDefaultTun())) {
            network_interface->ComponentId = ppp::tap::TapWindows::FindComponentId(network_interface->Wintun);
            if (network_interface->ComponentId.empty()) {
                network_interface->ComponentId = ppp::tap::ITap::FindAnyDevice();
            }
        }

        if (network_interface->ComponentId.empty()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
            return false;
        }
    }
    return true;
}
#endif

/**
 * @brief Executes main startup flow after arguments/configuration are prepared.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Zero on success, negative value on failure.
 */
int PppApplication::Main(int argc, const char* argv[]) noexcept {
    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Success);

    ppp::app::runtime::RuntimeSnapshot runtime_seed;
    runtime_seed.role = proxy_mode_ ? "proxy" : (client_mode_ ? "client" : "server");
    runtime_seed.capabilities = {
        "mux.compat", "mux.flow", "mux.balance", "mux.stripe"};
    if (configuration_) {
        runtime_seed.p2p_state = ppp::p2p::P2PCapabilityGate::Evaluate(
            configuration_->p2p.enabled,
            configuration_->p2p.mode.c_str(),
            false,
            false,
            ppp::p2p::ProductionAuthenticatedControlV1Ready).state;
    }
    const std::uint64_t runtime_generation =
        runtime_lifecycle_.Begin(std::move(runtime_seed), Executors::GetTickCount());
    runtime_lifecycle_.Transition(
        runtime_generation,
        ppp::app::runtime::RuntimePhase::PreparingHost,
        Executors::GetTickCount());

    if (!proxy_mode_ && !ppp::IsUserAnAdministrator()) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppPrivilegeRequired);
        return -1;
    }

    ppp::string rerun_prefix = "server://";
    if (proxy_mode_) {
        rerun_prefix = "proxy://";
    }
    elif(client_mode_) {
        rerun_prefix = "client://";
    }
    ppp::string rerun_name = rerun_prefix + configuration_path_;
    if (prevent_rerun_.Exists(rerun_name.data())) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppAlreadyRunning);
        return -1;
    }

    if (!prevent_rerun_.Open(rerun_name.data())) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppLockAcquireFailed);
        return -1;
    }

#if defined(_WIN32)
    if (client_mode_ && !proxy_mode_) {
        if (!Windows_PreparedEthernetEnvironment(network_interface_)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
            return -1;
        }
    }

    quic_ = ppp::net::proxies::HttpProxy::IsSupportExperimentalQuicProtocol();
#endif

    runtime_lifecycle_.Transition(
        runtime_generation,
        ppp::app::runtime::RuntimePhase::Connecting,
        Executors::GetTickCount());
    if (!PreparedLoopbackEnvironment(network_interface_)) {
        if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppPreflightCheckFailed);
        }
        return -1;
    }
    runtime_lifecycle_.Transition(
        runtime_generation,
        ppp::app::runtime::RuntimePhase::Handshaking,
        Executors::GetTickCount());

    /**
     * @brief TUI startup with isatty-based fallback.
     *
     * When stdout is not connected to a terminal (pipe / file redirection),
     * the full-screen TUI is skipped to avoid corrupting captured output.
     * A brief plain-text summary is printed instead, and the process continues
     * with full VPN functionality but without an interactive interface.
     */
    bool tui_enabled = ConsoleUI::ShouldEnable();
    if (tui_enabled) {
        if (!ConsoleUI::GetInstance().Start()) {
            /**
             * @brief Non-fatal TUI initialization failure.
             *
             * Terminal setup failure (e.g. PrepareInputTerminal on an unsupported
             * pseudo-terminal) is treated as a warning rather than an error.
             * The process continues with plain-text output mode.
             */
            ppp::ConsoleWrite(
                "Warning: ConsoleUI initialization failed. "
                "Continuing in plain-text mode.\n");
            tui_enabled = false;
        }
    }

    if (!tui_enabled) {
        /**
         * @brief Plain-text startup banner for no-tty / redirected-output mode.
         *
         * Printed once at startup so that log files and pipes receive at least
         * basic identification information about this process instance.
         */
        ppp::ConsoleFormat(
            "PPP PRIVATE NETWORK(TM) 2  version: %s\n",
            PPP_APPLICATION_VERSION);
        ppp::ConsoleFormat(
            "Mode    : %s\n",
            ApplicationModeName(application_mode_));
        ppp::ConsoleFormat(
            "Process : %d\n",
            static_cast<int>(ppp::GetCurrentProcessId()));
        ppp::ConsoleFormat(
            "Config  : %s\n",
            configuration_path_.data());
        ppp::ConsoleFormat(
            "Cwd     : %s\n",
            ppp::GetCurrentDirectoryPath().data());
    }

    stopwatch_.Restart();
    transmission_statistics_.Clear();

    std::shared_ptr<client::VEthernetNetworkSwitcher> client = client_;
    if (NULLPTR != client) {
#if defined(_WIN32)
        ppp::net::proxies::HttpProxy::SetSupportExperimentalQuicProtocol(!network_interface_->BlockQUIC);
#endif
        client->BlockQUIC(network_interface_->BlockQUIC);

#if defined(_WIN32)
        if (!proxy_mode_ && network_interface_->SetHttpProxy) {
            client->SetHttpProxyToSystemEnv();
        }
#endif

        GLOBAL_VIRR.store(ppp::HasCommandArgument("--virr", argc, argv), std::memory_order_relaxed);
        if (GLOBAL_VIRR.load(std::memory_order_relaxed)) {
            GLOBAL_.bypass = network_interface_->Bypass;
            GLOBAL_.virr_argument = ppp::GetCommandArgument("--virr", argc, argv);
        }

        GLOBAL_VBGP.store(ppp::ToBoolean(ppp::GetCommandArgument("--vbgp", argc, argv, "y").data()), std::memory_order_relaxed);
    }

    {
        ppp::string auto_restart_arg = ppp::GetCommandArgument("--auto-restart", argc, argv);
        char* endptr = NULLPTR;
        long auto_restart_val = strtol(auto_restart_arg.data(), &endptr, 10);
        GLOBAL_.auto_restart = (NULLPTR != endptr && endptr != auto_restart_arg.data() && *endptr == '\x0') ? static_cast<int>(std::max<long>(0, auto_restart_val)) : 0;
    }
    {
        ppp::string link_restart_arg = ppp::GetCommandArgument("--link-restart", argc, argv);
        char* endptr = NULLPTR;
        long link_restart_val = strtol(link_restart_arg.data(), &endptr, 10);
        GLOBAL_.link_restart = (NULLPTR != endptr && endptr != link_restart_arg.data() && *endptr == '\x0') ? static_cast<uint8_t>(std::max<long>(0, link_restart_val)) : 0;
    }

    if (!NextTickAlwaysTimeout(false)) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerStartFailed);
        Dispose();
        return -1;
    }

    return 0;
}

} // namespace ppp::app

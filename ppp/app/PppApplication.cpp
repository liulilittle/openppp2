#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/PppApplicationInternal.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>

namespace ppp::app {

using server::VirtualEthernetSwitcher;
using client::VEthernetNetworkSwitcher;

std::shared_ptr<PppApplication> DEFAULT_;
/* Serializes every access to the process-wide DEFAULT_ application pointer. */
static std::mutex DEFAULT_LOCK_;
std::atomic<bool> GLOBAL_RESTART{false};
std::atomic<bool> GLOBAL_VBGP{false};
std::atomic<uint64_t> GLOBAL_VBGP_LAST{0};
std::atomic<bool> GLOBAL_VIRR{false};
std::atomic<uint64_t> GLOBAL_VIRR_NEXT{0};
ApplicationGlobals GLOBAL_;

PppApplication& PppApplication::GetInstance() noexcept {
    static std::shared_ptr<PppApplication> instance = ppp::make_shared_object<PppApplication>();
    {
        std::lock_guard<std::mutex> scope(DEFAULT_LOCK_);
        if (DEFAULT_ != instance) {
            DEFAULT_ = instance;
        }
    }
    return *instance;
}

int PppApplication::Run(int argc, char** argv) noexcept {
    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Success);

    ppp::RT = ppp::ToBoolean(ppp::GetCommandArgument("--rt", argc, const_cast<const char**>(argv), "y").data());
    ppp::global::cctor();

#if BOOST_ASIO_HAS_IO_URING != 0
    if (!ppp::diagnostics::IfIOUringKernelVersion()) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        return -1;
    }
#endif

    std::shared_ptr<PppApplication> app;
    {
        std::lock_guard<std::mutex> scope(DEFAULT_LOCK_);
        app = DEFAULT_;
        if (NULLPTR == app) {
            app = ppp::make_shared_object<PppApplication>();
            if (NULLPTR == app) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return -1;
            }
            DEFAULT_ = app;
        }
    }

    int prepared_status = app->PreparedArgumentEnvironment(argc, const_cast<const char**>(argv));
    int result_code = Executors::Run(
        app->GetBufferAllocator(),
        [app, prepared_status](int inner_argc, const char* inner_argv[]) noexcept -> int {
            int rc = RunPreparedApplication(app, prepared_status, inner_argc, inner_argv);
#if defined(_WIN32)
            if (rc != 0) {
                ppp::win32::Win32Native::PauseWindowsConsole();
            }
#endif
            return rc;
        },
        argc,
        const_cast<const char**>(argv));

    app->Release();
    ppp::telemetry::Shutdown();

    if (GLOBAL_RESTART.load(std::memory_order_relaxed)) {
#if defined(_WIN32)
        ppp::string command_line = "\"" + ppp::string(*argv) + "\"";
        for (int i = 1; i < argc; ++i) {
            command_line += " \"" + ppp::string(argv[i]) + "\"";
        }

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        if (CreateProcessA(NULLPTR, command_line.data(), NULLPTR, NULLPTR, FALSE, 0, NULLPTR, NULLPTR, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
#else
        execvp(*argv, argv);
#endif
    }

    return result_code;
}

std::shared_ptr<VirtualEthernetSwitcher> PppApplication::GetServer() noexcept {
    return server_;
}

std::shared_ptr<VEthernetNetworkSwitcher> PppApplication::GetClient() noexcept {
    return client_;
}

std::shared_ptr<PppApplication> PppApplication::GetDefault() noexcept {
    std::lock_guard<std::mutex> scope(DEFAULT_LOCK_);
    return DEFAULT_;
}

std::shared_ptr<AppConfiguration> PppApplication::GetConfiguration() noexcept {
    return configuration_;
}

ppp::app::runtime::RuntimeSnapshot PppApplication::GetRuntimeSnapshot() const noexcept {
    return runtime_lifecycle_.GetSnapshot();
}

std::string PppApplication::GetRuntimeSnapshotJson() const noexcept {
    return ppp::app::runtime::SerializeRuntimeSnapshot(GetRuntimeSnapshot());
}

std::uint64_t PppApplication::SubscribeRuntimeSnapshots(
    ppp::app::runtime::RuntimeLifecycle::Listener listener) noexcept {
    return runtime_lifecycle_.Subscribe(std::move(listener));
}

void PppApplication::UnsubscribeRuntimeSnapshots(std::uint64_t token) noexcept {
    runtime_lifecycle_.Unsubscribe(token);
}

bool PppApplication::OnShutdownApplication() noexcept {
    return ShutdownApplication(false);
}

bool PppApplication::ShutdownApplication(bool restart) noexcept {
    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULLPTR == context) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
        return false;
    }

    GLOBAL_RESTART.store(GLOBAL_RESTART.load(std::memory_order_relaxed) || restart, std::memory_order_relaxed);
    boost::asio::post(*context, [restart, context]() noexcept {
        std::shared_ptr<PppApplication> app;
        {
            std::lock_guard<std::mutex> scope(DEFAULT_LOCK_);
            app = std::move(DEFAULT_);
        }
        if (NULLPTR == app) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppContextUnavailable);
            return false;
        }

        app->Dispose();
        std::shared_ptr<Timer> timeout = Timer::Timeout(context, 1000, [](Timer*) noexcept { Executors::Exit(); });
        if (NULLPTR == timeout) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerStartFailed);
        }
        return NULLPTR != timeout;
    });
    return true;
}

bool PppApplication::AddShutdownApplicationEventHandler() noexcept {
#if defined(_WIN32)
    bool registered = ppp::win32::Win32Native::AddShutdownApplicationEventHandler(PppApplication::OnShutdownApplication);
#else
    bool registered = ppp::unix__::UnixAfx::AddShutdownApplicationEventHandler(PppApplication::OnShutdownApplication);
#endif
    if (!registered) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEventDispatchFailed);
    }
    return registered;
}

bool PppApplication::NextTickAlwaysTimeout(bool next) noexcept {
    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULLPTR == context) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
        return false;
    }

    std::shared_ptr<PppApplication> app;
    {
        std::lock_guard<std::mutex> scope(DEFAULT_LOCK_);
        app = DEFAULT_;
    }
    if (NULLPTR == app) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppContextUnavailable);
        return false;
    }

    std::shared_ptr<VirtualEthernetSwitcher> server = app->server_;
    std::shared_ptr<VEthernetNetworkSwitcher> client = app->client_;
    if (NULLPTR == server && NULLPTR == client) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
        return false;
    }

    std::shared_ptr<Timer> timeout = Timer::Timeout(context, 1000, [](Timer*) noexcept {
        std::shared_ptr<PppApplication> inner;
        {
            std::lock_guard<std::mutex> scope(DEFAULT_LOCK_);
            inner = DEFAULT_;
        }
        if (NULLPTR != inner) {
            inner->NextTickAlwaysTimeout(true);
        }
    });
    if (NULLPTR == timeout) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerStartFailed);
        return false;
    }

    app->timeout_ = std::move(timeout);
    app->OnTick(Executors::GetTickCount());
    return true;
}

void PppApplication::ClearTickAlwaysTimeout() noexcept {
    std::shared_ptr<Timer> timeout = std::move(timeout_);
    if (NULLPTR != timeout) {
        timeout->Dispose();
    }
}

int RunPreparedApplication(const std::shared_ptr<PppApplication>& app, int prepared_status, int argc, const char* argv[]) noexcept {
    if (ppp::HasCommandArgument("--pull-iplist", argc, argv)) {
        app->PullIPList(ppp::GetCommandArgument("--pull-iplist", argc, argv), false);
        int rc = ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::Success ? 0 : -1;
        Executors::Exit();
        return rc;
    }

#if defined(_WIN32)
    if (Windows_PreferredNetwork(argc, argv)) {
        return ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::Success ? 0 : -1;
    }

    if (Windows_NoLsp(argc, argv)) {
        return ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::Success ? 0 : -1;
    }

    if (ppp::HasCommandArgument("--system-network-optimization", argc, argv)) {
        if (!ppp::win32::Win32Native::OptimizationSystemNetworkSettings()) {
            if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
            }
        }
        return ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::Success ? 0 : -1;
    }
#endif

    if (prepared_status != 0) {
        app->PrintHelpInformation();
        if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppInvalidCommandLine);
        }
        return -1;
    }

    PppApplication::AddShutdownApplicationEventHandler();

#if SIGRESTART
    signal(SIGRESTART, [](int) noexcept { PppApplication::ShutdownApplication(true); });
#endif

    return app->Main(argc, argv);
}

} // namespace ppp::app

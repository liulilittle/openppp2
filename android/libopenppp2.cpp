// https://www-numi.fnal.gov/offline_software/srt_public_context/WebDocs/Errors/unix_system_errors.html
// #define ENOENT           2      /* No such file or directory */
// #define EAGAIN          11      /* Try again */

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/IDisposable.h>
#include <ppp/Int128.h>
#include <ppp/io/File.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/native/rib.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/vdns.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Stopwatch.h>

#include <ppp/auxiliary/JsonAuxiliary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/auxiliary/UriAuxiliary.h>

#include <ppp/threading/Timer.h>
#include <ppp/threading/Thread.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>

#include <ppp/app/ApplicationClientBootstrap.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetManagedServer.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/proxys/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetSocksProxySwitcher.h>
#include <common/aggligator/aggligator.h>
#include <ppp/app/client/GeoRuleGenerator.h>
#include <ppp/app/runtime/RuntimeLifecycle.h>
#include <ppp/app/runtime/RuntimeSnapshotJson.h>

#include <android/OpenPPP2VpnProtectBridge.h>
#include <android/OpenPPP2TelemetryBridge.h>

#include <linux/ppp/tap/TapLinux.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <chrono>

#include <signal.h>
#include <setjmp.h>
#include <assert.h>

#include <fcntl.h>
#include <errno.h>
#include <malloc.h>

#include <unistd.h>
#include <netdb.h>
#if !defined(__BIONIC__) && !defined(_ANDROID)
#include <error.h>
#endif
#include <pthread.h>
#include <sched.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <sys/resource.h>
#include <sys/ptrace.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <android/log.h>
#include <jni.h>

#include <iostream>
#include <algorithm>
#include <string>
#include <memory>
#include <exception>
#include <atomic>
#include <mutex>

#ifndef __LIBOPENPPP2__
#define __LIBOPENPPP2__(JNIType)                                            extern "C" JNIEXPORT __unused JNIType JNICALL
#endif

#ifndef __LIBOPENPPP2_MAIN__
#define __LIBOPENPPP2_MAIN__                                                libopenppp2_application::GetDefault();
#endif

#ifdef _ANDROID_REDEF_STD_IN_OUT_ERR
#ifdef ANDROID
#undef stdin
#undef stdout
#undef stderr
FILE* stdin = &__sF[0];
FILE* stdout = &__sF[1];
FILE* stderr = &__sF[2];
#endif
#endif

// Runtime snapshot push bridge.
//
// RuntimeLifecycle::Subscribe invokes listeners on whichever thread produced the
// transition -- the JVM thread inside run(), the executor timer thread, or the
// thread that completed Dispose() -- so the JVM is attached per call and JNIEnv*
// is never cached. The class is resolved in JNI_OnLoad because FindClass on an
// attached native thread uses the system class loader and cannot see
// application classes.
static JavaVM*                                                              libopenppp2_runtime_vm = NULLPTR;
static jclass                                                               libopenppp2_runtime_clazz = NULLPTR;
static jmethodID                                                            libopenppp2_runtime_method = NULLPTR;

static bool                                                                 libopenppp2_cache_runtime_snapshot_method(JavaVM* vm, JNIEnv* env) noexcept {
    if (NULLPTR == vm || NULLPTR == env) {
        return false;
    }

    jclass clazz = env->FindClass(LIBOPENPPP2_CLASSNAME);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }

    if (NULLPTR == clazz) {
        return false;
    }

    jmethodID method = env->GetStaticMethodID(clazz, "runtime_snapshot", "(Ljava/lang/String;)V");
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }

    if (NULLPTR == method) {
        env->DeleteLocalRef(clazz);
        return false;
    }

    jclass global_clazz = static_cast<jclass>(env->NewGlobalRef(clazz));
    env->DeleteLocalRef(clazz);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }

    if (NULLPTR == global_clazz) {
        return false;
    }

    libopenppp2_runtime_vm = vm;
    libopenppp2_runtime_clazz = global_clazz;
    libopenppp2_runtime_method = method;
    return true;
}

static void                                                                 libopenppp2_publish_runtime_snapshot(const std::string& json) noexcept {
    JavaVM* vm = libopenppp2_runtime_vm;
    if (NULLPTR == vm || NULLPTR == libopenppp2_runtime_clazz ||
        NULLPTR == libopenppp2_runtime_method || json.empty()) {
        return;
    }

    JNIEnv* env = NULLPTR;
    bool attached = false;
    jint status = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (JNI_EDETACHED == status) {
#if defined(__ANDROID__)
        if (JNI_OK != vm->AttachCurrentThread(&env, NULLPTR)) {
#else
        if (JNI_OK != vm->AttachCurrentThread(reinterpret_cast<void**>(&env), NULLPTR)) {
#endif
            return;
        }

        attached = true;
    }
    else if (JNI_OK != status) {
        return;
    }

    jstring json_string = env->NewStringUTF(json.data());
    if (NULLPTR != json_string) {
        env->CallStaticVoidMethod(libopenppp2_runtime_clazz, libopenppp2_runtime_method, json_string);
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }

        env->DeleteLocalRef(json_string);
    }
    else if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }

    if (attached) {
        vm->DetachCurrentThread();
    }
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    if (NULLPTR == vm) {
        return JNI_ERR;
    }

    JNIEnv* env = NULLPTR;
    if (JNI_OK != vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6)) {
        return JNI_ERR;
    }

    ppp::android::InitializeProtectBridge(vm, env);
    ppp::android::InitializeTelemetryBridge(vm, env);
    libopenppp2_cache_runtime_snapshot_method(vm, env);
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved) {
    JNIEnv* env = NULLPTR;
    if (NULLPTR != vm && JNI_OK == vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6)) {
        ppp::android::ShutdownProtectBridge(env);
        ppp::android::ShutdownTelemetryBridge(env);
    }
    else {
        ppp::android::ShutdownProtectBridge();
        ppp::android::ShutdownTelemetryBridge();
    }
}

static inline jstring                                                       JNIENV_NewStringUTF(JNIEnv* env, const char* v) noexcept { return NULLPTR != v ? env->NewStringUTF(v) : NULLPTR; }
static std::shared_ptr<ppp::string>                                         JNIENV_GetStringUTFChars(JNIEnv* env, const jstring& v) noexcept {
    std::shared_ptr<ppp::string> result;
    if (NULLPTR != v) {
        char* s = (char*)env->GetStringUTFChars(v, NULLPTR);
        if (NULLPTR != s) {
            result =
                ppp::make_shared_object<ppp::string>(s);
            env->ReleaseStringUTFChars(v, s);
        }
    }

    return result;
}

enum {
    LIBOPENPPP2_LINK_STATE_ESTABLISHED                                      = 0,
    LIBOPENPPP2_LINK_STATE_UNKNOWN                                          = 1,
    LIBOPENPPP2_LINK_STATE_CLIENT_UNINITIALIZED                             = 2,
    LIBOPENPPP2_LINK_STATE_EXCHANGE_UNINITIALIZED                           = 3,
    LIBOPENPPP2_LINK_STATE_RECONNECTING                                     = 4,
    LIBOPENPPP2_LINK_STATE_CONNECTING                                       = 5,
    LIBOPENPPP2_LINK_STATE_APPLICATIION_UNINITIALIZED                       = 6,
};

enum {
    LIBOPENPPP2_AGGLIGATOR_STATE_NONE                                       = 0,
    LIBOPENPPP2_AGGLIGATOR_STATE_UNKNOWN                                    = 1,
    LIBOPENPPP2_AGGLIGATOR_STATE_CONNECTING                                 = 2,
    LIBOPENPPP2_AGGLIGATOR_STATE_RECONNECTING                               = 3,
    LIBOPENPPP2_AGGLIGATOR_STATE_ESTABLISHED                                = 4,
};

enum {
    // COMMON
    LIBOPENPPP2_ERROR_SUCCESS                                               = 0,
    LIBOPENPPP2_ERROR_UNKNOWN                                               = 1,
    LIBOPENPPP2_ERROR_ALLOCATED_MEMORY                                      = 2,
    LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED                            = 3,

    // SET_APP_CONFIGURATION
    LIBOPENPPP2_ERROR_NEW_CONFIGURATION_FAIL                                = 101,
    LIBOPENPPP2_ERROR_ARG_CONFIGURATION_STRING_IS_NULL_OR_EMPTY             = 102,
    LIBOPENPPP2_ERROR_ARG_CONFIGURATION_STRING_NOT_IS_JSON_OBJECT_STRING    = 103,
    LIBOPENPPP2_ERROR_ARG_CONFIGURATION_STRING_CONFIGURE_ERROR              = 104,

    // SET_NETWORK_INTERFACE
    LIBOPENPPP2_ERROR_NEW_NETWORKINTERFACE_FAIL                             = 201,
    LIBOPENPPP2_ERROR_ARG_TUN_IS_INVALID                                    = 202,
    LIBOPENPPP2_ERROR_ARG_IP_IS_NULL_OR_EMPTY                               = 203,
    LIBOPENPPP2_ERROR_ARG_MASK_IS_NULL_OR_EMPTY                             = 204,
    LIBOPENPPP2_ERROR_ARG_IP_IS_NOT_AF_INET_FORMAT                          = 205,
    LIBOPENPPP2_ERROR_ARG_MASK_IS_NOT_AF_INET_FORMAT                        = 206,
    LIBOPENPPP2_ERROR_ARG_MASK_SUBNET_IP_RANGE_GREATER_65535                = 207,
    LIBOPENPPP2_ERROR_ARG_IP_IS_INVALID                                     = 208,

    // RUN
    LIBOPENPPP2_ERROR_IT_IS_RUNING                                          = 301,
    LIBOPENPPP2_ERROR_NETWORK_INTERFACE_NOT_CONFIGURED                      = 302,
    LIBOPENPPP2_ERROR_APP_CONFIGURATION_NOT_CONFIGURED                      = 303,
    LIBOPENPPP2_ERROR_OPEN_VETHERNET_FAIL                                   = 304,
    LIBOPENPPP2_ERROR_OPEN_TUNTAP_FAIL                                      = 305,
    LIBOPENPPP2_ERROR_VETHERNET_PPPD_THREAD_NOT_RUNING                      = 306,

    // STOP
    LIBOPENPPP2_ERROR_IT_IS_NOT_RUNING                                      = 401,
};

static ppp::diagnostics::ErrorCode                                          libopenppp2_translate_error(int err) noexcept {
    using ErrorCode = ppp::diagnostics::ErrorCode;

    switch (err) {
    case LIBOPENPPP2_ERROR_SUCCESS:
        return ErrorCode::Success;
    case LIBOPENPPP2_ERROR_ALLOCATED_MEMORY:
    case LIBOPENPPP2_ERROR_NEW_CONFIGURATION_FAIL:
    case LIBOPENPPP2_ERROR_NEW_NETWORKINTERFACE_FAIL:
        return ErrorCode::MemoryAllocationFailed;
    case LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED:
        return ErrorCode::AppContextUnavailable;
    case LIBOPENPPP2_ERROR_ARG_CONFIGURATION_STRING_IS_NULL_OR_EMPTY:
        return ErrorCode::ConfigFieldMissing;
    case LIBOPENPPP2_ERROR_ARG_CONFIGURATION_STRING_NOT_IS_JSON_OBJECT_STRING:
        return ErrorCode::ConfigFileMalformed;
    case LIBOPENPPP2_ERROR_ARG_CONFIGURATION_STRING_CONFIGURE_ERROR:
        return ErrorCode::ConfigLoadFailed;
    case LIBOPENPPP2_ERROR_ARG_TUN_IS_INVALID:
        return ErrorCode::TunnelDeviceMissing;
    case LIBOPENPPP2_ERROR_ARG_IP_IS_NULL_OR_EMPTY:
    case LIBOPENPPP2_ERROR_ARG_MASK_IS_NULL_OR_EMPTY:
        return ErrorCode::ConfigFieldMissing;
    case LIBOPENPPP2_ERROR_ARG_IP_IS_NOT_AF_INET_FORMAT:
    case LIBOPENPPP2_ERROR_ARG_IP_IS_INVALID:
        return ErrorCode::NetworkAddressInvalid;
    case LIBOPENPPP2_ERROR_ARG_MASK_IS_NOT_AF_INET_FORMAT:
    case LIBOPENPPP2_ERROR_ARG_MASK_SUBNET_IP_RANGE_GREATER_65535:
        return ErrorCode::NetworkMaskInvalid;
    case LIBOPENPPP2_ERROR_IT_IS_RUNING:
        return ErrorCode::AppAlreadyRunning;
    case LIBOPENPPP2_ERROR_NETWORK_INTERFACE_NOT_CONFIGURED:
        return ErrorCode::NetworkInterfaceUnavailable;
    case LIBOPENPPP2_ERROR_APP_CONFIGURATION_NOT_CONFIGURED:
        return ErrorCode::AppConfigurationMissing;
    case LIBOPENPPP2_ERROR_OPEN_VETHERNET_FAIL:
        return ErrorCode::NetworkInterfaceOpenFailed;
    case LIBOPENPPP2_ERROR_OPEN_TUNTAP_FAIL:
        return ErrorCode::TunnelOpenFailed;
    case LIBOPENPPP2_ERROR_VETHERNET_PPPD_THREAD_NOT_RUNING:
        return ErrorCode::RuntimeThreadStartFailed;
    case LIBOPENPPP2_ERROR_IT_IS_NOT_RUNING:
        return ErrorCode::AndroidLibInvalidState;
    case LIBOPENPPP2_ERROR_UNKNOWN:
    default:
        return ErrorCode::AndroidLibUnknownFailure;
    }
}

static inline int                                                            libopenppp2_set_last_error_for_result(int err) noexcept {
    using ErrorCode = ppp::diagnostics::ErrorCode;

    if (err == LIBOPENPPP2_ERROR_SUCCESS) {
        ppp::diagnostics::SetLastErrorCode(ErrorCode::Success);
        return err;
    }

    if (ppp::diagnostics::GetLastErrorCodeSnapshot() == ErrorCode::Success) {
        ppp::diagnostics::SetLastErrorCode(libopenppp2_translate_error(err));
    }

    return err;
}

static inline int                                                            libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode code, int err) noexcept {
    ppp::diagnostics::SetLastErrorCode(code);
    return err;
}

typedef std::mutex                                                          SynchronizedObject;
typedef std::lock_guard<SynchronizedObject>                                 SynchronizedObjectScope;

using ppp::configurations::AppConfiguration;
using ppp::threading::Executors;
using ppp::threading::Thread;
using ppp::threading::Timer;
using ppp::threading::BufferswapAllocator;
using ppp::coroutines::YieldContext;
using ppp::tap::ITap;
using ppp::net::Ipep;
using ppp::net::IPEndPoint;
using ppp::net::asio::IAsynchronousWriteIoQueue;
using ppp::diagnostics::Stopwatch;
using ppp::auxiliary::JsonAuxiliary;
using ppp::auxiliary::StringAuxiliary;
using ppp::auxiliary::UriAuxiliary;
using ppp::app::client::VEthernetExchanger;
using ppp::app::client::VEthernetNetworkSwitcher;
using ppp::app::client::VEthernetExchanger;
using ppp::app::client::proxys::VEthernetHttpProxySwitcher;
using ppp::app::client::proxys::VEthernetSocksProxySwitcher;
using ppp::IDisposable;

struct libopenppp2_network_interface final {
    int                                                                     VTun       = -1;
    uint16_t                                                                VMux       = 0;
    bool                                                                    VNet       = false;
    bool                                                                    StaticMode = false;
    bool                                                                    BlockQUIC  = false;

    boost::asio::ip::address                                                IPAddress;
    boost::asio::ip::address                                                GatewayServer;
    boost::asio::ip::address                                                SubmaskAddress;
};

class libopenppp2_application final : public std::enable_shared_from_this<libopenppp2_application> {
public:
    static std::shared_ptr<libopenppp2_application>                         GetDefault() noexcept;
    void                                                                    DllMain() noexcept;
    bool                                                                    Release() noexcept;
    bool                                                                    Release(bool success, ppp::app::runtime::RuntimeError error) noexcept;
    bool                                                                    OnTick(uint64_t now) noexcept;
    static bool                                                             Post(int sequence) noexcept;
    static int                                                              Invoke(const ppp::function<int()>& task) noexcept;
    static bool                                                             Timeout() noexcept;

public:
    std::shared_ptr<Timer>                                                  timeout_ = 0;
    Stopwatch                                                               stopwatch_;
    std::shared_ptr<VEthernetNetworkSwitcher>                               client_;
    std::shared_ptr<AppConfiguration>                                       configuration_;
    std::shared_ptr<libopenppp2_network_interface>                          network_interface_;
    std::shared_ptr<ppp::string>                                            bypass_ip_list_;
    std::shared_ptr<ppp::string>                                            dns_rules_list_;
    ppp::transmissions::ITransmissionStatistics                             transmission_statistics_;
    struct {
        uint64_t                                                            tx = UINT64_MAX;
        uint64_t                                                            rx = UINT64_MAX;
        uint64_t                                                            in = UINT64_MAX;
        uint64_t                                                            out = UINT64_MAX;
    }                                                                       last_reported_statistics_;
    uint32_t                                                                stats_perf_log_ticks_ = 0;
    ppp::app::runtime::RuntimeLifecycle                                     runtime_lifecycle_;

private:
    bool                                                                    ReportTransmissionStatistics(uint64_t now) noexcept;
    bool                                                                    GetTransmissionStatistics(uint64_t& incoming_traffic, uint64_t& outgoing_traffic, std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept;

public:
    bool                                                                    PostExecJNI(JNIEnv* env, int sequence) noexcept;
    bool                                                                    StartJNI(JNIEnv* env, int key) noexcept;
    bool                                                                    ExecJNI(JNIEnv* env, const char* method_name, int param) noexcept;
    bool                                                                    PostJNI(const ppp::function<void(JNIEnv*)>& task) noexcept;
};

std::shared_ptr<libopenppp2_application>                                    libopenppp2_application::GetDefault() noexcept {
    struct libopenppp2_application_domain final {
    public:
        libopenppp2_application_domain() noexcept {
            // Run vpn/pppd main loop thread, which is the main thread of the VPN application driver, not the JVM managed thread.
            std::shared_ptr<Executors::Awaitable> awaitable = ppp::make_shared_object<Executors::Awaitable>();
            if (NULLPTR != awaitable) {
                std::weak_ptr<Executors::Awaitable> awaitable_weak = awaitable;
                std::thread(
                    [this, awaitable_weak]() noexcept {
                        // Global static constructor for PPP PRIVATE NETWORK™ 2. (For OS X platform compatibility.)
                        ppp::global::cctor();

                        std::shared_ptr<libopenppp2_application> app = ppp::make_shared_object<libopenppp2_application>();
                        app_ = app;

                        if (NULLPTR != app) {
                            auto start =
                                [app, awaitable_weak](int argc, const char* argv[]) noexcept -> int {
                                    std::shared_ptr<Executors::Awaitable> awaitable = awaitable_weak.lock();
                                    if (NULLPTR != awaitable) {
                                        awaitable->Processed();
                                    }

                                    app->DllMain();
                                    return 0;
                                };
                            Executors::Run(NULLPTR, start);
                        }
                    }).detach();
                awaitable->Await();
            }
        }

    public:
        std::shared_ptr<libopenppp2_application>                            app_;
    };

    static libopenppp2_application_domain domain;
    return domain.app_;
}

void                                                                        libopenppp2_application::DllMain() noexcept {
    // fork and run the vpn background work subthread.
    int max_concurrent = ppp::GetProcesserCount();
    if (max_concurrent > 1) {
        // The android platform only allows the client adapter mode to work, so there is no need to set the maximum working subthread.
        Executors::SetMaxSchedulers(max_concurrent);
    }
}

bool                                                                        libopenppp2_application::Timeout() noexcept {
    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULLPTR == context) {
        return false;
    }

    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return false;
    }

    std::shared_ptr<VEthernetNetworkSwitcher> client = std::atomic_load(&app->client_);
    if (NULLPTR == client) {
        return false;
    }

    std::shared_ptr<Timer> timeout = Timer::Timeout(context, 1000,
        [](Timer*) noexcept {
            std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
            if (NULLPTR != app) {
                app->timeout_.reset();
                libopenppp2_application::Timeout();
            }
        });
    if (NULLPTR == timeout) {
        return false;
    }

    app->timeout_ = std::move(timeout);
    app->OnTick(Executors::GetTickCount());
    return true;
}

bool                                                                        libopenppp2_application::OnTick(uint64_t now) noexcept {
    const ppp::app::runtime::RuntimeSnapshot runtime = runtime_lifecycle_.GetSnapshot();
    std::shared_ptr<VEthernetNetworkSwitcher> client = std::atomic_load(&client_);
    if (runtime.generation != 0 &&
        runtime.phase != ppp::app::runtime::RuntimePhase::Stopping &&
        NULLPTR != client) {
        std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger();
        if (NULLPTR == exchanger) {
            runtime_lifecycle_.Transition(
                runtime.generation,
                ppp::app::runtime::RuntimePhase::Connecting,
                now);
        }
        else {
            runtime_lifecycle_.UpdateMuxState(
                runtime.generation,
                exchanger->GetMuxRuntimeState(),
                now);
        }
        if (NULLPTR != exchanger && exchanger->GetNetworkState() == VEthernetExchanger::NetworkState_Reconnecting) {
            runtime_lifecycle_.Transition(
                runtime.generation,
                ppp::app::runtime::RuntimePhase::Reconnecting,
                now);
        }
        else if (NULLPTR != exchanger && exchanger->GetNetworkState() == VEthernetExchanger::NetworkState_Established) {
            runtime_lifecycle_.UpdateReadiness(
                runtime.generation,
                client->GetRuntimeReadiness(),
                now);
            runtime_lifecycle_.Transition(
                runtime.generation,
                ppp::app::runtime::RuntimePhase::Connected,
                now);
        }
        else if (NULLPTR != exchanger) {
            runtime_lifecycle_.Transition(
                runtime.generation,
                ppp::app::runtime::RuntimePhase::Handshaking,
                now);
        }
    }
    ReportTransmissionStatistics(now);
    return true;
}

bool                                                                        libopenppp2_application::ReportTransmissionStatistics(uint64_t now) noexcept {
    // Get statistics on the physical network transport layer of the Virtual Ethernet switcher.
    uint64_t incoming_traffic = 0;
    uint64_t outgoing_traffic = 0;
    std::shared_ptr<ppp::transmissions::ITransmissionStatistics> statistics_snapshot;
    if (!GetTransmissionStatistics(incoming_traffic, outgoing_traffic, statistics_snapshot)) {
        incoming_traffic = 0;
        outgoing_traffic = 0;
        statistics_snapshot = NULLPTR;
    }

    const uint64_t in_total = NULLPTR != statistics_snapshot ? statistics_snapshot->IncomingTraffic.load() : 0;
    const uint64_t out_total = NULLPTR != statistics_snapshot ? statistics_snapshot->OutgoingTraffic.load() : 0;

    // The runtime snapshot is the only traffic surface; consumers derive rates
    // from two snapshots instead of accumulating per-tick deltas.
    if (const uint64_t generation = runtime_lifecycle_.GetSnapshot().generation; generation != 0) {
        ppp::app::runtime::RuntimeTraffic traffic;
        traffic.rx_bytes = in_total;
        traffic.tx_bytes = out_total;
        runtime_lifecycle_.UpdateTraffic(generation, traffic, now);
    }

    if (last_reported_statistics_.tx == outgoing_traffic &&
        last_reported_statistics_.rx == incoming_traffic &&
        last_reported_statistics_.in == in_total &&
        last_reported_statistics_.out == out_total) {
        return true;
    }

    last_reported_statistics_.tx = outgoing_traffic;
    last_reported_statistics_.rx = incoming_traffic;
    last_reported_statistics_.in = in_total;
    last_reported_statistics_.out = out_total;

    ++stats_perf_log_ticks_;
    if ((stats_perf_log_ticks_ % 10) == 0) {
        __android_log_print(ANDROID_LOG_INFO, "libopenppp2",
            "perf throughput tx=%llu rx=%llu in=%llu out=%llu",
            static_cast<unsigned long long>(outgoing_traffic),
            static_cast<unsigned long long>(incoming_traffic),
            static_cast<unsigned long long>(in_total),
            static_cast<unsigned long long>(out_total));
    }

    return true;
}

bool                                                                        libopenppp2_application::PostJNI(const ppp::function<void(JNIEnv*)>& task) noexcept {
    if (NULLPTR == task) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AndroidLibNullCallback);
        return false;
    }

    std::shared_ptr<VEthernetNetworkSwitcher> client = std::atomic_load(&client_);
    if (NULLPTR == client) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
        return false;
    }

    std::shared_ptr<ppp::net::ProtectorNetwork> protector = client->GetProtectorNetwork();
    if (NULLPTR == protector) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        return false;
    }

    std::shared_ptr<boost::asio::io_context> context = protector->GetContext();
    if (NULLPTR == context) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
        return false;
    }

    std::weak_ptr<ppp::net::ProtectorNetwork> protector_weak = protector;
    boost::asio::post(*context,
        [context, protector_weak, task]() noexcept {
            std::shared_ptr<ppp::net::ProtectorNetwork> protector = protector_weak.lock();
            if (NULLPTR == protector) {
                __android_log_print(ANDROID_LOG_WARN, "libopenppp2",
                    "PostJNI: protector expired, task dropped");
                return;
            }

            JNIEnv* env = protector->GetEnvironment();
            if (NULLPTR == env) {
                __android_log_print(ANDROID_LOG_WARN, "libopenppp2",
                    "PostJNI: JNI env unavailable, task dropped");
                return;
            }

            task(env);
        });
    return true;
}

bool                                                                        libopenppp2_application::GetTransmissionStatistics(uint64_t& incoming_traffic, uint64_t& outgoing_traffic, std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept {
    // Initialization requires the initial value of the FAR outgoing parameter.
    statistics_snapshot = NULLPTR;
    incoming_traffic = 0;
    outgoing_traffic = 0;

    // The transport layer network statistics are obtained only when the current client switch or server switch is not released.
    std::shared_ptr<VEthernetNetworkSwitcher> client = std::atomic_load(&client_);
    if (NULLPTR != client && !client->IsDisposed()) {
        // Obtain transport layer traffic statistics from the client switch or server switch management object.
        std::shared_ptr<ppp::transmissions::ITransmissionStatistics>transmission_statistics = client->GetStatistics();
        if (NULLPTR != transmission_statistics) {
            return ppp::transmissions::ITransmissionStatistics::GetTransmissionStatistics(transmission_statistics, transmission_statistics_, incoming_traffic, outgoing_traffic, statistics_snapshot);
        }
    }

    return false;
}

bool                                                                        libopenppp2_application::Post(int sequence) noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return false;
    }

    libopenppp2_application* p = app.get();
    return app->PostJNI(
        [p, sequence](JNIEnv* env) noexcept {
            p->PostExecJNI(env, sequence);
        });
}

static int                                                                         libopenppp2_invoke_on_run_context(const ppp::function<int()>& task) noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::AppContextUnavailable, LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED);
    }

    std::shared_ptr<VEthernetNetworkSwitcher> client = std::atomic_load(&app->client_);
    if (NULLPTR == client) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable, LIBOPENPPP2_ERROR_VETHERNET_PPPD_THREAD_NOT_RUNING);
    }

    std::shared_ptr<ppp::net::ProtectorNetwork> protector = client->GetProtectorNetwork();
    if (NULLPTR == protector) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid, LIBOPENPPP2_ERROR_VETHERNET_PPPD_THREAD_NOT_RUNING);
    }

    std::shared_ptr<boost::asio::io_context> context = protector->GetContext();
    if (NULLPTR == context) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing, LIBOPENPPP2_ERROR_VETHERNET_PPPD_THREAD_NOT_RUNING);
    }

    std::shared_ptr<Executors::Awaitable> awaitable = ppp::make_shared_object<Executors::Awaitable>();
    if (NULLPTR == awaitable) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::MemoryAllocationFailed, LIBOPENPPP2_ERROR_ALLOCATED_MEMORY);
    }

    int err = LIBOPENPPP2_ERROR_UNKNOWN;
    boost::asio::post(*context,
        [context, awaitable, &err, task]() noexcept {
            err = task();
            awaitable->Processed();
        });

    bool ok = awaitable->Await();
    if (!ok) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::RuntimeEventDispatchFailed, LIBOPENPPP2_ERROR_UNKNOWN);
    }

    return err;
}

int                                                                         libopenppp2_application::Invoke(const ppp::function<int()>& task) noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::AppContextUnavailable, LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED);
    }

    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULLPTR == context) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing, LIBOPENPPP2_ERROR_VETHERNET_PPPD_THREAD_NOT_RUNING);
    }

    std::shared_ptr<Executors::Awaitable> awaitable = ppp::make_shared_object<Executors::Awaitable>();
    if (NULLPTR == awaitable) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::MemoryAllocationFailed, LIBOPENPPP2_ERROR_ALLOCATED_MEMORY);
    }

    int err = LIBOPENPPP2_ERROR_UNKNOWN;
    boost::asio::post(*context,
        [context, awaitable, &err, task]() noexcept {
            err = task();
            awaitable->Processed();
        });

    bool ok = awaitable->Await();
    if (!ok) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::RuntimeEventDispatchFailed, LIBOPENPPP2_ERROR_UNKNOWN);
    }

    return err;
}

bool                                                                        libopenppp2_application::Release() noexcept {
    return Release(true, ppp::app::runtime::RuntimeError());
}

bool                                                                        libopenppp2_application::Release(
    bool success,
    ppp::app::runtime::RuntimeError error) noexcept {
    bool any = false;
    const ppp::app::runtime::RuntimeSnapshot runtime = runtime_lifecycle_.GetSnapshot();
    const bool stop_owner = runtime.generation != 0 &&
        runtime_lifecycle_.TryBeginStop(runtime.generation, Executors::GetTickCount());
    std::shared_ptr<Timer> timeout = std::move(timeout_);
    if (NULLPTR != timeout) {
        timeout->Dispose();
    }

    configuration_.reset();
    stopwatch_.Reset();

    network_interface_.reset();
    bypass_ip_list_.reset();
    dns_rules_list_.reset();
    transmission_statistics_.Clear();
    last_reported_statistics_ = {};
    stats_perf_log_ticks_ = 0;

    auto complete_stop =
        [self = shared_from_this(), runtime, success, error = std::move(error)](
            bool cleanup_success) mutable noexcept {
            if (!cleanup_success) {
                error.code = static_cast<std::uint32_t>(
                    ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                error.severity = "error";
                error.retryable = true;
                error.user_message_key = "CleanupFailed";
            }
            self->runtime_lifecycle_.CompleteStop(
                runtime.generation,
                success && cleanup_success,
                std::move(error),
                Executors::GetTickCount());
        };

    std::shared_ptr<VEthernetNetworkSwitcher> client = std::atomic_exchange(
        &client_, std::shared_ptr<VEthernetNetworkSwitcher>());
    if (NULLPTR != client) {
        any = true;
        ppp::function<void(bool)> completion;
        if (stop_owner) {
            completion = complete_stop;
        }
        client->Dispose(std::move(completion));
    }
    else if (stop_owner) {
        complete_stop(true);
    }
    return any;
}

bool                                                                        libopenppp2_application::ExecJNI(JNIEnv* env, const char* method_name, int param) noexcept {
    jclass clazz = env->FindClass(LIBOPENPPP2_CLASSNAME);
    if (NULLPTR != env->ExceptionOccurred()) {
        env->ExceptionClear();
    }

    if (NULLPTR == clazz) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        return false;
    }

    jboolean result = false;
    jmethodID method = env->GetStaticMethodID(clazz, method_name, "(I)Z");
    if (NULLPTR != env->ExceptionOccurred()) {
        env->ExceptionClear();
    }
    else if (NULLPTR != method) {
        result = env->CallStaticBooleanMethod(clazz, method, (jint)param);
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
            result = false;
        }
    }

    env->DeleteLocalRef(clazz);
    if (!result) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEventDispatchFailed);
    }
    return result ? true : false;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public static bool post_exec(int sequence)
bool                                                                        libopenppp2_application::PostExecJNI(JNIEnv* env, int sequence) noexcept {
    return ExecJNI(env, "post_exec", sequence);
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public static bool start_exec(int key)
bool                                                                        libopenppp2_application::StartJNI(JNIEnv* env, int key) noexcept {
    return ExecJNI(env, "start_exec", key);
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native string get_default_ciphersuites()
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_1default_1ciphersuites(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    const char* ciphersuites = ppp::GetDefaultCipherSuites();
    return JNIENV_NewStringUTF(env, ciphersuites);
}

static int                                                                  libopenppp2_get_link_state() noexcept {
    using NetworkState = VEthernetExchanger::NetworkState;

    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return LIBOPENPPP2_LINK_STATE_APPLICATIION_UNINITIALIZED;
    }

    std::shared_ptr<VEthernetNetworkSwitcher> client = std::atomic_load(&app->client_);
    if (NULLPTR == client) {
        return LIBOPENPPP2_LINK_STATE_CLIENT_UNINITIALIZED;
    }

    std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger();
    if (NULLPTR == exchanger) {
        return LIBOPENPPP2_LINK_STATE_EXCHANGE_UNINITIALIZED;
    }

    NetworkState network_state = exchanger->GetNetworkState();
    if (network_state == NetworkState::NetworkState_Connecting) {
        return LIBOPENPPP2_LINK_STATE_CONNECTING;
    }
    else if (network_state == NetworkState::NetworkState_Reconnecting) {
        return LIBOPENPPP2_LINK_STATE_RECONNECTING;
    }
    else if (network_state == NetworkState::NetworkState_Established) {
        return LIBOPENPPP2_LINK_STATE_ESTABLISHED;
    }

    return LIBOPENPPP2_LINK_STATE_UNKNOWN;
}

static int                                                                  libopenppp2_get_aggligator_state() noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return LIBOPENPPP2_AGGLIGATOR_STATE_UNKNOWN;
    }

    std::shared_ptr<VEthernetNetworkSwitcher> client = std::atomic_load(&app->client_);
    if (NULLPTR == client) {
        return LIBOPENPPP2_AGGLIGATOR_STATE_UNKNOWN;
    }

    std::shared_ptr<aggligator::aggligator> aggligator = client->GetAggligator();
    if (NULLPTR == aggligator) {
        return LIBOPENPPP2_AGGLIGATOR_STATE_NONE;
    }

    return (int)aggligator->status();
}

static int64_t                                                              libopenppp2_duration_time() noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return -1;
    }

    Stopwatch& sw = app->stopwatch_;
    return sw.IsRunning() ? sw.ElapsedMilliseconds() : 0;
}

static std::shared_ptr<ppp::string>                                         libopenppp2_get_app_configuration() noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return NULLPTR;
    }

    std::shared_ptr<AppConfiguration> configuration = app->configuration_;
    if (NULLPTR == configuration) {
        return NULLPTR;
    }

    return ppp::make_shared_object<ppp::string>(configuration->ToString());
}

static std::shared_ptr<ppp::string>                                         libopenppp2_get_bypass_ip_list() noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return NULLPTR;
    }

    std::shared_ptr<VEthernetNetworkSwitcher> client = std::atomic_load(&app->client_);
    if (NULLPTR == client) {
        return app->bypass_ip_list_;
    }

    auto fib = client->GetRib();
    if (NULLPTR == fib) {
        return NULLPTR;
    }

    std::shared_ptr<ppp::string> bypass_ip_list = ppp::make_shared_object<ppp::string>();
    if (NULLPTR == bypass_ip_list) {
        return NULLPTR;
    }

    auto& entriess = fib->GetAllRoutes();
    for (auto&& [_, entries] : entriess) {
        static constexpr int BUFF_SIZE = 1000;
        char BUFF[BUFF_SIZE + 1];

        for (auto&& r : entries) {
            ppp::string ip = IPEndPoint(r.Destination, IPEndPoint::MinPort).ToAddressString();
            if (ip.empty()) {
                continue;
            }

            int len = std::_snprintf(BUFF, BUFF_SIZE, "%s/%d", ip.data(), r.Prefix);
            if (len > 0) {
                *bypass_ip_list += ppp::string(BUFF) + "\r\n";
            }
        }
    }

    return bypass_ip_list;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native int get_link_state()
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_get_1link_1state(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    int status = LIBOPENPPP2_LINK_STATE_UNKNOWN;
    int err = libopenppp2_application::Invoke(
        [&status]() noexcept {
            status = libopenppp2_get_link_state();
            return LIBOPENPPP2_ERROR_SUCCESS;
        });

    if (err == LIBOPENPPP2_ERROR_SUCCESS) {
        return status;
    }

    libopenppp2_set_last_error_for_result(err);

    if (err == LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED || err == LIBOPENPPP2_ERROR_VETHERNET_PPPD_THREAD_NOT_RUNING) {
        return LIBOPENPPP2_LINK_STATE_APPLICATIION_UNINITIALIZED;
    }
    else {
        return LIBOPENPPP2_LINK_STATE_UNKNOWN;
    }
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native string get_runtime_snapshot()
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_1runtime_1snapshot(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return JNIENV_NewStringUTF(env, NULLPTR);
    }

    const std::string json = ppp::app::runtime::SerializeRuntimeSnapshot(
        app->runtime_lifecycle_.GetSnapshot());
    return JNIENV_NewStringUTF(env, json.c_str());
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native int get_aggligator_state()
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_get_1aggligator_1state(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    int status = LIBOPENPPP2_AGGLIGATOR_STATE_UNKNOWN;
    int err = libopenppp2_application::Invoke(
        [&status]() noexcept {
            status = libopenppp2_get_aggligator_state();
            return LIBOPENPPP2_ERROR_SUCCESS;
        });

    if (err == LIBOPENPPP2_ERROR_SUCCESS) {
        return status;
    }

    libopenppp2_set_last_error_for_result(err);

    return LIBOPENPPP2_AGGLIGATOR_STATE_UNKNOWN;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native long get_duration_time()
__LIBOPENPPP2__(jlong) Java_supersocksr_ppp_android_c_libopenppp2_get_1duration_1time(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    int64_t milliseconds = 0;
    int err = libopenppp2_application::Invoke(
        [&milliseconds]() noexcept {
            milliseconds = libopenppp2_duration_time();
            return LIBOPENPPP2_ERROR_SUCCESS;
        });

    if (err != LIBOPENPPP2_ERROR_SUCCESS) {
        libopenppp2_set_last_error_for_result(err);
        return -1;
    }

    return milliseconds;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native int get_last_error_code()
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_get_1last_1error_1code(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCodeSnapshot();
    return (jint)static_cast<uint32_t>(code);
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native string get_last_error_text()
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_1last_1error_1text(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCodeSnapshot();
    const char* text = ppp::diagnostics::FormatErrorString(code);
    return JNIENV_NewStringUTF(env, text);
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native string get_app_configuration()
// return:
//  json: appsettings.json
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_1app_1configuration(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<ppp::string> json;
    int err = libopenppp2_application::Invoke(
        [&json]() noexcept {
            json = libopenppp2_get_app_configuration();
            return LIBOPENPPP2_ERROR_SUCCESS;
        });

    if (err != LIBOPENPPP2_ERROR_SUCCESS) {
        libopenppp2_set_last_error_for_result(err);
    }

    if (NULLPTR == json) {
        return JNIENV_NewStringUTF(env, NULLPTR);
    }

    return JNIENV_NewStringUTF(env, json->data());
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native int set_app_configuration(string configurations /* configurations is appsettings.json */)
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_set_1app_1configuration(JNIEnv* env, jobject* this_, jstring configurations) noexcept {
    __LIBOPENPPP2_MAIN__;

    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Success);

    std::shared_ptr<ppp::string> json_string = JNIENV_GetStringUTFChars(env, configurations);
    if (NULLPTR == json_string || json_string->empty()) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::ConfigFieldMissing, LIBOPENPPP2_ERROR_ARG_CONFIGURATION_STRING_IS_NULL_OR_EMPTY);
    }

    std::shared_ptr<AppConfiguration> config = ppp::make_shared_object<AppConfiguration>();
    if (NULLPTR == config) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::MemoryAllocationFailed, LIBOPENPPP2_ERROR_NEW_CONFIGURATION_FAIL);
    }

    Json::Value json = JsonAuxiliary::FromString(*json_string);
    if (!json.isObject()) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::ConfigFileMalformed, LIBOPENPPP2_ERROR_ARG_CONFIGURATION_STRING_NOT_IS_JSON_OBJECT_STRING);
    }

    bool ok = config->Load(json);
    if (!ok) {
        return libopenppp2_set_last_error_for_result(LIBOPENPPP2_ERROR_ARG_CONFIGURATION_STRING_CONFIGURE_ERROR);
    }

    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::AppContextUnavailable, LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED);
    }

    int err = libopenppp2_application::Invoke(
        [&app, &config]() noexcept {
            ppp::net::asio::vdns::ttl = config->udp.dns.cache ? config->udp.dns.ttl : 0;
            ppp::net::asio::vdns::enabled = config->udp.dns.turbo;
            ppp::net::asio::vdns::ClearCache();

            app->configuration_ = config;
            ppp::android::ConfigureNativeTelemetry(config);
            return LIBOPENPPP2_ERROR_SUCCESS;
        });
    return libopenppp2_set_last_error_for_result(err);
}

__LIBOPENPPP2__(void) Java_supersocksr_ppp_android_c_libopenppp2_installNativeTelemetryHttpPost(JNIEnv* env, jobject* this_) noexcept {
    (void)env;
    (void)this_;
    ppp::android::InstallHttpPostSink();
}

__LIBOPENPPP2__(void) Java_supersocksr_ppp_android_c_libopenppp2_setNativeTelemetryResourceAttribute(
    JNIEnv* env,
    jobject* this_,
    jstring key,
    jstring value) noexcept
{
    (void)this_;
    std::shared_ptr<ppp::string> key_string = JNIENV_GetStringUTFChars(env, key);
    std::shared_ptr<ppp::string> value_string = JNIENV_GetStringUTFChars(env, value);
    if (NULLPTR == key_string || key_string->empty() || NULLPTR == value_string)
    {
        return;
    }

    ppp::android::SetTelemetryResourceAttribute(key_string->c_str(), value_string->c_str());
}

__LIBOPENPPP2__(void) Java_supersocksr_ppp_android_c_libopenppp2_clearNativeTelemetryResourceAttributes(JNIEnv* env, jobject* this_) noexcept {
    (void)env;
    (void)this_;
    ppp::android::ClearTelemetryResourceAttributes();
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native bool set_default_flash_type_of_service(bool flash_mode)
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_set_1default_1flash_1type_1of_1service(JNIEnv* env, jobject* this_, jboolean flash_mode) noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return false;
    }

    ppp::net::Socket::SetDefaultFlashTypeOfService(flash_mode);
    return true;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native int is_default_flash_type_of_service()
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_is_1default_1flash_1type_1of_1service(JNIEnv* env, jobject* this_) noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return -1;
    }

    return ppp::net::Socket::IsDefaultFlashTypeOfService() ? 1 : 0;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native int set_network_interface(int tun, int mux, bool vnet, bool block_quic, bool static_mode, string ip, string mask, string gw)
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_set_1network_1interface(JNIEnv* env, jobject* this_,
    jint                                                                                    tun,
    jint                                                                                    mux,
    jboolean                                                                                vnet,
    jboolean                                                                                block_quic,
    jboolean                                                                                static_mode,
    jstring                                                                                 ip,
    jstring                                                                                 mask) noexcept {
    __LIBOPENPPP2_MAIN__;

    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Success);

    boost::system::error_code ec;
    if (tun == -1) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::TunnelDeviceMissing, LIBOPENPPP2_ERROR_ARG_TUN_IS_INVALID);
    }

    // 10.0.0.2
    std::shared_ptr<ppp::string> ip_string = JNIENV_GetStringUTFChars(env, ip);
    if (NULLPTR == ip_string || ip_string->empty()) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::ConfigFieldMissing, LIBOPENPPP2_ERROR_ARG_IP_IS_NULL_OR_EMPTY);
    }

    // 255.255.255.0
    std::shared_ptr<ppp::string> mask_string = JNIENV_GetStringUTFChars(env, mask);
    if (NULLPTR == mask_string || mask_string->empty()) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::ConfigFieldMissing, LIBOPENPPP2_ERROR_ARG_MASK_IS_NULL_OR_EMPTY);
    }

    boost::asio::ip::address ip_address = ppp::StringToAddress(ip_string->data(), ec);
    if (ec || !ip_address.is_v4()) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::NetworkAddressInvalid, LIBOPENPPP2_ERROR_ARG_IP_IS_NOT_AF_INET_FORMAT);
    }

    boost::asio::ip::address mask_address = ppp::StringToAddress(mask_string->data(), ec);
    if (ec || !mask_address.is_v4()) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::NetworkMaskInvalid, LIBOPENPPP2_ERROR_ARG_MASK_IS_NOT_AF_INET_FORMAT);
    }

    uint32_t addresses[2] = {
        IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(ip_address, IPEndPoint::MinPort)).GetAddress(),
        IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(mask_address, IPEndPoint::MinPort)).GetAddress(),
    };

    if (addresses[0] == IPEndPoint::AnyAddress || addresses[0] == IPEndPoint::LoopbackAddress || addresses[0] == IPEndPoint::NoneAddress) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::NetworkAddressInvalid, LIBOPENPPP2_ERROR_ARG_IP_IS_INVALID);
    }

    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::AppContextUnavailable, LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED);
    }
    else {
        int prefix = IPEndPoint::NetmaskToPrefix(addresses[1]);
        if (prefix < 16) {
            return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::NetworkMaskInvalid, LIBOPENPPP2_ERROR_ARG_MASK_SUBNET_IP_RANGE_GREATER_65535);
        }
        else if (prefix > 30) {
            addresses[1] = IPEndPoint::NetmaskToPrefix(prefix);
            mask_address = Ipep::ToAddress(addresses[1]);
        }

        if (IPEndPoint::IsInvalid(ip_address)) {
            return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::NetworkAddressInvalid, LIBOPENPPP2_ERROR_ARG_IP_IS_INVALID);
        }
    }

    boost::asio::ip::address gw_address = ppp::net::Ipep::FixedIPAddress(ip_address, mask_address);
    ip_address = Ipep::FixedIPAddress(ip_address, gw_address, mask_address);

    std::shared_ptr<libopenppp2_network_interface> network_interface = ppp::make_shared_object<libopenppp2_network_interface>();
    if (NULLPTR == network_interface) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::MemoryAllocationFailed, LIBOPENPPP2_ERROR_NEW_NETWORKINTERFACE_FAIL);
    }

    network_interface->BlockQUIC = block_quic;
    network_interface->VNet = vnet;
    network_interface->VTun = tun;
    network_interface->VMux = (uint16_t)std::min<int>(std::max<int>(0, mux), UINT16_MAX);
    network_interface->StaticMode = static_mode;
    network_interface->IPAddress = ip_address;
    network_interface->GatewayServer = gw_address;
    network_interface->SubmaskAddress = mask_address;

    int err = libopenppp2_application::Invoke(
        [&app, &network_interface]() noexcept {
            app->network_interface_ = network_interface;
            return LIBOPENPPP2_ERROR_SUCCESS;
        });
    return libopenppp2_set_last_error_for_result(err);
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native bool set_root_path(string path)
//
// Changes the process working directory so that relative paths embedded in
// the AppConfiguration JSON (`./rules/GeoIP.dat`, `./generated/bypass-cn.txt`,
// etc.) resolve against the Android app's filesDir instead of `/`. The
// caller is expected to pass `Context.getFilesDir().getAbsolutePath()`.
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_set_1root_1path(JNIEnv* env, jobject* this_, jstring path) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<ppp::string> root_path = JNIENV_GetStringUTFChars(env, path);
    if (NULLPTR == root_path || root_path->empty()) {
        return false;
    }

    int rc = chdir(root_path->data());
    __android_log_print(ANDROID_LOG_INFO, "libopenppp2",
        "set_root_path: chdir(%s) rc=%d errno=%d", root_path->data(), rc, errno);
    return rc == 0;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native bool set_bypass_ip_list(string iplist)
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_set_1bypass_1ip_1list(JNIEnv* env, jobject* this_, jstring iplist) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppContextUnavailable);
        return false;
    }

    std::shared_ptr<ppp::string> bypass_ip_list = JNIENV_GetStringUTFChars(env, iplist);
    int err = LIBOPENPPP2_ERROR_SUCCESS;
    app->bypass_ip_list_ = bypass_ip_list;
    if (err != LIBOPENPPP2_ERROR_SUCCESS) {
        libopenppp2_set_last_error_for_result(err);
    }
    return err == LIBOPENPPP2_ERROR_SUCCESS;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native bool set_dns_rules_list(string rules)
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_set_1dns_1rules_1list(JNIEnv* env, jobject* this_, jstring rules) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppContextUnavailable);
        return false;
    }

    std::shared_ptr<ppp::string> dns_rules_list = JNIENV_GetStringUTFChars(env, rules);
    int err = LIBOPENPPP2_ERROR_SUCCESS;
    app->dns_rules_list_ = dns_rules_list;
    if (err != LIBOPENPPP2_ERROR_SUCCESS) {
        libopenppp2_set_last_error_for_result(err);
    }
    return err == LIBOPENPPP2_ERROR_SUCCESS;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native bool set_dns_bcl(bool turbo, int ttl, string dns)
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_set_1dns_1bcl(JNIEnv* env, jobject* this_, jboolean turbo, jint ttl, jstring dns) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppContextUnavailable);
        return false;
    }

    if (ttl < 1) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigValueOutOfRange);
        return false;
    }

    std::shared_ptr<ppp::string> dns_string = JNIENV_GetStringUTFChars(env, dns);
    if (NULLPTR == dns_string) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigFieldMissing);
        return false;
    }

    if (dns_string->empty()) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigFieldMissing);
        return false;
    }

    ppp::vector<boost::asio::ip::address> ips;
    ppp::net::Ipep::ToDnsAddresses(*dns_string, ips);

    if (ips.empty()) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsAddressInvalid);
        return false;
    }

    auto addresses = ppp::make_shared_object<ppp::net::asio::vdns::IPEndPointVector>();
    if (NULLPTR == addresses) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
        return false;
    }

    for (const boost::asio::ip::address& ip : ips) {
        addresses->emplace_back(boost::asio::ip::udp::endpoint(ip, PPP_DNS_SYS_PORT));
    }

    ppp::net::asio::vdns::enabled = turbo;
    ppp::net::asio::vdns::ttl = ttl;
    ppp::net::asio::vdns::servers = addresses;
    ppp::net::asio::vdns::ClearCache();
    return true;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native string get_bypass_ip_list()
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_1bypass_1ip_1list(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<ppp::string> bypass_ip_list;
    int err = libopenppp2_application::Invoke(
        [&bypass_ip_list]() noexcept {
            bypass_ip_list = libopenppp2_get_bypass_ip_list();
            return LIBOPENPPP2_ERROR_SUCCESS;
        });

    if (err != LIBOPENPPP2_ERROR_SUCCESS) {
        libopenppp2_set_last_error_for_result(err);
    }

    if (NULLPTR == bypass_ip_list) {
        return JNIENV_NewStringUTF(env, NULLPTR);
    }

    return JNIENV_NewStringUTF(env, bypass_ip_list->data());
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native string get_network_interface()
// return
//  json: {
//      block-quic: bool,
//      tun:        int,
//      mux:        int,
//      vnet:       bool,
//      ip:         string,
//      gw:         string,
//      mask:       string
//  }
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_1network_1interface(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return JNIENV_NewStringUTF(env, NULLPTR);
    }

    std::shared_ptr<ppp::string> json_string;
    int err = libopenppp2_application::Invoke(
        [&app, &json_string]() noexcept {
            std::shared_ptr<libopenppp2_network_interface> network_interface = app->network_interface_;
            if (NULLPTR != network_interface) {
                Json::Value json;
                json["block-quic"] = network_interface->BlockQUIC;
                json["tun"] = network_interface->VTun;
                json["mux"] = network_interface->VMux;
                json["vnet"] = network_interface->VNet;
                json["static"] = network_interface->StaticMode;
                json["gw"] = stl::transform<ppp::string>(network_interface->GatewayServer.to_string());
                json["ip"] = stl::transform<ppp::string>(network_interface->IPAddress.to_string());
                json["mask"] = stl::transform<ppp::string>(network_interface->SubmaskAddress.to_string());

                json_string = ppp::make_shared_object<ppp::string>(JsonAuxiliary::ToStyledString(json));
            }

            return LIBOPENPPP2_ERROR_SUCCESS;
        });

    if (err != LIBOPENPPP2_ERROR_SUCCESS) {
        libopenppp2_set_last_error_for_result(err);
    }

    if (NULLPTR == json_string) {
        return JNIENV_NewStringUTF(env, NULLPTR);
    }

    return JNIENV_NewStringUTF(env, json_string->data());
}

// Post a JAVA function call to the JVM managed thread that is blocking the VPN that handles network protection.
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_post(JNIEnv* env, jobject* this_, int sequence) noexcept {
    __LIBOPENPPP2_MAIN__;

    return libopenppp2_application::Post(sequence);
}

// package: supersocksr.ppp.android.c
// public final class libopenppp2
// public static native boolean set_protect_enabled(boolean enabled)
// Enables/disables the native VpnService.protect(fd) bridge.  The Java side must
// provide: public static boolean protect(int fd), usually delegating to
// VpnService.protect(fd) on the active service instance.
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_set_1protect_1enabled(JNIEnv* env, jobject* this_, jboolean enabled) noexcept {
    ppp::android::SetProtectEnabled(enabled == JNI_TRUE);
    return JNI_TRUE;
}

// package: supersocksr.ppp.android.c
// public final class libopenppp2
// public static native boolean protect_socket_fd(int fd)
// Optional direct native entrypoint for app-side smoke tests.  Normal C++ users
// should call ppp::android::ProtectSocketFd(fd) directly.
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_protect_1socket_1fd(JNIEnv* env, jobject* this_, jint fd) noexcept {
    return ppp::android::ProtectSocketFd(static_cast<int>(fd)) ? JNI_TRUE : JNI_FALSE;
}

static std::shared_ptr<ITap>                                                        libopenppp2_from_tuntap_driver_new(
    std::shared_ptr<boost::asio::io_context>                                        context,
    std::shared_ptr<libopenppp2_network_interface>                                  network_interface) noexcept {

    if (NULLPTR == context || NULLPTR == network_interface) {
        return NULLPTR;
    }

    auto tun_fd = network_interface->VTun;
    if (tun_fd == -1) {
        return NULLPTR;
    }

    uint32_t ip = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(network_interface->IPAddress, IPEndPoint::MinPort)).GetAddress();
    uint32_t mask = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(network_interface->SubmaskAddress, IPEndPoint::MinPort)).GetAddress();
    uint32_t gw = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(network_interface->GatewayServer, IPEndPoint::MinPort)).GetAddress();

    ppp::string dev = ITap::FindAnyDevice();
    bool promisc = true;
    bool hosted_network = true;

    void* tun = (void*)(std::intptr_t)tun_fd;
    return ppp::tap::TapLinux::From(context, dev, tun, ip, gw, mask, promisc, hosted_network);
}

static ppp::string                                                               libopenppp2_routing_source_without_file_uri(
    const ppp::string& source) noexcept {
    constexpr std::size_t file_uri_prefix_length = 7;
    const bool has_file_uri_prefix = source.size() >= file_uri_prefix_length &&
        (source[0] == 'f' || source[0] == 'F') &&
        (source[1] == 'i' || source[1] == 'I') &&
        (source[2] == 'l' || source[2] == 'L') &&
        (source[3] == 'e' || source[3] == 'E') &&
        source[4] == ':' && source[5] == '/' && source[6] == '/';
    if (has_file_uri_prefix) {
        return source.substr(file_uri_prefix_length);
    }
    return source;
}

static bool                                                                         libopenppp2_read_routing_source(
    const ppp::string& source,
    ppp::string& resolved_path,
    ppp::string& inline_text) noexcept {
    ppp::string candidate = libopenppp2_routing_source_without_file_uri(source);
    ppp::string rewritten_path = ppp::io::File::RewritePath(candidate.data());
    ppp::string full_path = ppp::io::File::GetFullPath(rewritten_path.data());
    if (!full_path.empty() && ppp::io::File::Exists(full_path.data())) {
        resolved_path = std::move(full_path);
        inline_text = ppp::io::File::ReadAllText(resolved_path.data());
        return true;
    }

    resolved_path.clear();
    inline_text = std::move(candidate);
    return false;
}

static void                                                                         libopenppp2_append_routing_text(
    ppp::string& target,
    const ppp::string& text) noexcept {
    if (text.empty()) {
        return;
    }
    if (!target.empty() && target.back() != '\n') {
        target.push_back('\n');
    }
    target += text;
}

static int                                                                          libopenppp_try_open_ethernet_switcher_new(
    std::shared_ptr<boost::asio::io_context>                                        context,
    std::shared_ptr<libopenppp2_application>                                        app,
    std::shared_ptr<ITap>                                                           tap,
    std::shared_ptr<VEthernetNetworkSwitcher>&                                      client,
    std::shared_ptr<libopenppp2_network_interface>                                  network_interface,
    std::shared_ptr<AppConfiguration>                                               configuration) noexcept {
    const auto open_switcher_begin = std::chrono::steady_clock::now();

    bool lwip = false;
    int max_concurrent = ppp::GetProcesserCount();
    const bool proxy_only_runtime = configuration->client.proxy_only;
    const bool canonical_routing_configured = configuration->client.routing.configured;

    client = ppp::make_shared_object<VEthernetNetworkSwitcher>(context, lwip, network_interface->VNet, max_concurrent > 1, configuration);
    if (NULLPTR == client) {
        __android_log_print(ANDROID_LOG_ERROR, "libopenppp2", "open_switcher: create client failed");
        return LIBOPENPPP2_ERROR_ALLOCATED_MEMORY;
    }
    else {
        client->Mux(&network_interface->VMux);
        bool static_mode = ppp::app::NormalizeClientStaticMode(network_interface->StaticMode, proxy_only_runtime);
        client->StaticMode(&static_mode);
        client->BlockQUIC(network_interface->BlockQUIC);
    }

    if (proxy_only_runtime) {
        configuration->ApplyProxyModeDefaults();
        bool proxy_only_flag = true;
        client->ProxyOnly(&proxy_only_flag);
        __android_log_print(ANDROID_LOG_INFO, "libopenppp2", "open_switcher: proxy-only mode enabled");
    }

    // Legacy JNI sources are used only when client.routing is absent.  When
    // canonical routing is present, its source vectors are authoritative and
    // stale platform-provided values are deliberately ignored.
    ppp::string bypass_text;
    ppp::string canonical_bypass_text;
    if (canonical_routing_configured) {
        for (const ppp::string& source : configuration->client.routing.bypass) {
            ppp::string resolved_path;
            ppp::string inline_text;
            const bool source_is_file = libopenppp2_read_routing_source(
                source, resolved_path, inline_text);
            libopenppp2_append_routing_text(canonical_bypass_text, inline_text);
            __android_log_print(ANDROID_LOG_INFO, "libopenppp2",
                "open_switcher: canonical bypass source type=%s len=%d path=%s",
                source_is_file ? "file" : "inline",
                (int)inline_text.size(),
                source_is_file ? resolved_path.data() : "");
        }
    }
    elif (!canonical_routing_configured) {
        std::shared_ptr<ppp::string> bypass_ip_list = std::move(app->bypass_ip_list_);
        if (NULLPTR != bypass_ip_list) {
            bypass_text = std::move(*bypass_ip_list);
            __android_log_print(ANDROID_LOG_INFO, "libopenppp2",
                "open_switcher: legacy bypass ip list captured len=%d",
                (int)bypass_text.size());
        }
    }

    // Legacy DNS is loaded before Geo for compatibility. Canonical DNS sources
    // are loaded after Geo below, giving explicit canonical rules precedence.
    std::shared_ptr<ppp::string> dns_rules_list;
    if (!canonical_routing_configured) {
        dns_rules_list = std::move(app->dns_rules_list_);
        if (NULLPTR != dns_rules_list) {
            bool dns_ok = client->LoadAllDnsRules(*dns_rules_list, false);
            __android_log_print(ANDROID_LOG_INFO, "libopenppp2",
                "open_switcher: legacy dns rules applied len=%d ok=%d",
                (int)dns_rules_list->size(), dns_ok ? 1 : 0);
        }
    }

    // Phase G: GeoIP/GeoSite rule generation pipeline.
    //
    // ApplicationInitialize.cpp gates this behind `#if !defined(_ANDROID)`,
    // so on Android we have to invoke it explicitly here. The generator reads
    // configuration->geo_rules.{geoip_dat, geosite_dat, geoip[], geosite[],
    // dns_provider_*, output_*} (already populated by AppConfiguration::Load
    // from the JSON `geo-rules` block) and writes two text files:
    //   - output_bypass:    newline-separated CIDR list
    //   - output_dns_rules: newline-separated DNS redirect rules
    // We then feed those files back into the client.
    if (configuration->geo_rules.enabled) {
        const auto geo_begin = std::chrono::steady_clock::now();
        __android_log_print(ANDROID_LOG_INFO, "libopenppp2",
            "open_switcher: geo-rules enabled country=%s geoip_dat=%s geosite_dat=%s",
            configuration->geo_rules.country.data(),
            configuration->geo_rules.geoip_dat.data(),
            configuration->geo_rules.geosite_dat.data());

        // Build a bypass-file seed list from canonical sources, mirroring the
        // desktop behaviour in ApplicationClientBootstrap.cpp.  When canonical
        // routing is absent the generator runs without a seed (NULLPTR), which
        // was the previous Android behaviour.
        ppp::vector<ppp::string> bypass_seed_paths;
        if (canonical_routing_configured) {
            for (const ppp::string& source : configuration->client.routing.bypass) {
                ppp::string resolved_path;
                ppp::string inline_text;
                if (libopenppp2_read_routing_source(source, resolved_path, inline_text) &&
                    !resolved_path.empty()) {
                    bypass_seed_paths.emplace_back(resolved_path);
                }
            }
        }
        const ppp::vector<ppp::string>* seed_ptr =
            bypass_seed_paths.empty() ? NULLPTR : &bypass_seed_paths;

        ppp::app::client::GeoRuleGenerateResult geo_result =
            ppp::app::client::GeoRuleGenerator::Generate(*configuration, seed_ptr);

        const auto geo_elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - geo_begin).count();
        __android_log_print(ANDROID_LOG_INFO, "libopenppp2",
            "open_switcher: geo-rules %s bypass=%s(%d) dns_rules=%s(%d) elapsed_ms=%lld",
            geo_result.cache_hit ? "cache_hit" : "generated",
            geo_result.output_bypass_path.data(), geo_result.bypass_line_count,
            geo_result.output_dns_rules_path.data(), geo_result.dns_rule_line_count,
            static_cast<long long>(geo_elapsed_ms));

        // Merge generated bypass CIDRs after legacy/default sources. Canonical
        // sources are appended after Geo below so they remain explicit.
        if (!geo_result.output_bypass_path.empty()) {
            ppp::string geo_bypass_text =
                ppp::io::File::ReadAllText(geo_result.output_bypass_path.data());
            libopenppp2_append_routing_text(bypass_text, geo_bypass_text);
        }

        // Load generated DNS redirect rules from file.
        if (!geo_result.output_dns_rules_path.empty()) {
            bool ok = client->LoadAllDnsRules(geo_result.output_dns_rules_path, true);
            __android_log_print(ANDROID_LOG_INFO, "libopenppp2",
                "open_switcher: geo-rules dns rules loaded path=%s ok=%d",
                geo_result.output_dns_rules_path.data(), ok ? 1 : 0);
        }
    }

    if (canonical_routing_configured) {
        for (const ppp::string& source : configuration->client.routing.dns_rules) {
            ppp::string resolved_path;
            ppp::string inline_text;
            const bool source_is_file = libopenppp2_read_routing_source(
                source, resolved_path, inline_text);
            const ppp::string& rules = source_is_file ? resolved_path : inline_text;
            if (rules.empty()) {
                continue;
            }
            bool dns_ok = client->LoadAllDnsRules(rules, source_is_file);
            __android_log_print(ANDROID_LOG_INFO, "libopenppp2",
                "open_switcher: canonical dns rules applied type=%s len=%d path=%s ok=%d",
                source_is_file ? "file" : "inline",
                (int)rules.size(),
                source_is_file ? resolved_path.data() : "",
                dns_ok ? 1 : 0);
        }
        libopenppp2_append_routing_text(bypass_text, canonical_bypass_text);
    }

    if (!bypass_text.empty()) {
        int bypass_len = (int)bypass_text.size();
        client->SetBypassIpList(std::move(bypass_text));
        __android_log_print(ANDROID_LOG_INFO, "libopenppp2",
            "open_switcher: bypass ip list applied (legacy+geo+canonical) len=%d", bypass_len);
    }

    __android_log_print(ANDROID_LOG_INFO, "libopenppp2",
        "open_switcher: before client->Open tap=%p vnet=%d static=%d mux=%d",
        tap.get(), network_interface->VNet ? 1 : 0, network_interface->StaticMode ? 1 : 0, network_interface->VMux);
    bool ok = client->Open(tap);
    __android_log_print(ANDROID_LOG_INFO, "libopenppp2",
        "open_switcher: client->Open result=%d last_error=%d",
        ok ? 1 : 0,
        (int)static_cast<uint32_t>(ppp::diagnostics::GetLastErrorCodeSnapshot()));
    if (!ok) {
        if (ppp::diagnostics::GetLastErrorCodeSnapshot() == ppp::diagnostics::ErrorCode::Success) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceOpenFailed);
        }

        return LIBOPENPPP2_ERROR_OPEN_VETHERNET_FAIL;
    }

    VEthernetNetworkSwitcher::ProtectorNetworkPtr protector = client->GetProtectorNetwork();
    if (NULLPTR == protector) {
        __android_log_print(ANDROID_LOG_ERROR, "libopenppp2", "open_switcher: protector is null");
        if (ppp::diagnostics::GetLastErrorCodeSnapshot() == ppp::diagnostics::ErrorCode::Success) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        }

        return LIBOPENPPP2_ERROR_UNKNOWN;
    }

    std::atomic_store(&app->client_, client);
    libopenppp2_application::Timeout();
    const auto open_switcher_elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - open_switcher_begin).count();
    __android_log_print(ANDROID_LOG_INFO, "libopenppp2",
        "open_switcher: success elapsed_ms=%lld",
        static_cast<long long>(open_switcher_elapsed_ms));
    return LIBOPENPPP2_ERROR_SUCCESS;
}

static int                                                                          libopenppp2_try_open_ethernet_switcher(
    std::shared_ptr<boost::asio::io_context>                                            context,
    std::shared_ptr<VEthernetNetworkSwitcher>&                                          ethernet) noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULLPTR == app) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::AppContextUnavailable, LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED);
    }

    std::shared_ptr<VEthernetNetworkSwitcher> client = std::atomic_load(&app->client_);
    if (NULLPTR != client) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::AppAlreadyRunning, LIBOPENPPP2_ERROR_IT_IS_RUNING);
    }

    std::shared_ptr<libopenppp2_network_interface> network_interface = app->network_interface_;
    if (NULLPTR == network_interface) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable, LIBOPENPPP2_ERROR_NETWORK_INTERFACE_NOT_CONFIGURED);
    }

    std::shared_ptr<AppConfiguration> configuration = app->configuration_;
    if (NULLPTR == configuration) {
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::AppConfigurationMissing, LIBOPENPPP2_ERROR_APP_CONFIGURATION_NOT_CONFIGURED);
    }

    std::shared_ptr<ITap> tap = libopenppp2_from_tuntap_driver_new(context, network_interface);
    __android_log_print(ANDROID_LOG_INFO, "libopenppp2",
        "try_open_switcher: tap=%p fd=%d ip=%s mask=%s gw=%s",
        tap.get(),
        network_interface->VTun,
        network_interface->IPAddress.to_string().c_str(),
        network_interface->SubmaskAddress.to_string().c_str(),
        network_interface->GatewayServer.to_string().c_str());
    if (NULLPTR == tap) {
        __android_log_print(ANDROID_LOG_ERROR, "libopenppp2", "try_open_switcher: tap create failed");
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::TunnelOpenFailed, LIBOPENPPP2_ERROR_OPEN_TUNTAP_FAIL);
    }

    int err = libopenppp_try_open_ethernet_switcher_new(context, app, tap, client, network_interface, configuration);
    if (err == LIBOPENPPP2_ERROR_SUCCESS) {
        ethernet = client;
    }
    else {
        IDisposable::DisposeReferences(tap, client);
    }

    return err;
}

// When calling this function, you must first create a new JVM background thread.
// Calling this function in the context of that thread blocks the thread until the VPN is requested to disconnect and exit.
//
// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native int run(int key)
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_run(JNIEnv* env, jobject* this_, jint key_) noexcept {
    __LIBOPENPPP2_MAIN__;
    __android_log_print(ANDROID_LOG_INFO, "libopenppp2", "run() called with key=%d", key_);

    // Install a process-wide terminate handler the first time run() is called.
    // boost::asio handlers running on internal worker threads (e.g. ITap reader,
    // Executors::GetDefault() thread pool) may throw boost::system::system_error
    // such as "cancel: Bad file descriptor" when a TUN/socket descriptor becomes
    // invalid. Without a handler, such exceptions bypass the io_context try/catch
    // below and call std::terminate() -> SIGABRT, which kills the :vpn process and
    // causes the Android service to be re-created in a loop. We log and force a
    // graceful _exit instead so the service stays in the disconnected state.
    static std::once_flag s_install_terminate_once;
    std::call_once(s_install_terminate_once, []() {
        std::set_terminate([]() noexcept {
            const char* what = "<unknown>";
            try {
                if (auto eptr = std::current_exception()) {
                    std::rethrow_exception(eptr);
                }
            } catch (const std::exception& e) {
                what = e.what();
            } catch (...) {
                what = "<non-std exception>";
            }
            __android_log_print(ANDROID_LOG_ERROR, "libopenppp2",
                "[set_terminate] uncaught exception: %s", what);
            // Use _exit to avoid running global destructors which may double-free
            // resources already in an inconsistent state.
            _exit(0);
        });
    });

    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Success);

    // Registered once for the process. The application object outlives every
    // session, the listener captures nothing, and never unsubscribing means a
    // publish racing teardown cannot reach a freed capture -- which also keeps
    // the terminal Idle/Failed snapshot, published after the client is
    // released, on its way to the service.
    if (std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault(); NULLPTR != app) {
        static std::once_flag s_runtime_snapshot_bridge_once;
        std::call_once(s_runtime_snapshot_bridge_once, [&app]() noexcept {
            app->runtime_lifecycle_.Subscribe(
                [](const ppp::app::runtime::RuntimeSnapshot& snapshot) noexcept {
                    libopenppp2_publish_runtime_snapshot(
                        ppp::app::runtime::SerializeRuntimeSnapshot(snapshot));
                });
        });
    }

    std::shared_ptr<boost::asio::io_context> context = ppp::make_shared_object<boost::asio::io_context>();
    if (NULLPTR == context) {
        __android_log_print(ANDROID_LOG_ERROR, "libopenppp2", "run() failed to create io_context");
        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::MemoryAllocationFailed, LIBOPENPPP2_ERROR_ALLOCATED_MEMORY);
    }
    __android_log_print(ANDROID_LOG_INFO, "libopenppp2", "run() io_context created");

    int err = LIBOPENPPP2_ERROR_SUCCESS;
    boost::asio::post(*context,
        [&err, env, context, key_]() noexcept {
            auto start = [env, context](const std::shared_ptr<libopenppp2_application>& app) noexcept -> int {
                    std::shared_ptr<VEthernetNetworkSwitcher> ethernet = std::atomic_load(&app->client_);
                    if (NULLPTR != ethernet) {
                        __android_log_print(ANDROID_LOG_WARN, "libopenppp2",
                            "run() stale client detected, releasing before restart");
                        app->Release();
                        ethernet = std::atomic_load(&app->client_);
                        if (NULLPTR != ethernet) {
                            return LIBOPENPPP2_ERROR_IT_IS_RUNING;
                        }
                    }

                    ppp::app::runtime::RuntimeSnapshot runtime_seed;
                    runtime_seed.role = "client";
                    runtime_seed.capabilities = {
                        "mux.compat", "mux.flow", "mux.balance", "mux.stripe"};
                    const std::uint64_t runtime_generation = app->runtime_lifecycle_.Begin(
                        std::move(runtime_seed),
                        Executors::GetTickCount());
                    app->runtime_lifecycle_.Transition(
                        runtime_generation,
                        ppp::app::runtime::RuntimePhase::PreparingHost,
                        Executors::GetTickCount());
                    app->runtime_lifecycle_.Transition(
                        runtime_generation,
                        ppp::app::runtime::RuntimePhase::Connecting,
                        Executors::GetTickCount());

                    int err = libopenppp2_try_open_ethernet_switcher(context, ethernet);
                    if (err != LIBOPENPPP2_ERROR_SUCCESS) {
                        return err;
                    }

                    app->runtime_lifecycle_.Transition(
                        runtime_generation,
                        ppp::app::runtime::RuntimePhase::Handshaking,
                        Executors::GetTickCount());

                    auto protector = ethernet->GetProtectorNetwork();
                    if (NULLPTR == protector) {
                        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid, LIBOPENPPP2_ERROR_UNKNOWN);
                    }

                    if (!protector->JoinJNI(context, env)) {
                        return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid, LIBOPENPPP2_ERROR_UNKNOWN);
                    }

                    return LIBOPENPPP2_ERROR_SUCCESS;
                };

            std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
            if (NULLPTR == app) {
                err = LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED;
            } else {
                err = start(app);
                if (err == LIBOPENPPP2_ERROR_SUCCESS) {
                    app->PostJNI(
                        [app, key_](JNIEnv* env) noexcept {
                            app->StartJNI(env, key_);
                        });
                }
                else if (err != LIBOPENPPP2_ERROR_IT_IS_RUNING) {
                    ppp::app::runtime::RuntimeError error;
                    error.code = static_cast<std::uint32_t>(std::max(0, err));
                    error.severity = "error";
                    error.user_message_key = "RuntimeFailed";
                    app->Release(false, std::move(error));
                    context->stop();
                }
            }
        });

    auto work = boost::asio::make_work_guard(*context);
    __android_log_print(ANDROID_LOG_INFO, "libopenppp2", "run() work guard created, about to call context->run()");
    boost::system::error_code ec;
    context->restart();

    // boost::asio handlers may throw (e.g. boost::system::system_error on
    // descriptor cancel/close after fd becomes invalid). When a handler throws
    // out of run(), the default behavior is std::terminate which kills the
    // process. We catch and log here, then continue running the io_context
    // until normal completion or stop. This matches the recommended pattern
    // in boost::asio docs (basic_io_context overview - exception handling).
    for (;;) {
        try {
            context->run(ec);
            break;
        } catch (const std::exception& e) {
            __android_log_print(ANDROID_LOG_ERROR, "libopenppp2",
                "run() handler exception: %s", e.what());
        } catch (...) {
            __android_log_print(ANDROID_LOG_ERROR, "libopenppp2",
                "run() handler exception: <unknown>");
        }
    }
    __android_log_print(ANDROID_LOG_INFO, "libopenppp2", "run() context->run() returned, ec=%d", ec.value());

    return libopenppp2_set_last_error_for_result(err);
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native void stop()
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_stop(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Success);

    int err = libopenppp2_invoke_on_run_context(
        []() noexcept -> int {
            std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
            if (NULLPTR == app) {
                return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::AppContextUnavailable, LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED);
            }

            bool ok = app->Release();
            if (!ok) {
                return libopenppp2_set_last_error_and_return(ppp::diagnostics::ErrorCode::AndroidLibInvalidState, LIBOPENPPP2_ERROR_IT_IS_NOT_RUNING);
            }

            return LIBOPENPPP2_ERROR_SUCCESS;
        });
    return libopenppp2_set_last_error_for_result(err);
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native void clear_configure()
__LIBOPENPPP2__(void) Java_supersocksr_ppp_android_c_libopenppp2_clear_1configure() noexcept {
    __LIBOPENPPP2_MAIN__;

    libopenppp2_application::Invoke(
        []() noexcept -> int {
            std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
            if (NULLPTR != app) {
                app->bypass_ip_list_.reset();
                app->dns_rules_list_.reset();
                app->configuration_.reset();
                app->network_interface_.reset();
            }

            return LIBOPENPPP2_ERROR_SUCCESS;
        });
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native bool if_subnet(string ip1_, string ip2_, string mask_)
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_if_1subnet(JNIEnv* env, jobject* this_, jstring ip1_, jstring ip2_, jstring mask_) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<ppp::string> ip1_string = JNIENV_GetStringUTFChars(env, ip1_);
    std::shared_ptr<ppp::string> ip2_string = JNIENV_GetStringUTFChars(env, ip2_);
    std::shared_ptr<ppp::string> mask_string = JNIENV_GetStringUTFChars(env, mask_);
    if (NULLPTR == ip1_string || NULLPTR == ip2_string || NULLPTR == mask_string) {
        return false;
    }

    boost::system::error_code ec;
    boost::asio::ip::address ip1 = ppp::StringToAddress(ip1_string->data(), ec);
    if (ec) {
        return false;
    }

    boost::asio::ip::address ip2 = ppp::StringToAddress(ip2_string->data(), ec);
    if (ec) {
        return false;
    }

    boost::asio::ip::address mask = ppp::StringToAddress(mask_string->data(), ec);
    if (ec) {
        return false;
    }

    if (ip1.is_v4() && ip2.is_v4() && mask.is_v4()) {
        uint32_t nip1 = htonl(ip1.to_v4().to_uint());
        uint32_t nip2 = htonl(ip2.to_v4().to_uint());
        uint32_t nmask = htonl(mask.to_v4().to_uint());

        nip1 &= nmask;
        nip2 &= nmask;
        return nip1 == nip2;
    }
    else if (ip1.is_v6() && ip2.is_v6() && mask.is_v6()) {
        ppp::Int128 nip1 = *(ppp::Int128*)(ip1.to_v6().to_bytes().data());
        ppp::Int128 nip2 = *(ppp::Int128*)(ip2.to_v6().to_bytes().data());
        ppp::Int128 nmask = *(ppp::Int128*)(mask.to_v6().to_bytes().data());

        nip1 = nip1 & nmask;
        nip2 = nip2 & nmask;
        return nip1 == nip2;
    }
    else {
        return false;
    }
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native int netmask_to_prefix(byte[] address_)
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_netmask_1to_1prefix(JNIEnv* env, jobject* this_, jbyteArray address_) noexcept {
    __LIBOPENPPP2_MAIN__;

    int length = env->GetArrayLength(address_);
    if (length < 4) {
        return -1;
    }

    const char* address_bytes = (char*)env->GetByteArrayElements(address_, NULLPTR);
    if (NULLPTR == address_bytes) {
        return -1;
    }

    int prefix = IPEndPoint::NetmaskToPrefix((unsigned char*)address_bytes, length);
    env->ReleaseByteArrayElements(address_, (jbyte*)address_bytes, 0);

    return prefix;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native string prefix_to_netmask(bool v4_or_v6, int prefix_)
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_prefix_1to_1netmask(JNIEnv* env, jobject* this_, jboolean v4_or_v6, jint prefix_) noexcept {
    __LIBOPENPPP2_MAIN__;

    prefix_ = std::max<int>(0, prefix_);
    if (v4_or_v6) {
        prefix_ = std::min<int>(prefix_, ppp::net::native::MAX_PREFIX_VALUE_V4);
    }
    else {
        prefix_ = std::min<int>(prefix_, ppp::net::native::MAX_PREFIX_VALUE_V6);
    }

    if (v4_or_v6) {
        uint32_t mask = IPEndPoint::PrefixToNetmask(prefix_);
        std::string mask_string = Ipep::ToAddress(mask).to_string();

        return JNIENV_NewStringUTF(env, mask_string.data());
    }
    else {
        ppp::Int128 mask = ppp::PrefixMask128(prefix_);
        mask = Ipep::NetworkToHostOrder(mask);

        ppp::string mask_string = IPEndPoint(ppp::net::AddressFamily::InterNetworkV6, &mask, sizeof(mask), 0).ToAddressString();
        return JNIENV_NewStringUTF(env, mask_string.data());
    }
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native string get_http_proxy_address_endpoint()
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_1http_1proxy_1address_1endpoint(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<ppp::string> address_string;
    int err = libopenppp2_application::Invoke(
        [&address_string]() noexcept -> int {
            std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
            if (NULLPTR != app) {
                std::shared_ptr<VEthernetNetworkSwitcher> client = std::atomic_load(&app->client_);
                if (NULLPTR != client) {
                    std::shared_ptr<VEthernetHttpProxySwitcher> http_proxy = client->GetHttpProxy();
                    if (NULLPTR != http_proxy) {
                        address_string = ppp::make_shared_object<ppp::string>(IPEndPoint::ToEndPoint(http_proxy->GetLocalEndPoint()).ToString());
                    }
                }
            }

            return LIBOPENPPP2_ERROR_SUCCESS;
        });

    if (err != LIBOPENPPP2_ERROR_SUCCESS) {
        libopenppp2_set_last_error_for_result(err);
    }

    if (NULLPTR == address_string) {
        return JNIENV_NewStringUTF(env, NULLPTR);
    }

    return JNIENV_NewStringUTF(env, address_string->data());
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native string get_socks_proxy_address_endpoint()
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_1socks_1proxy_1address_1endpoint(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<ppp::string> address_string;
    int err = libopenppp2_application::Invoke(
        [&address_string]() noexcept -> int {
            std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
            if (NULLPTR != app) {
                std::shared_ptr<VEthernetNetworkSwitcher> client = std::atomic_load(&app->client_);
                if (NULLPTR != client) {
                    std::shared_ptr<VEthernetSocksProxySwitcher> socks_proxy = client->GetSocksProxy();
                    if (NULLPTR != socks_proxy) {
                        address_string = ppp::make_shared_object<ppp::string>(IPEndPoint::ToEndPoint(socks_proxy->GetLocalEndPoint()).ToString());
                    }
                }
            }

            return LIBOPENPPP2_ERROR_SUCCESS;
        });

    if (err != LIBOPENPPP2_ERROR_SUCCESS) {
        libopenppp2_set_last_error_for_result(err);
    }

    if (NULLPTR == address_string) {
        return JNIENV_NewStringUTF(env, NULLPTR);
    }

    return JNIENV_NewStringUTF(env, address_string->data());
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native string get_ethernet_information(bool default_)
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_1ethernet_1information(JNIEnv* env, jobject* this_, jboolean default_) noexcept {
    typedef VEthernetExchanger::VirtualEthernetInformation VirtualEthernetInformation;

    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<ppp::string> json;
    int err = libopenppp2_application::Invoke(
        [&json, default_]() noexcept -> int {
            std::shared_ptr<VirtualEthernetInformation> information;
            std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
            if (NULLPTR != app) {
                std::shared_ptr<VEthernetNetworkSwitcher> client = std::atomic_load(&app->client_);
                if (NULLPTR != client) {
                    std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger();
                    if (NULLPTR != exchanger) {
                        information = exchanger->GetInformation();
                    }
                }
            }

            if (NULLPTR == information) {
                if (!default_) {
                    return LIBOPENPPP2_ERROR_UNKNOWN;
                }

                information = ppp::make_shared_object<VirtualEthernetInformation>();
                if (NULLPTR == information) {
                    return LIBOPENPPP2_ERROR_UNKNOWN;
                }
            }

            json = ppp::make_shared_object<ppp::string>(information->ToString());
            return LIBOPENPPP2_ERROR_SUCCESS;
        });

    if (err != LIBOPENPPP2_ERROR_SUCCESS) {
        libopenppp2_set_last_error_for_result(err);
    }

    if (NULLPTR == json) {
        return JNIENV_NewStringUTF(env, NULLPTR);
    }

    return JNIENV_NewStringUTF(env, json->data());
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native string link_of(string url)
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_link_1of(JNIEnv* env, jobject* this_, jstring url) noexcept {
    typedef UriAuxiliary::ProtocolType ProtocolType;

    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<ppp::string> url_string = JNIENV_GetStringUTFChars(env, url);
    if (NULLPTR == url_string || url_string->empty()) {
        return NULLPTR;
    }

    ppp::string hostname;
    ppp::string address;
    ppp::string path;
    int port;
    ProtocolType protocol;
    ppp::string raw;

    ppp::string server = UriAuxiliary::Parse(*url_string, hostname, address, path, port, protocol, &raw, ppp::nullof<YieldContext>());
    if (server.empty()) {
        return NULLPTR;
    }

    Json::Value json;
    json["server"] = server;
    json["hostname"] = hostname;
    json["address"] = address;
    json["path"] = path;
    json["url"] = raw;
    json["port"] = port;

    if (protocol == ProtocolType::ProtocolType_Http || protocol == ProtocolType::ProtocolType_WebSocket) {
        json["proto"] = "ws";
        json["protocol"] = "ppp+ws";
    }
    else if (protocol == ProtocolType::ProtocolType_HttpSSL || protocol == ProtocolType::ProtocolType_WebSocketSSL) {
        json["proto"] = "wss";
        json["protocol"] = "ppp+wss";
    }
    else {
        json["proto"] = BOOST_BEAST_VERSION_STRING;
        json["protocol"] = "ppp+tcp";
    }

    ppp::string json_string = JsonAuxiliary::ToStyledString(json);
    return JNIENV_NewStringUTF(env, json_string.data());
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native bool ip_address_string_is_invalid(string address)
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_ip_1address_1string_1is_1invalid(JNIEnv* env, jobject this_, jstring address_) {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<ppp::string> address_managed = JNIENV_GetStringUTFChars(env, address_);
    if (NULLPTR == address_managed || address_managed->empty()) {
        return true;
    }

    boost::system::error_code ec;
    boost::asio::ip::address ip = ppp::StringToAddress(address_managed->data(), ec);
    if (ec) {
        return true;
    }

    bool b = ip.is_v4() || ip.is_v6();
    if (!b) {
        return true;
    }

    return IPEndPoint::IsInvalid(ip);
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native string bytes_to_address_string(byte[] address)
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_bytes_1to_1address_1string(JNIEnv* env, jobject this_, jbyteArray address_) {
    __LIBOPENPPP2_MAIN__;

    if (NULLPTR == address_) {
        return env->NewStringUTF("0.0.0.0");
    }

    int length = env->GetArrayLength(address_);
    if (length < 4) {
        return env->NewStringUTF("0.0.0.0");
    }

    const char* address_bytes = (char*)env->GetByteArrayElements(address_, NULLPTR);
    if (NULLPTR == address_bytes) {
        return env->NewStringUTF("0.0.0.0");
    }

    char sz[INET6_ADDRSTRLEN];
    const char* r = inet_ntop(length >= 16 ? INET6_ADDRSTRLEN : AF_INET, (struct in_addr*)address_bytes, sz, sizeof(sz)); /* in6_addr */
    env->ReleaseByteArrayElements(address_, (jbyte*)address_bytes, 0);

    if (!r) {
        return env->NewStringUTF("0.0.0.0");
    }

    return env->NewStringUTF(sz); // inet_ntoa(*(struct in_addr*)address);
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native int socket_get_socket_type(int fd_)
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_socket_1get_1socket_1type(JNIEnv* env, jobject this_, jint fd_) {
    __LIBOPENPPP2_MAIN__;

    if (fd_ == -1) {
        return -1;
    }

    int type;
    socklen_t len = sizeof(type);

    int err = getsockopt(fd_, SOL_SOCKET, SO_TYPE, &type, &len);
    if (err < 0) {
        return -1;
    }

    return type;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2
// public native byte[] string_to_address_bytes(string address)
__LIBOPENPPP2__(jbyteArray) Java_supersocksr_ppp_android_c_libopenppp2_string_1to_1address_1bytes(JNIEnv* env, jobject this_, jstring address_) {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<ppp::string> address_managed = JNIENV_GetStringUTFChars(env, address_);
    uint8_t bytes[16];
    int af = 0;

    if (NULLPTR == address_managed || address_managed->empty()) {
        *(uint32_t*)bytes = 0;
        af = AF_INET;
    }
    else {
        const char* address = NULLPTR;
        if (NULLPTR != address_managed) {
            address = address_managed->data();
        }

        boost::system::error_code ec;
        boost::asio::ip::address ip = ppp::StringToAddress(address, ec);
        if (ec) {
            return NULLPTR;
        }

        if (ip.is_v4()) {
            af = AF_INET;
            *(uint32_t*)bytes = htonl(ip.to_v4().to_uint());
        }
        else if (ip.is_v6()) {
            boost::asio::ip::address_v6::bytes_type tb = ip.to_v6().to_bytes();
            af = AF_INET6;
            memcpy(bytes, tb.data(), tb.size());
        }
    }

    int result_count =
        af == AF_INET ?
        4 :
        16;

    jbyteArray result = env->NewByteArray(result_count);
    if (NULLPTR == result) {
        return NULLPTR;
    }

    jbyte* p = env->GetByteArrayElements(result, NULLPTR);
    if (NULLPTR != p) {
        memcpy(p, bytes, result_count);

        env->ReleaseByteArrayElements(result, p, 0);
    }

    return result;
}

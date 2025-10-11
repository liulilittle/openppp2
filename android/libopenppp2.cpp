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
#include <ppp/diagnostics/Stopwatch.h>

#include <ppp/auxiliary/JsonAuxiliary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/auxiliary/UriAuxiliary.h>

#include <ppp/threading/Timer.h>
#include <ppp/threading/Thread.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>

#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetManagedServer.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>

#include <linux/ppp/tap/TapLinux.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <signal.h>
#include <setjmp.h>
#include <assert.h>

#include <fcntl.h>
#include <errno.h>
#include <malloc.h>

#include <unistd.h>
#include <netdb.h>
#include <error.h>
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
#include <string>
#include <memory>

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

static inline jstring                                                       JNIENV_NewStringUTF(JNIEnv* env, const char* v) noexcept { return NULL != v ? env->NewStringUTF(v) : NULL; }
static std::shared_ptr<ppp::string>                                         JNIENV_GetStringUTFChars(JNIEnv* env, const jstring& v) noexcept {
    std::shared_ptr<ppp::string> result;
    if (NULL != v) {
        char* s = (char*)env->GetStringUTFChars(v, NULL);
        if (NULL != s) {
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

private:
    bool                                                                    ReportTransmissionStatistics() noexcept;
    bool                                                                    GetTransmissionStatistics(uint64_t& incoming_traffic, uint64_t& outgoing_traffic, std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept;

public:
    bool                                                                    StatisticsJNI(JNIEnv* env, const char* json) noexcept;
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
            if (NULL != awaitable) {
                std::weak_ptr<Executors::Awaitable> awaitable_weak = awaitable;
                std::thread(
                    [this, awaitable_weak]() noexcept {
                        // Global static constructor for PPP PRIVATE NETWORK™ 2. (For OS X platform compatibility.)
                        ppp::global::cctor();

                        std::shared_ptr<libopenppp2_application> app = ppp::make_shared_object<libopenppp2_application>();
                        app_ = app; 

                        if (NULL != app) {
                            auto start = 
                                [app, awaitable_weak](int argc, const char* argv[]) noexcept -> int {
                                    std::shared_ptr<Executors::Awaitable> awaitable = awaitable_weak.lock();
                                    if (NULL != awaitable) {
                                        awaitable->Processed();
                                    }

                                    app->DllMain();
                                    return 0;
                                };
                            Executors::Run(NULL, start);
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
    if (NULL == context) {
        return false;
    }

    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULL == app) {
        return false;
    }

    std::shared_ptr<VEthernetNetworkSwitcher> client = app->client_;
    if (NULL == client) {
        return false;
    }

    std::shared_ptr<Timer> timeout = Timer::Timeout(context, 1000, 
        [](Timer*) noexcept {
            std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
            if (NULL != app) {
                app->timeout_.reset();
                libopenppp2_application::Timeout();
            }
        });
    if (NULL == timeout) {
        return false;
    }

    app->timeout_ = std::move(timeout);
    app->OnTick(Executors::GetTickCount());
    return true;
}

bool                                                                        libopenppp2_application::OnTick(uint64_t now) noexcept {
    ReportTransmissionStatistics();
    return true;
}

bool                                                                        libopenppp2_application::ReportTransmissionStatistics() noexcept {
    // Get statistics on the physical network transport layer of the Virtual Ethernet switcher.
    struct {
        uint64_t                                                            incoming_traffic;
        uint64_t                                                            outgoing_traffic;
        std::shared_ptr<ppp::transmissions::ITransmissionStatistics>        statistics_snapshot;
    } TransmissionStatistics;

    if (!GetTransmissionStatistics(TransmissionStatistics.incoming_traffic, TransmissionStatistics.outgoing_traffic, TransmissionStatistics.statistics_snapshot)) {
        TransmissionStatistics.incoming_traffic = 0;
        TransmissionStatistics.outgoing_traffic = 0;
        TransmissionStatistics.statistics_snapshot = NULL;
    }

    Json::Value json;
    json["tx"] = stl::to_string<ppp::string>(TransmissionStatistics.outgoing_traffic);
    json["rx"] = stl::to_string<ppp::string>(TransmissionStatistics.incoming_traffic);

    if (auto statistics = TransmissionStatistics.statistics_snapshot; statistics) {
        json["in"] = stl::to_string<ppp::string>(statistics->IncomingTraffic.load());
        json["out"] = stl::to_string<ppp::string>(statistics->OutgoingTraffic.load());
    }

    std::shared_ptr<ppp::string> json_string = ppp::make_shared_object<ppp::string>(JsonAuxiliary::ToStyledString(json));
    if (NULL == json_string) {
        return false;
    }

    return PostJNI(
        [this, json_string](JNIEnv* env) noexcept {
            StatisticsJNI(env, json_string->data());
        });
}

bool                                                                        libopenppp2_application::PostJNI(const ppp::function<void(JNIEnv*)>& task) noexcept {
    if (NULL == task) {
        return false;
    }

    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;
    if (NULL == client) {
        return false;
    }

    std::shared_ptr<ppp::net::ProtectorNetwork> protector = client->GetProtectorNetwork();
    if (NULL == protector) {
        return false;
    }

    std::shared_ptr<boost::asio::io_context> context = protector->GetContext();
    if (NULL == context) {
        return false;
    }

    std::weak_ptr<ppp::net::ProtectorNetwork> protector_weak = protector;
    boost::asio::post(*context, 
        [context, protector_weak, task]() noexcept {
            std::shared_ptr<ppp::net::ProtectorNetwork> protector = protector_weak.lock();
            if (NULL != protector) {
                JNIEnv* env = protector->GetEnvironment();
                if (NULL != env) {
                    task(env);
                }
            }
        });
    return true;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public static void statistics(string json)
// param
//  json: {
//      tx:         string(int64),
//      rx:         string(int64),
//      in:         string(int64),
//      out :       string(int64)
//  }
bool                                                                        libopenppp2_application::StatisticsJNI(JNIEnv* env, const char* json) noexcept {
    jclass clazz = env->FindClass(LIBOPENPPP2_CLASSNAME);
    if (NULL != env->ExceptionOccurred()) {
        env->ExceptionClear();
    }

    if (NULL == clazz) {
        return false;
    }

    jmethodID method = env->GetStaticMethodID(clazz, "statistics", "(Ljava/lang/String;)V");
    if (NULL != env->ExceptionOccurred()) {
        env->ExceptionClear();
    }

    bool result = false;
    if (NULL != method) {
        jstring json_string = JNIENV_NewStringUTF(env, json);
        env->CallStaticVoidMethod(clazz, method, json_string);

        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        else {
            result = true;
        }

        if (NULL != json_string) {
            env->DeleteLocalRef(json_string);
        }
    }

    env->DeleteLocalRef(clazz);
    return result;
}

bool                                                                        libopenppp2_application::GetTransmissionStatistics(uint64_t& incoming_traffic, uint64_t& outgoing_traffic, std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept {
    // Initialization requires the initial value of the FAR outgoing parameter.
    statistics_snapshot = NULL;
    incoming_traffic = 0;
    outgoing_traffic = 0;

    // The transport layer network statistics are obtained only when the current client switch or server switch is not released.
    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;
    if (NULL != client && !client->IsDisposed()) {
        // Obtain transport layer traffic statistics from the client switch or server switch management object.
        std::shared_ptr<ppp::transmissions::ITransmissionStatistics>transmission_statistics = client->GetStatistics();
        if (NULL != transmission_statistics) {
            return ppp::transmissions::ITransmissionStatistics::GetTransmissionStatistics(transmission_statistics, transmission_statistics_, incoming_traffic, outgoing_traffic, statistics_snapshot);
        }
    }

    return false;
}

bool                                                                        libopenppp2_application::Post(int sequence) noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULL == app) {
        return false;
    }

    libopenppp2_application* p = app.get();
    return app->PostJNI(
        [p, sequence](JNIEnv* env) noexcept {
            p->PostExecJNI(env, sequence);
        });
}

int                                                                         libopenppp2_application::Invoke(const ppp::function<int()>& task) noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULL == app) {
        return LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED;
    }

    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULL == context) {
        return LIBOPENPPP2_ERROR_VETHERNET_PPPD_THREAD_NOT_RUNING;
    }

    std::shared_ptr<Executors::Awaitable> awaitable = ppp::make_shared_object<Executors::Awaitable>();
    if (NULL == awaitable) {
        return LIBOPENPPP2_ERROR_ALLOCATED_MEMORY;
    }

    int err = LIBOPENPPP2_ERROR_UNKNOWN;
    boost::asio::post(*context, 
        [context, awaitable, &err, task]() noexcept {
            err = task();
            awaitable->Processed();
        });

    bool ok = awaitable->Await();
    if (!ok) {
        return LIBOPENPPP2_ERROR_UNKNOWN;
    }

    return err;
}

bool                                                                        libopenppp2_application::Release() noexcept {
    bool any = false;
    std::shared_ptr<Timer> timeout = std::move(timeout_); 
    if (NULL != timeout) {
        timeout->Dispose();
    }
    
    std::shared_ptr<VEthernetNetworkSwitcher> client = std::move(client_); 
    if (NULL != client) {
        any = true;
        client->Dispose();
    }

    configuration_.reset();
    client_.reset();
    stopwatch_.Reset();

    network_interface_.reset();
    bypass_ip_list_.reset();
    dns_rules_list_.reset();
    transmission_statistics_.Clear();
    return any;
}

bool                                                                        libopenppp2_application::ExecJNI(JNIEnv* env, const char* method_name, int param) noexcept {
    jclass clazz = env->FindClass(LIBOPENPPP2_CLASSNAME);
    if (NULL != env->ExceptionOccurred()) {
        env->ExceptionClear();
    }

    if (NULL == clazz) {
        return false;
    }

    jboolean result = false;
    jmethodID method = env->GetStaticMethodID(clazz, method_name, "(I)Z");
    if (NULL != env->ExceptionOccurred()) {
        env->ExceptionClear();
    }
    else if (NULL != method) {
        result = env->CallStaticBooleanMethod(clazz, method, (jint)param);
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
            result = false;
        }
    }

    env->DeleteLocalRef(clazz);
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
    if (NULL == app) {
        return LIBOPENPPP2_LINK_STATE_APPLICATIION_UNINITIALIZED;
    }

    std::shared_ptr<VEthernetNetworkSwitcher> client = app->client_;
    if (NULL == client) {
        return LIBOPENPPP2_LINK_STATE_CLIENT_UNINITIALIZED;
    }

    std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger();
    if (NULL == exchanger) {
        return LIBOPENPPP2_LINK_STATE_EXCHANGE_UNINITIALIZED;
    }

    NetworkState network_state = exchanger->GetNetworkState();
    if (network_state == NetworkState::NetworkState_Connecting) {
        return LIBOPENPPP2_LINK_STATE_CONNECTING;
    }
    elif(network_state == NetworkState::NetworkState_Reconnecting) {
        return LIBOPENPPP2_LINK_STATE_RECONNECTING;
    }
    elif(network_state == NetworkState::NetworkState_Established) {
        return LIBOPENPPP2_LINK_STATE_ESTABLISHED;
    }

    return LIBOPENPPP2_LINK_STATE_UNKNOWN;
}

static int                                                                  libopenppp2_get_aggligator_state() noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULL == app) {
        return LIBOPENPPP2_AGGLIGATOR_STATE_UNKNOWN;
    }

    std::shared_ptr<VEthernetNetworkSwitcher> client = app->client_;
    if (NULL == client) {
        return LIBOPENPPP2_AGGLIGATOR_STATE_UNKNOWN;
    }

    std::shared_ptr<aggligator::aggligator> aggligator = client->GetAggligator();
    if (NULL == aggligator) {
        return LIBOPENPPP2_AGGLIGATOR_STATE_NONE;
    }

    return (int)aggligator->status();
}

static int64_t                                                              libopenppp2_duration_time() noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULL == app) {
        return -1;
    }

    Stopwatch& sw = app->stopwatch_;
    return sw.IsRunning() ? sw.ElapsedMilliseconds() : 0;
}

static std::shared_ptr<ppp::string>                                         libopenppp2_get_app_configuration() noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULL == app) {
        return NULL;
    }

    std::shared_ptr<AppConfiguration> configuration = app->configuration_;
    if (NULL == configuration) {
        return NULL;
    }

    return ppp::make_shared_object<ppp::string>(configuration->ToString());
}

static std::shared_ptr<ppp::string>                                         libopenppp2_get_bypass_ip_list() noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULL == app) {
        return NULL;
    }

    std::shared_ptr<VEthernetNetworkSwitcher> client = app->client_;
    if (NULL == client) {
        return app->bypass_ip_list_;
    }

    auto fib = client->GetRib();
    if (NULL == fib) {
        return NULL;
    }

    std::shared_ptr<ppp::string> bypass_ip_list = ppp::make_shared_object<ppp::string>();
    if (NULL == bypass_ip_list) {
        return NULL;
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
    elif(err == LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED || err == LIBOPENPPP2_ERROR_VETHERNET_PPPD_THREAD_NOT_RUNING) {
        return LIBOPENPPP2_LINK_STATE_APPLICATIION_UNINITIALIZED;
    }
    else {
        return LIBOPENPPP2_LINK_STATE_UNKNOWN;
    }
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
    else {
        return LIBOPENPPP2_AGGLIGATOR_STATE_UNKNOWN;
    }
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

    return err != LIBOPENPPP2_ERROR_SUCCESS ? -1 : milliseconds;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public native string get_app_configuration()
// return:
//  json: appsettings.json
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_1app_1configuration(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<ppp::string> json;
    libopenppp2_application::Invoke(
        [&json]() noexcept {
            json = libopenppp2_get_app_configuration();
            return LIBOPENPPP2_ERROR_SUCCESS;
        });

    if (NULL == json) {
        return JNIENV_NewStringUTF(env, NULL);
    }

    return JNIENV_NewStringUTF(env, json->data());
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public native int set_app_configuration(string configurations /* configurations is appsettings.json */)
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_set_1app_1configuration(JNIEnv* env, jobject* this_, jstring configurations) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<ppp::string> json_string = JNIENV_GetStringUTFChars(env, configurations);
    if (NULL == json_string || json_string->empty()) {
        return LIBOPENPPP2_ERROR_ARG_CONFIGURATION_STRING_IS_NULL_OR_EMPTY;
    }

    std::shared_ptr<AppConfiguration> config = ppp::make_shared_object<AppConfiguration>();
    if (NULL == config) {
        return LIBOPENPPP2_ERROR_NEW_CONFIGURATION_FAIL;
    }

    Json::Value json = JsonAuxiliary::FromString(*json_string);
    if (!json.isObject()) {
        return LIBOPENPPP2_ERROR_ARG_CONFIGURATION_STRING_NOT_IS_JSON_OBJECT_STRING;
    }

    bool ok = config->Load(json);
    if (!ok) {
        return LIBOPENPPP2_ERROR_ARG_CONFIGURATION_STRING_CONFIGURE_ERROR;
    }

    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULL == app) {
        return LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED;
    }

    return libopenppp2_application::Invoke(
        [&app, &config]() noexcept {
            ppp::net::asio::vdns::ttl = config->udp.dns.ttl;
            ppp::net::asio::vdns::enabled = config->udp.dns.turbo;

            app->configuration_ = config;
            return LIBOPENPPP2_ERROR_SUCCESS;
        });
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public native bool set_default_flash_type_of_service(bool flash_mode)
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_set_1default_1flash_1type_1of_1service(JNIEnv* env, jobject* this_, jboolean flash_mode) noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULL == app) {
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
    if (NULL == app) {
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

    boost::system::error_code ec;
    if (tun == -1) {
        return LIBOPENPPP2_ERROR_ARG_TUN_IS_INVALID;
    }

    // 10.0.0.2
    std::shared_ptr<ppp::string> ip_string = JNIENV_GetStringUTFChars(env, ip);
    if (NULL == ip_string || ip_string->empty()) {
        return LIBOPENPPP2_ERROR_ARG_IP_IS_NULL_OR_EMPTY;
    }

    // 255.255.255.0
    std::shared_ptr<ppp::string> mask_string = JNIENV_GetStringUTFChars(env, mask);
    if (NULL == mask_string || mask_string->empty()) {
        return LIBOPENPPP2_ERROR_ARG_MASK_IS_NULL_OR_EMPTY;
    }

    boost::asio::ip::address ip_address = ppp::StringToAddress(ip_string->data(), ec);
    if (ec || !ip_address.is_v4()) {
        return LIBOPENPPP2_ERROR_ARG_IP_IS_NOT_AF_INET_FORMAT;
    }

    boost::asio::ip::address mask_address = ppp::StringToAddress(mask_string->data(), ec);
    if (ec || !mask_address.is_v4()) {
        return LIBOPENPPP2_ERROR_ARG_MASK_IS_NOT_AF_INET_FORMAT;
    }

    uint32_t addresses[2] = {
        IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(ip_address, IPEndPoint::MinPort)).GetAddress(),
        IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(mask_address, IPEndPoint::MinPort)).GetAddress(),
    };

    if (addresses[0] == IPEndPoint::AnyAddress || addresses[0] == IPEndPoint::LoopbackAddress || addresses[0] == IPEndPoint::NoneAddress) {
        return LIBOPENPPP2_ERROR_ARG_IP_IS_INVALID;
    }

    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULL == app) {
        return LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED;
    }
    else {
        int prefix = IPEndPoint::NetmaskToPrefix(addresses[1]);
        if (prefix < 16) {
            return LIBOPENPPP2_ERROR_ARG_MASK_SUBNET_IP_RANGE_GREATER_65535;
        }
        elif(prefix > 30) {
            addresses[1] = IPEndPoint::NetmaskToPrefix(prefix);
            mask_address = Ipep::ToAddress(addresses[1]);
        }

        if (IPEndPoint::IsInvalid(ip_address)) {
            return LIBOPENPPP2_ERROR_ARG_IP_IS_INVALID;
        }
    }

    boost::asio::ip::address gw_address = ppp::net::Ipep::FixedIPAddress(ip_address, mask_address);
    ip_address = Ipep::FixedIPAddress(ip_address, gw_address, mask_address);

    std::shared_ptr<libopenppp2_network_interface> network_interface = ppp::make_shared_object<libopenppp2_network_interface>();
    if (NULL == network_interface) {
        return LIBOPENPPP2_ERROR_NEW_NETWORKINTERFACE_FAIL;
    }

    network_interface->BlockQUIC = block_quic;
    network_interface->VNet = vnet;
    network_interface->VTun = tun;
    network_interface->VMux = (uint16_t)std::min<int>(std::max<int>(0, mux), UINT16_MAX);
    network_interface->StaticMode = static_mode;
    network_interface->IPAddress = ip_address;
    network_interface->GatewayServer = gw_address;
    network_interface->SubmaskAddress = mask_address;

    return libopenppp2_application::Invoke(
        [&app, &network_interface]() noexcept {
            app->network_interface_ = network_interface;
            return LIBOPENPPP2_ERROR_SUCCESS;
        });
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public native bool set_bypass_ip_list(string iplist)
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_set_1bypass_1ip_1list(JNIEnv* env, jobject* this_, jstring iplist) noexcept {
    __LIBOPENPPP2_MAIN__;
    
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULL == app) {
        return false;
    }

    std::shared_ptr<ppp::string> bypass_ip_list = JNIENV_GetStringUTFChars(env, iplist);
    int err = libopenppp2_application::Invoke(
        [&app, &bypass_ip_list]() noexcept {
            app->bypass_ip_list_ = bypass_ip_list;
            return LIBOPENPPP2_ERROR_SUCCESS;
        });
    return err == LIBOPENPPP2_ERROR_SUCCESS;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public native bool set_dns_rules_list(string rules)
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_set_1dns_1rules_1list(JNIEnv* env, jobject* this_, jstring rules) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULL == app) {
        return false;
    }

    std::shared_ptr<ppp::string> dns_rules_list = JNIENV_GetStringUTFChars(env, rules);
    int err = libopenppp2_application::Invoke(
        [&app, &dns_rules_list]() noexcept {
            app->dns_rules_list_ = dns_rules_list;
            return LIBOPENPPP2_ERROR_SUCCESS;
        });
    return err == LIBOPENPPP2_ERROR_SUCCESS;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public native bool set_dns_bcl(bool turbo, int ttl, string dns)
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_set_1dns_1bcl(JNIEnv* env, jobject* this_, jboolean turbo, jint ttl, jstring dns) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULL == app) {
        return false;
    }

    if (ttl < 1) {
        return false;
    }

    std::shared_ptr<ppp::string> dns_string = JNIENV_GetStringUTFChars(env, dns);
    if (NULL == dns_string) {
        return false;
    }

    if (dns_string->empty()) {
        return false;
    }

    ppp::vector<boost::asio::ip::address> ips;
    ppp::net::Ipep::ToDnsAddresses(*dns_string, ips);

    if (ips.empty()) {
        return false;
    }

    auto addresses = ppp::make_shared_object<ppp::net::asio::vdns::IPEndPointVector>();
    if (NULL == addresses) {
        return false;
    }

    for (const boost::asio::ip::address& ip : ips) {
        addresses->emplace_back(boost::asio::ip::udp::endpoint(ip, PPP_DNS_SYS_PORT));
    }

    ppp::net::asio::vdns::enabled = turbo;
    ppp::net::asio::vdns::ttl = ttl;
    ppp::net::asio::vdns::servers = addresses;
    return true;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public native string get_bypass_ip_list()
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_1bypass_1ip_1list(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<ppp::string> bypass_ip_list;
    libopenppp2_application::Invoke(
        [&bypass_ip_list]() noexcept {
            bypass_ip_list = libopenppp2_get_bypass_ip_list();
            return LIBOPENPPP2_ERROR_SUCCESS;
        });

    if (NULL == bypass_ip_list) {
        return JNIENV_NewStringUTF(env, NULL);
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
    if (NULL == app) {
        return JNIENV_NewStringUTF(env, NULL);
    }

    std::shared_ptr<ppp::string> json_string;
    libopenppp2_application::Invoke(
        [&app, &json_string]() noexcept {
            std::shared_ptr<libopenppp2_network_interface> network_interface = app->network_interface_;
            if (NULL != network_interface) {
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

    if (NULL == json_string) {
        return JNIENV_NewStringUTF(env, NULL);
    }

    return JNIENV_NewStringUTF(env, json_string->data());
}

// Post a JAVA function call to the JVM managed thread that is blocking the VPN that handles network protection.
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_post(JNIEnv* env, jobject* this_, int sequence) noexcept {
    __LIBOPENPPP2_MAIN__;

    return libopenppp2_application::Post(sequence);
}

static std::shared_ptr<ITap>                                                        libopenppp2_from_tuntap_driver_new(
    std::shared_ptr<boost::asio::io_context>                                        context,
    std::shared_ptr<libopenppp2_network_interface>                                  network_interface) noexcept {

    auto tun_fd = network_interface->VTun;
    if (tun_fd == -1) {
        return NULL;
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

static int                                                                          libopenppp_try_open_ethernet_switcher_new(
    std::shared_ptr<boost::asio::io_context>                                        context,
    std::shared_ptr<libopenppp2_application>                                        app,
    std::shared_ptr<ITap>                                                           tap,
    std::shared_ptr<VEthernetNetworkSwitcher>&                                      client,
    std::shared_ptr<libopenppp2_network_interface>                                  network_interface,
    std::shared_ptr<AppConfiguration>                                               configuration) noexcept {

    bool lwip = false;
    int max_concurrent = ppp::GetProcesserCount();
    
    client = ppp::make_shared_object<VEthernetNetworkSwitcher>(context, lwip, network_interface->VNet, max_concurrent > 1, configuration);
    if (NULL == client) {
        return LIBOPENPPP2_ERROR_ALLOCATED_MEMORY;
    }
    else {
        client->Mux(&network_interface->VMux);
        client->StaticMode(&network_interface->StaticMode);
    }

    std::shared_ptr<ppp::string> bypass_ip_list = std::move(app->bypass_ip_list_); 
    if (NULL != bypass_ip_list) {
        app->bypass_ip_list_.reset();
        client->SetBypassIpList(std::move(*bypass_ip_list));
    }
    
    std::shared_ptr<ppp::string> dns_rules_list = std::move(app->dns_rules_list_); 
    if (NULL != dns_rules_list) {
        app->dns_rules_list_.reset();
        client->LoadAllDnsRules(std::move(*dns_rules_list), false);
    }

    bool ok = client->Open(tap);
    if (!ok) {
        return LIBOPENPPP2_ERROR_OPEN_VETHERNET_FAIL;
    }

    VEthernetNetworkSwitcher::ProtectorNetworkPtr protector = client->GetProtectorNetwork();
    if (NULL == protector) {
        return LIBOPENPPP2_ERROR_UNKNOWN;
    }

    app->client_ = client;
    libopenppp2_application::Timeout();
    return LIBOPENPPP2_ERROR_SUCCESS;
}

static int                                                                          libopenppp2_try_open_ethernet_switcher(std::shared_ptr<VEthernetNetworkSwitcher>& ethernet) noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    std::shared_ptr<VEthernetNetworkSwitcher> client = app->client_;
    if (NULL != client) {
        return LIBOPENPPP2_ERROR_IT_IS_RUNING;
    }

    std::shared_ptr<libopenppp2_network_interface> network_interface = app->network_interface_;
    if (NULL == network_interface) {
        return LIBOPENPPP2_ERROR_NETWORK_INTERFACE_NOT_CONFIGURED;
    }

    std::shared_ptr<AppConfiguration> configuration = app->configuration_;
    if (NULL == configuration) {
        return LIBOPENPPP2_ERROR_APP_CONFIGURATION_NOT_CONFIGURED;
    }

    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    std::shared_ptr<ITap> tap = libopenppp2_from_tuntap_driver_new(context, network_interface);
    if (NULL == tap) {
        return LIBOPENPPP2_ERROR_OPEN_TUNTAP_FAIL;
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
    
    std::shared_ptr<boost::asio::io_context> context = ppp::make_shared_object<boost::asio::io_context>();
    if (NULL == context) {
        return LIBOPENPPP2_ERROR_ALLOCATED_MEMORY;
    }

    int err = LIBOPENPPP2_ERROR_SUCCESS;
    boost::asio::post(*context, 
        [&err, env, context, key_]() noexcept {
            auto start = [env, context](const std::shared_ptr<libopenppp2_application>& app) noexcept -> int {
                    std::shared_ptr<VEthernetNetworkSwitcher> ethernet = app->client_;
                    if (NULL != ethernet) {
                        return LIBOPENPPP2_ERROR_IT_IS_RUNING;
                    }

                    int err = libopenppp2_try_open_ethernet_switcher(ethernet);
                    if (err != LIBOPENPPP2_ERROR_SUCCESS) {
                        return err;
                    }

                    auto protector = ethernet->GetProtectorNetwork();
                    if (NULL == protector) {
                        return LIBOPENPPP2_ERROR_UNKNOWN;
                    }

                    if (!protector->JoinJNI(context, env)) {
                        return LIBOPENPPP2_ERROR_UNKNOWN;
                    }

                    return LIBOPENPPP2_ERROR_SUCCESS;
                };

            err = libopenppp2_application::Invoke(
                [start, context, key_]() noexcept -> int {
                    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
                    if (NULL == app) {
                        return LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED;
                    }

                    int err = start(app);
                    if (err == LIBOPENPPP2_ERROR_SUCCESS) {
                        app->PostJNI(
                            [app, key_](JNIEnv* env) noexcept {
                                app->StartJNI(env, key_);
                            });
                    }
                    elif(err != LIBOPENPPP2_ERROR_IT_IS_RUNING) {
                        app->Release();
                        context->stop();
                    }

                    return err;
                });
        });

    boost::asio::io_context::work work(*context);
    boost::system::error_code ec;
    context->restart();
    context->run(ec);

    return err;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public native void stop()
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_stop(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    return libopenppp2_application::Invoke(
        []() noexcept -> int {
            std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
            if (NULL == app) {
                return LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED;
            }

            bool ok = app->Release();
            if (!ok) {
                return LIBOPENPPP2_ERROR_IT_IS_NOT_RUNING;
            }

            return LIBOPENPPP2_ERROR_SUCCESS;
        });
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public native void clear_configure()
__LIBOPENPPP2__(void) Java_supersocksr_ppp_android_c_libopenppp2_clear_1configure() noexcept {
    __LIBOPENPPP2_MAIN__;

    libopenppp2_application::Invoke(
        []() noexcept -> int {
            std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
            if (NULL != app) {
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
    if (NULL == ip1_string || NULL == ip2_string || NULL == mask_string) {
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
    elif(ip1.is_v6() && ip2.is_v6() && mask.is_v6()) {
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

    const char* address_bytes = (char*)env->GetByteArrayElements(address_, NULL);
    if (NULL == address_bytes) {
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
        ppp::Int128 mask = prefix_ ? (((ppp::Int128)-1L) << (128L - prefix_)) : 0L;
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
    libopenppp2_application::Invoke(
        [&address_string]() noexcept -> int {
            std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
            if (NULL != app) {
                std::shared_ptr<VEthernetNetworkSwitcher> client = app->client_;
                if (NULL != client) {
                    std::shared_ptr<VEthernetHttpProxySwitcher> http_proxy = client->GetHttpProxy();
                    if (NULL != http_proxy) {
                        address_string = ppp::make_shared_object<ppp::string>(IPEndPoint::ToEndPoint(http_proxy->GetLocalEndPoint()).ToString());
                    }
                }
            }

            return LIBOPENPPP2_ERROR_SUCCESS;
        });

    if (NULL == address_string) {
        return JNIENV_NewStringUTF(env, NULL);
    }

    return JNIENV_NewStringUTF(env, address_string->data());
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public native string get_socks_proxy_address_endpoint()
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_1socks_1proxy_1address_1endpoint(JNIEnv* env, jobject* this_) noexcept {
    __LIBOPENPPP2_MAIN__;

    std::shared_ptr<ppp::string> address_string;
    libopenppp2_application::Invoke(
        [&address_string]() noexcept -> int {
            std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
            if (NULL != app) {
                std::shared_ptr<VEthernetNetworkSwitcher> client = app->client_;
                if (NULL != client) {
                    std::shared_ptr<VEthernetSocksProxySwitcher> socks_proxy = client->GetSocksProxy();
                    if (NULL != socks_proxy) {
                        address_string = ppp::make_shared_object<ppp::string>(IPEndPoint::ToEndPoint(socks_proxy->GetLocalEndPoint()).ToString());
                    }
                }
            }

            return LIBOPENPPP2_ERROR_SUCCESS;
        });

    if (NULL == address_string) {
        return JNIENV_NewStringUTF(env, NULL);
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
    libopenppp2_application::Invoke(
        [&json, default_]() noexcept -> int {
            std::shared_ptr<VirtualEthernetInformation> information;
            std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
            if (NULL != app) {
                std::shared_ptr<VEthernetNetworkSwitcher> client = app->client_;
                if (NULL != client) {
                    std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger();
                    if (NULL != exchanger) {
                        information = exchanger->GetInformation();
                    }
                }
            }

            if (NULL == information) {
                if (!default_) {
                    return LIBOPENPPP2_ERROR_UNKNOWN;
                }

                information = ppp::make_shared_object<VirtualEthernetInformation>();
                if (NULL == information) {
                    return LIBOPENPPP2_ERROR_UNKNOWN;
                }
            }

            json = ppp::make_shared_object<ppp::string>(information->ToString());
            return LIBOPENPPP2_ERROR_SUCCESS;
        });

    if (NULL == json) {
        return JNIENV_NewStringUTF(env, NULL);
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
    if (NULL == url_string || url_string->empty()) {
        return NULL;
    }

    ppp::string hostname;
    ppp::string address;
    ppp::string path;
    int port;
    ProtocolType protocol;
    ppp::string raw;

    ppp::string server = UriAuxiliary::Parse(*url_string, hostname, address, path, port, protocol, &raw, ppp::nullof<YieldContext>());
    if (server.empty()) {
        return NULL;
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
    elif(protocol == ProtocolType::ProtocolType_HttpSSL || protocol == ProtocolType::ProtocolType_WebSocketSSL) {
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
    if (NULL == address_managed || address_managed->empty()) {
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

    if (NULL == address_) {
        return env->NewStringUTF("0.0.0.0");
    }

    int length = env->GetArrayLength(address_);
    if (length < 4) {
        return env->NewStringUTF("0.0.0.0");
    }

    const char* address_bytes = (char*)env->GetByteArrayElements(address_, NULL);
    if (NULL == address_bytes) {
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

    if (NULL == address_managed || address_managed->empty()) {
        *(uint32_t*)bytes = 0;
        af = AF_INET;
    }
    else {
        const char* address = NULL;
        if (NULL != address_managed) {
            address = address_managed->data();
        }

        boost::system::error_code ec;
        boost::asio::ip::address ip = ppp::StringToAddress(address, ec);
        if (ec) {
            return NULL;
        }

        if (ip.is_v4()) {
            af = AF_INET;
            *(uint32_t*)bytes = htonl(ip.to_v4().to_uint());
        }
        elif(ip.is_v6()) {
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
    if (NULL == result) {
        return NULL;
    }

    jbyte* p = env->GetByteArrayElements(result, NULL);
    if (NULL != p) {
        memcpy(p, bytes, result_count);

        env->ReleaseByteArrayElements(result, p, 0);
    }

    return result;
}
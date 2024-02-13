// https://www-numi.fnal.gov/offline_software/srt_public_context/WebDocs/Errors/unix_system_errors.html
// #define ENOENT           2      /* No such file or directory */
// #define EAGAIN          11      /* Try again */

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/IDisposable.h>
#include <ppp/Int128.h>
#include <ppp/io/File.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/auxiliary/JsonAuxiliary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/diagnostics/Stopwatch.h>
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
#include <string>
#include <iostream>
#include <memory>
#include <signal.h>
#include <setjmp.h>
#include <assert.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <malloc.h>

#include <netdb.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <error.h>
#include <sys/poll.h>
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/ptrace.h>

#include <android/log.h>
#include <jni.h>

#ifndef __LIBOPENPPP2__
#ifdef _ANDROID
#define __LIBOPENPPP2__(JNIType) extern "C" JNIEXPORT __unused JNIType JNICALL
#else
#define __LIBOPENPPP2__(JNIType) JNIType
#endif
#endif

#ifdef ANDROID
#undef stdin
#undef stdout
#undef stderr
FILE *stdin = &__sF[0];
FILE *stdout = &__sF[1];
FILE *stderr = &__sF[2];
#endif

static inline const char*                                                   JNIENV_GetStringUTFChars(JNIEnv* env, const jstring& v) noexcept { return NULL != v ? (char*)env->GetStringUTFChars(v, NULL) : NULL; }
static inline jstring                                                       JNIENV_NewStringUTF(JNIEnv* env, const char* v) noexcept         { return NULL != v ? env->NewStringUTF(v) : NULL; }

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
using ppp::coroutines::YieldContext;
using ppp::tap::ITap;
using ppp::net::Ipep;
using ppp::net::IPEndPoint;
using ppp::diagnostics::Stopwatch;
using ppp::auxiliary::JsonAuxiliary;
using ppp::auxiliary::StringAuxiliary;
using ppp::app::client::VEthernetExchanger;
using ppp::app::client::VEthernetNetworkSwitcher;
using ppp::app::client::VEthernetExchanger;
using ppp::app::client::http::VEthernetHttpProxySwitcher;
using ppp::IDisposable;

struct libopenppp2_network_interface final {
    int                                                                     VTun = -1;
    bool                                                                    VNet = false;
    bool                                                                    BlockQUIC = false;

    boost::asio::ip::address                                                IPAddress;
    boost::asio::ip::address                                                GatewayServer;
    boost::asio::ip::address                                                SubmaskAddress;
};

class libopenppp2_application final : public std::enable_shared_from_this<libopenppp2_application> {
public:
    static std::shared_ptr<libopenppp2_application>                         GetDefault() noexcept;
    void                                                                    DllMain() noexcept;
    void                                                                    Release() noexcept;
    bool                                                                    OnTick(uint64_t now) noexcept;
    static bool                                                             Post(int sequence) noexcept;
    static int                                                              Invoke(const ppp::function<int()>& task) noexcept;
    static bool                                                             Timeout() noexcept;

public:
    std::shared_ptr<Timer>                                                  timeout_;
    Stopwatch                                                               stopwatch_;
    std::shared_ptr<VEthernetNetworkSwitcher>                               client_;
    std::shared_ptr<AppConfiguration>                                       configuration_;
    std::shared_ptr<libopenppp2_network_interface>                          network_interface_;
    std::shared_ptr<ppp::string>                                            bypass_ip_list_;
    ppp::transmissions::ITransmissionStatistics                             transmission_statistics_;

private:
    bool                                                                    ReportTransmissionStatistics() noexcept;
    bool                                                                    GetTransmissionStatistics(uint64_t& incoming_traffic, uint64_t& outgoing_traffic, std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept;
    
private:
    bool                                                                    StatisticsJNI(JNIEnv* env, const char* json) noexcept;
    bool                                                                    PostExecJNI(JNIEnv* env, int sequence) noexcept;
    bool                                                                    PostJNI(const ppp::function<void(JNIEnv*)>& task) noexcept;
};

std::shared_ptr<libopenppp2_application>                                    libopenppp2_application::GetDefault() noexcept {
    struct libopenppp2_application_domain final {
    public:
        libopenppp2_application_domain() noexcept {
            // Global static constructor for PPP PRIVATE NETWORK™ 2. (For OS X platform compatibility.)
            ppp::global::cctor();

            // Run vpn/pppd main loop thread, which is the main thread of the VPN application driver, not the JVM managed thread.
            std::shared_ptr<Executors::Awaitable> awaitable = ppp::make_shared_object<Executors::Awaitable>();
            if (NULL != awaitable) {
                std::weak_ptr<Executors::Awaitable> awaitable_weak = awaitable;
                auto start = [this, awaitable_weak]() noexcept {
                        std::shared_ptr<libopenppp2_application> app = ppp::make_shared_object<libopenppp2_application>();
                        app_ = app; {
                            std::shared_ptr<Executors::Awaitable> awaitable = awaitable_weak.lock();
                            if (NULL != awaitable) {
                                awaitable->Processed();
                            }
                        }

                        if (NULL != app) {
                            Executors::Run(NULL,
                                [app](int argc, const char* argv[]) noexcept -> int {
                                    app->DllMain();
                                    return 0;
                                });
                        }
                    };
                std::thread(start).detach();
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

    auto fx = ppp::make_shared_object<Timer::TimeoutEventHandler>(
        []() noexcept {
            std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
            if (NULL != app) {
                app->timeout_.reset();
                libopenppp2_application::Timeout();
            }
        });

    if (NULL == fx) {
        return false;
    }

    std::shared_ptr<Timer> timeout = Timer::Timeout(context, 1000, fx);
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
    context->dispatch(
        [protector_weak, task]() noexcept {
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
    context->post(
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

void                                                                        libopenppp2_application::Release() noexcept {
    if (std::shared_ptr<Timer> timeout = std::move(timeout_); NULL != timeout) {
        timeout->Dispose();
    }

    if (std::shared_ptr<VEthernetNetworkSwitcher> client = std::move(client_); NULL != client) {
        client->Dispose();
    }

    configuration_.reset();
    client_.reset();
    stopwatch_.Reset();
    network_interface_.reset();
    bypass_ip_list_.reset();
    transmission_statistics_.Clear();
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public static bool post_exec(int sequence)
bool                                                                        libopenppp2_application::PostExecJNI(JNIEnv* env, int sequence) noexcept {
    jclass clazz = env->FindClass(LIBOPENPPP2_CLASSNAME);
    if (NULL != env->ExceptionOccurred()) {
        env->ExceptionClear();
    }

    if (NULL == clazz) {
        return false;
    }

    jboolean result = false;
    jmethodID method = env->GetStaticMethodID(clazz, "post_exec", "(I)Z");
    if (NULL != env->ExceptionOccurred()) {
        env->ExceptionClear();
    }
    else if (NULL != method) {
        result = env->CallStaticBooleanMethod(clazz, method, (jint)sequence);
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
// public native string get_default_ciphersuites()
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_default_ciphersuites(JNIEnv* env, jobject* this_) noexcept {
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
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_get_link_state(JNIEnv* env, jobject* this_) noexcept {
    int status = LIBOPENPPP2_LINK_STATE_UNKNOWN;
    int err = libopenppp2_application::Invoke(
        [&status]() noexcept {
            status = libopenppp2_get_link_state();
            return LIBOPENPPP2_ERROR_SUCCESS;
        });

    if (err == LIBOPENPPP2_ERROR_SUCCESS) {
        return status;
    }
    elif(err == LIBOPENPPP2_ERROR_APPLICATIION_UNINITIALIZED || 
        err == LIBOPENPPP2_ERROR_VETHERNET_PPPD_THREAD_NOT_RUNING) {
        return LIBOPENPPP2_LINK_STATE_APPLICATIION_UNINITIALIZED;
    }
    else {
        return LIBOPENPPP2_LINK_STATE_UNKNOWN;
    }
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public native long get_duration_time()
__LIBOPENPPP2__(jlong) Java_supersocksr_ppp_android_c_libopenppp2_get_duration_time(JNIEnv* env, jobject* this_) noexcept {
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
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_app_configuration(JNIEnv* env, jobject* this_) noexcept {
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
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_set_app_configuration(JNIEnv* env, jobject* this_, jstring configurations) noexcept {
    const char* json_string = JNIENV_GetStringUTFChars(env, configurations);
    if (NULL == json_string || *json_string == '\x0') {
        return LIBOPENPPP2_ERROR_ARG_CONFIGURATION_STRING_IS_NULL_OR_EMPTY;
    }
    
    std::shared_ptr<AppConfiguration> config = ppp::make_shared_object<AppConfiguration>();
    if (NULL == config) {
        return LIBOPENPPP2_ERROR_NEW_CONFIGURATION_FAIL;
    }

    Json::Value json = JsonAuxiliary::FromString(json_string);
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
            app->configuration_ = config;
            return LIBOPENPPP2_ERROR_SUCCESS;
        });
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public native int set_network_interface(int tun, bool vnet, bool block_quic, string ip, string mask, string gw)
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_set_network_interface(JNIEnv* env, jobject* this_, 
    jint                                                                                    tun,
    jboolean                                                                                vnet,
    jboolean                                                                                block_quic,
    jstring                                                                                 ip,
    jstring                                                                                 mask) noexcept {

    boost::system::error_code ec;
    if (tun == -1) {
        return LIBOPENPPP2_ERROR_ARG_TUN_IS_INVALID;
    }

    // 10.0.0.2
    const char* ip_string = JNIENV_GetStringUTFChars(env, ip);
    if (NULL == ip_string || *ip_string == '\x0') {
        return LIBOPENPPP2_ERROR_ARG_IP_IS_NULL_OR_EMPTY;
    }

    // 255.255.255.0
    const char* mask_string = JNIENV_GetStringUTFChars(env, mask);
    if (NULL == mask_string || *mask_string == '\x0') {
        return LIBOPENPPP2_ERROR_ARG_MASK_IS_NULL_OR_EMPTY;
    }

    boost::asio::ip::address ip_address = boost::asio::ip::address::from_string(ip_string, ec);
    if (ec || !ip_address.is_v4()) {
        return LIBOPENPPP2_ERROR_ARG_IP_IS_NOT_AF_INET_FORMAT;
    }

    boost::asio::ip::address mask_address = boost::asio::ip::address::from_string(ip_string, ec);
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

    boost::asio::ip::address gw_address = ppp::net::Ipep::FixedIPAddress(ip_address, gw_address);
    ip_address = Ipep::FixedIPAddress(ip_address, gw_address, mask_address);

    std::shared_ptr<libopenppp2_network_interface> network_interface = ppp::make_shared_object<libopenppp2_network_interface>();
    if (NULL == network_interface) {
        return LIBOPENPPP2_ERROR_NEW_NETWORKINTERFACE_FAIL;
    }

    network_interface->BlockQUIC = block_quic;
    network_interface->VNet = vnet;
    network_interface->VTun = tun;
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
// public native int set_bypass_ip_list(string iplist)
__LIBOPENPPP2__(jboolean) Java_supersocksr_ppp_android_c_libopenppp2_set_bypass_ip_list(JNIEnv* env, jobject* this_, jstring iplist) noexcept {
    std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
    if (NULL == app) {
        return false;
    }

    std::shared_ptr<ppp::string> bypass_ip_list; {
        const char* iplist_string = JNIENV_GetStringUTFChars(env, iplist);
        if (NULL != iplist_string && *iplist_string != '\x0') {
            bypass_ip_list = std::make_shared<ppp::string>(iplist_string);   
        }
    }

    int err = libopenppp2_application::Invoke(
        [&app, &bypass_ip_list]() noexcept {
            app->bypass_ip_list_ = bypass_ip_list;
            return LIBOPENPPP2_ERROR_SUCCESS;
        });
    return err == LIBOPENPPP2_ERROR_SUCCESS;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public native string get_bypass_ip_list()
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_bypass_ip_list(JNIEnv* env, jobject* this_) noexcept {
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
//      vnet:       bool,
//      ip:         string,
//      gw:         string,
//      mask:       string
//  }
__LIBOPENPPP2__(jstring) Java_supersocksr_ppp_android_c_libopenppp2_get_network_interface(JNIEnv* env, jobject* this_) noexcept {
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
                json["vnet"] = network_interface->VNet;
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
    client = ppp::make_shared_object<VEthernetNetworkSwitcher>(
        context, 
        lwip, 
        network_interface->VNet, 
        configuration);
    if (NULL == client) {
        return LIBOPENPPP2_ERROR_ALLOCATED_MEMORY;
    }
    
    std::shared_ptr<ppp::string> bypass_ip_list = std::move(app->bypass_ip_list_);
    if (NULL != bypass_ip_list) {
        app->bypass_ip_list_.reset();
        client->SetBypassIpList(std::move(*bypass_ip_list));
    }

    bool ok = client->Constructor(tap);
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
// public native int run()
__LIBOPENPPP2__(jint) Java_supersocksr_ppp_android_c_libopenppp2_run(JNIEnv* env, jobject* this_) noexcept {
    static SynchronizedObject synchronized_object;
    struct SYNCHRONIZED_OBJECT_SCOPE final {
    public:
        SYNCHRONIZED_OBJECT_SCOPE() noexcept
            : owns_lock(false) {
            synchronized_object.lock();
        } 
        ~SYNCHRONIZED_OBJECT_SCOPE() noexcept {
            UNLOCK();
        }
        
    public:
        void UNLOCK() noexcept {
            if (owns_lock) {
                owns_lock = false;
                synchronized_object.unlock();
            }
        }
        
    public:
        bool owns_lock;
    } synchronized_object_scoped;

    std::shared_ptr<VEthernetNetworkSwitcher> ethernet;
    int err = libopenppp2_application::Invoke(
        [&ethernet]() noexcept -> int {
            return libopenppp2_try_open_ethernet_switcher(ethernet);
        });
    
    if (err != LIBOPENPPP2_ERROR_SUCCESS) {
        return err;
    }

    VEthernetNetworkSwitcher::ProtectorNetworkPtr protector = ethernet->GetProtectorNetwork();
    if (NULL == protector) {
        return LIBOPENPPP2_ERROR_UNKNOWN;
    }

    protector->MainJNI(env, &synchronized_object_scoped, 
        [](const std::shared_ptr<boost::asio::io_context>& context, JNIEnv* env, void* state) noexcept {
            SYNCHRONIZED_OBJECT_SCOPE* synchronized_object_scoped = (SYNCHRONIZED_OBJECT_SCOPE*)state;
            synchronized_object_scoped->UNLOCK();
        });

    return LIBOPENPPP2_ERROR_SUCCESS;
}

// package: supersocksr.ppp.android.c
// public final class libopenpppp2 
// public native void stop()
__LIBOPENPPP2__(void) Java_supersocksr_ppp_android_c_libopenppp2_stop(JNIEnv* env, jobject* this_) noexcept {
    libopenppp2_application::Invoke(
        []() noexcept -> int {
            std::shared_ptr<libopenppp2_application> app = libopenppp2_application::GetDefault();
            if (NULL != app) {
                app->Release();
            }

            return LIBOPENPPP2_ERROR_SUCCESS;
        });
}
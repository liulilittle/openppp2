#pragma once

#include <stdio.h>
#include <stddef.h>
#include <string.h>

#if !defined(NULL)
#define NULL 0
#endif

#if defined(_DEBUG)
#if !defined(DEBUG)
#define DEBUG 1
#endif
#endif

#if defined(DEBUG)
#if !defined(_DEBUG)
#define _DEBUG 1
#endif
#endif

#if defined(_WIN64)
#if !defined(WIN64)
#define WIN64 1
#endif
#endif

#if defined(WIN64)
#if !defined(_WIN64)
#define _WIN64 1
#endif
#endif

#if defined(_WIN64)
#if !defined(_WIN32)
#define _WIN32 1
#endif
#endif

#if defined(_WIN32)
#if !defined(WIN32)
#define WIN32 1
#endif
#endif

#if defined(WIN32)
#if !defined(_WIN32)
#define _WIN32 1
#endif
#endif

#if defined(__linux__)
#if !defined(_LINUX)
#define _LINUX 1
#endif

#if !defined(LINUX)
#define LINUX 1
#endif
#elif defined(__APPLE__) && defined(__MACH__)
#if !defined(_MACOS)
#define _MACOS 1
#endif

#if !defined(MACOS)
#define MACOS 1
#endif
#endif

#if defined(__ANDROID__) || __ANDROID_API__ > 0
#if !defined(_ANDROID)
#define _ANDROID 1
#endif
#endif

#if defined(_ANDROID)
#if !defined(ANDROID)
#define ANDROID 1
#endif
#endif

#if defined(ANDROID)
#if !defined(_ANDROID)
#define _ANDROID 1
#endif
#endif

#if defined(_ANDROID)
#if !defined(_LINUX)
#define _LINUX 1
#endif

#if !defined(LINUX)
#define LINUX 1
#endif

#if !defined(__clang__)
#define __clang__ 1
#endif
#endif

#if defined(__harmony__)
#if !defined(_HARMONYOS)
#define _HARMONYOS 1
#endif
#endif

#if defined(_HARMONYOS)
#if !defined(HARMONYOS)
#define HARMONYOS 1
#endif
#endif

#if defined(HARMONYOS)
#if !defined(_HARMONYOS)
#define _HARMONYOS 1
#endif
#endif

#if defined(__MUSL__)
#if !defined(__musl__)
#define __musl__ 1
#endif
#endif

#if defined(__musl__)
#if !defined(__MUSL__)
#define __MUSL__ 1
#endif
#endif

#if ((defined(__IPHONE_OS_VERSION_MIN_REQUIRED)) || (defined(__APPLE__) && defined(__MACH__) && defined(TARGET_OS_IOS) && TARGET_OS_IOS != 0))
#if !defined(_IPHONE)
#define _IPHONE 1
#endif

#if !defined(IPHONE)
#define IPHONE 1
#endif
#endif

#if defined(_WIN32)
#if defined(_MSC_VER) && defined(_M_IX86) && !defined(_M_IA64) && !defined(_M_X64)
#define __ORDER_LITTLE_ENDIAN__     1
#define __ORDER_BIG_ENDIAN__        0
#define __BYTE_ORDER__              __ORDER_LITTLE_ENDIAN__
#elif defined(_MSC_VER) && (defined(_M_IA64) || defined(_M_X64))
#define __ORDER_LITTLE_ENDIAN__     1
#define __ORDER_BIG_ENDIAN__        0
#define __BYTE_ORDER__              __ORDER_LITTLE_ENDIAN__
#else
#define __ORDER_LITTLE_ENDIAN__     0
#define __ORDER_BIG_ENDIAN__        1
#define __BYTE_ORDER__              __ORDER_LITTLE_ENDIAN__
#endif
#endif

#if defined(_WIN32)
#include <io.h>

#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#endif

#ifndef R_OK
#define R_OK 4 /* Test for read permission. */
#endif

#ifndef W_OK
#define W_OK 2 /* Test for write permission. */
#endif

#ifndef X_OK
#define X_OK 1 /* Test for execute permission. */
#endif

#ifndef F_OK
#define F_OK 0 /* Test for existence. */
#endif

#ifndef elif
#define elif else if
#endif

#ifndef nameof
#define nameof(variable) #variable
#endif

#ifndef arraysizeof
#define arraysizeof(array_) (sizeof(array_) / sizeof(*array_))
#endif

#if !defined(_WIN32)
#define sscanf_s sscanf
#endif

#ifdef __AES_NI__
#ifndef __SIMD__
#define __SIMD__ 1
#endif
#endif

#ifdef __SIMD__
#ifndef __AES_NI__
#define __AES_NI__ 1
#endif
#endif

// stddef.h
// offsetof
#ifndef offset_of
#define offset_of(s,m) ((::size_t)&reinterpret_cast<char const volatile&>((((s*)0)->m)))
#endif
 
#ifndef container_of
#define container_of(ptr, type, member) ((type*)((char*)static_cast<const decltype(((type*)0)->member)*>(ptr) - offset_of(type,member))) 
#endif

#ifndef PPP_APPLICATION_VERSION
#define PPP_APPLICATION_VERSION ("1.0.0.25414") /* 1.0.0.20251009 */
#endif

#ifndef PPP_APPLICATION_NAME
#define PPP_APPLICATION_NAME ("PPP")
#endif

#include <stdint.h>
#include <signal.h>
#include <limits.h>
#include <time.h>

#if defined(_MACOS)
#include <stdlib.h>
#else
#include <malloc.h>
#endif

#include <type_traits>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <atomic>
#include <thread>
#include <utility>
#include <functional>
#include <memory>
#include <string>
#include <list>
#include <map>
#include <set>
#include <regex>
#include <vector>
#include <fstream>
#include <unordered_set>
#include <unordered_map>

#ifndef BOOST_BEAST_VERSION_HPP
#define BOOST_BEAST_VERSION_HPP

#include <boost/beast/core/detail/config.hpp>
#include <boost/config.hpp>

/*  BOOST_BEAST_VERSION

    Identifies the API version of Beast.

    This is a simple integer that is incremented by one every
    time a set of code changes is merged to the develop branch.
*/
#define BOOST_BEAST_VERSION 322
#define BOOST_BEAST_VERSION_STRING "ppp"
#endif

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/fields.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/string_body.hpp>

#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>

#include <boost/lockfree/queue.hpp>
#include <boost/lockfree/stack.hpp>

#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#if defined(__GNUC__) /* __FUNCTION__ */
#define __FUNC__ __PRETTY_FUNCTION__
#elif defined(_MSC_VER)
#define __FUNC__ __FUNCSIG__
#else
#define __FUNC__ __func__
#endif

static constexpr int                                                        PPP_AGGLIGATOR_CONGESTIONS      = 1024;
static constexpr int                                                        PPP_BUFFER_SIZE                 = 65536;
static constexpr int                                                        PPP_BUFFER_SIZE_SKATEBOARDING   = 60000;
static constexpr int                                                        PPP_LISTEN_BACKLOG              = 511;
static constexpr int                                                        PPP_TCP_CONNECT_TIMEOUT         = 5;
static constexpr int                                                        PPP_TCP_CONNECT_NEXCEPT         = 4;
static constexpr int                                                        PPP_TCP_INACTIVE_TIMEOUT        = 300;
static constexpr int                                                        PPP_MUX_CONNECT_TIMEOUT         = 20;
static constexpr int                                                        PPP_MUX_INACTIVE_TIMEOUT        = 60;
static constexpr int                                                        PPP_MUX_MIN_CONGESTIONS         = 1 << 20;
static constexpr int                                                        PPP_MUX_DEFAULT_CONGESTIONS     = 128 << 20; /* 134217728 */
static constexpr int                                                        PPP_UDP_INACTIVE_TIMEOUT        = 72; 
static constexpr int                                                        PPP_UDP_KEEP_ALIVED_MIN_TIMEOUT = 20;
static constexpr int                                                        PPP_UDP_KEEP_ALIVED_MAX_TIMEOUT = 60;
static constexpr int                                                        PPP_DNS_SYS_PORT                = 53;
static constexpr int                                                        PPP_HTTP_SYS_PORT               = 80;
static constexpr int                                                        PPP_HTTPS_SYS_PORT              = 443;
static constexpr int                                                        PPP_UDP_TIMER_INTERVAL          = 10;
static constexpr int                                                        PPP_MEMORY_ALIGNMENT_SIZE       = 16;
static constexpr int                                                        PPP_MUX_ACCELERATION_REMOTE     = 1;
static constexpr int                                                        PPP_MUX_ACCELERATION_LOCAL      = 2;
static constexpr int                                                        PPP_MUX_ACCELERATION_MAX        = 3;
static constexpr int                                                        PPP_DEFAULT_DNS_TIMEOUT         = 4;
static constexpr int                                                        PPP_RESOLVE_DNS_TIMEOUT         = PPP_DEFAULT_DNS_TIMEOUT * 1000;
static constexpr int                                                        PPP_DEFAULT_DNS_TTL             = 60;
static constexpr int                                                        PPP_MAX_DNS_PACKET_BUFFER_SIZE  = 512; 
static constexpr int                                                        PPP_COROUTINE_STACK_SIZE        = 65536; /* boost::context::stack_traits::default_size() */
#define                                                                     PPP_PREFERRED_DNS_SERVER_1      "8.8.8.8"
#define                                                                     PPP_PREFERRED_DNS_SERVER_2      "8.8.4.4"
static constexpr const char*                                                PPP_DEFAULT_KEY_PROTOCOL        = "aes-128-cfb";
static constexpr const char*                                                PPP_DEFAULT_KEY_TRANSPORT       = "aes-256-cfb";
static constexpr int                                                        PPP_DEFAULT_HTTP_PROXY_PORT     = 8080;
static constexpr int                                                        PPP_DEFAULT_SOCKS_PROXY_PORT    = 1080;
static constexpr const char*                                                PPP_PUBLIC_DNS_SERVER_LIST[]    = {
    "1.0.0.1",
    "1.1.1.1",

    "1.2.4.8",
    "210.2.4.8",

    "1.12.12.12",
    "120.53.53.53"

    PPP_PREFERRED_DNS_SERVER_1,
    PPP_PREFERRED_DNS_SERVER_2,

    "9.9.9.9",

    "114.114.114.114",
    "114.114.115.115",

    "223.5.5.5",
    "223.6.6.6",

    "101.226.4.6",
    "218.30.118.6",

    "123.125.81.6",
    "140.207.198.6",

    "185.222.222.222",
    "185.184.222.222",

    "208.67.222.222",
    "208.67.220.220",

    "199.91.73.222",
    "178.79.131.110",

    "183.60.83.19",
    "183.60.82.98",

    "180.76.76.76",

    "4.2.2.1",
    "4.2.2.2",

    "80.80.80.80",
    "80.80.81.81",

    "122.112.208.1",
    "139.9.23.90",

    "114.115.192.11",
    "116.205.5.1",

    "116.205.5.30",
    "122.112.208.175",

    "139.159.208.206",

    "180.184.1.1",
    "180.184.2.2",

    "168.95.192.1",
    "168.95.1.1",

    "203.PPP_HTTP_SYS_PORT.96.10",
    "203.PPP_HTTP_SYS_PORT.96.9",

    "199.85.126.10",
    "199.85.127.10",

    "216.146.35.35",
    "216.146.36.36",

    "64.6.64.6",
    "64.6.65.6",

    "211.162.78.1",
    "211.162.78.2",

    "116.199.0.200",
    "116.116.116.116",

    "61.235.70.252",
    "211.98.4.1",

    "211.148.192.141"
};

namespace ppp {
    typedef unsigned char                                                   Byte;
    typedef signed char                                                     SByte;
    typedef signed short int                                                Int16;
    typedef signed int                                                      Int32;
    typedef signed long long                                                Int64;
    typedef unsigned short int                                              UInt16;
    typedef unsigned int                                                    UInt32;
    typedef unsigned long long                                              UInt64;
    typedef double                                                          Double;
    typedef float                                                           Single;
    typedef bool                                                            Boolean;
    typedef signed char                                                     Char;
}

namespace std {
    inline int                                                              _snprintf(char* const _Buffer, size_t const _BufferCount, char const* const _Format, ...) noexcept {
        va_list ap;
        va_start(ap, _Format);
        int r = vsnprintf(_Buffer, _BufferCount, _Format, ap);
        va_end(ap);
        return r;
    }
}

namespace stl {
    template <class T, T V>
    struct integral_constant {
        static constexpr T value = V;

        using value_type = T;
        using type = integral_constant;

        constexpr operator value_type() const noexcept {
            return value;
        }

        constexpr value_type operator()() const noexcept {
            return value;
        }
    };

    template <bool V>
    using bool_constant = integral_constant<bool, V>;

    using true_type = bool_constant<true>;
    using false_type = bool_constant<false>;

    template <typename _Ty>
    struct is_signed : false_type {};

    template <>
    struct is_signed<char> : true_type {};

    template <>
    struct is_signed<int> : true_type {};

    template <>
    struct is_signed<short> : true_type {};

    template <>
    struct is_signed<long> : true_type {};

    template <>
    struct is_signed<long long> : true_type {};

    template <>
    struct is_signed<float> : true_type {};

    template <>
    struct is_signed<double> : true_type {};

    template <>
    struct is_signed<long double> : true_type {};

    template <>
    struct is_signed<signed char> : true_type {};

    template <class T, class U>
    struct is_same : false_type {};

    template <class T>
    struct is_same<T, T> : true_type {};

    template <typename T>
    struct is_shared_ptr : false_type {};

    template <typename T>
    struct is_shared_ptr<std::shared_ptr<T>> : true_type {};

    template <typename T>
    struct is_unique_ptr : false_type {};

    template <typename T>
    struct is_unique_ptr<std::unique_ptr<T>> : true_type {};

    template <class T>
    struct remove_pointer {
        typedef T type;
    };

    template <class T>
    struct remove_pointer<T*> {
        typedef T type;
    };

    template <class T>
    struct remove_pointer<T* const> {
        typedef T type;
    };

    template <class T>
    struct remove_pointer<T* volatile> {
        typedef T type;
    };

    template <class T>
    struct remove_pointer<T* const volatile> {
        typedef T type;
    };

    template <class T>
    struct remove_pointer<std::shared_ptr<T> > {
        typedef T type;
    };

    template <class T>
    struct remove_pointer<std::shared_ptr<T>&> {
        typedef T type;
    };

    template <class T>
    struct remove_pointer<std::shared_ptr<T> const&> {
        typedef T type;
    };

    template <class T>
    struct remove_reference {
        typedef T type;
    };

    template <class T>
    struct remove_reference<T&> {
        typedef T type;
    };

    template <class T>
    struct remove_reference<T&&> {
        typedef T type;
    };

    template <typename T>
    struct is_template : std::false_type {};

    template <template <typename...> class C, typename... Ts>
    struct is_template<C<Ts...>> : std::true_type {};

    template <typename T>
    struct template_type : std::false_type {
        using value_type = T;
    };

    template <template <typename> class C, typename T>
    struct template_type<C<T>> : std::true_type {
        using value_type = T;
    };

    template <typename F, typename... Args>
    class is_invocable {
        template <typename U>
        static auto test(int) -> decltype(std::declval<U>()(std::declval<Args>()...), std::true_type());

        template <typename U>
        static std::false_type test(...);

    public:
        static constexpr bool value = std::is_same<decltype(test<F>(0)), std::true_type>::value;
    };

    template <typename TOUT, typename TIN>
    TOUT                                                                    transform(const TIN& s) noexcept {
        return TOUT(s.data(), s.size());
    }

    template <typename TString>
    TString                                                                 to_string(float num) noexcept {
        char buf[536];
        return snprintf(buf, sizeof(buf), "%f", num) > 0 ? buf : "";
    }

    template <typename TString>
    TString                                                                 to_string(double num) noexcept {
        char buf[536];
        return snprintf(buf, sizeof(buf), "%lf", num) > 0 ? buf : "";
    }

    template <typename TString>
    TString                                                                 to_string(long double num) noexcept {
        char buf[536];
        return snprintf(buf, sizeof(buf), "%Lf", num) > 0 ? buf : "";
    }

    template <typename TString>
    constexpr TString                                                       to_string(bool v) noexcept {
        return v ? "true" : "false";
    }

    template <typename TString, typename TNumber>
    TString                                                                 to_string(TNumber num, int radix = 10) noexcept {
        static constexpr char hex[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        char buf[536];
        if (radix < 2) {
            radix = 10;
        }
        elif(radix > 36) {
            radix = 36;
        }

        if (num == 0) {
            buf[0] = '0';
            buf[1] = '\x0';
            return buf;
        }
        
        bool n = false;
        if constexpr (stl::is_signed<TNumber>::value) {
            n = num < 0;
        }

        char* p = buf + sizeof(buf);
        char* m = p;

        p--;
        *p = '\x0';

        TNumber t;
        if constexpr (stl::is_signed<TNumber>::value) {
            t = n ? -num : num;
        }
        else {
            t = num;
        }

        while (t > 0) {
            p--;
            *p = hex[(int)(t % radix)];
            t = t / radix;
        }

        if (n) {
            p--;
            *p = '-';
        }

        return TString(p, m - p - 1);
    }

    template <typename TNumber, typename TString>
    TNumber                                                                 to_number(const TString& v, int radix) noexcept 
    {
        int length = v.size();
        if (length < 1)
        {
            return 0;
        }

        if (radix < 2)
        {
            radix = 10;
        }
        elif(radix > 36)
        {
            radix = 36;
        }

        TNumber num = 0;
        bool is_negative = false;
        int i = 0;

        if (v[i] == '-')
        {
            is_negative = true;
            i++;
        }
        elif(v[i] == '+')
        {
            i++;
        }

        while (i < length)
        {
            char ch = v[i];
            int val = -1;
            if (ch >= '0' && ch <= '9')
            {
                val = ch - '0';
            }
            elif(ch >= 'A' && ch <= 'Z')
            {
                val = ch - 'A' + 10;
            }
            elif(ch >= 'a' && ch <= 'z')
            {
                val = ch - 'a' + 10;
            }

            if (val >= 0 && val < radix)
            {
                num = num * radix + val;
                i++;
            }
            else
            {
                break;
            }
        }

        if (is_negative)
        {
            num = -num;
        }

        return num;
    }
}

#if defined(_WIN32)
namespace boost { // boost::asio::posix::stream_descriptor
    namespace asio {
        namespace posix {
            typedef boost::asio::windows::stream_handle stream_descriptor;
        }
    }
}
#include <WinSock2.h>
#else
namespace boost {
    namespace asio {
        typedef io_service io_context;
    }
}
#endif

#if defined(JEMALLOC)
#if defined(_WIN32)
#if defined(__cplusplus)
extern "C" {
#endif
    void*                                                                   je_malloc(size_t size);
    void                                                                    je_free(void* size);
    int                                                                     je_mallctl(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
#if defined(__cplusplus)
}
#endif

// Under the Windows platform, the default project compiled by microsoft vcpkg jemalloc for windowos does not have the C/C++ compiler macro version information, 
// And the compiler user needs to manually define it in this header file so that it can be included in the help information. 
// Displays the library version information that is directly dependent.
// 
// Jemalloc compiled by vcpkg on windows, version macro information summary: Windows 0.0.0-0-g000000missing_version_try_git_fetch_tags
#if !defined(JEMALLOC_VERSION_MAJOR) && !defined(JEMALLOC_VERSION_MINOR) && !defined(JEMALLOC_VERSION_BUGFIX) && !defined(JEMALLOC_VERSION_NREV)
#define JEMALLOC_VERSION_MAJOR  5
#define JEMALLOC_VERSION_MINOR  3
#define JEMALLOC_VERSION_BUGFIX 0
#define JEMALLOC_VERSION_NREV   0
#endif
#else
#define JEMALLOC_NO_DEMANGLE
#include <jemalloc/jemalloc.h>
#endif
#endif

#if defined(CURLINC_CURL)
#include <curl/curl.h>
#include <curl/easy.h>
#endif

#if defined(_ANDROID)
#include <android/log.h>

// 定义日志输出函数
#define LOG_TAG (BOOST_BEAST_VERSION_STRING)
#define LOG_INFO(...)               __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOG_ERROR(...)              __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOG_WARN(...)               __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOG_DEBUG(...)              __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LIBOPENPPP2_CLASSNAME       "supersocksr/ppp/android/c/libopenppp2"

#if defined(_WIN32)
#pragma optimize("", off)
#pragma optimize("gsyb2", on) /* /O1 = /Og /Os /Oy /Ob2 /GF /Gy */
#else
// TRANSMISSIONO1 compiler macros are defined to perform O1 optimizations, 
// Otherwise gcc compiler version If <= 7.5.X, 
// The O1 optimization will also be applied, 
// And the other cases will not be optimized, 
// Because this will cause the program to crash, 
// Which is a fatal BUG caused by the gcc compiler optimization. 
// Higher-version compilers should not optimize the code for gcc compiling this section.
#if defined(__clang__)
#pragma clang optimize off
#else
#pragma GCC push_options
#if defined(TRANSMISSION_O1) || (__GNUC__ < 7) || (__GNUC__ == 7 && __GNUC_MINOR__ <= 5) /* __GNUC_PATCHLEVEL__ */
#pragma GCC optimize("O1")
#else
#pragma GCC optimize("O0")
#endif
#endif
#endif
#else
#if defined(_WIN32)
#define LOG_TAG(TAG, FORMAT, ...)   ::fprintf(stdout, "[%s][" ## TAG ## "](%s:%d): " ## FORMAT ## "\r\n", ((char*)::ppp::GetCurrentTimeText<ppp::string>().data()), __FILE__, __LINE__, __VA_ARGS__)
#else   
#define LOG_TAG(TAG, FORMAT, ...)   ::fprintf(stdout, "[%s][" TAG "](%s:%d): " FORMAT "\r\n", ((char*)::ppp::GetCurrentTimeText<ppp::string>().data()), __FILE__, __LINE__, __VA_ARGS__)
#endif

#define LOG_INFO(FORMAT, ...)       LOG_TAG("INFO", FORMAT, __VA_ARGS__)
#define LOG_ERROR(FORMAT, ...)      LOG_TAG("ERROR", FORMAT, __VA_ARGS__)
#define LOG_WARN(FORMAT, ...)       LOG_TAG("WARN", FORMAT, __VA_ARGS__)
#define LOG_DEBUG(FORMAT, ...)      LOG_TAG("DEBUG", FORMAT, __VA_ARGS__)
#endif

#ifndef strcasecmp
#define strcasecmp strcasecmp_
#endif

#ifndef strncasecmp
#define strncasecmp strncasecmp_
#endif

#ifndef BOOST_ASIO_MOVE_CAST
#define BOOST_ASIO_MOVE_CAST(type) static_cast<type&&>
#endif

#ifndef BOOST_ASIO_MOVE_ARG
#define BOOST_ASIO_MOVE_ARG(type) type&&
#endif

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((void*)(-1))
#endif

inline int                                                                  strncasecmp_(const void* x, const void* y, size_t length) noexcept {
    if (x == y || length == 0) {
        return 0;
    }

    char* px = (char*)x;
    char* py = (char*)y;

    for (size_t i = 0; i < length; i++) {
        int xch = toupper(*px++);
        int ych = toupper(*py++);

        if (xch != ych) {
            return xch > ych ? 1 : -1;
        }
    }
    return 0;
}

inline int                                                                  strcasecmp_(const void* x, const void* y) noexcept {
    if (x == y) {
        return 0;
    }

    char* px = (char*)x;
    char* py = (char*)y;

    size_t xlen = strlen(px);
    size_t ylen = strlen(py);

    if (xlen != ylen) {
        return xlen > ylen ? 1 : -1;
    }

    return strncasecmp(x, y, xlen);
}

namespace ppp {
    template <typename T>
    constexpr T                                                             Malign(const T size, int alignment) noexcept {
        return (T)(((uint64_t)size + alignment - 1) & ~(static_cast<unsigned long long>(alignment) - 1));
    }

    inline void*                                                            Malloc(size_t size) noexcept {
        if (!size) {
            return NULL;
        }

        size = Malign(size, PPP_MEMORY_ALIGNMENT_SIZE);
#if defined(JEMALLOC)
        return (void*)::je_malloc(size);
#else
        return (void*)::malloc(size);
#endif
    }

    inline void                                                             Mfree(const void* p) noexcept {
        if (p) {
#if defined(JEMALLOC)
            ::je_free((void*)p);
#else
            ::free((void*)p);
#endif
        }
    }

    template <typename T>
    constexpr T*                                                            addressof(const T& v) noexcept {
        return (T*)&reinterpret_cast<const char&>(v);
    }

    template <typename T>
    constexpr T*                                                            addressof(const T* v) noexcept {
        return const_cast<T*>(v);
    }

    template <typename T>
    constexpr T&                                                            constantof(const T& v) noexcept {
        return const_cast<T&>(v);
    }

    template <typename T>                                                           
    constexpr T*                                                            constantof(const T* v) noexcept {
        return const_cast<T*>(v);
    }

    template <typename T>
    constexpr T&&                                                           constant0f(const T&& v) noexcept {
        return const_cast<T&&>(v);
    }

    template <typename T>
    constexpr T&&                                                           forward0f(const T& v) noexcept {
        return std::forward<T>(constantof(v));
    }

    template <typename T>
    constexpr T&                                                            nullof() noexcept { return *(T*)NULL;}

    template <typename T>
    void                                                                    destructor_invoked(T* const v) noexcept {
        if (NULL != v) {
            v->~T();
        }
    }

    inline uint64_t                                                         MAKE_QWORD(uint32_t low, uint32_t high) noexcept {
        return ((uint64_t)high << 32) | ((uint64_t)low);
    }

    inline uint32_t                                                         MAKE_DWORD(uint16_t low, uint16_t high) noexcept {
        return ((uint32_t)high << 16) | ((uint32_t)low);
    }

    inline uint16_t                                                         MAKE_WORD(uint8_t low, uint8_t high) noexcept {
        return ((uint16_t)high << 16) | ((uint16_t)low);
    }

    template <typename TValue>
    TValue                                                                  abs(TValue n) noexcept {
        TValue bits = (sizeof(TValue) << 3) - 1;
        return (n ^ (n >> bits)) - (n >> bits);
    }

    template <typename T>
    constexpr T                                                             exchangeof(T& location, const T& value) noexcept {
        volatile T* p = (volatile T*)&reinterpret_cast<const char&>(location);
        T r = *p;
        *p = value;
        return r;
    }

    template <class _Ty>
    class allocator {
    public:
        static_assert(!std::is_const<_Ty>::value, "The C++ Standard forbids containers of const elements "
            "because allocator<const T> is ill-formed.");

        using _From_primary = allocator;

        using value_type = _Ty;

        using pointer = _Ty*;
        using const_pointer = const _Ty*;

        using reference = _Ty&;
        using const_reference = const _Ty&;

        using size_type = size_t;
        using difference_type = ptrdiff_t;

        using propagate_on_container_move_assignment = std::true_type;
        using is_always_equal = std::true_type;

        template <class _Other>
        struct rebind {
            using other = allocator<_Other>;
        };

        _Ty* address(_Ty& _Val) const noexcept {
            return std::addressof(_Val);
        }

        const _Ty* address(const _Ty& _Val) const noexcept {
            return std::addressof(_Val);
        }

        constexpr allocator() noexcept {}
        constexpr allocator(const allocator&) noexcept = default;

        template <class _Other>
        constexpr allocator(const allocator<_Other>&) noexcept {}

        ~allocator() = default;
        allocator& operator=(const allocator&) = default;

        void deallocate(_Ty* const _Ptr, const size_t _Count) {
            assert((_Ptr != NULL || _Count == 0) && "null pointer cannot point to a block of non-zero size");
            // no overflow check on the following multiply; we assume _Allocate did that check
            ppp::Mfree(_Ptr);
        }

        _Ty* allocate(const size_t _Count) {
            static_assert(sizeof(value_type) > 0, "value_type must be complete before calling allocate.");

            void* memory = (void*)ppp::Malloc(sizeof(_Ty) * _Count);
            return static_cast<_Ty*>(memory);
        }

        _Ty* allocate(const size_t _Count, const void*) {
            return allocate(_Count);
        }

        // C++ 11...cxx0x
        // C++ 14...cxx1y
        template <typename _Iter>
        typename std::enable_if<std::is_pointer<_Iter>::value, void*>::type
        constexpr _Voidify_iter(_Iter _It) noexcept {
            return const_cast<void*>(static_cast<const volatile void*>(_It));
        }

        template <typename _Iter>
        typename std::enable_if<!std::is_pointer<_Iter>::value, void*>::type
        constexpr _Voidify_iter(_Iter _It) noexcept {
            return const_cast<void*>(static_cast<const volatile void*>(std::addressof(*_It)));
        }

        template <class _Objty, class... _Types>
        void construct(_Objty* const _Ptr, _Types&&... _Args) {
            using _Ptrty = typename std::remove_reference<decltype(_Voidify_iter(_Ptr))>::type;

            _Ptrty _X = _Voidify_iter(_Ptr);
            if (_X) {
                new (_X) _Objty(std::forward<_Types>(_Args)...);
            }
        }

        template <class _Uty>
        void destroy(_Uty* const _Ptr) {
            if (NULL != _Ptr) {
                _Ptr->~_Uty();
            }
        }

        size_t max_size() const noexcept {
            return static_cast<size_t>(-1) / sizeof(_Ty);
        }

        template <typename _Uty>
        bool operator==(const _Uty& v) const noexcept {
            return std::is_same<_Uty, allocator>::value;
        }

        template <typename _Uty>
        bool operator!=(const _Uty& v) const noexcept {
            return !std::is_same<_Uty, allocator>::value;
        }

        // The number of user bytes a single byte of ASAN shadow memory can track.
        static constexpr size_t _Asan_granularity = 8;
        static constexpr size_t _Minimum_allocation_alignment = _Asan_granularity;
    };

    using string            = std::basic_string<char, std::char_traits<char>, allocator<char>>;
    using stringbuf         = std::basic_stringbuf<char, std::char_traits<char>, allocator<char>>;
    using istringstream     = std::basic_istringstream<char, std::char_traits<char>, allocator<char>>;
    using ostringstream     = std::basic_ostringstream<char, std::char_traits<char>, allocator<char>>;
    using stringstream      = std::basic_stringstream<char, std::char_traits<char>, allocator<char>>;

    template <typename TValue>
    using list = std::list<TValue, allocator<TValue>>;

    template <typename TValue>
    using vector = std::vector<TValue, allocator<TValue>>;

    template <typename TValue>
    using set = std::set<TValue, std::less<TValue>, allocator<TValue>>;

    template <typename TKey, typename TValue>
    using map = std::map<TKey, TValue, std::less<TKey>, allocator<std::pair<const TKey, TValue>>>;

    template <typename TValue>
    using unordered_set = std::unordered_set<TValue, std::hash<TValue>, std::equal_to<TValue>, allocator<TValue>>;

    template <typename TKey, typename TValue>
    using unordered_map = std::unordered_map<TKey, TValue, std::hash<TKey>, std::equal_to<TKey>, allocator<std::pair<const TKey, TValue>>>;
}

namespace ppp {
    inline bool                                                             isspace(char ch) noexcept { return ::isspace(ch) || ch == '\x0'; }

    template <typename _Ty>
    int                                                                     Tokenize(const _Ty& str, ppp::vector<_Ty>& tokens, const _Ty& delimiters) noexcept {
        if (str.empty()) {
            return 0;
        }
        elif(delimiters.empty()) {
            tokens.emplace_back(str);
            return 1;
        }

        char* deli_ptr = (char*)delimiters.data();
        char* deli_endptr = deli_ptr + delimiters.size();
        char* data_ptr = (char*)str.data();
        char* data_endptr = data_ptr + str.size();
        char* last_ptr = NULL;

        int length = 0;
        int seg = 0;
        while (data_ptr < data_endptr) {
            int ch = *data_ptr;
            int b = 0;
            for (char* p = deli_ptr; p < deli_endptr; p++) {
                if (*p == ch) {
                    b = 1;
                    break;
                }
            }

            if (b) {
                if (seg) {
                    int sz = data_ptr - last_ptr;
                    if (sz > 0) {
                        length++;
                        tokens.emplace_back(_Ty(last_ptr, sz));
                    }
                    seg = 0;
                }
            }
            elif(!seg) {
                seg = 1;
                last_ptr = data_ptr;
            }

            data_ptr++;
        }

        if ((seg && last_ptr) && last_ptr < data_ptr) {
            length++;
            tokens.emplace_back(_Ty(last_ptr, data_ptr - last_ptr));
        }
        return length;
    }

    template <typename _Ty> /* 65279u */
    _Ty                                                                     ZTrim(const _Ty& s) noexcept {
        std::size_t length = s.size();
        if (length == 0) {
            return _Ty();
        }

        char* r = (char*)Malloc(length);
        char* p = (char*)s.data();

        std::size_t l = 0;
        for (std::size_t i = 0; i < length;) {
            std::size_t c0 = (unsigned char)p[i];
            std::size_t c1 = c0;
            std::size_t c2 = c0;

            std::size_t n = i + 1;
            if (n < length) {
                c1 = c0 | (unsigned char)p[n] << 8; // LE
                c2 = c0 << 8 | (unsigned char)p[n]; // BE
            }

            if (c1 == 65279u || c2 == 65279u) {
                i += 2;
            }
            else {
                i++;
                r[l++] = (signed char)c0;
            }
        }

        _Ty result(r, l);
        Mfree(r);
        return result;
    }

    template <typename _Ty> 
    _Ty                                                                     ATrim(const _Ty& s) noexcept {
        if (s.empty()) {
            return s;
        }

        _Ty r;
        for (size_t i = 0, l = s.size(); i < l; ++i) {
            unsigned char ch = (unsigned char)s[i];
            if (isspace(ch)) {
                continue;
            }
            else {
                r.append(1, ch);
            }
        }
        return r;
    }

    template <typename _Ty> 
    _Ty                                                                     LTrim(const _Ty& s) noexcept {
        _Ty str = s;
        if (str.empty()) {
            return str;
        }

        int64_t pos = -1;
        for (size_t i = 0, l = str.size(); i < l; ++i) {
            unsigned char ch = (unsigned char)str[i];
            if (isspace(ch)) {
                pos = (static_cast<int64_t>(i) + 1);
            }
            else {
                break;
            }
        }

        if (pos >= 0) {
            if (pos >= (int64_t)str.size()) {
                return "";
            }

            str = str.substr(pos);
        }

        return str;
    }

    template <typename _Ty>
    _Ty                                                                     RTrim(const _Ty& s) noexcept {
        _Ty str = s;
        if (str.empty()) {
            return str;
        }

        int64_t pos = -1;
        int64_t i = str.size();
        i--;
        for (; i >= 0u; --i) {
            unsigned char ch = (unsigned char)str[i];
            if (isspace(ch)) {
                pos = i;
            }
            else {
                break;
            }
        }

        if (pos >= 0) {
            if (0 >= pos) {
                return "";
            }

            str = str.substr(0, pos);
        }

        return str;
    }

    template <typename _Ty>
    _Ty                                                                     ToUpper(const _Ty& s) noexcept {
        _Ty r = s;
        if (!r.empty()) {
            std::transform(s.begin(), s.end(), r.begin(), toupper);
        }
        return r;
    }

    template <typename _Ty>
    _Ty                                                                     ToLower(const _Ty& s) noexcept {
        _Ty r = s;
        if (!r.empty()) {
            std::transform(s.begin(), s.end(), r.begin(), tolower);
        }

        return r;
    }

    template <typename _Ty>
    _Ty                                                                     Replace(const _Ty& s, const _Ty& old_value, const _Ty& new_value) noexcept {
        _Ty r = s;
        if (r.empty() || old_value.empty()) {
            return r;
        }

        for (;;) {
            typename _Ty::size_type pos = r.find(old_value);
            if (pos != _Ty::npos) {
                r.replace(pos, old_value.length(), new_value);
            }
            else {
                break;
            }
        }

        return r;
    }

    template <typename _Ty>
    int                                                                     Split(const _Ty& str, ppp::vector<_Ty>& tokens, const _Ty& delimiters) noexcept {
        if (str.empty()) {
            return 0;
        }
        elif(delimiters.empty()) {
            tokens.emplace_back(str);
            return 1;
        }

        size_t last_pos = 0;
        size_t curr_cnt = 0;
        for (;;) {
            size_t pos = str.find(delimiters, last_pos);
            if (pos == _Ty::npos) {
                pos = str.size();
            }

            size_t len = pos - last_pos;
            if (len != 0) {
                curr_cnt++;
                tokens.emplace_back(str.substr(last_pos, len));
            }

            if (pos == str.size()) {
                break;
            }

            last_pos = pos + delimiters.size();
        }
        return curr_cnt;
    }

    template <typename _Ty>
    _Ty                                                                     PaddingLeft(const _Ty& s, int count, char padding_char) noexcept {
        int string_length = (int)s.size();
        if (count < 1 || count <= string_length) {
            return s;
        }

        _Ty c = _Ty(1ul, padding_char);
        _Ty r = s;
        for (int i = 0, loop = count - string_length; i < loop; i++) {
            r = c + r;
        }
        return r;
    }

    template <typename _Ty>
    _Ty                                                                     PaddingRight(const _Ty& s, int count, char padding_char) noexcept {
        int string_length = (int)s.size();
        if (count < 1 || count <= string_length) {
            return s;
        }

        _Ty c = _Ty(1ul, padding_char);
        _Ty r = s;
        for (int i = 0, loop = count - string_length; i < loop; i++) {
            r = r + c;
        }
        return r;
    }

    template <typename _Ty>
    _Ty                                                                     GetCurrentTimeText() noexcept {
        time_t rawtime;
        struct tm* ptminfo;

        time(&rawtime);
        ptminfo = localtime(&rawtime);

        auto fmt = [](int source, char* dest) noexcept {
            if (source < 10) {
                char temp[3];
                strcpy(dest, "0");
                sprintf(temp, "%d", source);
                strcat(dest, temp);
            }
            else {
                sprintf(dest, "%d", source);
            }
        };

        char yyyy[5], MM[3], dd[3], hh[3], mm[3], ss[3];
        sprintf(yyyy, "%d", (ptminfo->tm_year + 1900));

        fmt(ptminfo->tm_mon + 1, MM);
        fmt(ptminfo->tm_mday, dd);
        fmt(ptminfo->tm_hour, hh);
        fmt(ptminfo->tm_min, mm);
        fmt(ptminfo->tm_sec, ss);

        _Ty sb;
        sb.append(yyyy).
            append("-").
            append(MM).
            append("-").
            append(dd).
            append(" ").
            append(hh).
            append(":").
            append(mm).
            append(":").
            append(ss);
        return sb;
    }

    boost::asio::ip::address                                                StringToAddress(const char* s, boost::system::error_code& ec) noexcept;

    inline boost::asio::ip::address                                         StringToAddress(const std::string& s, boost::system::error_code& ec) noexcept { 
        return StringToAddress(s.data(), ec); 
    }

    inline boost::asio::ip::address                                         StringToAddress(const ppp::string& s, boost::system::error_code& ec) noexcept { 
        return StringToAddress(s.data(), ec); 
    }

    uint64_t                                                                GetTickCount() noexcept;

    int64_t                                                                 GetCurrentThreadId() noexcept;

    int                                                                     GetCurrentProcessId() noexcept;

    int                                                                     GetProcesserCount() noexcept;

    bool                                                                    ToBoolean(const char* s) noexcept;

    ppp::string                                                             StrFormatByteSize(Int64 size) noexcept;

    Char                                                                    RandomPrintableAsciiBytes() noexcept;

    Char                                                                    RandomAscii() noexcept;

    int                                                                     RandomNext() noexcept;

    int                                                                     RandomNext(int minValue, int maxValue) noexcept;

    double                                                                  RandomNextDouble() noexcept;

    inline int                                                              BufferSkateboarding(int sb, int buffer_size, int max_buffer_size) noexcept {
        max_buffer_size = std::max<int>(max_buffer_size, PPP_BUFFER_SIZE_SKATEBOARDING);

        if (buffer_size > max_buffer_size) {
            buffer_size = max_buffer_size;
        }

        if (sb < 1 || buffer_size <= PPP_BUFFER_SIZE_SKATEBOARDING) {
            return buffer_size;
        }

        int sn = buffer_size - sb;
        if (sn < PPP_BUFFER_SIZE_SKATEBOARDING) {
            sn = PPP_BUFFER_SIZE_SKATEBOARDING;
        }

        return RandomNext(sn, buffer_size);
    }

    int                                                                     GetHashCode(const char* s, int len) noexcept;

    void                                                                    SetThreadPriorityToMaxLevel() noexcept;

    void                                                                    SetProcessPriorityToMaxLevel() noexcept;
  
    bool                                                                    IsInputHelpCommand(int argc, const char* argv[]) noexcept;

    bool                                                                    HasCommandArgument(const char* name, int argc, const char** argv) noexcept;

    ppp::string                                                             GetCommandArgument(int argc, const char** argv) noexcept;

    bool                                                                    GetCommandArgument(const char* name, int argc, const char** argv, bool defaultValue) noexcept;
 
    ppp::string                                                             GetCommandArgument(const char* name, int argc, const char** argv) noexcept;

    ppp::string                                                             GetCommandArgument(const char* name, int argc, const char** argv, const char* defaultValue) noexcept;

    ppp::string                                                             GetCommandArgument(const char* name, int argc, const char** argv, const ppp::string& defaultValue) noexcept;

    ppp::string                                                             GetCommandText() noexcept;

    ppp::string                                                             GetFullExecutionFilePath() noexcept;

    ppp::string                                                             GetApplicationStartupPath() noexcept;

    ppp::string                                                             GetExecutionFileName() noexcept;

    ppp::string                                                             GetCurrentDirectoryPath() noexcept;

    void                                                                    Sleep(int milliseconds) noexcept;

    bool                                                                    HideConsoleCursor(bool value) noexcept;

    bool                                                                    ClearConsoleOutputCharacter() noexcept;

    bool                                                                    GetConsoleWindowSize(int& x, int& y) noexcept;

    bool                                                                    SetConsoleCursorPosition(int x, int y) noexcept;

    bool                                                                    MoveConsoleCursorPositionToNextLine(int line) noexcept;

    bool                                                                    MoveConsoleCursorPositionToPreviousLine(int line) noexcept;

    bool                                                                    IsUserAnAdministrator() noexcept;

    const char*                                                             GetSystemCode() noexcept;

    const char*                                                             GetPlatformCode() noexcept;

    const char*                                                             GetDefaultCipherSuites() noexcept;

    bool                                                                    IfVersion(const ppp::vector<uint64_t>& now, const ppp::vector<uint64_t> min) noexcept;

    boost::uuids::uuid                                                      GuidGenerate() noexcept;

    boost::uuids::uuid                                                      LexicalCast(const void* guid, int length) noexcept;

    boost::uuids::uuid                                                      StringToGuid(const ppp::string& guid) noexcept;

    ppp::string                                                             GuidToString(const boost::uuids::uuid& uuid) noexcept;

    ppp::string                                                             GuidToStringB(const boost::uuids::uuid& uuid) noexcept;

    ppp::string                                                             GuidToStringN(const boost::uuids::uuid& uuid) noexcept;

    ppp::string                                                             GuidToStringP(const boost::uuids::uuid& uuid) noexcept;

    ppp::string                                                             LexicalCast(const boost::uuids::uuid& uuid) noexcept;

    void                                                                    PrintStackTrace() noexcept;

    std::string                                                             CaptureStackTrace() noexcept;

    int                                                                     GetSystemPageSize() noexcept;

    int                                                                     GetMemoryPageSize() noexcept;

    bool                                                                    CloseHandle(const void* handle) noexcept;

    bool                                                                    IsNaN(double d) noexcept;

    float                                                                   Sqrt(float x) noexcept;

    unsigned int                                                            Div3(unsigned int i) noexcept;

    unsigned long long                                                      Div3(unsigned long long i) noexcept;

    bool                                                                    SetThreadName(const char* name) noexcept;

    ppp::string                                                             PaddingRightAllLines(std::size_t padding_length, char padding_char, const ppp::string& s, int* line_count = NULL) noexcept;

    ppp::string                                                             PaddingLeftAllLines(std::size_t padding_length, char padding_char, const ppp::string& s, int* line_count = NULL) noexcept;

    template <typename T>
    int                                                                     FindIndexOf(int* next, T* src, int src_len, T* sub, int sub_len) noexcept {
        static constexpr auto FindNextOf = 
            [](int* next, T* sub, int sub_len) noexcept {
                int l = sub_len - 1;
                int i = 0;
                int j = -1;     
                next[0] = -1;
                while (i < l) {
                    if (j == -1 || sub[i] == sub[j]) {
                        j++;
                        i++;
                        
                        if (sub[i] == sub[j]) {
                            next[i] = next[j];
                        }
                        else {
                            next[i] = j;
                        }
                    }
                    else {
                        j = next[j];
                    }
                }
            };

        int i = 0;
        int j = 0;
        FindNextOf(next, sub, sub_len);

        while (i < src_len && j < sub_len) {
            if (j == -1 || src[i] == sub[j]) {
                i++;
                j++;
            }
            else {
                j = next[j];
            }
        }

        if (j >= sub_len) {
            return i - sub_len;
        }
        else {
            return -1;
        }
    }

    template <typename T>
    std::shared_ptr<T>                                                      make_shared_alloc(int length) noexcept {
        static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

        // https://pkg.go.dev/github.com/google/agi/core/os/device
        // ARM64v8a: __ALIGN(8)
        // ARMv7a  : __ALIGN(4)
        // X86_64  : __ALIGN(8)
        // X64     : __ALIGN(4)
        if (length < 1) {
            return NULL;
        }

        T* p = (T*)Malloc(length * sizeof(T));
        if (NULL == p) {
            return NULL;
        }

        return std::shared_ptr<T>(p, Mfree);
    }

    template <typename T, typename... A>
    std::shared_ptr<T>                                                      make_shared_object(A&&... args) noexcept {
        static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

        void* memory = Malloc(sizeof(T));
        if (NULL == memory) {
            return NULL;
        }
        
        memset(memory, 0, sizeof(T));
        return std::shared_ptr<T>(new (memory) T(std::forward<A&&>(args)...),
            [](T* p) noexcept {
                p->~T();
                Mfree(p);
            });
    }

    template <typename T, typename... A>
    std::shared_ptr<void*>                                                  make_shared_void_pointer(A&&... args) noexcept {
        static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

        void* memory = Malloc(sizeof(T));
        if (NULL == memory) {
            return NULL;
        }
        
        memset(memory, 0, sizeof(T));
        return std::shared_ptr<void*>(reinterpret_cast<void**>(new (memory) T(std::forward<A&&>(args)...)),
            [](void** p) noexcept {
                T* m = reinterpret_cast<T*>(p);
                m->~T();
                Mfree(p);
            });
    }

    template <typename T>
    std::shared_ptr<T>                                                      wrap_shared_pointer(const T* v) noexcept {
        return NULL != v ? std::shared_ptr<T>(constantof(v), [](T*) noexcept {}) : NULL;
    }

    template <typename T, typename Reference>
    std::shared_ptr<T>                                                      wrap_shared_pointer(const T* v, const Reference& reference) noexcept {
        return NULL != v ? std::shared_ptr<T>(constantof(v), [reference](T*) noexcept {}) : NULL;
    }

    namespace global {
        void cctor() noexcept;
    }

    template <typename Signature>
    class function;

    template <typename R, typename... Args>
    class function<R(Args...)> {
    public:
        using Function = R(*)(Args...);

    public:
        function() noexcept {}
        function(std::nullptr_t) noexcept {}
        function(function&& other) noexcept {
            move(std::forward<function>(other));
        }
        function(const function& other) noexcept {
            LockScope<typename std::decay<decltype(*this)>::type> scope(constantof(other));
            this->f_ = other.f_;
            this->callable_ = other.callable_;
        }

    public:
        template <typename F>
        function(F&& f) {
            reset(std::forward<F>(f));
        }

    public:
        virtual ~function() noexcept {
            reset();
        }

    public:
        function&                                                           operator=(function&& other) noexcept {
            move(std::forward<function>(other));
            return *this;
        }
        function&                                                           operator=(const function& other) noexcept {
            function* const reft = (function*)&reinterpret_cast<const char&>(other);
            function* const left = this;
            if (left != reft) {
                // Copy the field value on the right to the top of the stack.
                Function                                reft_f = NULL;
                std::shared_ptr<ICallable>              reft_callable;
                for (;;) {
                    LockScope<typename std::decay<decltype(*this)>::type> reft_scope(constantof(other));
                    reft_f = other.f_;
                    reft_callable = other.callable_;
                    break;
                }

                // Writes the field value stored on the stack to the corresponding field of this function object.
                for (;;) {
                    LockScope<typename std::decay<decltype(*this)>::type> left_scope(*this);
                    this->f_ = reft_f;
                    this->callable_ = reft_callable;
                    break;
                }
            }
            return *left;
        }
        function&                                                           operator=(std::nullptr_t) {
            reset();
            return *this;
        }
        explicit                                                            operator bool() const {
            using TFunctionConst = typename std::decay<decltype(*this)>::type;
            using TFunctionMutable = typename std::remove_const<TFunctionConst>::type;

            LockScope<TFunctionMutable> scope(constantof(*this));
            return NULL != f_ || NULL != callable_;
        }

    public:
        virtual R                                                           operator()(Args... args) const {
            using TFunctionConst = typename std::decay<decltype(*this)>::type;
            using TFunctionMutable = typename std::remove_const<TFunctionConst>::type;

            // Calls still first synchronize the destination function address, 
            // held from the  function object or wrap a reference to the calling object onto the stack.
            do {
                Function f = NULL;
                std::shared_ptr<ICallable> i;
                for (;;) {
                    LockScope<TFunctionMutable> scope(constantof(*this));
                    f = this->f_;
                    i = this->callable_;
                    break;
                }

                if (NULL != i) {
                    return i->Invoke(std::forward<Args>(args)...);
                }

                if (NULL != f) {
                    return f(std::forward<Args>(args)...);
                }
            } while (false);

            // It may be a thread-safe issue to throw an exception for the caller to catch 
            // if the current function object is not a null pointer.
            throw std::runtime_error("Cannot call a function with an null address delegated.");
        }
        virtual void                                                        invoke(Args... args) const {
            using TFunctionConst = typename std::decay<decltype(*this)>::type;
            using TFunctionMutable = typename std::remove_const<TFunctionConst>::type;

            // Calls still first synchronize the destination function address, 
            // held from the  function object or wrap a reference to the calling object onto the stack.
            do {
                Function f = NULL;
                std::shared_ptr<ICallable> i;
                for (;;) {
                    LockScope<TFunctionMutable> scope(constantof(*this));
                    f = this->f_;
                    i = this->callable_;
                    break;
                }

                if (NULL != i) {
                    i->Invoke(std::forward<Args>(args)...);
                    return;
                }

                if (NULL != f) {
                    f(std::forward<Args>(args)...);
                    return;
                }
            } while (false);

            // It may be a thread-safe issue to throw an exception for the caller to catch 
            // if the current function object is not a null pointer.
            throw std::runtime_error("Cannot call a function with an null address delegated.");
        }

    public:
        void                                                                swap(function& other) noexcept {
            // Copy the field values of the function on the left.
            Function                                left_f = NULL;
            std::shared_ptr<ICallable>              left_callable;
            for (;;) {
                LockScope<typename std::decay<decltype(*this)>::type> left_scope(*this);
                left_f = this->f_;
                left_callable = this->callable_;
                break;
            }

            // Copy the field values of the function on the right.
            Function                                reft_f = NULL;
            std::shared_ptr<ICallable>              reft_callable;
            for (;;) {
                LockScope<typename std::decay<decltype(*this)>::type> reft_scope(constantof(other));
                reft_f = other.f_;
                reft_callable = other.callable_;
                break;
            }

            // Formally replace the values on both sides, but in the process of exchange, 
            // high concurrency may occur and the newly written field values will be overwritten, 
            // there will be new and old data overwriting problems, developers need to use the function carefully, 
            // or ensure the linearity of the logic outside.
            for (;;) {
                LockScope<typename std::decay<decltype(*this)>::type> left_scope(*this);
                this->f_ = reft_f;
                this->callable_ = reft_callable;
                break;
            }

            // Swap the value on the left to the function object on the right.
            for (;;) {
                LockScope<typename std::decay<decltype(*this)>::type> reft_scope(constantof(other));
                other.f_ = left_f;
                other.callable_ = left_callable;
                break;
            }
        }
        void                                                                reset() noexcept {
            LockScope<typename std::decay<decltype(*this)>::type> scope(*this);
            this->f_ = NULL;
            this->callable_.reset();
        }
        void                                                                reset(const Function& f) noexcept {
            LockScope<typename std::decay<decltype(*this)>::type> scope(*this);
            this->f_ = f;
            this->callable_.reset();
        }

        template <typename F>
        void                                                                reset(F&& f) {
            using TFunction = typename std::decay<F>::type;
            using TSynchronizedObject = typename std::decay<decltype(*this)>::type;

            LockScope<TSynchronizedObject> scope(*this);
            reset<F, TFunction>(std::forward<F>(f));
        }

    private:
        template <typename F, typename TFunction>
        void                                                                reset(F&& f) {
            using TCallable = Callable<TFunction>;

            this->f_ = NULL;
            this->callable_.reset();

            if constexpr (std::is_same<Function, TFunction>::value) {
                this->f_ = f;
                this->callable_ = NULL;
            }
            elif constexpr (std::is_same<function, TFunction>::value) {
                this->f_ = f.f_;
                this->callable_ = f.callable_;
            }
            elif constexpr (std::is_empty<TFunction>::value) {
                static_assert(stl::is_invocable<TFunction, Args...>::value, "Unknown expressions, not supported!");

                this->f_ = f;
                this->callable_ = NULL;
            }
            elif constexpr (std::is_integral<TFunction>::value) {
                if (f != 0) {
                    throw std::runtime_error("It's not allowed to pass an integer value to the constructor, but it's allowed to pass an integer 0 to the constructor of a function, which represents a NULL function pointer.");
                }
            }
            else {
                TCallable* fx = new TCallable(std::forward<TFunction>(f));
                if (NULL != fx) {
                    this->callable_ = std::shared_ptr<TCallable>(fx);
                }
            }
        }

    private:
        void                                                                lock() noexcept {
            for (;;) {
                int expected = FALSE;
                if (lk_.compare_exchange_strong(expected, TRUE, std::memory_order_acquire)) {
                    break;
                }
            }
        }
        void                                                                unlock() {
            int expected = TRUE;
            bool ok = lk_.compare_exchange_strong(expected, FALSE, std::memory_order_release);
            if (!ok) {
                throw std::runtime_error("failed to acquire the atomic lock.");
            }
        }
        void                                                                move(function&& other) noexcept {
            Function                    left_f = NULL;
            std::shared_ptr<ICallable>  left_callable; // COW.
            for (;;) {
                // Move and copy the field value of the right function object to the left function object.
                LockScope<typename std::decay<decltype(*this)>::type> scope(other);
                left_f = other.f_;
                left_callable = std::move(other.callable_);

                // Reset and release the field value reference technique held by the function object on the right and so on.
                other.f_ = NULL;
                other.callable_.reset();
                break;
            }

            // Writes the field value stored on the stack to the corresponding field of this function object.
            for (;;) {
                LockScope<typename std::decay<decltype(*this)>::type> scope(*this);
                this->f_ = left_f;
                this->callable_ = left_callable;
                break;
            }
        }

    private:
        class ICallable {
        public:
            ICallable() = default;
            virtual ~ICallable() noexcept = default;

        public:
            virtual R                                                       Invoke(Args&&... args) const = 0;
        };

        template <typename F>
        class Callable : public ICallable {
        public:
            Callable(const F& f) noexcept : f_(f) {}
            Callable(F&& f) noexcept : f_(std::forward<F>(f)) {}
            virtual ~Callable() noexcept = default;

        public:
            virtual R                                                       Invoke(Args&&... args) const override {
                if constexpr (std::is_same<R, void>::value) { /* sizeof...(args) */
                    f_(std::forward<Args>(args)...);
                }
                else {
                    return f_(std::forward<Args>(args)...); /* return R{}; */
                }
            }

        private:
            mutable F                                                       f_;
        };

        template <typename T>
        class LockScope {
        public:
            LockScope(T& obj) noexcept
                : obj_(obj) {
                obj_.lock();
            }
            ~LockScope() noexcept {
                obj_.unlock();
            }

        private:
            T&                                                              obj_;
        };

    private:
        mutable std::atomic<int>                                            lk_       = false;
        mutable Function                                                    f_        = NULL;
        mutable std::shared_ptr<ICallable>                                  callable_ = NULL; // COW.
    };

    template <class F>
    inline bool operator==(const function<F>& other, std::nullptr_t) noexcept {
        return !other;
    }

    template <class F>
    inline bool operator==(std::nullptr_t, const function<F>& other) noexcept {
        return !other;
    }

    template <class F>
    inline bool operator!=(const function<F>& other, std::nullptr_t) noexcept {
        return static_cast<bool>(other);
    }

    template <class F>
    inline bool operator!=(std::nullptr_t, const function<F>& other) noexcept {
        return static_cast<bool>(other);
    }
}

#if !defined(_WIN32)
namespace std {
    template <>
    struct hash<ppp::string> {
    public:
        std::size_t operator()(const ppp::string& v) const noexcept {
            return ppp::GetHashCode(v.data(), v.size());
        }
    };
}
#endif
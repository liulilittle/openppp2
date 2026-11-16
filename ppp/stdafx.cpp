#include <ppp/stdafx.h>
#include <ppp/Random.h>
#include <ppp/io/File.h>
#include <ppp/threading/Executors.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file stdafx.cpp
 * @brief Implements platform and utility helpers declared in stdafx.h.
 */

#if defined(_WIN32)
#include <io.h>
#include <Windows.h>
#include <timeapi.h>
#include <mmsystem.h>
#else
#include <unistd.h>
#include <sched.h>
#include <pthread.h>

#if defined(_MACOS)
#include <libproc.h>
#endif

#if defined(_LINUX)
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/syscall.h>
#else
#include <mach-o/dyld.h>
#include <mach/thread_act.h>
#include <mach/mach_init.h>
#endif

#include <sys/resource.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#endif

#include <stdio.h>
#include <math.h>

#include <cmath>
#include <memory>
#include <cstdlib>

#if !defined(_IPHONE)
#if BOOST_VERSION >= 108700
#include <boost/stacktrace/stacktrace.hpp>
#else
#include <boost/stacktrace.hpp>
#endif
#endif
#include <ppp/text/Encoding.h>
#include <ppp/hash/hash_bytes.h>

#if defined(_WIN32)
#include <windows/ppp/win32/Win32Native.h>
#else
#include <common/unix/UnixAfx.h>
#if defined(_LINUX)
#include <linux/ppp/diagnostics/UnixStackTrace.h>
#endif
#endif

//#if _MSC_VER >= 1600
//#pragma execution_character_set("utf-8")
//#endif

namespace ppp {
    /** @brief Thread-local random source for global random helpers. */
    static thread_local Random  GLOBAL_RANDOBJECT;

    /** @brief Global runtime flag used by startup initialization. */
    bool                        RT = false;

    /**
     * @brief Raises current thread priority to a realtime-capable level.
     */
    void SetThreadPriorityToMaxLevel() noexcept {
#if defined(_WIN32)
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
#else
        /* ps -eo state,uid,pid,ppid,rtprio,time,comm */
        struct sched_param param_{};
        param_.sched_priority = sched_get_priority_max(SCHED_FIFO); /* SCHED_RR */

        pthread_setschedparam(pthread_self(), SCHED_FIFO, &param_); /* pthread_getthreadid_np() */
#endif
    }

    /**
     * @brief Raises current process priority to the highest available level.
     */
    void SetProcessPriorityToMaxLevel() noexcept {
#if defined(_WIN32)
        SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
#else
#if defined(_LINUX)
        char path_[PATH_MAX];
        snprintf(path_, sizeof(path_), "/proc/%d/oom_adj", getpid());

        char level_[] = "-17";
        ppp::io::File::WriteAllBytes(path_, level_, sizeof(level_));
#endif

        /* Processo pai deve ter prioridade maior que os filhos. */
        setpriority(PRIO_PROCESS, getpid(), -20);

#if defined(_LINUX)
        /* ps -eo state,uid,pid,ppid,rtprio,time,comm */
        struct sched_param param_{};
        param_.sched_priority = sched_get_priority_max(SCHED_FIFO); // SCHED_RR
        
        if (sched_setscheduler(getpid(), SCHED_RR, &param_) < 0) {
            sched_setscheduler(getpid(), SCHED_FIFO, &param_);
        }
#endif
#endif
    }

    /**
     * @brief Converts a textual switch value into boolean semantics.
     * @param s Text pointer.
     * @return `false` for recognized falsy prefixes, otherwise `true`.
     */
    bool ToBoolean(const char* s) noexcept {
        if (NULLPTR == s || *s == '\x0') {
            return false;
        }

        char ch = s[0];
        if (ch == '0' || ch == ' ') {
            return false;
        }

        if (ch == 'f' || ch == 'F') {
            return false;
        }

        if (ch == 'n' || ch == 'N') {
            return false;
        }

        if (ch == 'c' || ch == 'C') {
            return false;
        }
        return true;
    }

    /**
     * @brief Hashes a raw byte sequence.
     * @param s Input memory pointer.
     * @param len Number of bytes.
     * @return Hash code as signed integer.
     */
    int GetHashCode(const void* s, int len) noexcept {
        /* std::_Hash_array_representation<Byte>(static_cast<Byte*>(s), len) */
        /* std::_Hash_impl::hash(s, len) */

        constexpr size_t __seed = static_cast<size_t>(0xc70f6907UL);

        return ppp::hash_bytes::_Hash_bytes(s, len, __seed);
    }

    /**
     * @brief Computes CRC32 for a C-string or binary buffer.
     * @param s Input buffer pointer.
     * @param len Number of bytes, or negative to use `strlen`.
     * @return CRC32 value.
     */
    int CRC32(const char* s, int len) noexcept {
        if (NULLPTR == s) {
            return 0;
        }

        if (len < 0) {
            len = (int)strlen((char*)s);
        }

        if (len < 1) {
            return 0;
        }

        /** @brief CRC32 lookup table. */
        static unsigned int qualityTable[] = {
             0x0, 0x77073096, 0xee0e612c, 0x990951ba, 0x76dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
             0xedb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x9b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
             0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
             0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
             0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
             0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
             0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
             0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
             0x76dc4190, 0x1db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x6b6b51f, 0x9fbfe4a5, 0xe8b8d433,
             0x7807c9a2, 0xf00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x86d3d2d, 0x91646c97, 0xe6635c01,
             0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
             0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
             0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
             0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
             0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
             0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
             0xedb88320, 0x9abfb3b6, 0x3b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x4db2615, 0x73dc1683,
             0xe3630b12, 0x94643b84, 0xd6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0xa00ae27, 0x7d079eb1,
             0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
             0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
             0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
             0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
             0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
             0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
             0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x26d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x5005713,
             0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0xcb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0xbdbdf21,
             0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
             0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
             0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
             0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
             0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
             0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
        };
        unsigned int hash = 0xFFFFFFFF;
        unsigned char* buf = (unsigned char*)s;

        for (int i = 0; i < len; i++) {
            hash = ((hash >> 8) & 0x00FFFFFF) ^ qualityTable[(hash ^ buf[i]) & 0xFF];
        }

        unsigned int num = hash ^ 0xFFFFFFFF;
        return (int)num;
    }

    /**
     * @brief Generates a random printable ASCII character.
     * @return A character in range `0x20`..`0x7E`.
     */
    Char RandomPrintableAsciiBytes() noexcept {
        int ch_ = GLOBAL_RANDOBJECT.Next('\x20', '\x7e');
        return (Char)ch_;
    }

    /**
     * @brief Generates a random ASCII letter or digit.
     * @return A character from `[a-zA-Z0-9]` groups.
     */
    Char RandomAscii() noexcept {
        static const int m_ = 3;
        static const Byte x_[m_] = { 'a', 'A', '0' };
        static const Byte y_[m_] = { 'z', 'Z', '9' };

        int i_ = abs(GLOBAL_RANDOBJECT.Next()) % m_;
        return (Char)GLOBAL_RANDOBJECT.Next(x_[i_], y_[i_]);
    }

    /** @brief Generates a non-negative random integer. */
    int RandomNext() noexcept {
        return GLOBAL_RANDOBJECT.Next(0, INT_MAX);
    }

    /**
     * @brief Generates a random integer within the specified bounds.
     */
    int RandomNext(int minValue, int maxValue) noexcept {
        return GLOBAL_RANDOBJECT.Next(minValue, maxValue);
    }

    /** @brief Generates a random double precision value. */
    double RandomNextDouble() noexcept {
        return GLOBAL_RANDOBJECT.NextDouble();
    }

    /**
     * @brief Formats byte size using human-readable units.
     * @param size Size in bytes.
     * @return Formatted text such as `12.5 MB`.
     */
    ppp::string StrFormatByteSize(Int64 size) noexcept {
        static const char* aszByteUnitsNames[] = { "B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB", "DB", "NB" };

        long double d = llabs(size);
        unsigned int i = 0;
        while (i < 10 && d > 1024) {
            d /= 1024;
            i++;
        }

        char sz[1000 + 1];
        snprintf(sz, 1000, "%Lf %s", d, aszByteUnitsNames[i]);
        return sz;
    }

    /**
     * @brief Returns a boolean argument value with default fallback.
     */
    bool GetCommandArgument(const char* name, int argc, const char** argv, bool defaultValue) noexcept {
        ppp::string str = GetCommandArgument(name, argc, argv);
        if (str.empty()) {
            return defaultValue;
        }

        return ToBoolean(str.data());
    }

    /**
     * @brief Returns a string argument value with C-string default fallback.
     */
    ppp::string GetCommandArgument(const char* name, int argc, const char** argv, const char* defaultValue) noexcept {
        ppp::string defValue;
        if (defaultValue) {
            defValue = defaultValue;
        }

        return GetCommandArgument(name, argc, argv, defValue);
    }

    /**
     * @brief Returns a string argument value with string default fallback.
     */
    ppp::string GetCommandArgument(const char* name, int argc, const char** argv, const ppp::string& defaultValue) noexcept {
        ppp::string str = GetCommandArgument(name, argc, argv);
        return str.empty() ? defaultValue : str;
    }

    /**
     * @brief Detects whether a help option is present.
     */
    bool IsInputHelpCommand(int argc, const char* argv[]) noexcept {
        const int HELP_COMMAND_COUNT = 4;
        const char* HELP_COMMAND_LIST[HELP_COMMAND_COUNT] = {
            "-h",
            "--h",
            "-help",
            "--help"
        };

        for (int i = 0; i < HELP_COMMAND_COUNT; i++) {
            const char* command = HELP_COMMAND_LIST[i];
            if (HasCommandArgument(command, argc, argv)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Checks whether a named argument appears in command text.
     *
     * Supports `name` and `name=value` forms while honoring quoting.
     */
    bool HasCommandArgument(const char* name, int argc, const char** argv) noexcept {
        if (NULLPTR == name || *name == '\0') {
            return false;
        }

        if (argc <= 1) {
            return false;
        }

        ppp::string line = ppp::GetCommandArgument(argc, argv);;
        if (line.empty()) {
            return false;
        }

        const size_t name_len = strlen(name);
        bool in_double_quote = false;
        bool in_single_quote = false;
        size_t start = 0;

        for (size_t i = 0; i <= line.size(); ++i) {
            char c = (i < line.size()) ? line[i] : ' ';
            if (c == '"' && !in_single_quote) {
                in_double_quote = !in_double_quote;
                continue;
            }

            if (c == '\'' && !in_double_quote) {
                in_single_quote = !in_single_quote;
                continue;
            }

            if (c == ' ' && !in_double_quote && !in_single_quote) {
                if (i > start) {
                    size_t token_len = i - start;
                    if (token_len >= name_len &&
                        memcmp(line.data() + start, name, name_len) == 0) {

                        if (token_len == name_len) {
                            return true;
                        }
                        elif (line[start + name_len] == '=') {
                            return true;
                        }
                    }
                }

                start = i + 1;
            }
        }
        return false;
    }

    /**
     * @brief Rebuilds command arguments as a single space-separated string.
     */
    ppp::string GetCommandArgument(int argc, const char** argv) noexcept {
        if (NULLPTR == argv || argc <= 1) {
            return "";
        }

        ppp::string line;
        for (int i = 1; i < argc; i++) {
            line.append(RTrim(LTrim<ppp::string>(argv[i])));
            line.append(" ");
        }

        return line;
    }

    /**
     * @brief Removes matching outer quotes from a token.
     */
    static ppp::string unquote(const char* data, size_t len) noexcept {
        if (len < 2) {
            return ppp::string(data, len);
        }

        if (data[0] == '"' && data[len - 1] == '"') {
            return ppp::string(data + 1, len - 2);
        }

        if (data[0] == '\'' && data[len - 1] == '\'') {
            return ppp::string(data + 1, len - 2);
        }

        return ppp::string(data, len);
    }

    /**
     * @brief Gets value for a specific named command argument.
     */
    ppp::string GetCommandArgument(const char* name, int argc, const char** argv) noexcept {
        if (NULLPTR == name || argc <= 1) {
            return "";
        }

        ppp::string line = GetCommandArgument(argc, argv);
        if (line.empty()) {
            return "";
        }

        const size_t line_len = line.size();
        const size_t name_len = strlen(name);
        if (name_len == 0) {
            return "";
        }

        bool in_double_quote = false;
        bool in_single_quote = false;
        size_t start = 0;
        bool waiting_for_value = false;

        for (size_t i = 0; i <= line_len; ++i) {
            char c = (i < line_len) ? line[i] : ' ';
            if (c == '"' && !in_single_quote) {
                in_double_quote = !in_double_quote;
                continue;
            }

            if (c == '\'' && !in_double_quote) {
                in_single_quote = !in_single_quote;
                continue;
            }

            if (c == ' ' && !in_double_quote && !in_single_quote) {
                if (i > start) {
                    const char* token = line.data() + start;
                    size_t token_len = i - start;

                    if (waiting_for_value) {
                        if (token_len > 0) {
                            return unquote(token, token_len);
                        }

                        waiting_for_value = false;
                    }

                    if (token_len >= name_len) {
                        if (memcmp(token, name, name_len) == 0) {
                            if (token_len == name_len) {
                                waiting_for_value = true;
                            }
                            elif (token_len > name_len && token[name_len] == '=') {
                                size_t value_start = name_len + 1;
                                if (value_start < token_len) {
                                    return unquote(token + value_start, token_len - value_start);
                                }

                                return "";
                            }
                        }
                    }
                }

                start = i + 1;
            }
        }

        return "";
    }

    /** @brief Returns absolute executable file path for current process. */
    ppp::string GetFullExecutionFilePath() noexcept {
#if defined(_WIN32)
        static constexpr int EXE_MAX = INT16_MAX; /* Long Paths. */

        char exe[EXE_MAX + 1]; /* MAX_PATH */
        exe[EXE_MAX] = '\x0';

        GetModuleFileNameA(NULLPTR, exe, EXE_MAX);
        return exe;
#elif defined(_MACOS)
        char path[PATH_MAX + 1];
        path[PATH_MAX] = '\x0';

        uint32_t size = PATH_MAX;
        if (_NSGetExecutablePath(path, &size) == 0) {
            return path;
        }

#if defined(PROC_PIDPATHINFO_MAXSIZE)
        char pathbuf[PROC_PIDPATHINFO_MAXSIZE + 1];
        pathbuf[PROC_PIDPATHINFO_MAXSIZE] = '\x0';

        proc_pidpath(getpid(), pathbuf, PROC_PIDPATHINFO_MAXSIZE);
        return pathbuf;
#else
        return "";
#endif
#else
        char sz[PATH_MAX + 1];
        sz[PATH_MAX] = '\x0';

        int dw = readlink("/proc/self/exe", sz, PATH_MAX);
        sz[dw] = '\x0';

        return dw < 1 ? "" : sz;
#endif
    }

    /** @brief Returns full command text used to launch current process. */
    ppp::string GetCommandText() noexcept {
#if defined(_WIN32)
        LPCSTR cmdline = ::GetCommandLineA();
        return NULLPTR != cmdline ? cmdline : "";
#else
        char sz[PATH_MAX + 1];
        sz[PATH_MAX] = '\x0';

        int dw = readlink("/proc/self/cmdline", sz, PATH_MAX);
        sz[dw] = '\x0';

        return dw < 1 ? "" : sz;
#endif
    }

    /** @brief Determines whether current user has administrator/root rights. */
    bool IsUserAnAdministrator() noexcept {
#if defined(_WIN32)
        return ppp::win32::Win32Native::IsUserAnAdministrator();
#else
        return ::getuid() == 0; // $ROOT is 0.
#endif
    }

    /** @brief Returns current working directory path. */
    ppp::string GetCurrentDirectoryPath() noexcept {
#if defined(_WIN32)
        static constexpr int CWD_MAX = INT16_MAX; /* Long Paths. */

        char cwd[CWD_MAX + 1];
        cwd[CWD_MAX] = '\x0';

        ::GetCurrentDirectoryA(CWD_MAX, cwd);
        return cwd;
#else
        char sz[PATH_MAX + 1];
        sz[PATH_MAX] = '\x0';

        return ::getcwd(sz, PATH_MAX);
#endif
    }

    /** @brief Returns directory path that contains the executable. */
    ppp::string GetApplicationStartupPath() noexcept {
        ppp::string exe = GetFullExecutionFilePath();
#if defined(_WIN32)
        std::size_t pos = exe.rfind('\\');
#else
        std::size_t pos = exe.rfind('/');
#endif
        if (pos == ppp::string::npos) {
            return exe;
        }
        else {
            return exe.substr(0, pos);
        }
    }

    /** @brief Returns executable file name without directory components. */
    ppp::string GetExecutionFileName() noexcept {
        ppp::string exe = GetFullExecutionFilePath();
#if defined(_WIN32)
        std::size_t pos = exe.rfind('\\');
#else
        std::size_t pos = exe.rfind('/');
#endif
        if (pos == ppp::string::npos) {
            return exe;
        }
        else {
            return exe.substr(pos + 1);
        }
    }

    /** @brief Returns native process identifier. */
    int GetCurrentProcessId() noexcept {
#if defined(_WIN32) || defined(_WIN64)
        return ::GetCurrentProcessId();
#else
        return ::getpid();
#endif
    }

    /** @brief Resolves native thread identifier using platform-specific syscall APIs. */
    static int64_t GetCurrentThreadIdSysCall() noexcept {
#if defined(_WIN32) || defined(_WIN64)
        return ::GetCurrentThreadId();
#else
        // https://android.googlesource.com/platform/bionic/+/master/libc/bionic/gettid.cpp
        // ::gettid();
#if defined(SYS_gettid)
        return syscall(SYS_gettid); /* syscall(__NR_gettid) or syscall(SYS_gettid); */
#elif defined(__NR_gettid) || defined(_ANDROID)
        return syscall(__NR_gettid);
#else
        /* https://elliotth.blogspot.com/2012/04/gettid-on-mac-os.html */
        uint64_t tid;
        pthread_threadid_np(NULLPTR, &tid);
  
        return static_cast<int64_t>(tid);
#endif
#endif
    }

    /** @brief Returns cached native thread identifier for current thread. */
    int64_t GetCurrentThreadId() noexcept {
        static thread_local int64_t tid = GetCurrentThreadIdSysCall();

        return tid;
    }

    /** @brief Returns number of processors available to the current process. */
    int GetProcesserCount() noexcept {
        int count = 0;

#if defined(_WIN32) || defined(_WIN64)
        SYSTEM_INFO si;
        ::GetSystemInfo(&si);

        count = si.dwNumberOfProcessors;
#elif defined(__ANDROID_API__) && __ANDROID_API__ >= 23
        count = get_nprocs();
#elif defined(_SC_NPROCESSORS_ONLN)
        count = sysconf(_SC_NPROCESSORS_ONLN); // MAOOS && LINUX
#else
        count = std::thread::hardware_concurrency();        
#endif

        if (count < 1) {
            count = 1;
        }

        return count;
    }

    /** @brief Generates a random UUID value. */
    boost::uuids::uuid GuidGenerate() noexcept {
        boost::uuids::random_generator rgen;
        return rgen();
    }

    /** @brief Converts UUID to textual representation via lexical cast. */
    ppp::string LexicalCast(const boost::uuids::uuid& uuid) noexcept {
        return boost::lexical_cast<ppp::string>(uuid);
    }

    /**
     * @brief Converts UUID to canonical dashed format.
     * @return UUID text like `6f9619ff-8b86-d011-b42d-00c04fc964ff`.
     */
    ppp::string GuidToString(const boost::uuids::uuid& uuid) noexcept {
        // https://www.boost.org/users/history/version_1_77_0.html
#if BOOST_VERSION >= 107700
        ppp::string result(36, char()); 
        boost::uuids::to_chars(uuid, &result[0]); 
        return result;
#else
        // string::data() returns const char* before C++17
        std::string result = boost::uuids::to_string(uuid);
        return ppp::string(result.data(), result.size()); 
#endif
    }

    /** @brief Converts UUID to brace-wrapped format. */
    ppp::string GuidToStringB(const boost::uuids::uuid& uuid) noexcept {
        return "{" + GuidToString(uuid) + "}";
    }

    /** @brief Converts UUID to upper-case dashed format. */
    ppp::string GuidToStringN(const boost::uuids::uuid& uuid) noexcept {
        return ToUpper(GuidToString(uuid));
    }

    /** @brief Converts UUID to parenthesized format. */
    ppp::string GuidToStringP(const boost::uuids::uuid& uuid) noexcept {
        return "(" + GuidToString(uuid) + ")";
    }

    /**
     * @brief Converts raw bytes into UUID structure.
     * @param guid Byte source pointer.
     * @param length Available byte length.
     * @return UUID filled from input bytes and zero-padded when needed.
     */
    boost::uuids::uuid LexicalCast(const void* guid, int length) noexcept {
        boost::uuids::uuid uuid;
        if (NULLPTR == guid) {
            length = 0;
        }

        const int max_length = sizeof(uuid.data);
        if (length >= max_length) {
            memcpy(uuid.data, guid, max_length);
        }
        elif(length > 0) {
            memcpy(uuid.data, guid, length);
            memset(uuid.data + length, 0, max_length - length);
        }
        else {
            memset(uuid.data, 0, sizeof(uuid.data));
        }
        return uuid;
    }

    /** @brief Parses UUID from text, returning zero UUID on failure. */
    boost::uuids::uuid StringToGuid(const ppp::string& guid) noexcept {
        boost::uuids::string_generator sgen;
        try {
            return sgen(guid);
        }
        catch (const std::exception&) {
            return LexicalCast(NULLPTR, 0);
        }
    }

    /** @brief Returns normalized system code string. */
    const char* GetSystemCode() noexcept {
#if defined(_WIN32) || defined(_WIN64)
        return "windows";
#elif defined(_HARMONYOS)
        return "harmonyos";
#elif defined(_ANDROID)
        return "android";
#elif defined(_MACOS)
        return "macos"; // osx:drawin
#else
        return "linux";
#endif
    }

    /** @brief Returns normalized architecture code string. */
    const char* GetPlatformCode() noexcept {
#if defined(__x86_64__) || defined(_M_X64)
        return "X86_64";
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
        return "X86_32";
#elif defined(__ARM_ARCH_2__)
        return "ARMv2";
#elif defined(__ARM_ARCH_3M__)
        return "ARMv3M";
#elif defined(__ARM_ARCH_3__)
        return "ARMv3";
#elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
        return "ARMv4T";
#elif defined(__ARM_ARCH_5E_)
        return "ARMv5E"
#elif defined(__ARM_ARCH_5_)
        return "ARMv5"
#elif defined(__ARM_ARCH_6T2_)
        return "ARMv6T2";
#elif defined(__ARM_ARCH_6J__)
        return "ARMv6J";
#elif defined(__ARM_ARCH_6ZK__)
        return "ARMv6ZK";
#elif defined(__ARM_ARCH_6K__)
        return "ARMv6K";
#elif defined(__ARM_ARCH_6Z__)
        return "ARMv6Z";
#elif defined(__ARM_ARCH_6__)
        return "ARMv6";
#elif defined(__ARM_ARCH_7L__)
        return "ARMv7L";
#elif defined(__ARM_ARCH_7R__)
        return "ARMv7R";
#elif defined(__ARM_ARCH_7M__)
        return "ARMv7M";
#elif defined(__ARM_ARCH_7S__)
        return "ARMv7S";
#elif defined(__ARM_ARCH_7A__)
        return "ARMv7A";
#elif defined(__ARM_ARCH_7__)
        return "ARMv7";
#elif defined(__arm__)
        return "ARM";
#elif defined(__aarch64__) || defined(_M_ARM64)
        return "ARMv8A"; /* AARCH64 */
#elif defined(__mips64) || defined(__mips64__)
        return "MIPS64";
#elif defined(mips) || defined(__mips__) || defined(__mips)
#if defined(__LP64__)
        return "MIPS64";
#else
        return "MIPS";
#endif
#elif defined(__sh__)
        return "SUPERH";
#elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__PPC__) || defined(_ARCH_PPC)
        return "POWERPC";
#elif defined(__PPC64__) || defined(__ppc64__) || defined(_ARCH_PPC64)
        return "POWERPC64";
#elif defined(__sparc__) || defined(__sparc)
        return "SPARC";
#elif defined(__m68k__)
        return "M68K";
#elif defined(__s390x__)
        return "S390X";
#elif defined(__riscv) || defined(__riscv__) || defined(__riscv32__) || defined(__riscv64__)
#if __riscv_xlen == 32 // https://chromium.googlesource.com/external/webrtc/+/master/rtc_base/system/arch.h
        return "RISC-V";
#else
        return "RISC-V64"; // 64
#endif
#elif defined(__loongarch32) /* https://github.com/gcc-mirror/gcc/blob/master/gcc/config/loongarch/loongarch.h */
        return "LOONGARCH32";
#elif defined(__loongarch64) /* https://www.boost.org/doc/libs/1_81_0/boost/predef/architecture/loongarch.h */
        return "LOONGARCH64";
#elif defined(__loongarch)
        return sizeof(void*) == 8 ? "LOONGARCH32" : "LOONGARCH64";
#else
        return "UNKNOWN";
#endif
    }

    /** @brief Returns default TLS 1.3 cipher suite preference list. */
    const char* GetDefaultCipherSuites() noexcept {
#if defined(__arm__) || defined(__aarch64__)
        static constexpr int pointer_size = sizeof(void*);

        if (pointer_size < 8) {
            return "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
        }
#endif

        return "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
    }

    /** @brief Captures and prints stack trace to standard output. */
    void PrintStackTrace() noexcept {
        std::string stack_trace = CaptureStackTrace();
        std::cout << stack_trace << std::endl;
    }

    /** @brief Captures current call stack as text. */
    std::string CaptureStackTrace() noexcept {
#if defined(_IPHONE)
        return "";
#else
#if defined(_LINUX) && !defined(_ANDROID) && !defined(__MUSL__)
        if (ppp::diagnostics::Addr2lineIsSupport()) {
            return ppp::diagnostics::CaptureStackTrace();
        }
#endif

        boost::stacktrace::stacktrace st;
        return boost::stacktrace::to_string(st);
#endif
    }

    /** @brief Queries operating system memory page size. */
    int GetSystemPageSize() noexcept {
#if defined(_WIN32)
        SYSTEM_INFO si{};
        GetSystemInfo(&si);

        int pagesize = si.dwPageSize;
#else
        int pagesize = sysconf(_SC_PAGESIZE);
#endif

        if (pagesize < 1) {
            pagesize = 4096;
        }
        
        return pagesize;
    }

    /** @brief Returns cached memory page size for fast repeated access. */
    int GetMemoryPageSize() noexcept {
        static int pagesize = GetSystemPageSize();
        return pagesize;
    }

    /** @brief Checks whether a floating-point value is invalid or special. */
    bool IsNaN(double d) noexcept {
        if (isnan(d)) {
            return true;
        }

        // NegativeInfinity 
        if (d == std::numeric_limits<double>::infinity()) {
            return true;
        }

        if (d == std::numeric_limits<double>::epsilon()) {
            return true;
        }

        if (d == std::numeric_limits<double>::quiet_NaN()) {
            return true;
        }

        if (d == std::numeric_limits<double>::signaling_NaN()) {
            return true;
        }

        return false;
    }

    /** @brief Fast inverse-square-root style approximation helper. */
    float Sqrt(float x) noexcept { /* 0x5f3759df */
        float xhalf = 0.5f * x;
        int32_t i = *(int32_t*)&x;
        i = 0x5f375a86 - (i >> 1);
        x = *(float*)&i;
        x = x * (1.5f - xhalf * x * x);
        return x;
    }

    /** @brief Fast divide-by-three for 32-bit unsigned values. */
    unsigned int Div3(unsigned int i) noexcept {
        // AT&T:
        // movl    $2863311531, %edx
        // imulq   %rcx, %rdx
        // shrq    $33, %rdx

        // INTEL:
        // mov     edx, 2863311531
        // imul    rdx, rcx
        // shr     rdx, 33

        unsigned long long n = static_cast<long long>(i) * 2863311531;
        unsigned int r = static_cast<unsigned int>(n >> 33);
        return r;
    }

    /** @brief Fast divide-by-three for 64-bit unsigned values. */
    unsigned long long Div3(unsigned long long i) noexcept {
        // INTEL:
        // mov     rax, -6148914691236517205; 
        // mul     rcx
        // shr     rdx, 1

        int64_t rax = -6148914691236517205;
        int64_t rdx = (rax * i) >> 1;
        return rdx;
    }

    /**
     * @brief Returns a monotonic tick count in milliseconds.
     *
     * Uses std::chrono::steady_clock so the value is immune to system-time
     * adjustments (NTP steps, manual clock changes, DST, etc.).  The epoch
     * is arbitrary (typically process start or OS boot); callers must only
     * rely on *differences* between two calls, never on the absolute value.
     *
     * @note  All internal timeout and expiration calculations depend on this
     *        function.  Keeping it monotonic prevents two failure modes:
     *        - Clock moved forward  → all sessions instantly expire.
     *        - Clock moved backward → sessions never expire (resource leak).
     * @return Milliseconds elapsed since an arbitrary monotonic epoch.
     */
    uint64_t GetTickCount() noexcept {
        std::chrono::time_point now = std::chrono::steady_clock::now();
        return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    }

    /**
     * @brief Moves cursor up or down by a number of console lines.
     * @param previous `true` moves up, `false` moves down.
     * @param line Line count to move.
     * @return `true` on success.
     */
    static bool MoveConsoleCursorPositionToPreviousNextLine(bool previous, int line) noexcept {
        if (line < 0) {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::StdAfxMoveConsoleCursorInvalidLine);
        }

        if (line == 0) {
            return true;
        }

#if defined(_WIN32)
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (NULLPTR == hConsole) {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        }

        if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        }

        COORD pos{};
        pos.X = csbi.dwCursorPosition.X;
        pos.Y = previous ? csbi.dwCursorPosition.Y - 1 : csbi.dwCursorPosition.Y + 1;

        if (!SetConsoleCursorPosition(hConsole, pos)) {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        }
        return true;
#else
        if (::fprintf(stdout, previous ? "\033[%dA" : "\033[%dB", line) <= 0) {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileWriteFailed);
        }
        return true;
#endif
    }

    /** @brief Moves cursor to previous line(s). */
    bool MoveConsoleCursorPositionToPreviousLine(int line) noexcept {
        return MoveConsoleCursorPositionToPreviousNextLine(true, line);
    }

    /** @brief Moves cursor to next line(s). */
    bool MoveConsoleCursorPositionToNextLine(int line) noexcept {
        return MoveConsoleCursorPositionToPreviousNextLine(false, line);
    }

    /** @brief Sets cursor position in the console buffer. */
    bool SetConsoleCursorPosition(int x, int y) noexcept {
#if defined(_WIN32)
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (NULLPTR == hConsole) {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        }

        COORD coord = { (SHORT)x, (SHORT)y };
        if (!::SetConsoleCursorPosition(hConsole, coord)) {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        }
        return true;
#else
        if (::fprintf(stdout, "\033[%d;%dH", x, y) <= 0) {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileWriteFailed);
        }
        return true;
#endif
    }

    /** @brief Gets terminal width and height in characters. */
    bool GetConsoleWindowSize(int& x, int& y) noexcept {
        x = 0;
        y = 0;

#if defined(_WIN32)
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (NULLPTR == hConsole) {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        }

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (!::GetConsoleScreenBufferInfo(hConsole, &csbi)) {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        }

        y = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        x = csbi.srWindow.Right - csbi.srWindow.Left + 1;
#else
        struct winsize w;
        memset(&w, 0, sizeof(w));

        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) < 0) {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        }

        x = w.ws_col;
        y = w.ws_row;
#endif
        return true;
    }

    /** @brief Clears console output area and resets cursor position. */
    bool ClearConsoleOutputCharacter() noexcept {
#if defined(_WIN32)
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (NULLPTR != hStdOut) {
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            if (GetConsoleScreenBufferInfo(hStdOut, &csbi)) {
                DWORD consoleSize = csbi.dwSize.X * csbi.dwSize.Y;
                DWORD charsWritten;
                
                FillConsoleOutputCharacter(hStdOut, ' ', consoleSize, { 0, 0 }, &charsWritten);
                FillConsoleOutputAttribute(hStdOut, csbi.wAttributes, consoleSize, { 0, 0 }, &charsWritten);

                if (::SetConsoleCursorPosition(hStdOut, { 0, 0 })) {
                    return true;
                }
            }
        }
        if (0 != system("cls")) {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        }
        return true;
#elif defined(_IPHONE)
        return true;
#else
        if (0 != system("clear")) {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        }
        return true;
#endif
    }

    /** @brief Hides or shows the console cursor. */
    bool HideConsoleCursor(bool value) noexcept {
#if defined(_WIN32)
        HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
        if (NULLPTR != consoleHandle) {
            CONSOLE_CURSOR_INFO cursorInfo;
            if (GetConsoleCursorInfo(consoleHandle, &cursorInfo)) {
                cursorInfo.bVisible = !value;
                if (SetConsoleCursorInfo(consoleHandle, &cursorInfo)) {
                    return true;
                }
            }
        }
        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
#else
        if (value) {
            fprintf(stdout, "\033[?25l");
        }
        else {
            fprintf(stdout, "\033[?25h");
        }
        // Flush immediately so the escape reaches the terminal even if the
        // process exits abnormally (e.g. SIGTERM) before stdio buffers drain.
        fflush(stdout);
        return true;
#endif
    }

    /**
     * @brief Pads each line in a multi-line string to fixed width.
     */
    static ppp::string PaddingLeftRightAllLines(std::size_t padding_length, char padding_char, const ppp::string& input_strings, bool right_or_left, int* line_count) noexcept {
        ppp::vector<ppp::string> lines;
        if (ppp::Tokenize<ppp::string>(input_strings, lines, "\r\n") < 1) {
            return ppp::string();
        }

        ppp::string result;
        std::size_t line_size = lines.size();
        for (std::size_t i = 0; i < line_size; i++) {
            ppp::string line = lines[i];
            if (right_or_left) {
                result += PaddingRight<ppp::string>(line, padding_length, padding_char) + "\r\n";
            }
            else {
                result += PaddingLeft<ppp::string>(line, padding_length, padding_char) + "\r\n";
            }
        }

        if (NULLPTR != line_count) {
            *line_count = line_size;
        }
        return result;
    }

    /** @brief Applies right padding to all lines in a text block. */
    ppp::string PaddingRightAllLines(std::size_t padding_length, char padding_char, const ppp::string& s, int* line_count) noexcept {
        return PaddingLeftRightAllLines(padding_length, padding_char, s, true, line_count);
    }

    /** @brief Applies left padding to all lines in a text block. */
    ppp::string PaddingLeftAllLines(std::size_t padding_length, char padding_char, const ppp::string& s, int* line_count) noexcept {
        return PaddingLeftRightAllLines(padding_length, padding_char, s, false, line_count);
    }

    /**
     * @brief Internal helper: detects whether stdout is attached to an
     *        interactive Windows console (as opposed to a file or pipe).
     */
#if defined(_WIN32)
    static bool IsConsoleStdout() noexcept {
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        if (h == INVALID_HANDLE_VALUE || h == NULLPTR) {
            return false;
        }
        DWORD mode = 0;
        return GetConsoleMode(h, &mode) != FALSE;
    }
#endif

    /** @brief Writes a UTF-8 string to the console with adaptive encoding. */
    void ConsoleWrite(const char* utf8String) noexcept {
        if (NULLPTR == utf8String) {
            return;
        }
#if defined(_WIN32)
        if (IsConsoleStdout()) {
            int wideLen = MultiByteToWideChar(CP_UTF8, 0, utf8String, -1, NULLPTR, 0);
            if (wideLen > 1) {
                ppp::vector<wchar_t> wideBuf;
                wideBuf.resize(wideLen);
                if (MultiByteToWideChar(CP_UTF8, 0, utf8String, -1, wideBuf.data(), wideLen) > 0) {
                    DWORD written = 0;
                    WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), wideBuf.data(), static_cast<DWORD>(wideLen - 1), &written, NULLPTR);
                    return;
                }
            }
        }
#endif
        fputs(utf8String, stdout);
    }

    /** @brief printf-style console output with adaptive encoding. */
    void ConsoleFormat(const char* fmt, ...) noexcept {
        if (NULLPTR == fmt) {
            return;
        }
        char buf[4096];
        va_list args;
        va_start(args, fmt);
        int len = vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
        if (len > 0 && len < static_cast<int>(sizeof(buf))) {
            buf[len] = '\x0';
            ConsoleWrite(buf);
        }
        else if (len >= static_cast<int>(sizeof(buf))) {
            // Fallback for very long strings: format to a dynamic buffer.
            ppp::vector<char> bigBuf;
            bigBuf.resize(len + 1);
            va_start(args, fmt);
            vsnprintf(bigBuf.data(), bigBuf.size(), fmt, args);
            va_end(args);
            ConsoleWrite(bigBuf.data());
        }
    }

    /** @brief Checks whether current version vector satisfies minimum version. */
    bool IfVersion(const ppp::vector<uint64_t>& now, const ppp::vector<uint64_t> min) noexcept {
        std::size_t now_length = now.size(), min_length = min.size();
        if (now_length == 0 && min_length == 0) {
            return true;
        }

        if (now_length > 0) {
            if (min_length == 0) {
                return true;
            }
        }

        for (std::size_t i = 0; i < now_length; i++) {
            uint32_t nx = now[i];
            uint32_t mx = i >= min_length ? 0 : min[i];
            if (nx > mx) {
                return true;
            }
            elif(nx < mx) {
                return false;
            }
        }
        
        return true;
    }

    /** @brief Closes a native OS handle using platform abstraction. */
    bool CloseHandle(const void* handle) noexcept {
#if defined(_WIN32)
        return ppp::win32::Win32Native::CloseHandle(handle);
#else
        return ppp::unix__::UnixAfx::CloseHandle(handle);
#endif
    }

    /** @brief Sleeps current thread for the specified duration. */
    void Sleep(int milliseconds) noexcept {
        if (milliseconds > 0) {
#if defined(_WIN32)
            ::timeBeginPeriod(1);
            ::Sleep(milliseconds);
            ::timeEndPeriod(1);
#else
            std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
#endif
        }
    }

    /** @brief Assigns a human-readable name to current thread. */
    bool SetThreadName(const char* name) noexcept {
        if (NULLPTR == name || *name == '\x0') {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::StdAfxSetThreadNameEmptyName);
        }

#if defined(_WIN32)
        ppp::win32::Win32Native::SetThreadDescription(name);
#elif defined(_MACOS) || defined(_IPHONE)
        pthread_setname_np(name);
#else
        pthread_setname_np(pthread_self(), name);
#endif
        return true;
    }

    /**
     * @brief Parses textual IP address with `inet_pton` fallback path.
     *
     * This implementation avoids Android release crashes observed when using
     * `boost::asio::ip::address::from_string` under optimization.
     */
    boost::asio::ip::address StringToAddress(const char* s, boost::system::error_code& ec) noexcept {
        ec = boost::asio::error::invalid_argument;
        if (NULLPTR == s || *s == '\x0') {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid, boost::asio::ip::address_v4::any());
        }

        struct in_addr addr4;
        struct in6_addr addr6;
        if (inet_pton(AF_INET6, s, &addr6) > 0) {
            boost::asio::ip::address_v6::bytes_type bytes;
            memcpy(bytes.data(), addr6.s6_addr, bytes.size());

            ec.clear();
            return boost::asio::ip::address_v6(bytes);
        }
        elif(inet_pton(AF_INET, s, &addr4) > 0) {
            ec.clear();
            return boost::asio::ip::address_v4(htonl(addr4.s_addr));
        }
        else {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid, boost::asio::ip::address_v4::any()); 
        }
    }
}

/**
 * @brief Declares global static constructor entrypoints required during startup.
 *
 * This compatibility path is primarily used for non-Windows platforms built
 * with LLVM/libc++ style toolchains.
 */
namespace lwip {
    void netstack_cctor() noexcept;
}

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                void VEthernetHttpProxyConnection_cctor() noexcept;
            }
        }
    }

    namespace cryptography {
        void EVP_cctor() noexcept;
    }

    namespace threading {
        void Thread_cctor() noexcept;
        void Executors_cctor() noexcept;
    }

    namespace net {
        namespace asio {
            namespace vdns {
                void vdns_ctor() noexcept;
                void UpdateAsync() noexcept;
            }

            void InternetControlMessageProtocol_DoEvents() noexcept;
        }
    }

    namespace ethernet {
        bool NetstackTryExit() noexcept;
    }

    namespace global {
        /**
         * @brief Executes one-time PPP global bootstrap sequence.
         */
        void cctor() noexcept {
#if !defined(_WIN32)
            /** @brief Ensure terminal type is set for UNIX console output. */
            putenv(const_cast<char*>("TERM=xterm"));
#endif

            ppp::SetThreadName(BOOST_BEAST_VERSION_STRING);
            if (ppp::RT) {
                ppp::SetThreadPriorityToMaxLevel();
                ppp::SetProcessPriorityToMaxLevel();
            }

            lwip::netstack_cctor();

            ppp::threading::Thread_cctor();
            ppp::threading::Executors_cctor();
            ppp::cryptography::EVP_cctor();
            ppp::net::asio::vdns::vdns_ctor();

            // The executor layer exposes hooks instead of calling up into DNS, ICMP and
            // the netstack; this composition root wires them.
            ppp::threading::Executors::SetSecondTickHandler(
                []() noexcept {
                    ppp::net::asio::vdns::UpdateAsync();
                    ppp::net::asio::InternetControlMessageProtocol_DoEvents();
                });
            ppp::threading::Executors::SetWorkersStoppedHandler(
                []() noexcept {
                    ppp::ethernet::NetstackTryExit();
                });

            ppp::app::client::proxys::VEthernetHttpProxyConnection_cctor();
        }
    }
}

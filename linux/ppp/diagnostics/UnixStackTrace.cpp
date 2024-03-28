#include <linux/ppp/diagnostics/UnixStackTrace.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <cxxabi.h>
#include <sys/resource.h>

#if !defined(_ANDROID)
#include <execinfo.h>
#endif

#include <cstdlib>
#include <iostream>

namespace ppp
{
    namespace diagnostics
    {
        static ppp::string GetExecutablePath() noexcept
        {
            char path[8192];
            ssize_t count = readlink("/proc/self/exe", path, sizeof(path));
            return ppp::string(path, count > 0 ? count : 0);
        }

        bool Addr2lineIsSupport() noexcept
        {
            static bool supported = Addr2lineIsSupportIf();
            return supported;
        }

        bool Addr2lineIsSupportIf() noexcept
        {
            int status = std::system("addr2line -v > /dev/null 2>&1");
            return status == 0; /* sudo apt-get remove binutils */
        }

#if !defined(_ANDROID)
        static ppp::string ExtractSymbol(const char* symbol)
        {
            if (NULL == symbol || *symbol == '\x0')
            {
                return ppp::string();
            }

            const char* symbolStart = NULL;
            const char* symbolEnd = NULL;
            const char* strPtr = symbol;
            while (*strPtr)
            {
                if (*strPtr == '(')
                {
                    symbolStart = strPtr + 1;
                }
                elif(*strPtr == ')' && symbolStart)
                {
                    symbolEnd = strPtr;
                    break;
                }
                strPtr++;
            }

            if (symbolStart && symbolEnd)
            {
                char symbolBuf[symbolEnd - symbolStart + 1];
                strncpy(symbolBuf, symbolStart, symbolEnd - symbolStart);

                symbolBuf[symbolEnd - symbolStart] = '\0';
                return symbolBuf;
            }
            else
            {
                return ppp::string();
            }
        }

        std::string CaptureStackTrace(int skip) noexcept
        {
            size_t constexpr max_stackframe_size = 3000;
            void* stackframe_addrs[max_stackframe_size];

            if (skip < 0)
            {
                skip = 0;
            }

            size_t stackframe_size = backtrace(stackframe_addrs, max_stackframe_size);
            char** stackframe_symbols = backtrace_symbols(stackframe_addrs, stackframe_size);

            ppp::string stacktraces = "Stack Trace:";
            if (NULL != stackframe_symbols)
            {
                ppp::string executable_path = GetExecutablePath();
                ppp::string default_line = "\r\n  at ";
                for (int i = skip; i < stackframe_size; i++)
                {
                    char buf[8192];
                    sprintf(buf, "addr2line -e %s %p", executable_path.data(), stackframe_addrs[i]);

                    FILE* f = popen(buf, "r");
                    if (NULL == f)
                    {
                        continue;
                    }

                    if (fgets(buf, sizeof(buf), f))
                    {
                        int symbol_size = strlen(buf);
                        if (buf[symbol_size - 1] == '\n')
                        {
                            buf[--symbol_size] = '\0';
                        }

                        ppp::string line = default_line;
                        if (symbol_size > 0)
                        {
                            if (*buf != '?')
                            {
                                line += buf;
                            }
                        }

                        ppp::string symbol = ExtractSymbol(stackframe_symbols[i]);
                        if (symbol.size() > 0)
                        {
                            int status = -1;
                            char* demangle = NULL;
                            char* p = strchr((char*)symbol.data(), '+');
                            if (p)
                            {
                                *p = '\x0';
                                demangle = abi::__cxa_demangle((char*)symbol.data(), NULL, 0, &status);
                            }
                            else
                            {
                                p = (char*)"??";
                            }

                            if (status == 0)
                            {
                                snprintf(buf, sizeof(buf), "(%s+%s) [%p]", demangle, p + 1, stackframe_addrs[i]);
                                line += buf;
                            }
                            else
                            {
                                if (default_line.size() == line.size())
                                {
                                    line += stackframe_symbols[i];
                                }
                                else
                                {
                                    snprintf(buf, sizeof(buf), "(%s+%s) [%p]", symbol.data(), p + 1, stackframe_addrs[i]);
                                    line += buf;
                                }
                            }

                            if (NULL != demangle)
                            {
                                std::free(demangle);
                            }
                        }
                        else
                        {
                            snprintf(buf, sizeof(buf), " [%p]", stackframe_addrs[i]);
                            line += buf;
                        }

                        stacktraces += line;
                    }

                    pclose(f);
                }

                std::free(stackframe_symbols);
            }
            
            return std::string(stacktraces.data(), stacktraces.size());
        }
#endif

        int GetMaxOpenFileDescriptors() noexcept
        {
            struct rlimit limit;
            if (getrlimit(RLIMIT_NOFILE, &limit) < 0)
            {
                return -1;
            }

            return std::min<int>(limit.rlim_cur, limit.rlim_max);
        }

        bool SetMaxOpenFileDescriptors(int max_open_file_descriptors) noexcept
        {
            if (max_open_file_descriptors < 1)
            {
                return false;
            }

            struct rlimit limit;
            limit.rlim_cur = max_open_file_descriptors; // 设置软限制
            limit.rlim_max = max_open_file_descriptors; // 设置硬限制
            return setrlimit(RLIMIT_NOFILE, &limit) > -1;
        }
    }
}
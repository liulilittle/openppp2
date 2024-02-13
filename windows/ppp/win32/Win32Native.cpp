#include <windows/ppp/win32/Win32Native.h>
#include <windows/ppp/win32/Win32Variant.h>
#include <windows/ppp/win32/Win32RegistryKey.h>
#include <ppp/io/File.h>
#include <ppp/text/Encoding.h>
#include <ppp/threading/Executors.h>
#include <common/chnroutes2/chnroutes2.h>

#include <Windows.h>
#include <process.h>
#include <Shlwapi.h>
#include <Shellapi.h>
#include <shlobj_core.h>
#include <psapi.h>
#include <netcfgx.h>

#include <intrin.h>
#include <initguid.h>
#include <atlbase.h>
#include <atlcom.h>
#include <io.h>
#include <fcntl.h>
#include <propkey.h>
#include <propsys.h>
#include <propvarutil.h>

#include <winternl.h>
#include <winnt.h>
#include <comdef.h>
#include <comutil.h>
#include <Wbemidl.h>
#include <crtdbg.h>
#include <dbghelp.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "propsys.lib")
#pragma comment(lib, "Dbghelp.lib")

namespace ppp
{
    namespace win32
    {
        static Win32Native::ShutdownApplicationEventHandler SHUTDOWN_APPLICATION_EVENT;

        static ppp::string Seh_NewDumpFileName() noexcept
        {
            ppp::string path = ppp::GetExecutionFileName();
            std::size_t index = path.rfind(".");
            if (index != ppp::string::npos)
            {
                path = path.substr(0, index);
            }

            struct tm tm_;
            time_t datetime = time(NULL);
            localtime_s(&tm_, &datetime);

            char sz[1000];
            sprintf_s(sz, sizeof(sz), "%04d%02d%02d-%02d%02d%02d", 1900 + tm_.tm_year, 1 + tm_.tm_mon, tm_.tm_mday, tm_.tm_hour, tm_.tm_min, tm_.tm_sec);

            path = path + "-" + sz + ".dmp";
            path = "./" + path;
            path = ppp::io::File::RewritePath(path.data());
            path = ppp::io::File::GetFullPath(path.data());

            return path;
        }

        static LONG WINAPI Seh_UnhandledExceptionFilter(EXCEPTION_POINTERS* exceptionInfo) noexcept
        {
            // Give user code a chance to approve or prevent writing a minidump.  If the
            // filter returns false, don't handle the exception at all.  If this method
            // was called as a result of an exception, returning false will cause
            // HandleException to call any previous handler or return
            // EXCEPTION_CONTINUE_SEARCH on the exception thread, allowing it to appear
            // as though this handler were not present at all.
            HANDLE hFile = CreateFileA(Seh_NewDumpFileName().data(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                MINIDUMP_EXCEPTION_INFORMATION exceptionParam;
                exceptionParam.ThreadId = GetCurrentThreadId();
                exceptionParam.ExceptionPointers = exceptionInfo;
                exceptionParam.ClientPointers = TRUE;

                MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpWithFullMemory, &exceptionParam, NULL, NULL);
                CloseHandle(hFile);
            }

            // The handler either took care of the invalid parameter problem itself,
            // or passed it on to another handler.  "Swallow" it by exiting, paralleling
            // the behavior of "swallowing" exceptions.
            exit(-1); /* abort(); */
            return EXCEPTION_EXECUTE_HANDLER;
        }
        
#if _MSC_VER >= 1400 
        // https://chromium.googlesource.com/breakpad/breakpad/src/+/master/client/windows/handler/exception_handler.cc
        static void __CRTDECL Crt_InvalidParameterHandler(const wchar_t* expression, const wchar_t* function, const wchar_t* file, unsigned int line, uintptr_t pReserved) noexcept
        {
            std::wcerr << L"Invalid parameter detected:" << std::endl;
            std::wcerr << L"Expression: " << expression << std::endl;
            std::wcerr << L"Function: " << function << std::endl;
            std::wcerr << L"File: " << file << std::endl;
            std::wcerr << L"Line: " << line << std::endl;

            _CrtDumpMemoryLeaks();
            _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG);
            _CrtMemDumpAllObjectsSince(NULL);
            _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);

            // Make up an exception record for the current thread and CPU context
            // to make it possible for the crash processor to classify these
            // as do regular crashes, and to make it humane for developers to
            // analyze them.
            EXCEPTION_RECORD exception_record = {};
            CONTEXT exception_context = {};
            EXCEPTION_POINTERS exception_ptrs = { &exception_record, &exception_context };

            ::RtlCaptureContext(&exception_context);

            exception_record.ExceptionCode = STATUS_INVALID_PARAMETER;

            // We store pointers to the the expression and function strings,
            // and the line as exception parameters to make them easy to
            // access by the developer on the far side.
            exception_record.NumberParameters = 4;
            exception_record.ExceptionInformation[0] = reinterpret_cast<ULONG_PTR>(expression);
            exception_record.ExceptionInformation[1] = reinterpret_cast<ULONG_PTR>(file);
            exception_record.ExceptionInformation[2] = line;
            exception_record.ExceptionInformation[3] = reinterpret_cast<ULONG_PTR>(function);

            // Deliver exceptions to unhandled exception handler.
            Seh_UnhandledExceptionFilter(&exception_ptrs);
        }
#endif

        static int Seh_NoncontinuableException() noexcept
        {
            // Make up an exception record for the current thread and CPU context
            // to make it possible for the crash processor to classify these
            // as do regular crashes, and to make it humane for developers to
            // analyze them.
            EXCEPTION_RECORD exception_record = {};
            CONTEXT exception_context = {};
            EXCEPTION_POINTERS exception_ptrs = { &exception_record, &exception_context };

            ::RtlCaptureContext(&exception_context);

            exception_record.ExceptionCode = STATUS_NONCONTINUABLE_EXCEPTION;

            // We store pointers to the the expression and function strings,
            // and the line as exception parameters to make them easy to
            // access by the developer on the far side.
            exception_record.NumberParameters = 3;
            exception_record.ExceptionInformation[0] = NULL;
            exception_record.ExceptionInformation[1] = NULL;
            exception_record.ExceptionInformation[2] = 0;

            // Deliver exceptions to unhandled exception handler.
            return Seh_UnhandledExceptionFilter(&exception_ptrs);
        }

        static int __CRTDECL Crt_NewHandler(size_t) noexcept
        {
            return Seh_NoncontinuableException();
        }

        static void __CRTDECL Crt_HandlePureVirtualCall() noexcept
        {
            Seh_NoncontinuableException();
        }

        static void __CRTDECL Crt_TerminateHandler() noexcept
        {
            Seh_NoncontinuableException();
        }

        static void __CRTDECL Crt_UnexpectedHandler() noexcept
        {
            Seh_NoncontinuableException();
        }

        static void __CRTDECL Crt_SigabrtHandler(int) noexcept
        {
            Seh_NoncontinuableException();
        }

        SYSTEM_WINDOWS_COM_INITIALIZED::SYSTEM_WINDOWS_COM_INITIALIZED()
        {
            char messages[1000];
            HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
            if (FAILED(hr))
            {
                sprintf(messages, "Failed to initialize COM library. Error code = 0x%08x", hr);
                throw std::runtime_error(messages);
            }
            elif(SUCCEEDED(hr))
            {
                hr = CoInitializeSecurity(
                    NULL,
                    -1,
                    NULL,
                    NULL,
                    RPC_C_AUTHN_LEVEL_DEFAULT,
                    RPC_C_IMP_LEVEL_IMPERSONATE,
                    NULL,
                    EOAC_NONE,
                    NULL);
                if (FAILED(hr))
                {
                    sprintf(messages, "Failed to initialize security. Error code = 0x%08x", hr);
                    throw std::runtime_error(messages);
                }
            }

            // Windows platforms need to mount unhandled exception handlers so that they can print dump debug files for app crashes.
#ifdef _DEBUG
            ::_CrtSetDbgFlag(_CRTDBG_LEAK_CHECK_DF | _CRTDBG_ALLOC_MEM_DF);
#endif
            ::_set_abort_behavior(_CALL_REPORTFAULT, _CALL_REPORTFAULT);

            ::_set_purecall_handler(Crt_HandlePureVirtualCall);
            ::_set_new_handler(Crt_NewHandler); /* std::set_new_handler(...) */

#if _MSC_VER >= 1400 
            ::_set_invalid_parameter_handler(Crt_InvalidParameterHandler);
#endif

            ::signal(SIGABRT, Crt_SigabrtHandler);
            ::signal(SIGINT, Crt_SigabrtHandler);
            ::signal(SIGTERM, Crt_SigabrtHandler);
            ::signal(SIGILL, Crt_SigabrtHandler);

            ::set_terminate(Crt_TerminateHandler);
            ::set_unexpected(Crt_UnexpectedHandler);

            ::SetUnhandledExceptionFilter(Seh_UnhandledExceptionFilter);
        }

        SYSTEM_WINDOWS_COM_INITIALIZED::~SYSTEM_WINDOWS_COM_INITIALIZED() noexcept
        {
            CoUninitialize();
        }

        LONG Win32Native::DumpApplicationAndExit(EXCEPTION_POINTERS* e) noexcept
        {
            return Seh_UnhandledExceptionFilter(e);
        }

        void* Win32Native::GetProcAddress(const char* moduleName, const char* functionName) noexcept
        {
            if (NULL != moduleName && *moduleName == '\x0')
            {
                moduleName = NULL;
            }

            HMODULE hModule = GetModuleHandleA(moduleName);
            if (NULL == hModule)
            {
                hModule = LoadLibraryA(moduleName);
                if (NULL == hModule)
                {
                    return NULL;
                }
            }

            if (NULL == functionName || *functionName == '\x0')
            {
                return NULL;
            }

            return ::GetProcAddress(hModule, functionName);
        }

        ppp::string Win32Native::GetLoginUser() noexcept
        {
            char username[1000 + 1];
            DWORD size = sizeof(username);
            if (!GetUserNameA(username, &size))
            {
                return "";
            }
            else
            {
                return username;
            }
        }

        bool Win32Native::RtlGetNtVersionNumbers(PULONG dwMajor, PULONG dwMinor, PULONG dwBuildNumber) noexcept
        {
            typedef NTSTATUS(WINAPI* RtlGetNtVersionNumbersProc)(PULONG, PULONG, PULONG);

            static const RtlGetNtVersionNumbersProc WINAPI_RtlGetNtVersionNumbers = (RtlGetNtVersionNumbersProc)Win32Native::GetProcAddress("ntdll.dll", "RtlGetNtVersionNumbers");
            if (NULL == WINAPI_RtlGetNtVersionNumbers)
            {
                return false;
            }

            return WINAPI_RtlGetNtVersionNumbers(dwMajor, dwMinor, dwBuildNumber) >= 0; /* NT_SUCCESS */
        }

        bool Win32Native::DnsFlushResolverCache() noexcept
        {
            typedef DWORD(WINAPI* DnsFlushResolverCacheProc)();

            static DnsFlushResolverCacheProc WINAPI_DnsFlushResolverCache = (DnsFlushResolverCacheProc)GetProcAddress("Dnsapi.dll", "DnsFlushResolverCache");
            if (NULL == WINAPI_DnsFlushResolverCache)
            {
                return false;
            }

            return WINAPI_DnsFlushResolverCache();
        }

        bool Win32Native::IsUserAnAdministrator() noexcept
        {
            bool bTokenIsElevated = false;
            if (IsUserAnAdmin())
            {
                return true;
            }

            HANDLE hToken = NULL;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            {
                return false;
            }

            TOKEN_ELEVATION tokenElevation;
            DWORD dwSize;

            if (GetTokenInformation(hToken, TokenElevation, &tokenElevation, sizeof(TOKEN_ELEVATION), &dwSize))
            {
                if (tokenElevation.TokenIsElevated)
                {
                    bTokenIsElevated = true;
                }
            }

            CloseHandle(hToken);
            return bTokenIsElevated;
        }

        bool Win32Native::CloseHandle(const void* handle) noexcept
        {
            if (handle == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            __try
            {
                ::CloseHandle((HANDLE)handle);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        bool Win32Native::WSACloseEvent(const void* handle) noexcept
        {
            if (NULL == handle)
            {
                return false;
            }

            __try
            {
                ::WSACloseEvent((HANDLE)handle);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        bool Win32Native::Execute(bool runas, const char* filePath, const char* argumentText, int* returnCode) noexcept
        {
            if (NULL == filePath || *filePath == '\x0')
            {
                return false;
            }

            if (NULL == argumentText)
            {
                argumentText = "";
            }

            if (NULL != returnCode)
            {
                *returnCode = INFINITE;
            }

            SHELLEXECUTEINFOA sei;
            memset(&sei, 0, sizeof(sei));

            sei.cbSize = sizeof(sei);
            sei.fMask = SEE_MASK_NOCLOSEPROCESS;
            sei.nShow = SW_HIDE;
            sei.lpVerb = runas ? "runas" : "open";
            sei.lpFile = filePath;
            sei.lpParameters = argumentText;

            if (!ShellExecuteExA(&sei))
            {
                return false;
            }

            if (NULL != returnCode)
            {
                WaitForSingleObject(sei.hProcess, INFINITE);
                if (!GetExitCodeProcess(sei.hProcess, reinterpret_cast<DWORD*>(returnCode)))
                {
                    *returnCode = INFINITE;
                }
            }

            CloseHandle(sei.hProcess);
            return true;
        }

        bool Win32Native::Execute(bool runas, const char* commandText) noexcept
        {
            if (NULL == commandText || *commandText == '\x0')
            {
                return false;
            }

            if (runas)
            {
                return ShellExecuteA(NULL, "runas", commandText, NULL, NULL, SW_SHOWNORMAL);
            }
            else
            {
                return ShellExecuteA(NULL, "open", commandText, NULL, NULL, SW_SHOWNORMAL);
            }
        }

        bool Win32Native::EnableDebugPrivilege() noexcept
        {
            HANDLE hToken = NULL;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            {
                return false;
            }

            TOKEN_PRIVILEGES tkp;
            tkp.PrivilegeCount = 1;

            if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid))
            {
                CloseHandle(hToken);
                return false;
            }
            else
            {
                tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            }

            bool ok = AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
            if (ok)
            {
                int lastError = GetLastError();
                if (lastError != ERROR_SUCCESS)
                {
                    ok = lastError != ERROR_NOT_ALL_ASSIGNED;
                }
            }

            CloseHandle(hToken);
            return ok;
        }

        bool Win32Native::RunAsAdministrator() noexcept
        {
            ppp::string commandText = GetCommandText();
            return RunAsAdministrator(commandText.data());
        }

        bool Win32Native::RunAsAdministrator(const char* commandText) noexcept
        {
            return Execute(true, commandText);
        }

        bool Win32Native::DeviceIoControl(const void* tap, uint32_t commands, const void* contents, int content_size) noexcept
        {
            if (NULL == tap || tap == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            if (content_size < 1)
            {
                contents = NULL;
            }

            BOOL bOK = false;
            HANDLE hEvent = ::CreateEvent(NULL, false, false, NULL);
            do
            {
                OVERLAPPED overlapped{};
                overlapped.hEvent = hEvent;

                DWORD dw = 0;
                if (NULL == contents)
                {
                    bOK = ::DeviceIoControl((LPVOID)tap, commands,
                        (LPVOID)contents, 0, (LPVOID)contents, 0, &dw, &overlapped);
                }
                else
                {
                    bOK = ::DeviceIoControl((LPVOID)tap, commands,
                        (LPVOID)contents, content_size, (LPVOID)contents, content_size, &dw, &overlapped);
                }
            } while (false);

            if (NULL != hEvent)
            {
                ::CloseHandle(hEvent);
            }
            return bOK;
        }

        ppp::string Win32Native::GetFullPath(const char* path) noexcept
        {
            if (NULL == path || *path == '\x0')
            {
                return "";
            }

            DWORD fullpath_size = GetFullPathNameA(path, 0, NULL, NULL);
            if (fullpath_size == 0 || fullpath_size == MAXDWORD)
            {
                return "";
            }

            LPSTR fullpath_string = (LPSTR)Malloc(fullpath_size + 1);
            if (NULL == fullpath_string)
            {
                return "";
            }

            ppp::string fullpath;
            DWORD dw = GetFullPathNameA(path, fullpath_size, fullpath_string, NULL);
            if (dw != 0)
            {
                fullpath = ppp::string(fullpath_string, dw);
            }

            Mfree(fullpath_string);
            return fullpath;
        }

        int Win32Native::GetCurrentProcessId() noexcept
        {
            return ::GetCurrentProcessId();
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
        typedef struct KERNEL_PROCESS_BASIC_INFORMATION
        {
            NTSTATUS ExitStatus;
            PPEB PebBaseAddress;
            ULONG_PTR AffinityMask;
            KPRIORITY BasePriority;
            ULONG_PTR UniqueProcessId;
            ULONG_PTR InheritedFromUniqueProcessId;
        } KERNEL_PROCESS_BASIC_INFORMATION, * KERNEL_PPROCESS_BASIC_INFORMATION;

        int Win32Native::GetInheritedFromUniqueProcessId(int process_id) noexcept
        {
            typedef NTSTATUS(WINAPI* NtQueryInformationProcess_Proc)(HANDLE, UINT, PVOID, ULONG, PULONG);

            DWORD dwInheritedFromUniqueProcessId = 0;
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
            if (NULL != hProcess)
            {
                KERNEL_PROCESS_BASIC_INFORMATION pbi;
                ZeroMemory(&pbi, sizeof(pbi));

                static NtQueryInformationProcess_Proc NtQueryInformationProcess = (NtQueryInformationProcess_Proc)GetProcAddress("ntdll.dll", "NtQueryInformationProcess");
                if (NULL != NtQueryInformationProcess)
                {
                    NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
                    if (status == 0)
                    {
                        dwInheritedFromUniqueProcessId = (DWORD)pbi.InheritedFromUniqueProcessId;
                    }
                }

                CloseHandle(hProcess);
            }
            return dwInheritedFromUniqueProcessId;
        }

        ppp::string Win32Native::GetProcessFullName(int process_id) noexcept
        {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
            if (NULL == hProcess)
            {
                return "";
            }

            char* szFilePath = NULL;
            DWORD dwBufferSize = MAX_PATH;
            DWORD dwPathLength = 0;

            ppp::string strProcessFullName;
            do
            {
                if (NULL != szFilePath)
                {
                    Mfree(szFilePath);
                }

                szFilePath = (char*)Malloc(dwBufferSize);
                dwPathLength = GetModuleFileNameExA(hProcess, NULL, szFilePath, dwBufferSize);
                if (dwPathLength == 0)
                {
                    break;
                }

                if (dwPathLength >= dwBufferSize)
                {
                    dwBufferSize <<= 1;
                }
                else
                {
                    strProcessFullName = ppp::string(szFilePath, dwPathLength);
                }
            } while (dwPathLength >= dwBufferSize);

            if (NULL != szFilePath)
            {
                Mfree(szFilePath);
            }

            CloseHandle(hProcess);
            return strProcessFullName;
        }

        bool Win32Native::IsRunningFromWindowsConsole() noexcept
        {
            constexpr const char* CONSOLES_PROGRESS_NAMES[] = { "vsdebugconsole.exe", "openconsole.exe", "cmd.exe", "powershell.exe", "windowsterminal.exe" };

            int process_id = Win32Native::GetInheritedFromUniqueProcessId(Win32Native::GetCurrentProcessId());
            if (process_id != 0)
            {
                ppp::string process_name = Win32Native::GetProcessFullName(process_id);
                if (process_name.empty())
                {
                    return false;
                }

                std::size_t i = process_name.rfind('\\');
                if (i == ppp::string::npos)
                {
                    return false;
                }
                else
                {
                    process_name = process_name.substr(i + 1);
                    std::transform(process_name.begin(), process_name.end(), process_name.begin(), ::tolower);
                }

                for (const char* CONSOLES_PROGRESS_NAME : CONSOLES_PROGRESS_NAMES)
                {
                    if (process_name.find(CONSOLES_PROGRESS_NAME) != ppp::string::npos)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        bool Win32Native::PauseWindowsConsole() noexcept
        {
            bool b = Win32Native::IsRunningFromWindowsConsole();
            if (b)
            {
                return false;
            }

            b = std::cin.good();
            if (!b)
            {
                return false;
            }

            if (feof(stdin))
            {
                return false;
            }

            if (ferror(stdin))
            {
                return false;
            }

            system("pause");
            return true;
        }

        bool Win32Native::EnabledConsoleWindowClosedButton(bool enabled) noexcept
        {
            HWND consoleWnd = GetConsoleWindow();
            if (NULL == consoleWnd)
            {
                return false;
            }

            HMENU systemMenu = GetSystemMenu(consoleWnd, FALSE);
            if (NULL == systemMenu)
            {
                return false;
            }

            if (enabled)
            {
                return EnableMenuItem(systemMenu, SC_CLOSE, MF_BYCOMMAND | MF_ENABLED) != FALSE;
            }
            else
            {
                return EnableMenuItem(systemMenu, SC_CLOSE, MF_BYCOMMAND | MF_GRAYED) != FALSE;
            }
        }

        bool Win32Native::AddShutdownApplicationEventHandler(ShutdownApplicationEventHandler e) noexcept
        {
            BOOL bOK;
            if (NULL == e)
            {
                bOK = SetConsoleCtrlHandler(NULL, TRUE);
            }
            else
            {
                PHANDLER_ROUTINE f = [](_In_ DWORD fdwCtrlType) -> BOOL
                {
                    const ShutdownApplicationEventHandler e = SHUTDOWN_APPLICATION_EVENT;
                    if (NULL == e)
                    {
                        return FALSE;
                    }

                    const DWORD fdw_shutdown_ctrl_types[] =
                    {
                        CTRL_C_EVENT,
                        CTRL_CLOSE_EVENT,
                        CTRL_LOGOFF_EVENT,
                        CTRL_SHUTDOWN_EVENT
                    };

                    const DWORD* max_fdw_shutdown_ctrl_types = fdw_shutdown_ctrl_types + arraysizeof(fdw_shutdown_ctrl_types);
                    const DWORD* tmp_fdw_shutdown_ctrl_types = fdw_shutdown_ctrl_types;
                    while (tmp_fdw_shutdown_ctrl_types < max_fdw_shutdown_ctrl_types)
                    {
                        if (*tmp_fdw_shutdown_ctrl_types++ == fdwCtrlType)
                        {
                            return e() ? TRUE : FALSE;
                        }
                    }
                    return FALSE;
                };
                bOK = SetConsoleCtrlHandler(f, TRUE);
            }

            if (bOK)
            {
                SHUTDOWN_APPLICATION_EVENT = e;
                return true;
            }
            else
            {
                return false;
            }
        }

        // Wrapper for SHCreateItemFromParsingName(), IShellItem2::GetString()
        // Throws std::system_error in case of any error.
        static std::wstring GetShellPropStringFromPath(CComPtr<IShellItem2>& pItem, CComHeapPtr<WCHAR>& pValue, LPCWSTR pPath, PROPERTYKEY const& key)
        {
            // Use CComPtr to automatically release the IShellItem2 interface when the function returns
            // or an exception is thrown.
            HRESULT hr = SHCreateItemFromParsingName(pPath, nullptr, IID_PPV_ARGS(&pItem));
            if (FAILED(hr))
            {
                throw std::system_error(hr, std::system_category(), "SHCreateItemFromParsingName() failed");
            }

            // Use CComHeapPtr to automatically release the string allocated by the shell when the function returns
            // or an exception is thrown (calls CoTaskMemFree).
            hr = pItem->GetString(key, &pValue);
            if (FAILED(hr))
            {
                throw std::system_error(hr, std::system_category(), "IShellItem2::GetString() failed");
            }

            // Copy to wstring for convenience
            return std::wstring(pValue);
        }

        static bool GetShellPropStringFromPath(LPCWSTR pPath, PROPERTYKEY const& key, std::wstring& out) noexcept
        {
            CComPtr<IShellItem2> pItem;
            CComHeapPtr<WCHAR> pValue;

            try
            {
                out = GetShellPropStringFromPath(pItem, pValue, pPath, key);
                return true;
            }
            catch (const std::exception&)
            {
                return false;
            }
        }

        static ppp::string GetShellPropStringFromPath(const ppp::string& path, PROPERTYKEY const& key) noexcept
        {
            ppp::string str_out;
            if (path.empty() || !ppp::io::File::Exists(path.data())) /* _setmode(_fileno(stdout), _O_U16TEXT);  // for proper UTF-16 console output */
            {
                return str_out;
            }

            // Show some properties of $path (adjust path if necessary)
            std::wstring wstr_out;
            _bstr_t bstr_path(path.data());
            if (!GetShellPropStringFromPath(bstr_path, key, wstr_out)) /* PKEY_Software_ProductName */
            {
                wstr_out.clear();
            }

            if (wstr_out.size() > 0)
            {
                _bstr_t bstr_out(wstr_out.data());
                str_out = VARIANT_string(bstr_out.GetBSTR());
            }

            return str_out;
        }

        ppp::string Win32Native::GetProductName(const ppp::string& path) noexcept
        {
            return GetShellPropStringFromPath(path, PKEY_Software_ProductName);
        }

        ppp::string Win32Native::GetFileDescription(const ppp::string& path) noexcept
        {
            return GetShellPropStringFromPath(path, PKEY_FileDescription);
        }

        bool Win32Native::OptimizedProcessWorkingSize(bool immediately) noexcept
        {
            static uint32_t next = 0;

            uint32_t now = ppp::threading::Executors::GetTickCount() / 1000;
            if (!immediately && now < next) 
            {
                return false;
            }
            else 
            {
                next = now + 10;
            }

            HANDLE hProcess = ::GetCurrentProcess();
            if (NULL == hProcess) 
            {
                return false;
            }

            BOOL ok = ::SetProcessWorkingSetSize(hProcess, INFINITE, INFINITE);
            return ok != FALSE;
        }

        bool Win32Native::IsWow64Process() noexcept
        {
            return sizeof(void*) < 8 ? false : true;
        }

        ppp::string Win32Native::GetFolderPathWithWindows() noexcept
        {
            CHAR path[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_WINDOWS, NULL, 0, path)))
            {
                return path;
            }
            else
            {
                return ppp::string();
            }
        }

        ppp::string Win32Native::GetConsoleWindowText() noexcept
        {
            CHAR szConsoleText[1024];
            *szConsoleText = '\x0';

            GetConsoleTitleA(szConsoleText, sizeof(szConsoleText));
            return szConsoleText;
        }

        ppp::string Win32Native::EchoTrim(const ppp::string& command) noexcept
        {
            ppp::string result = Echo(command);
            if (result.empty())
            {
                return result;
            }

            result = RTrim(result);
            result = LTrim(result);
            return result;
        }

        ppp::string Win32Native::Echo(const ppp::string& command) noexcept
        {
            SECURITY_ATTRIBUTES sa;
            sa.nLength = sizeof(SECURITY_ATTRIBUTES);
            sa.lpSecurityDescriptor = NULL;
            sa.bInheritHandle = TRUE;

            HANDLE hStdin, hStdout;
            if (!CreatePipe(&hStdin, &hStdout, &sa, 0))
            {
                return "";
            }

            STARTUPINFOA si;
            ZeroMemory(&si, sizeof(si));

            si.cb = sizeof(si);
            si.hStdError = hStdout;
            si.hStdOutput = hStdout;
            si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; // 添加标志以使用标准句柄和隐藏窗口
            si.wShowWindow = SW_HIDE; // 隐藏窗口

            PROCESS_INFORMATION pi;
            ZeroMemory(&pi, sizeof(pi));

            bool ok = CreateProcessA(NULL, (LPSTR)command.data(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
            if (!ok)
            {
                CloseHandle(hStdin);
                CloseHandle(hStdout);
                return "";
            }
            else
            {
                CloseHandle(hStdout);
            }

            ppp::string strOutput;
            do
            {
                const int nBufferSize = 4096;
                char szBuffers[nBufferSize];

                DWORD dwBytesRead = 0;
                while (ReadFile(hStdin, szBuffers, nBufferSize, &dwBytesRead, NULL))
                {
                    if (dwBytesRead == 0)
                    {
                        break;
                    }
                    else
                    {
                        strOutput.append(szBuffers, dwBytesRead);
                    }
                }

                CloseHandle(hStdin);
            } while (false);

            DWORD dwExitCode;
            if (!WaitForSingleObject(pi.hProcess, INFINITE))
            {
                dwExitCode = INFINITE;
            }
            elif(!GetExitCodeProcess(pi.hProcess, &dwExitCode))
            {
                dwExitCode = INFINITE;
            }

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return strOutput;
        }

        bool Win32Native::OptimizationSystemNetworkSettings() noexcept
        {
            bool any = false;
            any |= SetRegistryValueDword(HKEY_LOCAL_MACHINE, LR"(SYSTEM\CurrentControlSet\Services\Tcpip\Parameters)", L"MaxUserPort", 65534);
            any |= SetRegistryValueDword(HKEY_LOCAL_MACHINE, LR"(SYSTEM\CurrentControlSet\Services\Tcpip\Parameters)", L"TcpWindowSize", 62420);
            any |= SetRegistryValueDword(HKEY_LOCAL_MACHINE, LR"(SYSTEM\CurrentControlSet\Services\Tcpip\Parameters)", L"TcpTimedWaitDelay", 30);
            any |= SetRegistryValueDword(HKEY_LOCAL_MACHINE, LR"(SYSTEM\CurrentControlSet\Services\Tcpip\Parameters)", L"TcpNumConnections", 0xfffffe);

            Win32Native::Echo("netsh int tcp set global dca=enabled");
            Win32Native::Echo("netsh int tcp set global autotuninglevel=normal");

            Win32Native::EchoTrim("netsh int tcp set global congestionprovider=ctcp");
            Win32Native::EchoTrim("netsh int tcp set supplemental template=internet congestionprovider=ctcp");
            Win32Native::EchoTrim("netsh int tcp set global initialrto=1000");
            Win32Native::EchoTrim("netsh int tcp set global timestamps=enabled");
            return any;
        }

        ppp::string Win32Native::CPUID() noexcept
        {
            int s1, s2, s3, s4;

#if _WIN64
            int sn[4];
            __cpuid(sn, 0);
            s1 = sn[0];
            s2 = sn[3];

            __cpuid(sn, 1);
            s3 = sn[0];
            s4 = sn[3];
#else
            __asm
            {
                mov eax, 00h
                xor edx, edx
                cpuid
                mov dword ptr[s1], eax
                mov dword ptr[s2], edx

                mov eax, 01h
                xor ecx, ecx
                xor edx, edx
                cpuid
                mov dword ptr[s3], eax
                mov dword ptr[s4], edx
            }
#endif

            // You can query all CPU processor instances using WQL in wbemtest, 
            // View the ProcessorId attribute of the processor instance MOF, 
            // And clarify the rules for the operating system CPUID to obtain and format as text.

            char buf[40];
            snprintf(buf, sizeof(buf), "%016llX %016llX", ((int64_t)s4 << 32 | (int64_t)s3), ((int64_t)s2 << 32 | (int64_t)s1));
            return buf;
        }

        double Win32Native::CPULOAD() noexcept
        {
            static ULONGLONG g_tsSysDeltaTime = 0;
            static ULONGLONG g_tsSysLastTime = 0;

            FILETIME ftCreation, ftExit, ftKernel, ftUser;
            if (!GetProcessTimes(GetCurrentProcess(),
                &ftCreation,
                &ftExit,
                &ftKernel,
                &ftUser))
            {
                return 0;
            }

            ULONGLONG tsCpuUsageTime = (FiletimeToUlong(ftKernel) + FiletimeToUlong(ftUser));
            if (g_tsSysDeltaTime == 0)
            {
                g_tsSysDeltaTime = tsCpuUsageTime;
                return 0;
            }

            FILETIME ftNow;
            GetSystemTimeAsFileTime(&ftNow);

            ULONGLONG ftSystemNowTime = FiletimeToUlong(ftNow);
            ULONGLONG tsSysTimeDelta = ftSystemNowTime - g_tsSysLastTime;
            ULONGLONG tsSystemTimeDelta = tsCpuUsageTime - g_tsSysDeltaTime;

            double cpu_load = (tsSystemTimeDelta * 100.00 + tsSysTimeDelta / 2.00) / tsSysTimeDelta;
            g_tsSysLastTime = ftSystemNowTime;
            g_tsSysDeltaTime = tsCpuUsageTime;

            cpu_load = cpu_load / GetProcesserCount();
            if (cpu_load < 0 || IsNaN(cpu_load))
            {
                cpu_load = 0;
            }

            return cpu_load;
        }

        ppp::string Win32Native::GetAllLogicalDriveStrings() noexcept
        {
            int dw = GetLogicalDriveStringsA(0, NULL);
            if (dw < 1)
            {
                return "";
            }

            auto sb = make_shared_alloc<Byte>(dw);
            if (NULL == sb)
            {
                return "";
            }
            
            dw = GetLogicalDriveStringsA(dw, (LPSTR)sb.get());;
            if (dw == 0)
            {
                return "";
            }
            
            DWORD serials;
            DWORD maxcomp;
            if (!GetVolumeInformationA((LPSTR)sb.get(), NULL, 0, &serials, &maxcomp, 0, NULL, 0))
            {
                return "";
            }

            char buf[20];
            snprintf(buf, sizeof(buf), "%08X", serials);
            return buf;
        }

        SYSTEMTIME Win32Native::FiletimeToSystemTime(FILETIME fileTime) noexcept
        {
            SYSTEMTIME systemTime;
            ::FileTimeToSystemTime(&fileTime, &systemTime);
            return systemTime;
        }

        FILETIME Win32Native::DateTimeToFiletime(const SYSTEMTIME& systemTime) noexcept
        {
            FILETIME fileTime;
            ::SystemTimeToFileTime(&systemTime, &fileTime);
            return fileTime;
        }

        ULONGLONG Win32Native::FiletimeToUlong(const FILETIME& fileTime) noexcept
        {
            ULARGE_INTEGER uli;
            uli.LowPart = fileTime.dwLowDateTime;
            uli.HighPart = fileTime.dwHighDateTime;
            return uli.QuadPart;
        }

        void Win32Native::FindAllFilesWithNoRecursive(const ppp::string& directory, const ppp::string& extensions, ppp::vector<ppp::string>& files) noexcept
        {
            WIN32_FIND_DATAA findFileData;
            HANDLE hFind = FindFirstFileA((directory + "\\" + extensions).data(), &findFileData);
            if (hFind != INVALID_HANDLE_VALUE)
            {
                do
                {
                    if ((findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                    {
                        ppp::string fileName(findFileData.cFileName);
                        files.emplace_back(directory + "\\" + fileName);
                    }
                } while (FindNextFileA(hFind, &findFileData) != 0);
                FindClose(hFind);
            }
        }

        bool Win32Native::IsWindows11OrLaterVersion() noexcept
        {
            DWORD dwMajorVersion;
            DWORD dwMinorVersion;
            DWORD dwBuildNumber;
            if (!RtlGetSystemVersion(dwMajorVersion, dwMinorVersion, dwBuildNumber))
            {
                return false;
            }

            // 10.0.22000
            return IfVersion({ dwMajorVersion, dwMinorVersion, dwBuildNumber }, { 10, 0, 22000 });
        }

        bool Win32Native::RtlGetSystemVersion(DWORD& dwMajorVersion, DWORD& dwMinorVersion, DWORD& dwBuildNumber) noexcept
        {
            typedef LONG(WINAPI* RtlGetVersion_Proc)(PRTL_OSVERSIONINFOW lpVersionInformation);

            static RtlGetVersion_Proc __RtlGetVersion__ = (RtlGetVersion_Proc)GetProcAddress("ntdll.dll", "RtlGetVersion");
            if (NULL == __RtlGetVersion__)
            {
                return false;
            }

            RTL_OSVERSIONINFOW st;
            LONG status = __RtlGetVersion__(&st);
            if (status != ERROR_SUCCESS)
            {
                return false;
            }

            dwBuildNumber = st.dwBuildNumber;
            dwMinorVersion = st.dwMinorVersion;
            dwMajorVersion = st.dwMajorVersion;
            return true;
        }
    }
}
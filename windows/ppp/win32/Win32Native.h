#pragma once

#include <ppp/stdafx.h>

namespace ppp
{
    namespace win32
    {
        struct SYSTEM_WINDOWS_COM_INITIALIZED final
        {
        public:
            SYSTEM_WINDOWS_COM_INITIALIZED();
            ~SYSTEM_WINDOWS_COM_INITIALIZED() noexcept;
        };

        class Win32Native final
        {
        public:
            typedef ppp::function<bool(void)>                   ShutdownApplicationEventHandler;

        public:
            static void*                                        GetProcAddress(const char* moduleName, const char* functionName) noexcept;
            static bool                                         DnsFlushResolverCache() noexcept;
            static bool                                         Execute(bool runas, const char* filePath, const char* argumentText, int* returnCode) noexcept;
            static bool                                         Execute(bool runas, const char* commandText) noexcept;
            static bool                                         EnableDebugPrivilege() noexcept;
            static bool                                         CloseHandle(const void* handle) noexcept;
            static void                                         CloseHandle(boost::asio::windows::object_handle* handle) noexcept;
            static bool                                         WSACloseEvent(const void* handle) noexcept;
            static bool                                         DeviceIoControl(const void* tap, uint32_t commands, const void* contents, int content_size) noexcept;
            static ppp::string                                  GetFullPath(const char* path) noexcept;
            static bool                                         RtlGetNtVersionNumbers(PULONG dwMajor, PULONG dwMinor, PULONG dwBuildNumber) noexcept;
            static bool                                         EnabledConsoleWindowClosedButton(bool enabled) noexcept;
            static ppp::string                                  GetProductName(const ppp::string& path) noexcept;
            static ppp::string                                  GetFileDescription(const ppp::string& path) noexcept;
            static std::wstring                                 _A2W(const std::string& s) noexcept;
            static std::string                                  _W2A(const std::wstring& s) noexcept;
            static std::string                                  _UnicodeToUtf8(const std::wstring& s) noexcept;
            static std::wstring                                 _Utf8ToUnicode(const std::string& s) noexcept;

        public:
            static int                                          GetCurrentProcessId() noexcept;
            static ppp::string                                  GetProcessFullName(int process_id) noexcept;
            static int                                          GetInheritedFromUniqueProcessId(int process_id) noexcept;
            static bool                                         IsWow64Process() noexcept;
            static ppp::string                                  Echo(const ppp::string& command) noexcept;
            static ppp::string                                  EchoTrim(const ppp::string& command) noexcept;
            static ppp::string                                  GetConsoleWindowText() noexcept;
            static ppp::string                                  GetFolderPathWithWindows() noexcept;
            static bool                                         SetThreadDescription(const std::string& name) noexcept;

        public:
            static bool                                         IsRunningFromWindowsConsole() noexcept;
            static bool                                         PauseWindowsConsole() noexcept;
            static LONG                                         DumpApplicationAndExit(EXCEPTION_POINTERS* e) noexcept;
            static ppp::string                                  GetAllLogicalDriveStrings() noexcept;
            static bool                                         OptimizedProcessWorkingSize(bool immediately = false) noexcept;
            static bool                                         OptimizationSystemNetworkSettings() noexcept;

        public:
            static bool                                         IsWindows11OrLaterVersion() noexcept;
            static bool                                         IsWindows10OrLaterVersion() noexcept;
            static bool                                         IsWindows81OrLaterVersion() noexcept;

        public:
            static ppp::string                                  GetLoginUser() noexcept;
            static ppp::string                                  CPUID() noexcept;
            static double                                       CPULOAD() noexcept;
            static SYSTEMTIME                                   FiletimeToSystemTime(FILETIME fileTime) noexcept;
            static FILETIME                                     DateTimeToFiletime(const SYSTEMTIME& systemTime) noexcept;
            static ULONGLONG                                    FiletimeToUlong(const FILETIME& fileTime) noexcept;
            static bool                                         RtlGetSystemVersion(DWORD& dwMajorVersion, DWORD& dwMinorVersion, DWORD& dwBuildNumber) noexcept;

        public:
            static bool                                         AddShutdownApplicationEventHandler(ShutdownApplicationEventHandler e) noexcept;
            static void                                         FindAllFilesWithNoRecursive(const ppp::string& directory, const ppp::string& extensions, ppp::vector<ppp::string>& files) noexcept;

        public:
            static bool                                         IsUserAnAdministrator() noexcept;
            static bool                                         RunAsAdministrator() noexcept;
            static bool                                         RunAsAdministrator(const char* commandText) noexcept;
        };
    }
}
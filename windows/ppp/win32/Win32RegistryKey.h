#pragma once

#include <windows/ppp/win32/Win32Native.h>

namespace ppp
{
    namespace win32
    {
        bool GetRegistryValueBool(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, bool* bOK = NULL) noexcept;
        DWORD GetRegistryValueDword(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, bool* bOK = NULL) noexcept;
        ppp::vector<WORD> GetRegistryValueWordArray(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, bool* bOK = NULL) noexcept;
        std::wstring GetRegistryValueString(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, bool* bOK = NULL) noexcept;

        bool SetRegistryValueBool(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, bool valueData) noexcept;
        bool SetRegistryValueString(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& valueData) noexcept;
        bool SetRegistryValueDword(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, DWORD valueData) noexcept;
        bool SetRegistryValueWordArray(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, const WORD* valueData, DWORD dataSize) noexcept;
    }
}
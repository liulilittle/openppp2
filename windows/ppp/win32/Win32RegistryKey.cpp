#include <windows/ppp/win32/Win32RegistryKey.h>

namespace ppp
{
    namespace win32
    {
        // 读取BOOL值
        bool GetRegistryValueBool(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, bool* bOK) noexcept
        {
            DWORD data = GetRegistryValueDword(hKey, subKey, valueName, bOK);
            return (data != 0);
        }

        // 读取字符串值
        std::wstring GetRegistryValueString(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, bool* bOK) noexcept
        {
            LONG result;
            HKEY keyHandle;
            wchar_t buffer[MAX_PATH];
            DWORD size = MAX_PATH;
            DWORD type;

            if (NULL != bOK)
            {
                *bOK = false;
            }

            result = RegOpenKeyEx(hKey, subKey.c_str(), 0, KEY_READ, &keyHandle);
            if (result != ERROR_SUCCESS)
            {
                return L"";
            }

            result = RegQueryValueEx(keyHandle, valueName.c_str(), 0, &type, reinterpret_cast<BYTE*>(buffer), &size);
            RegCloseKey(keyHandle);

            if (result != ERROR_SUCCESS || type != REG_SZ)
            {
                return L"";
            }

            if (NULL != bOK)
            {
                *bOK = true;
            }

            return std::wstring(buffer, size / sizeof(wchar_t));
        }

        // 读取DWORD值
        DWORD GetRegistryValueDword(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, bool* bOK) noexcept
        {
            LONG result;
            HKEY keyHandle;
            DWORD data;
            DWORD size = sizeof(DWORD);
            DWORD type;

            if (NULL != bOK)
            {
                *bOK = false;
            }

            result = RegOpenKeyEx(hKey, subKey.c_str(), 0, KEY_READ, &keyHandle);
            if (result != ERROR_SUCCESS)
            {
                return 0;
            }

            result = RegQueryValueEx(keyHandle, valueName.c_str(), 0, &type, reinterpret_cast<BYTE*>(&data), &size);
            RegCloseKey(keyHandle);

            if (result != ERROR_SUCCESS || type != REG_DWORD)
            {
                return 0;
            }

            if (NULL != bOK)
            {
                *bOK = true;
            }

            return data;
        }

        // 读取WORD数组值
        ppp::vector<WORD> GetRegistryValueWordArray(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, bool* bOK) noexcept
        {
            LONG result;
            HKEY keyHandle;
            DWORD type;
            DWORD dataSize;

            if (NULL != bOK)
            {
                *bOK = false;
            }

            result = RegOpenKeyEx(hKey, subKey.c_str(), 0, KEY_READ, &keyHandle);
            if (result != ERROR_SUCCESS)
            {
                return ppp::vector<WORD>();
            }

            result = RegQueryValueEx(keyHandle, valueName.c_str(), 0, &type, NULL, &dataSize);
            if (result != ERROR_SUCCESS || type != REG_BINARY)
            {
                RegCloseKey(keyHandle);
                return ppp::vector<WORD>();
            }

            ppp::vector<BYTE> dataBuffer(dataSize);
            result = RegQueryValueEx(keyHandle, valueName.c_str(), 0, &type, dataBuffer.data(), &dataSize);
            RegCloseKey(keyHandle);

            if (result != ERROR_SUCCESS)
            {
                return ppp::vector<WORD>();
            }

            ppp::vector<WORD> dataArray(dataSize / sizeof(WORD));
            memcpy(dataArray.data(), dataBuffer.data(), dataSize);

            if (NULL != bOK)
            {
                *bOK = true;
            }

            return dataArray;
        }

        // 写入BOOL值
        bool SetRegistryValueBool(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, bool valueData) noexcept
        {
            DWORD data = valueData ? 1 : 0;
            return SetRegistryValueDword(hKey, subKey, valueName, data);
        }

        // 写入字符串值
        bool SetRegistryValueString(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& valueData) noexcept
        {
            LONG result;
            HKEY keyHandle;
            DWORD dwDisposition;

            result = RegCreateKeyEx(hKey, subKey.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &keyHandle, &dwDisposition);
            if (result != ERROR_SUCCESS)
            {
                return false;
            }

            result = RegSetValueEx(keyHandle, valueName.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(valueData.c_str()), static_cast<DWORD>(valueData.length() * sizeof(wchar_t)));
            RegCloseKey(keyHandle);

            return (result == ERROR_SUCCESS);
        }

        // 写入DWORD值
        bool SetRegistryValueDword(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, DWORD valueData) noexcept
        {
            LONG result;
            HKEY keyHandle;
            DWORD dwDisposition;

            result = RegCreateKeyEx(hKey, subKey.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &keyHandle, &dwDisposition);
            if (result != ERROR_SUCCESS)
            {
                return false;
            }

            result = RegSetValueEx(keyHandle, valueName.c_str(), 0, REG_DWORD, reinterpret_cast<BYTE*>(&valueData), sizeof(valueData));
            RegCloseKey(keyHandle);

            return (result == ERROR_SUCCESS);
        }

        // 写入WORD数组值
        bool SetRegistryValueWordArray(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, const WORD* valueData, DWORD dataSize) noexcept
        {
            LONG result;
            HKEY keyHandle;
            DWORD dwDisposition;

            result = RegCreateKeyEx(hKey, subKey.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &keyHandle, &dwDisposition);
            if (result != ERROR_SUCCESS)
            {
                return false;
            }

            result = RegSetValueEx(keyHandle, valueName.c_str(), 0, REG_BINARY, reinterpret_cast<const BYTE*>(valueData), dataSize);
            RegCloseKey(keyHandle);

            return (result == ERROR_SUCCESS);
        }
    }
}
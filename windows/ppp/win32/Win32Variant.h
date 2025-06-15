#pragma once

#include <ppp/stdafx.h>

#include <comdef.h>
#include <comutil.h>
#include <Wbemidl.h>

namespace ppp
{
    namespace win32
    {
        bool                       Win32Variant_Callvirt(IWbemServices* services, IWbemClassObject* obj, const _bstr_t& clazz, const _bstr_t& method, ppp::function<bool(IWbemClassObject*)>&& internal_call) noexcept;
         
        inline ppp::string         VARIANT_string(BSTR& bstrVal)
        {
            ppp::string result;
            LPSTR str = _com_util::ConvertBSTRToString(bstrVal);
            if (NULL != str)
            {
                result = str;
                delete[] str;
            }

            SysFreeString(bstrVal);
            return result;
        }
         
        inline ppp::string         VARIANT_string(VARIANT& vt) noexcept
        {
            ppp::string result;
            if (vt.vt & VT_BSTR)
            {
                result = VARIANT_string(vt.bstrVal);
            }

            if (vt.vt != VT_EMPTY)
            {
                VariantClear(&vt);
            }

            return result;
        }
         
        inline ppp::string         VARIANT_string(IWbemClassObject* obj, LPCWSTR name) noexcept
        {
            VARIANT vt;
            VariantInit(&vt);

            HRESULT hr = obj->Get(name, 0, &vt, 0, 0);
            if (SUCCEEDED(hr))
            {
                ppp::string result = VARIANT_string(vt);
                VariantClear(&vt);
                return result;
            }
            else
            {
                VariantClear(&vt);
                return ppp::string();
            }
        }
         
        template <typename T>
        inline T                   VARIANT_value(VARIANT& vt, T defaultValue) noexcept
        {
            if (vt.vt == VT_I1)
            {
                return vt.cVal;
            }

            if (vt.vt == VT_I2)
            {
                return vt.iVal;
            }

            if (vt.vt == VT_I4)
            {
                return vt.intVal;
            }

            if (vt.vt == VT_I8)
            {
                return vt.llVal;
            }

            if (vt.vt == VT_UI1)
            {
                return vt.bVal;
            }

            if (vt.vt == VT_UI2)
            {
                return vt.uiVal;
            }

            if (vt.vt == VT_UI4)
            {
                return vt.uintVal;
            }

            if (vt.vt == VT_UI8)
            {
                return vt.ullVal;
            }

            if (vt.vt == VT_BOOL)
            {
                return vt.boolVal != VARIANT_FALSE ? 1 : 0;
            }

            if (vt.vt == VT_R4)
            {
                return vt.fltVal;
            }

            if (vt.vt == VT_R8)
            {
                return vt.dblVal;
            }

            if (vt.vt == VT_PTR)
            {
                return (int64_t)vt.punkVal;
            }

            if (vt.vt == VT_INT_PTR)
            {
                return vt.intVal;
            }

            if (vt.vt == VT_INT_PTR)
            {
                return vt.uintVal;
            }

            return defaultValue;
        }
         
        template <typename T>
        inline T                   VARIANT_value(IWbemClassObject* obj, LPCWSTR name, T defaultValue) noexcept
        {
            VARIANT vt;
            VariantInit(&vt);

            HRESULT hr = obj->Get(name, 0, &vt, 0, 0);
            if (SUCCEEDED(hr))
            {
                T result = VARIANT_value<T>(vt, defaultValue);
                VariantClear(&vt);
                return result;
            }
            else
            {
                VariantClear(&vt);
                return defaultValue;
            }
        }
         
        template <>
        inline bool                VARIANT_value<bool>(IWbemClassObject* obj, LPCWSTR name, bool defaultValue) noexcept
        {
            int intValue = VARIANT_value<int>(obj, name, 0);
            return intValue != 0;
        }
         
        inline bool                VARIANT_strings(VARIANT& vt, ppp::vector<ppp::string>& strings) noexcept
        {
            bool b = false;
            if (vt.vt & VT_ARRAY) /* SafeArrayDestroy */
            {
                SAFEARRAY* parray = vt.parray;
                if (vt.vt & VT_BSTR)
                {
                    LONG lBound = 0;
                    LONG uBound = 0;

                    SafeArrayGetLBound(parray, 1, &lBound);
                    SafeArrayGetUBound(parray, 1, &uBound);

                    for (LONG i = lBound; i <= uBound; i++)
                    {
                        BSTR bstrIP;
                        HRESULT hr = SafeArrayGetElement(parray, &i, &bstrIP);
                        if (SUCCEEDED(hr))
                        {
                            ppp::string str = VARIANT_string(bstrIP);
                            if (!str.empty())
                            {
                                b |= true;
                                strings.emplace_back(str);
                            }
                        }
                    }
                }
            }

            VariantClear(&vt);
            return b;
        }
         
        inline bool                VARIANT_strings(IWbemClassObject* obj, LPCWSTR name, ppp::vector<ppp::string>& strings) noexcept
        {
            VARIANT vt;
            VariantInit(&vt);

            HRESULT hr = obj->Get(name, 0, &vt, 0, 0);
            if (SUCCEEDED(hr))
            {
                bool b = VARIANT_strings(vt, strings);
                VariantClear(&vt);
                return b;
            }

            VariantClear(&vt);
            return false;
        }
         
        inline HRESULT             VARIANT_create_safe_array(VARIANT& vt, const ppp::vector<ppp::string>& list) noexcept
        {
            LONG length = list.size();
            if (length < 0)
            {
                length = 0;
            }

            SAFEARRAY* sa = SafeArrayCreateVector(VT_BSTR, 0, length);
            vt.vt = VT_ARRAY | VT_BSTR;
            vt.parray = sa;

            HRESULT hr = ERROR_SUCCESS;
            for (LONG i = 0; i < length; i++)
            {
                _bstr_t bstr(list[i].data());
                hr = SafeArrayPutElement(sa, &i, bstr.GetBSTR());
                if (FAILED(hr))
                {
                    break;
                }
            }
            return hr;
        }
         
        template <typename InternalCall>
        inline bool                Callvirt(IWbemServices* services, IWbemClassObject* obj, const _bstr_t& clazz, const _bstr_t& method, InternalCall&& internal_call) noexcept { return Win32Variant_Callvirt(services, obj, clazz, method, internal_call); }
    }
}
#include <windows/ppp/win32/Win32Variant.h>

namespace ppp
{
    namespace win32
    {
        bool Win32Variant_Callvirt(IWbemServices* services, IWbemClassObject* obj, const _bstr_t& clazz, const _bstr_t& method, ppp::function<bool(IWbemClassObject*)>&& internal_call) noexcept
        {
            IWbemClassObject* pClass = NULLPTR;
            IWbemClassObject* pInParamsDefinition = NULLPTR;
            IWbemClassObject* pClassInstance = NULLPTR;
            IWbemClassObject* pOutParams = NULLPTR;

            VARIANT vtPATH;
            VariantInit(&vtPATH);

            VARIANT vtRET;
            VariantInit(&vtRET);

            bool ok = false;
            for (;;)
            {
                HRESULT hr = services->GetObject(clazz, 0, NULLPTR, &pClass, NULLPTR);
                if (FAILED(hr))
                {
                    break;
                }

                hr = pClass->GetMethod(method, 0, &pInParamsDefinition, NULLPTR);
                if (FAILED(hr))
                {
                    break;
                }

                hr = pInParamsDefinition->SpawnInstance(0, &pClassInstance);
                if (FAILED(hr))
                {
                    break;
                }

                hr = internal_call(pClassInstance);
                if (FAILED(hr))
                {
                    break;
                }

                hr = obj->Get(L"__PATH", 0, &vtPATH, NULLPTR, NULLPTR);
                if (FAILED(hr))
                {
                    break;
                }

                hr = services->ExecMethod(
                    vtPATH.bstrVal,
                    method, /* BSTR(L"SetDNSServerSearchOrder") */
                    0,
                    NULLPTR,
                    pClassInstance,
                    &pOutParams,
                    NULLPTR);
                if (FAILED(hr))
                {
                    break; /* SUCCEEDED */
                }

                hr = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &vtRET, NULLPTR, 0);
                if (FAILED(hr))
                {
                    break;
                }

                int err = VARIANT_value(vtRET, 0);
                if (err)
                {
                    break;
                }

                ok = true;
                break;
            }

            if (vtPATH.vt & VT_BSTR)
            {
                SysFreeString(vtPATH.bstrVal);
            }

            if (pOutParams)
            {
                pOutParams->Release();
            }

            if (pClassInstance)
            {
                pClassInstance->Release();
            }

            if (pInParamsDefinition)
            {
                pInParamsDefinition->Release();
            }

            if (pClass)
            {
                pClass->Release();
            }

            VariantClear(&vtRET);
            VariantClear(&vtPATH);
            return ok;
        }
    }
}
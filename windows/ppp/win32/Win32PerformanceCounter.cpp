#include <windows/ppp/win32/Win32PerformanceCounter.h>
#include <windows.h>
#include <pdh.h>

namespace ppp
{
    namespace win32
    {
        PerformanceCounter::PerformanceCounter() noexcept
            : m_phQuery(NULL)
            , m_phCounter(NULL)
        {

        }

        PerformanceCounter::~PerformanceCounter() noexcept
        {
            Release();
        }

        void PerformanceCounter::Open(int pid, LPCSTR counter)
        {
            void* phQuery = NULL;
            if (PdhOpenQueryA(NULL, pid, &phQuery) != ERROR_SUCCESS)
            {
                throw std::exception("The handle to the PerformanceCounter could not be opened.");
            }

            void* phCounter = NULL;
            if (PdhAddCounterA(phQuery, counter, 0, &phCounter) != ERROR_SUCCESS)
            {
                PdhCloseQuery(phCounter);
                throw std::exception("Unable to add a performance counter instance.");
            }
            else
            {
                Release();
            }

            m_phQuery.exchange(phQuery);
            m_phCounter.exchange(phCounter);
        }

        double PerformanceCounter::Next() noexcept
        {
            if (m_phQuery == NULL)
            {
                return 0;
            }
            else
            {
                PdhCollectQueryData(m_phQuery);
            }

            PDH_FMT_COUNTERVALUE counterValue;
            if (PdhGetFormattedCounterValue(m_phCounter, PDH_FMT_DOUBLE, NULL, &counterValue) == ERROR_SUCCESS)
            {
                return counterValue.doubleValue;
            }

            return 0;
        }

        void PerformanceCounter::Dispose() noexcept
        {
            Release();
        }

        void PerformanceCounter::Release() noexcept
        {
            void* phCounter = m_phCounter.exchange(NULL);
            if (NULL != phCounter)
            {
                PdhRemoveCounter(phCounter);
            }

            void* phQuery = m_phQuery.exchange(NULL);
            if (phQuery != NULL)
            {
                PdhCloseQuery(phQuery);
            }
        }
    }
}
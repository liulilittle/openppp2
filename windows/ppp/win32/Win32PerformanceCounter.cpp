#include <windows/ppp/win32/Win32PerformanceCounter.h>
#include <windows.h>
#include <pdh.h>

namespace ppp
{
    namespace win32
    {
        PerformanceCounter::PerformanceCounter() noexcept
            : m_phQuery(NULLPTR)
            , m_phCounter(NULLPTR)
        {

        }

        PerformanceCounter::~PerformanceCounter() noexcept
        {
            Release();
        }

        void PerformanceCounter::Open(int pid, LPCSTR counter)
        {
            void* phQuery = NULLPTR;
            if (PdhOpenQueryA(NULLPTR, pid, &phQuery) != ERROR_SUCCESS)
            {
                throw std::exception("The handle to the PerformanceCounter could not be opened.");
            }

            void* phCounter = NULLPTR;
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
            if (m_phQuery == NULLPTR)
            {
                return 0;
            }
            else
            {
                PdhCollectQueryData(m_phQuery);
            }

            PDH_FMT_COUNTERVALUE counterValue;
            if (PdhGetFormattedCounterValue(m_phCounter, PDH_FMT_DOUBLE, NULLPTR, &counterValue) == ERROR_SUCCESS)
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
            void* phCounter = m_phCounter.exchange(NULLPTR);
            if (NULLPTR != phCounter)
            {
                PdhRemoveCounter(phCounter);
            }

            void* phQuery = m_phQuery.exchange(NULLPTR);
            if (phQuery != NULLPTR)
            {
                PdhCloseQuery(phQuery);
            }
        }
    }
}
#pragma once

#include <ppp/stdafx.h>

namespace ppp
{
    namespace win32
    {
        class PerformanceCounter
        {
        public:
            PerformanceCounter() noexcept;
            virtual ~PerformanceCounter() noexcept;

        public:
            virtual double              Next() noexcept;
            virtual void                Open(int pid, LPCSTR counter);
            virtual void                Dispose() noexcept;

        private:
            void                        Release() noexcept;

        private:
            std::atomic<void*>          m_phQuery   = NULL;
            std::atomic<void*>          m_phCounter = NULL;
        };
    }
}
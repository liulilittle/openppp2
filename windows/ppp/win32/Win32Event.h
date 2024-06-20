#pragma once

#include <ppp/stdafx.h>

namespace ppp
{
    namespace win32
    {
        class Win32Event 
        {
        public:
            Win32Event() noexcept;
            Win32Event(const ppp::string& name, bool initialState, bool openOrCreate) noexcept;
            ~Win32Event() noexcept;

        public:
            bool                WaitOne(int millisecondsTimeout) noexcept;
            bool                WaitOne() noexcept;
            bool                Set() noexcept;
            bool                Reset() noexcept;
            void                Dispose() noexcept;
            void                Open(const ppp::string& name, bool initialState, bool openOrCreate);
            bool                IsValid() noexcept;
            static bool         Exists(const ppp::string& name) noexcept;

        private:
            int                 OpenKernelEventObject(const ppp::string& name, bool initialState, bool openOrCreate) noexcept;

        private:
            std::atomic<void*>  hKrlEvt = NULL;
        };
    }
}
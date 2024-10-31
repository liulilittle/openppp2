#pragma once

#include <ppp/stdafx.h>

#if defined(_WIN32)
#include <windows/ppp/win32/Win32Event.h>
#endif

namespace ppp 
{
    namespace diagnostics 
    {
        class PreventReturn final
        {
        public:
            ~PreventReturn() noexcept;

        public:
            bool                    Exists(const char* name) noexcept;
            bool                    Open(const char* name) noexcept;
            void                    Close() noexcept;

        private:
#if defined(_WIN32)
            ppp::win32::Win32Event  prevent_rerun_;
#else
            int                     pid_file_ = -1;
            ppp::string             pid_path_;
#endif
        };
    }
}
#pragma once

#include <ppp/net/SocketAcceptor.h>

namespace ppp
{
    namespace diagnostics
    {
#if !defined(_ANDROID)
#if !defined(__MUSL__)
        std::string                         CaptureStackTrace(int skip = 0) noexcept;
#endif
        
        bool                                GetKernelVersion(int& kernel, int& major, int& minor, int& patch) noexcept;
        bool                                IfIOUringKernelVersion() noexcept;
#endif

        bool                                Addr2lineIsSupport() noexcept;
        bool                                Addr2lineIsSupportIf() noexcept;
        int                                 GetMaxOpenFileDescriptors() noexcept;
        bool                                SetMaxOpenFileDescriptors(int max_open_file_descriptors) noexcept;
    }
}
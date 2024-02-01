#pragma once

#include <ppp/net/SocketAcceptor.h>

namespace ppp
{
    namespace diagnostics
    {
        bool                                Addr2lineIsSupport() noexcept;
        bool                                Addr2lineIsSupportIf() noexcept;
        std::string                         CaptureStackTrace(int skip = 0) noexcept;
        int                                 GetMaxOpenFileDescriptors() noexcept;
        bool                                SetMaxOpenFileDescriptors(int max_open_file_descriptors) noexcept;
    }
}
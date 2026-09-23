// bench 通用符号桩（BM1a/BM2 共用）：叶子基础设施，斩断 Error/hash/Executors 雪球。
// 绝不进生产构建。
#include <ppp/stdafx.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/io/File.h>
#include <ppp/threading/Executors.h>

namespace ppp {
    int GetHashCode(const void* s, int len) noexcept {
        const unsigned char* p = reinterpret_cast<const unsigned char*>(s);
        uint32_t h = 2166136261u;
        for (int i = 0; i < len && p != NULLPTR; ++i) {
            h ^= p[i];
            h *= 16777619u;
        }
        return static_cast<int>(h);
    }

    ppp::string GuidToString(const boost::uuids::uuid& /*uuid*/) noexcept {
        return ppp::string();
    }

    namespace diagnostics {
        ErrorCode SetLastErrorCode(ErrorCode code) noexcept { return code; }
        ErrorCode GetLastErrorCode() noexcept { return static_cast<ErrorCode>(0); }
    }

    namespace io {
        ppp::string File::GetFullPath(const char* path) noexcept {
            return ppp::string(path != NULLPTR ? path : "");
        }
        ppp::string File::RewritePath(const char* path) noexcept {
            return ppp::string(path != NULLPTR ? path : "");
        }
    }

    namespace threading {
        uint64_t Executors::GetTickCount() noexcept { return 0; }
    }
}

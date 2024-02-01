#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace io {
        enum FileAccess {
            Read                                = 1,
            Write                               = 2,
            ReadWrite                           = 3,
        };

        class File final {
        public:
            static ppp::string                  GetSeparator() noexcept;
            static ppp::string                  GetParentPath(const char* path) noexcept;
            static ppp::string                  GetFileName(const char* path) noexcept;
            static ppp::string                  GetFullPath(const char* path) noexcept;
            static ppp::string                  RewritePath(const char* path) noexcept;
            static bool                         CanAccess(const char* path, FileAccess access_) noexcept;
            static int                          GetLength(const char* path) noexcept;
            static bool                         Exists(const char* path) noexcept;
            static bool                         Delete(const char* path) noexcept;
            static bool                         Create(const char* path, size_t size) noexcept;
            static int                          GetEncoding(const void* p, int length, int& offset) noexcept;
            static bool                         GetAllFileNames(const char* path, bool recursion, ppp::vector<ppp::string>& out) noexcept;
            static bool                         CreateDirectories(const char* path) noexcept;

        public:
            static int                          ReadAllLines(const char* path, ppp::vector<ppp::string>& lines) noexcept;
            static ppp::string                  ReadAllText(const char* path) noexcept;
            static std::shared_ptr<Byte>        ReadAllBytes(const char* path, int& length) noexcept;
            static bool                         WriteAllBytes(const char* path, const void* data, int length) noexcept;
        };
    }
}
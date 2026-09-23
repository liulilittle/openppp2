// BM2 专用桩：用轻量 POSIX 实现 File::Create/Delete + GetMemoryPageSize，
// 避开真实 File.cpp 的 boost::filesystem/Encoding/Win32 雪球。内存池只需要一个
// 能 mmap 的后备文件，POSIX open+ftruncate 足矣。
#include <ppp/stdafx.h>
#include <ppp/io/File.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

namespace ppp {
    int GetMemoryPageSize() noexcept {
        long ps = ::sysconf(_SC_PAGESIZE);
        return ps > 0 ? static_cast<int>(ps) : 4096;
    }

    namespace io {
        bool File::Create(const char* path, size_t size) noexcept {
            if (path == NULLPTR) {
                return false;
            }
            int fd = ::open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
            if (fd < 0) {
                return false;
            }
            bool ok = ::ftruncate(fd, static_cast<off_t>(size)) == 0;
            ::close(fd);
            return ok;
        }

        bool File::Delete(const char* path) noexcept {
            if (path == NULLPTR) {
                return false;
            }
            return ::unlink(path) == 0 || errno == ENOENT;
        }
    }
}

#include <ppp/io/File.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/text/Encoding.h>

#if defined(_WIN32)
#include <windows/ppp/win32/Win32Native.h>
#endif

#include <fstream>
#include <sstream>
#include <iostream>

#include <boost/filesystem.hpp>

namespace ppp {
    namespace io {
        int File::GetLength(const char* path) noexcept {
            if (NULL == path) {
                return ~0;
            }

            FILE* stream = fopen(path, "rb");
            if (NULL == stream) {
                return ~0;
            }

            fseek(stream, 0, SEEK_END);
            long length = ftell(stream);
            fclose(stream);

            return length;
        }

        bool File::Exists(const char* path) noexcept {
            if (NULL == path) {
                return false;
            }

            return access(path, F_OK) == 0;
        }

        bool File::WriteAllBytes(const char* path, const void* data, int length) noexcept {
            if (NULL == path || length < 0) {
                return false;
            }

            if (NULL == data && length != 0) {
                return false;
            }

            FILE* f = fopen(path, "wb+");
            if (NULL == f) {
                return false;
            }

            if (length > 0) {
                fwrite((char*)data, length, 1, f);
            }

            fflush(f);
            fclose(f);
            return true;
        }

        bool File::CanAccess(const char* path, FileAccess access_) noexcept {
#if defined(_WIN32)
            if (NULL == path) {
                return false;
            }

            int flags = 0;
            if ((access_ & FileAccess::ReadWrite) == FileAccess::ReadWrite) {
                flags |= R_OK | W_OK;
            }
            else {
                if (access_ & FileAccess::Read) {
                    flags |= R_OK;
                }
                if (access_ & FileAccess::Write) {
                    flags |= W_OK;
                }
            }
            return access(path, flags) == 0;
#else
            int flags = 0;
            if ((access_ & FileAccess::ReadWrite) == FileAccess::ReadWrite) {
                flags |= O_RDWR;
            }
            else {
                if (access_ & FileAccess::Read) {
                    flags |= O_RDONLY;
                }
                if (access_ & FileAccess::Write) {
                    flags |= O_WRONLY;
                }
            }

            int fd = open(path, flags);
            if (fd == -1) {
                return false;
            }
            else {
                close(fd);
                return true;
            }
#endif
        }

        int File::GetEncoding(const void* p, int length, int& offset) noexcept {
            offset = 0;
            if (NULL == p || length < 3) {
                return ppp::text::Encoding::ASCII;
            }
            // byte[] Unicode = new byte[] { 0xFF, 0xFE, 0x41 };
            // byte[] UnicodeBIG = new byte[] { 0xFE, 0xFF, 0x00 };
            // byte[] UTF8 = new byte[] { 0xEF, 0xBB, 0xBF }; // BOM
            const Byte* s = (Byte*)p;
            if (s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF) {
                offset += 3;
                return ppp::text::Encoding::UTF8;
            }
            elif(s[0] == 0xFE && s[1] == 0xFF && s[2] == 0x00) {
                offset += 3;
                return ppp::text::Encoding::BigEndianUnicode;
            }
            elif(s[0] == 0xFF && s[1] == 0xFE && s[2] == 0x41) {
                offset += 3;
                return ppp::text::Encoding::Unicode;
            }
            else {
                return ppp::text::Encoding::ASCII;
            }
        }

        ppp::string File::ReadAllText(const char* path) noexcept {
            int file_length = 0;
            std::shared_ptr<Byte> file_content = File::ReadAllBytes(path, file_length);
            if (file_length < 0) {
                return "";
            }

            char* file_content_memory = (char*)file_content.get();
            if (file_length == 0) {
                return "";
            }
            else {
                int file_offset;
                File::GetEncoding(file_content_memory, file_length, file_offset);

                file_length -= file_offset;
                file_content_memory += file_offset;
            }

            return ppp::string(file_content_memory, file_length);
        }

        std::shared_ptr<Byte> File::ReadAllBytes(const char* path, int& length) noexcept {
            length = ~0;
            if (NULL == path) {
                return NULL;
            }

            FILE* file_ = fopen(path, "rb"); // Oracle Cloud Shells Compatibility...
            if (!file_) {
                return NULL;
            }

            MemoryStream stream_;
            char buff_[1400];
            for (;;) {
                size_t count_ = fread(buff_, 1, sizeof(buff_), file_);
                if (count_ == 0) {
                    break;
                }

                stream_.Write(buff_, 0, count_);
            }

            fclose(file_);
            length = stream_.GetPosition();
            return stream_.GetBuffer();
        }

        ppp::string File::GetSeparator() noexcept {
#if defined(_WIN32)
            return "\\";
#else
            return "/";
#endif
        }

        ppp::string File::RewritePath(const char* path) noexcept {
            ppp::string rewrite_path;
            if (NULL != path && *path != '\x0') {
                rewrite_path = path;
            }

            if (rewrite_path.empty()) {
                rewrite_path = "./";
            }

#if defined(_WIN32)
            rewrite_path = Replace<ppp::string>(rewrite_path, "/", "\\");
            rewrite_path = Replace<ppp::string>(rewrite_path, "\\\\", "\\");
#else
            rewrite_path = Replace<ppp::string>(rewrite_path, "\\", "/");
            rewrite_path = Replace<ppp::string>(rewrite_path, "//", "/");
#endif
            return rewrite_path;
        }

        ppp::string File::GetFullPath(const char* path) noexcept {
            if (NULL == path || *path == '\x0') {
                path = "./";
            }

#if defined(_WIN32)
            return ppp::win32::Win32Native::GetFullPath(path);
#else
            /* https://man7.org/linux/man-pages/man3/realpath.3.html */
            char* resolved_path = (char*)::realpath(path, NULL);
            if (NULL != resolved_path) {
                ppp::string fullpath_string = resolved_path;
                ::free(resolved_path);
                return fullpath_string;
            }

            ppp::string dir = path;
            ppp::vector<ppp::string> segments;
            for (;;) {
                std::size_t index = dir.rfind('/');
                if (index == ppp::string::npos) {
                    index = dir.rfind('\\');
                    if (index == ppp::string::npos) {
                        break;
                    }
                }

                ppp::string seg = dir.substr(index + 1);
                if (seg.size() > 0) {
                    segments.emplace_back(seg);
                }

                dir = dir.substr(0, index);
                if (dir.empty()) {
                    break;
                }

                resolved_path = (char*)::realpath(dir.data(), NULL);
                if (NULL == resolved_path) {
                    continue;
                }

                ppp::string fullpath_string = resolved_path;
                ::free(resolved_path);

                for (ppp::string& i : segments) fullpath_string.append("/" + i);
                return RewritePath(fullpath_string.data());
            }
            return "";
#endif
        }

        int File::ReadAllLines(const char* path, ppp::vector<ppp::string>& lines) noexcept {
            ppp::string content = ppp::io::File::ReadAllText(path);
            if (content.empty()) {
                return 0;
            }

            return Tokenize<ppp::string>(content, lines, "\r\n");
        }

        bool File::Delete(const char* path) noexcept {
            if (NULL == path || *path == '\x0') {
                return false;
            }

            ppp::string fullpath = GetFullPath(RewritePath(path).data());
            if (fullpath.empty()) {
                return false;
            }

#if defined(_WIN32)
            return ::DeleteFileA(fullpath.data());
#else
            return ::unlink(fullpath.data()) > -1;
#endif
        }

        bool File::Create(const char* path, size_t size) noexcept {
            if (NULL == path || *path == '\x0') {
                return false;
            }
            else {
                ppp::io::File::Delete(path);
            }

            std::ofstream ofs(path, std::ios::binary);
            if (ofs.is_open()) {
                ofs.seekp(size - 1);
                ofs.write("", 1);
                ofs.close();
                return true;
            }
            else {
                return false;
            }
        }

        template <class TDirectoryIterator>
        static bool FILE_GetAllFileNames(const char* path, ppp::vector<ppp::string>& out) noexcept {
            if (NULL == path || *path == '\x0') {
                return false;
            }

            try {
                boost::filesystem::path dir(path);
                TDirectoryIterator endl{};
                TDirectoryIterator tail(dir);
                for (; tail != endl; tail++) {
                    auto& entry = *tail;
                    if (boost::filesystem::is_regular_file(entry)) {
                        out.emplace_back(entry.path().string());
                    }
                }
                return true;
            }
            catch (const std::exception&) {
                return false;
            }
        }

        bool File::GetAllFileNames(const char* path, bool recursion, ppp::vector<ppp::string>& out) noexcept {
            if (recursion) {
                return FILE_GetAllFileNames<boost::filesystem::recursive_directory_iterator>(path, out);
            }
            else {
                return FILE_GetAllFileNames<boost::filesystem::directory_iterator>(path, out);
            }
        }

        bool File::CreateDirectories(const char* path) noexcept {
            if (NULL == path || *path == '\x0') {
                return false;
            }

            boost::filesystem::path dir(path);
            boost::system::error_code ec;
            try {
                if (boost::filesystem::is_directory(dir, ec)) {
                    return ec == boost::system::errc::success;
                }

                if (boost::filesystem::create_directories(dir, ec)) {
                    return ec == boost::system::errc::success;
                }
            }
            catch (const std::exception&) {}
            return false;
        }

        ppp::string File::GetParentPath(const char* path) noexcept {
            ppp::string s = File::GetFullPath(File::RewritePath(path).data());
            if (s.empty()) {
                return "";
            }

            ppp::string separator = File::GetSeparator();
            std::size_t i = s.rfind(separator);
            if (i == ppp::string::npos) {
                return s;
            }

            return s.substr(0, i);
        }

        ppp::string File::GetFileName(const char* path) noexcept {
            ppp::string s = File::GetFullPath(File::RewritePath(path).data());
            if (s.empty()) {
                return "";
            }

            ppp::string separator = File::GetSeparator();
            std::size_t i = s.rfind(separator);
            if (i == ppp::string::npos) {
                return s;
            }

            return s.substr(i + separator.size());
        }
    }
}

#include <ppp/io/File.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/text/Encoding.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file File.cpp
 * @brief Implements cross-platform file and path utility helpers.
 */

#if defined(_WIN32)
#include <windows/ppp/win32/Win32Native.h>
#endif

#include <fstream>
#include <sstream>
#include <iostream>
#include <limits.h>
#if defined(_IPHONE)
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#else
#include <boost/filesystem.hpp>
#endif

namespace ppp {
    namespace io {
#if defined(_IPHONE)
        static bool FILE_IsDirectory(const char* path) noexcept {
            struct stat st;
            return path != NULLPTR && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
        }

        static bool FILE_IsRegularFile(const char* path) noexcept {
            struct stat st;
            return path != NULLPTR && stat(path, &st) == 0 && S_ISREG(st.st_mode);
        }
#endif

        /**
         * @brief Gets file length in bytes.
         * @param path File path.
         * @return File size, or `~0` when unavailable.
         */
        int File::GetLength(const char* path) noexcept {
            if (NULLPTR == path) {
                return ppp::diagnostics::SetLastError<int>(ppp::diagnostics::ErrorCode::FilePathInvalid);
            }

            FILE* stream = fopen(path, "rb");
            if (NULLPTR == stream) {
                return ppp::diagnostics::SetLastError<int>(ppp::diagnostics::ErrorCode::FileOpenFailed);
            }

            fseek(stream, 0, SEEK_END);
            long length = ftell(stream);
            fclose(stream);

            return length;
        }

        /**
         * @brief Checks whether a regular file exists.
         * @param path File path.
         * @return `true` when file exists and is not a directory.
         */
        bool File::Exists(const char* path) noexcept {
            if (NULLPTR == path) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FilePathInvalid);
                return false;
            }

#if defined(_IPHONE)
            if (FILE_IsDirectory(path)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FileIsDirectory);
                return false;
            }
#else
            boost::system::error_code ec;
            if (boost::filesystem::is_directory(boost::filesystem::path(path), ec)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FileIsDirectory);
                return false;
            }

            if (ec) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FileStatFailed);
                return false;
            }
#endif

            if (access(path, F_OK) == 0) {
                return true;
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FileNotFound);
            return false;
        }

        /**
         * @brief Writes binary content to a file.
         * @param path Destination file path.
         * @param data Source buffer.
         * @param length Number of bytes to write.
         * @return `true` on success.
         */
        bool File::WriteAllBytes(const char* path, const void* data, int length) noexcept {
            if (NULLPTR == path || length < 0) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
            }

            if (NULLPTR == data && length != 0) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryBufferNull);
            }

            FILE* f = fopen(path, "wb+");
            if (NULLPTR == f) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileOpenFailed);
            }

            if (length > 0) {
                if (fwrite((char*)data, length, 1, f) != 1) {
                    fclose(f);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileWriteFailed);
                }
            }

            if (fflush(f) != 0) {
                fclose(f);
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileFlushFailed);
            }

            fclose(f);
            return true;
        }

        /**
         * @brief Tests whether a file can be opened with requested access.
         * @param path File path.
         * @param access_ Requested access flags.
         * @return `true` when access check succeeds.
         */
        bool File::CanAccess(const char* path, FileAccess access_) noexcept {
#if defined(_WIN32)
            if (NULLPTR == path) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
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
            if (NULLPTR == path) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
            }

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
                ppp::diagnostics::SetLastErrorCode(errno == EACCES ? ppp::diagnostics::ErrorCode::FileAccessDenied :
                    errno == ENOENT ? ppp::diagnostics::ErrorCode::FileNotFound :
                    ppp::diagnostics::ErrorCode::FileOpenFailed);
                return false;
            }
            else {
                close(fd);
                return true;
            }
#endif
        }

        /**
         * @brief Detects encoding from initial byte markers.
         * @param p Input byte buffer.
         * @param length Buffer length.
         * @param offset Receives number of leading marker bytes consumed.
         * @return One value from `ppp::text::Encoding` constants.
         */
        int File::GetEncoding(const void* p, int length, int& offset) noexcept {
            offset = 0;
            if (NULLPTR == p || length < 3) {
                return ppp::text::Encoding::ASCII;
            }
            
            /** Check common BOM signatures to determine text encoding. */
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

        /**
         * @brief Reads a full file as text and strips detected BOM bytes.
         * @param path File path.
         * @return File content as string, or empty string on failure.
         */
        ppp::string File::ReadAllText(const char* path) noexcept {
            int file_length = 0;
            std::shared_ptr<Byte> file_content = File::ReadAllBytes(path, file_length);
            if (file_length < 0) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileReadFailed, ppp::string());
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

        /** @brief Upper bound (64 MiB) for File::ReadAllBytes; larger files are rejected. */
        static constexpr size_t MAX_READ_ALL_BYTES_LENGTH = 64u * 1024u * 1024u;

        /**
         * @brief Reads all bytes from a file into memory.
         * @param path File path.
         * @param length Receives number of bytes read; `~0` when failed.
         * @return Shared byte buffer containing file data.
         */
        std::shared_ptr<Byte> File::ReadAllBytes(const char* path, int& length) noexcept {
            length = ~0;
            if (NULLPTR == path) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid, std::shared_ptr<Byte>());
            }

            FILE* file_ = fopen(path, "rb"); // Oracle Cloud Shells Compatibility...
            if (!file_) {
                return ppp::diagnostics::SetLastError(errno == EACCES ? ppp::diagnostics::ErrorCode::FileAccessDenied :
                    errno == ENOENT ? ppp::diagnostics::ErrorCode::FileNotFound :
                    ppp::diagnostics::ErrorCode::FileOpenFailed, std::shared_ptr<Byte>());
            }

            MemoryStream stream_;
            char buff_[1400];
            size_t total_ = 0;

            /** Read in chunks to avoid allocating based on uncertain file size. */
            for (;;) {
                size_t count_ = fread(buff_, 1, sizeof(buff_), file_);
                if (count_ == 0) {
                    if (ferror(file_)) {
                        fclose(file_);
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileReadFailed, std::shared_ptr<Byte>());
                    }

                    break;
                }

                total_ += count_;
                if (total_ > MAX_READ_ALL_BYTES_LENGTH) {
                    fclose(file_);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileReadFailed, std::shared_ptr<Byte>());
                }

                stream_.Write(buff_, 0, count_);
            }

            fclose(file_);
            
            length = stream_.GetPosition();
            return stream_.GetBuffer();
        }

        /**
         * @brief Returns platform-specific directory separator.
         * @return "\\" on Windows, otherwise "/".
         */
        ppp::string File::GetSeparator() noexcept {
#if defined(_WIN32)
            return "\\";
#else
            return "/";
#endif
        }

        /**
         * @brief Normalizes a path string for current platform conventions.
         * @param path Input path.
         * @return Rewritten path prefixed with relative marker when needed.
         */
        ppp::string File::RewritePath(const char* path) noexcept {
            ppp::string rewrite_path;
            if (NULLPTR != path && *path != '\x0') {
                rewrite_path = path;
            }

            rewrite_path = RTrim(LTrim(rewrite_path));
            if (rewrite_path.empty()) {
                rewrite_path = "./";
            }

#if defined(_WIN32)
            /** Convert to Windows separators and collapse duplicates. */
            rewrite_path = Replace<ppp::string>(rewrite_path, "/", "\\");
            rewrite_path = Replace<ppp::string>(rewrite_path, "\\\\", "\\");
            
            int ch = *rewrite_path.data();
            if (ch != '.' && rewrite_path.find(':') == ppp::string::npos) {
                rewrite_path = ".\\" + rewrite_path;
            }
#else
            /** Convert to Unix separators and collapse duplicates. */
            rewrite_path = Replace<ppp::string>(rewrite_path, "\\", "/");
            rewrite_path = Replace<ppp::string>(rewrite_path, "//", "/");

            int ch = *rewrite_path.data();
            if (ch != '/' && ch != '.') {
                rewrite_path = "./" + rewrite_path;
            }
#endif
            return rewrite_path;
        }

        /**
         * @brief Resolves an absolute path where possible.
         * @param path Input path.
         * @return Full path string, or empty string when unresolved.
         */
        ppp::string File::GetFullPath(const char* path) noexcept {
            if (NULLPTR == path || *path == '\x0') {
                path = "./";
            }

            ppp::string path_new = RewritePath(path);
            if (path_new.empty()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid, ppp::string());
            }

#if defined(_WIN32)            
            return ppp::win32::Win32Native::GetFullPath(path_new.data());
#else
            /* Keep realpath output on our stack; Darwin system allocation must not be released through jemalloc. */
            char resolved_path[PATH_MAX + 1];
            resolved_path[PATH_MAX] = '\x0';
            if (NULLPTR != ::realpath(path_new.data(), resolved_path)) {
                return resolved_path;
            }

            ppp::string dir = path_new;
            ppp::vector<ppp::string> segments;
            /**
             * Walk upward until a resolvable parent is found, then append skipped tail segments.
             */
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

                if (NULLPTR == ::realpath(dir.data(), resolved_path)) {
                    continue;
                }

                ppp::string fullpath_string = resolved_path;

                for (ppp::string& i : segments) {
                    fullpath_string.append("/" + i);
                }

                return RewritePath(fullpath_string.data());
            }
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid, ppp::string());
#endif
        }

        /**
         * @brief Reads all lines from a text file.
         * @param path File path.
         * @param lines Output container for lines.
         * @return Number of tokens appended to `lines`.
         */
        int File::ReadAllLines(const char* path, ppp::vector<ppp::string>& lines) noexcept {
            ppp::string content = ppp::io::File::ReadAllText(path);
            if (content.empty()) {
                return 0;
            }

            return Tokenize<ppp::string>(content, lines, "\r\n");
        }

        /**
         * @brief Deletes a file from disk.
         * @param path File path.
         * @return `true` when deletion succeeds.
         */
        bool File::Delete(const char* path) noexcept {
            if (NULLPTR == path || *path == '\x0') {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
            }

            ppp::string fullpath = RewritePath(path);
            if (fullpath.empty()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
            }

#if defined(_WIN32)
            BOOL deleted = ::DeleteFileA(fullpath.data());
            if (!deleted) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileDeleteFailed);
            }

            return true;
#else
            if (::unlink(fullpath.data()) > -1) {
                return true;
            }

            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileDeleteFailed);
#endif
        }

        /**
         * @brief Creates a new file with specified byte size.
         * @param path File path.
         * @param size Target file size.
         * @return `true` when file creation and resize succeed.
         */
        bool File::Create(const char* path, size_t size) noexcept {
            if (NULLPTR == path || *path == '\x0') {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
            }

            if (ppp::io::File::Exists(path)) {
                ::remove(path);
            }

            std::ofstream ofs(path, std::ios::binary);
            if (ofs.is_open()) {
                ofs.seekp(size - 1);
                ofs.write("", 1);
                ofs.close();
                return true;
            }
            else {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileCreateFailed);
            }
        }

#if defined(_IPHONE)
        static bool FILE_GetAllFileNames(const char* path, bool recursion, ppp::vector<ppp::string>& out) noexcept {
            if (NULLPTR == path || *path == '\x0') {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
            }

            DIR* dir = opendir(path);
            if (dir == NULLPTR) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileDirectoryEnumerateFailed);
            }

            bool ok = true;
            while (struct dirent* entry = readdir(dir)) {
                const char* name = entry->d_name;
                if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                    continue;
                }

                ppp::string fullpath = path;
                if (!fullpath.empty() && fullpath.back() != '/') {
                    fullpath.push_back('/');
                }
                fullpath.append(name);

                if (FILE_IsRegularFile(fullpath.data())) {
                    out.emplace_back(fullpath);
                }
                else if (recursion && FILE_IsDirectory(fullpath.data())) {
                    if (!FILE_GetAllFileNames(fullpath.data(), recursion, out)) {
                        ok = false;
                        break;
                    }
                }
            }

            closedir(dir);
            return ok;
        }
#else
        template <class TDirectoryIterator>
        /**
         * @brief Collects regular file names from a directory iterator type.
         * @tparam TDirectoryIterator Iterator type (recursive or non-recursive).
         * @param path Directory path.
         * @param out Output file path list.
         * @return `true` when traversal succeeds.
         */
        static bool FILE_GetAllFileNames(const char* path, ppp::vector<ppp::string>& out) noexcept {
            if (NULLPTR == path || *path == '\x0') {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
            }

            try {
                boost::filesystem::path dir(path);
                boost::system::error_code ec;
                TDirectoryIterator endl{};
                TDirectoryIterator tail(dir, ec);
                if (ec) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileDirectoryEnumerateFailed);
                }
                /** Iterate each entry and keep regular files only. */
                for (; tail != endl; tail.increment(ec)) {
                    if (ec) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileDirectoryEnumerateFailed);
                    }

                    auto& entry = *tail;
                    if (boost::filesystem::is_regular_file(entry.path(), ec) && !ec) {
                        out.emplace_back(entry.path().string());
                    }
                    ec.clear();
                }
                
                return true;
            }
            catch (const std::exception&) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileDirectoryEnumerateFailed);
            }
        }
#endif

        /**
         * @brief Lists file names in a directory, optionally recursively.
         * @param path Directory path.
         * @param recursion `true` for recursive traversal.
         * @param out Output file path list.
         * @return `true` when traversal succeeds.
         */
        bool File::GetAllFileNames(const char* path, bool recursion, ppp::vector<ppp::string>& out) noexcept {
#if defined(_IPHONE)
            return FILE_GetAllFileNames(path, recursion, out);
#else
            if (recursion) {
                return FILE_GetAllFileNames<boost::filesystem::recursive_directory_iterator>(path, out);
            }
            else {
                return FILE_GetAllFileNames<boost::filesystem::directory_iterator>(path, out);
            }
#endif
        }

        /**
         * @brief Creates directory hierarchy represented by `path`.
         * @param path Directory path.
         * @return `true` if directory already exists or creation succeeds.
         */
        bool File::CreateDirectories(const char* path) noexcept {
            if (NULLPTR == path || *path == '\x0') {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
            }

#if defined(_IPHONE)
            if (FILE_IsDirectory(path)) {
                return true;
            }

            ppp::string current;
            const char* cursor = path;
            if (*cursor == '/') {
                current = "/";
                ++cursor;
            }

            while (*cursor != '\x0') {
                const char* next = strchr(cursor, '/');
                if (next == cursor) {
                    ++cursor;
                    continue;
                }

                if (!current.empty() && current.back() != '/') {
                    current.push_back('/');
                }
                current.append(cursor, next == NULLPTR ? strlen(cursor) : static_cast<size_t>(next - cursor));

                if (!FILE_IsDirectory(current.data()) && mkdir(current.data(), 0755) != 0 && errno != EEXIST) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileDirectoryCreateFailed);
                }

                if (next == NULLPTR) {
                    break;
                }
                cursor = next + 1;
            }

            return FILE_IsDirectory(path) || ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileDirectoryCreateFailed);
#else
            boost::filesystem::path dir(path);
            boost::system::error_code ec;
            try {
                if (boost::filesystem::is_directory(dir, ec)) {
                    return !ec;
                }

                if (boost::filesystem::create_directories(dir, ec)) {
                    return !ec;
                }
            }
            catch (const std::exception&) {}
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileDirectoryCreateFailed);
#endif
        }

        /**
         * @brief Returns parent directory part of a path.
         * @param path Input path.
         * @return Parent path string, or empty string if invalid.
         */
        ppp::string File::GetParentPath(const char* path) noexcept {
            ppp::string s = File::RewritePath(path);
            if (s.empty()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid, ppp::string());
            }

            ppp::string separator = File::GetSeparator();
            std::size_t i = s.rfind(separator);
            if (i == ppp::string::npos) {
                return s;
            }

            return s.substr(0, i);
        }

        /**
         * @brief Returns filename part of a path.
         * @param path Input path.
         * @return File name string, or empty string if invalid.
         */
        ppp::string File::GetFileName(const char* path) noexcept {
            ppp::string s = File::File::RewritePath(path);
            if (s.empty()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid, ppp::string());
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

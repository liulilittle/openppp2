#pragma once

#if defined(__ANDROID__) || defined(_ANDROID)
#include <boost/filesystem.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <string>

namespace ppp::filesystem {
namespace fs = boost::filesystem;
using error_code = boost::system::error_code;

inline bool IsNotFound(const error_code& error) {
    return error == boost::system::errc::make_error_code(boost::system::errc::no_such_file_or_directory);
}

inline bool IsNotFound(fs::file_type type) {
    return type == fs::file_not_found;
}

inline std::string StreamPath(const fs::path& path) {
    return path.string();
}
}
#else
#include <filesystem>

namespace ppp::filesystem {
namespace fs = std::filesystem;
using error_code = std::error_code;

inline bool IsNotFound(const error_code& error) {
    return error == std::errc::no_such_file_or_directory;
}

inline bool IsNotFound(fs::file_type type) {
    return type == fs::file_type::not_found;
}

inline const fs::path& StreamPath(const fs::path& path) {
    return path;
}
}
#endif

#include <ppp/diagnostics/PreventReturn.h>
#include <ppp/io/File.h>
#include <ppp/cryptography/EVP.h>

#if !defined(_WIN32)
#include <iostream>
#include <fstream>

#include <fcntl.h>
#include <unistd.h>

#if defined(_LINUX)
#include <sys/file.h>
#endif
#endif

namespace ppp
{
    namespace diagnostics
    {
        static ppp::string NameTransform(const char* name) noexcept
        {
            if (NULL == name || *name == '\x0')
            {
                return ppp::string();
            }

            ppp::string result = ppp::cryptography::ComputeMD5(name, false);
            if (result.empty()) 
            {
                return ppp::string();
            }

            result = BOOST_BEAST_VERSION_STRING + ppp::string(".") + result;
            return result;
        }

        PreventReturn::~PreventReturn() noexcept
        {
            Close();
        }

#if defined(_WIN32)
        void PreventReturn::Close() noexcept
        {
            prevent_rerun_.Dispose();
        }

        bool PreventReturn::Exists(const char* name) noexcept
        {
            ppp::string name_string = NameTransform(name);
            if (name_string.empty())
            {
                return false;
            }

            return prevent_rerun_.Exists(name_string.data());
        }

        bool PreventReturn::Open(const char* name) noexcept
        {
            ppp::string name_string = NameTransform(name);
            if (name_string.empty())
            {
                return false;
            }

            try
            {
                prevent_rerun_.Open(name_string.data(), false, false);
                return true;
            }
            catch (const std::exception&)
            {
                return false;
            }
        }
#else
        // warning: anonymous non-C-compatible type given name for linkage purposes by typedef declaration; add a tag name here [-Wnon-c-typedef-for-linkage]
        // note: type is not C-compatible due to this default member initializer
        // note: type is given name 'FLOCK' for linkage purposes by this typedef declaration
        struct FLOCK
        {
            int                                     fd   = -1;
            ppp::string                             path;
            bool                                    open = false;
        };

        static FLOCK                                FLOCK_OPEN(const char* name) noexcept
        {
            if (NULL == name || *name == '\x0')
            {
                return { -1, "", false };
            }

#if defined(_MACOS)
            ppp::string path = ppp::io::File::GetFullPath(("/tmp/" + ppp::string(name) + ".pid").data());
#else
            ppp::string path = ppp::io::File::GetFullPath(("/var/run/" + ppp::string(name) + ".pid").data());
#endif

            int pid_file = open(path.data(), O_CREAT | O_RDWR, 0666);
            if (pid_file == -1)
            {
                return { -1, path, false };
            }

            if (flock(pid_file, LOCK_EX | LOCK_NB) < 0)
            {
                close(pid_file);
                return { -1, path, true };
            }

            return { pid_file, path, true };
        }

        static bool                                 FLOCK_CLOSE(const char* path, int pid_file) noexcept
        {
            if (NULL == path || *path == '\x0')
            {
                return false;
            }

            if (pid_file == -1)
            {
                return false;
            }

            flock(pid_file, LOCK_UN);
            close(pid_file);

            return unlink(path) > -1;
        }

        void PreventReturn::Close() noexcept
        {
            if (FLOCK_CLOSE(pid_path_.data(), pid_file_))
            {
                pid_file_ = -1;
                pid_path_.clear();
            }
        }

        bool PreventReturn::Exists(const char* name) noexcept
        {
            ppp::string name_string = NameTransform(name);
            if (name_string.empty())
            {
                return false;
            }

            FLOCK f = FLOCK_OPEN(name_string.data());
            if (f.fd == -1)
            {
                return f.open;
            }

            return !FLOCK_CLOSE(f.path.data(), f.fd);
        }

        bool PreventReturn::Open(const char* name) noexcept
        {
            ppp::string name_string = NameTransform(name);
            if (name_string.empty())
            {
                return false;
            }

            FLOCK f = FLOCK_OPEN(name_string.data());
            if (f.fd == -1)
            {
                return false;
            }

            pid_file_ = f.fd;
            pid_path_ = f.path;
            return true;
        }
#endif
    }
}
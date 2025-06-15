#pragma once

#include <ppp/stdafx.h>

namespace ppp
{
    namespace win32
    {
        class Win32Mci final
        {
        public:
            enum class PlayState
            {
                Closed,
                Stopped,
                Paused,
                Playing,
                NotReady,
                Open,
                Recording,
                Parked,
                Seeking,
            };

        public:
            explicit Win32Mci(const ppp::string& path);
            ~Win32Mci() noexcept;

        public:
            void                                    Play();
            void                                    Stop();
            void                                    Pause();
            void                                    Resume();
            void                                    Seek(int64_t offset, uint32_t loc);
            void                                    SetVolume(int volume);
            int64_t                                 Position() const;
            int64_t                                 Length() const;
            PlayState                               State() const;
            void                                    SetRepeat(bool repeat);
            void                                    Dispose() noexcept;

        private:
            ppp::string                             Command(const ppp::string& command) const;
            bool                                    PlayCommand(const ppp::string& command) const;

        private:
            ppp::string                             path_;
            ppp::string                             alias_;
            bool                                    Repeat_ = false;
        };
    }
}
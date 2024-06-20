#include <windows/ppp/win32/Win32Mci.h>
#include <ppp/stdafx.h>

#include <Windows.h>
#include <mmsystem.h>

#include <string>
#include <stdexcept>

namespace ppp
{
    namespace win32
    {
        Win32Mci::Win32Mci(const ppp::string& path)
            : Repeat_(false)
        {
            alias_ = "mci-" + stl::to_string<ppp::string>(ppp::GetTickCount()) + "-" + stl::to_string<ppp::string>(ppp::RandomNext());
            if (!path.empty())
            {
                path_ = path;
            }
            else
            {
                throw std::invalid_argument("Path is empty.");
            }

            ppp::string command = "open \"" + path_ + "\" type mpegvideo alias " + alias_;
            if (!PlayCommand(command))
            {
                throw std::runtime_error("Failed to open audio file.");
            }
        }

        Win32Mci::~Win32Mci() noexcept
        {
            Dispose();
        }

        void Win32Mci::Play()
        {
            if (Repeat_)
            {
                PlayCommand("play " + alias_ + " repeat");
            }
            else
            {
                PlayCommand("play " + alias_);
            }
        }

        void Win32Mci::Stop()
        {
            PlayCommand("stop " + alias_);
        }

        void Win32Mci::Pause()
        {
            PlayCommand("pause " + alias_);
        }

        void Win32Mci::Resume()
        {
            PlayCommand("resume " + alias_);
        }

        void Win32Mci::Seek(int64_t offset, uint32_t loc)
        {
            int64_t position = 0;

            switch (loc)
            {
            case SEEK_SET:
                position = offset;
                break;
            case SEEK_CUR:
                position = Position() + offset;
                break;
            case SEEK_END:
                position = Length() + offset;
                break;
            default:
                throw std::invalid_argument("Invalid seek origin.");
            }

            PlayCommand("seek " + alias_ + " to " + stl::to_string<ppp::string>(position));
        }

        void Win32Mci::SetVolume(int volume)
        {
            int vol = std::min(volume, 1000);
            if (vol < 0)
            {
                vol = 0;
            }

            PlayCommand("setaudio " + alias_ + " volume to " + stl::to_string<ppp::string>(vol));
        }

        int64_t Win32Mci::Position() const
        {
            ppp::string result = Command("status " + alias_ + " position");
            return atoll(result.data()); // std::stoll(result);
        }

        int64_t Win32Mci::Length() const
        {
            ppp::string result = Command("status " + alias_ + " length");
            return atoll(result.data()); // std::stoll(result);
        }

        Win32Mci::PlayState Win32Mci::State() const
        {
            ppp::string result = Command("status " + alias_ + " mode");
            ppp::string mode = result.empty() ? "" : result.substr(0, result.find_first_of("\r\n"));

            if (mode == "stopped")
            {
                return PlayState::Stopped;
            }
            else if (mode == "paused")
            {
                return PlayState::Paused;
            }
            else if (mode == "playing")
            {
                return PlayState::Playing;
            }
            else if (mode == "not ready")
            {
                return PlayState::NotReady;
            }
            else if (mode == "open")
            {
                return PlayState::Open;
            }
            else if (mode == "recording")
            {
                return PlayState::Recording;
            }
            else if (mode == "parked")
            {
                return PlayState::Parked;
            }
            else if (mode == "seeking")
            {
                return PlayState::Seeking;
            }

            return PlayState::Closed;
        }

        void Win32Mci::SetRepeat(bool repeat)
        {
            Repeat_ = repeat;

            if (State() == PlayState::Playing || State() == PlayState::Paused)
            {
                Seek(0, SEEK_SET);
                Play();
                if (State() == PlayState::Paused)
                {
                    Pause();
                }
            }
        }

        ppp::string Win32Mci::Command(const ppp::string& command) const
        {
            const DWORD bufferSize = 1000;
            char buffer[bufferSize] = { 0 };

            if (mciSendStringA(command.data(), buffer, bufferSize, NULL) != MMSYSERR_NOERROR)
            {
                throw std::runtime_error("MCI command failed.");
            }

            return buffer;
        }

        bool Win32Mci::PlayCommand(const ppp::string& command) const
        {
            MCIERROR err = mciSendStringA(command.data(), NULL, 0, NULL);
            return err == MMSYSERR_NOERROR;
        }

        void Win32Mci::Dispose() noexcept
        {
            PlayCommand("close " + alias_);
        }
    }
}
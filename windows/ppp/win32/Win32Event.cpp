#include <windows/ppp/win32/Win32Event.h>

#include <iostream>
#include <exception>
#include <string>

#include <Windows.h>

namespace ppp
{
    namespace win32
    {
        Win32Event::Win32Event() noexcept
            : hKrlEvt(NULL)
        {

        }

        Win32Event::Win32Event(const ppp::string& name, bool initialState, bool openOrCreate) noexcept
            : Win32Event()
        {
            OpenKernelEventObject(name, initialState, openOrCreate);
        }

        void Win32Event::Open(const ppp::string& name, bool initialState, bool openOrCreate)
        {
            int err = OpenKernelEventObject(name, initialState, openOrCreate);
            if (err < 0)
            {
                throw std::invalid_argument(name.data());
            }
            else if (err > 0)
            {
                throw std::runtime_error("Cannot create or open kernel event synchronization object. It may be because the event name has been used or the name string is incorrect.");
            }
        }

        int Win32Event::OpenKernelEventObject(const ppp::string& name, bool initialState, bool openOrCreate) noexcept
        {
            HANDLE h = hKrlEvt.exchange(NULL);
            if (NULL != h)
            {
                CloseHandle(h);
            }

            if (name.empty())
            {
                return -1;
            }

            hKrlEvt = OpenEventA(EVENT_ALL_ACCESS, FALSE, name.c_str());
            if (NULL == hKrlEvt)
            {
                if (openOrCreate)
                {
                    return -1;
                }

                if (initialState)
                {
                    hKrlEvt = CreateEventA(NULL, FALSE, TRUE, name.c_str());
                }
                else
                {
                    hKrlEvt = CreateEventA(NULL, TRUE, FALSE, name.c_str());
                }
            }

            return NULL != hKrlEvt ? 0 : 1;
        }

        Win32Event::~Win32Event() noexcept
        {
            Dispose();
        }

        void Win32Event::Dispose() noexcept
        {
            HANDLE h = hKrlEvt.exchange(NULL);
            if (NULL != h)
            {
                CloseHandle(h);
            }
        }

        bool Win32Event::WaitOne(int millisecondsTimeout) noexcept
        {
            HANDLE h = hKrlEvt.load();
            if (NULL == h)
            {
                return false;
            }
            return WaitForSingleObject(hKrlEvt, millisecondsTimeout) == WAIT_OBJECT_0;
        }

        bool Win32Event::WaitOne() noexcept
        {
            return WaitOne(INFINITE);
        }

        bool Win32Event::Set() noexcept
        {
            HANDLE h = hKrlEvt.load();
            if (NULL == h)
            {
                return false;
            }
            return SetEvent(h);
        }

        bool Win32Event::Reset() noexcept
        {
            HANDLE h = hKrlEvt.load();
            if (NULL == h)
            {
                return false;
            }
            return ResetEvent(h);
        }

        bool Win32Event::IsValid() noexcept
        {
            HANDLE h = hKrlEvt.load();
            return NULL != h;
        }

        bool Win32Event::Exists(const ppp::string& name) noexcept
        {
            HANDLE hEvt = OpenEventA(EVENT_ALL_ACCESS, FALSE, name.c_str());
            if (NULL == hEvt)
            {
                return false;
            }

            CloseHandle(hEvt);
            return true;
        }
    }
}
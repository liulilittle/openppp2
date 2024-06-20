#include <ppp/DateTime.h>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/local_time/local_time.hpp>

namespace ppp {
    static inline DateTime DateTimeToUnixOrLocalTime(DateTime& dateTime, bool to_local_or_unix_time) noexcept {
        DateTime local = DateTime::Now();
        DateTime utc = DateTime::UtcNow();

        int64_t ticks = local.Ticks() - utc.Ticks();
        if (ticks < 0) {
            ticks = -ticks;
        }

        if (to_local_or_unix_time) {
            return dateTime.AddTicks(+ticks);
        }
        else {
            return dateTime.AddTicks(-ticks);
        }
    }

    DateTime DateTime::ToUtc() noexcept {
        return DateTimeToUnixOrLocalTime(*this, false);
    }

    DateTime DateTime::ToLocal() noexcept {
        return DateTimeToUnixOrLocalTime(*this, true);
    }

    static DateTime PosixTimeToDateTime(boost::posix_time::ptime now) noexcept {
        boost::posix_time::time_duration d = now - boost::posix_time::ptime(boost::gregorian::date(1970, 1, 1));
        return DateTime(1970, 1, 1).AddSeconds(d.total_seconds());
    }

    DateTime DateTime::Now() noexcept {
        return PosixTimeToDateTime(boost::posix_time::second_clock::local_time());
    }

    DateTime DateTime::UtcNow() noexcept {
        return PosixTimeToDateTime(boost::posix_time::second_clock::universal_time());
    }

    int DateTime::GetGMTOffset(bool abs) noexcept {
        auto gmtOffset = []() noexcept {
            boost::posix_time::ptime localTime = boost::posix_time::second_clock::local_time();
            boost::posix_time::time_duration gmtOffset = localTime - boost::posix_time::second_clock::universal_time();
            return gmtOffset.total_seconds();
            };

        if (abs) {
            return gmtOffset();
        }

        static const int offset = gmtOffset();
        return offset;
    }

    bool DateTime::TryParse(const char* s, int len, DateTime& out) noexcept {
        out = MinValue();
        if (s == NULL && len != 0) {
            return false;
        }

        if (s != NULL && len == 0) {
            return false;
        }

        if (len < 0) {
            len = (int)strlen(s);
        }

        if (len < 1) {
            return false;
        }

        static const int max_segments_length = 7;
        ppp::string segments[max_segments_length + 1];

        const char* p = s;
        unsigned int length = 0;
        while (p < (s + len) && *p != '\x0') {
            char ch = *p;
            if (ch >= '0' && ch <= '9') {
                char buf[2] = { ch, '\x0' };
                segments[length] += buf;
            }
            else {
                if (!segments[length].empty()) {
                    length++;
                    if (length >= max_segments_length) {
                        break;
                    }
                    else {
                        segments[length].clear();
                    }
                }
            }
            p++;
        }

        struct {
            int y;
            int M;
            int d;
            int H;
            int m;
            int s;
            int f;
        } tm;

        if (0 == length) {
            return false;
        }
        else {
            int* t = (int*)&tm;
            for (unsigned int i = 1; i <= max_segments_length; i++) {
                if (i > (length + 1)) {
                    t[i - 1] = 0;
                }
                else {
                    ppp::string& sx = segments[i - 1];
                    if (sx.empty()) {
                        t[i - 1] = 0;
                    }
                    else {
                        t[i - 1] = atoi(sx.c_str());
                    }
                }
            }
            out = DateTime(tm.y, tm.M, tm.d, tm.H, tm.m, tm.s, tm.f);
        }
        return length > 0;
    }

    ppp::string DateTime::ToString(const char* format, bool fixed) noexcept {
        ppp::string result;
        if (NULL == format || *format == '\x0') {
            return result;
        }

        char symbol = 0;
        int symbol_size = 0;
        auto symbol_exec = [&](int ch) noexcept {
            ppp::string seg;
            switch (symbol) {
            case 'y':
                seg = stl::to_string<ppp::string>(Year());
                break;
            case 'M':
                seg = stl::to_string<ppp::string>(Month());
                break;
            case 'd':
                seg = stl::to_string<ppp::string>(Day());
                break;
            case 'H':
                seg = stl::to_string<ppp::string>(Hour());
                break;
            case 'm':
                seg = stl::to_string<ppp::string>(Minute());
                break;
            case 's':
                seg = stl::to_string<ppp::string>(Second());
                break;
            case 'f':
                seg = stl::to_string<ppp::string>(Millisecond());
                break;
            case 'u':
                seg = stl::to_string<ppp::string>(Microseconds());
                break;
            case 'T':
                seg = stl::to_string<ppp::string>((int64_t)TotalHours());
                break;
            };

            int64_t seg_size = seg.size();
            if (fixed && seg_size > symbol_size) {
                seg = seg.substr(seg_size - symbol_size);
            }
            elif(seg_size < symbol_size) {
                seg = PaddingLeft(seg, symbol_size, '0');
            }

            if (ch != 0) {
                seg.append(1, ch);
            }

            result += seg;
            symbol = 0;
            symbol_size = 0;
        };

        const char* p = format;
        for (;;) {
            char ch = *p++;
            if (ch != 0) { /* yMdHmsfuT */ 
                bool fb = 
                    ch == 'y' || 
                    ch == 'M' || 
                    ch == 'd' || 
                    ch == 'H' || 
                    ch == 'm' || 
                    ch == 's' || 
                    ch == 'f' || 
                    ch == 'u' ||
                    ch == 'T';
                if (fb) {
                    if (symbol != 0 && symbol != ch) {
                        symbol_exec(ch);
                    }

                    symbol = ch;
                    symbol_size++;
                    continue;
                }
            }

            symbol_exec(ch);
            if (ch == 0) {
                break;
            }
        }
        return result;
    }
}

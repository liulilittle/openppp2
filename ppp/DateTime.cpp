#include <ppp/DateTime.h>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/local_time/local_time.hpp>

namespace ppp {
    static DateTime DateTimeToUnixOrLocalTime(DateTime& dateTime, bool to_local_or_unix_time) noexcept {
        DateTime local = DateTime::Now();
        DateTime utc = DateTime::UtcNow();

        long long ticks = local.Ticks() - utc.Ticks();
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
        std::string segments[max_segments_length + 1];

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
                    std::string& sx = segments[i - 1];
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

    std::string DateTime::ToString(const char* format, int len) noexcept {
        if (format == NULL && len != 0) {
            return "";
        }

        if (format != NULL && len == 0) {
            return "";
        }

        if (len < 0) {
            len = (int)strlen(format);
        }

        if (len < 1) {
            return "";
        }

#define DATETIME_FORMAT_PROPERTY_TOSTRING(k, v) \
    { \
            { \
                int n = 0; \
                while ( (p + n) < e && p[n] == *(#k) ) n++; \
                if ( n > 0 ) \
                { \
                    char buf[ 255 ]; \
                    char fmt[ 50 ]; \
                    fmt[ 0 ] = '%'; \
                    fmt[ 1 ] = '0'; \
                    sprintf( fmt + 2, "%dlld", n ); \
                    sprintf( buf, fmt, (long long int)v ); \
                    s += buf; \
                    p += n; \
                } \
            } \
        DATETIME_FORMAT_DIVIDER_TOSTRING(); \
    }

#define DATETIME_FORMAT_DIVIDER_TOSTRING() \
        { \
                const char* fb = "yMdHmsfu"; \
                char buf[ 50 ]; \
                int n = 0; \
                while ( ( p + n ) < e && n < (int)(sizeof(buf) - 1)) { \
                    char ch = p[ n ]; \
                    if ( ch == '\x0' ) break; \
                    bool fx = false; \
                    for ( int i = 0; i < 8; i++ ) { \
                        if ( ch == fb[ i ] ) { \
                            fx = true; \
                            break; \
                        } \
                    } \
                    if ( fx ) break; else buf[n++] = ch; \
                } \
                buf[ n ] = '\x0'; \
                if ( buf[ 0 ] != '\x0' ) { \
                    s += buf; \
                    p += n; \
                } \
        }

        std::string s = "";

        const char* p = format;
        const char* e = p + len;
        while (p < e && *p != '\x0') {
            DATETIME_FORMAT_PROPERTY_TOSTRING(y, Year());
            DATETIME_FORMAT_PROPERTY_TOSTRING(M, Month());
            DATETIME_FORMAT_PROPERTY_TOSTRING(d, Day());
            DATETIME_FORMAT_PROPERTY_TOSTRING(H, Hour());
            DATETIME_FORMAT_PROPERTY_TOSTRING(m, Minute());
            DATETIME_FORMAT_PROPERTY_TOSTRING(s, Second());
            DATETIME_FORMAT_PROPERTY_TOSTRING(f, Millisecond());
            DATETIME_FORMAT_PROPERTY_TOSTRING(u, Microseconds());

            p++;
        }

#undef DATETIME_FORMAT_DIVIDER_TOSTRING
#undef DATETIME_FORMAT_PROPERTY_TOSTRING

        return s;
    }
}

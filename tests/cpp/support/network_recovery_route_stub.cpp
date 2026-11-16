#include <string_view>

#if defined(__linux__) && !defined(_LINUX)
#define _LINUX 1
#endif

#if defined(_WIN32)
#include <ppp/app/client/route/WindowsRoutePlatform.h>
namespace ppp::app::client::route {
bool WindowsRoutePlatform::RecoverRouteJournalEntry(std::string_view) noexcept {
    return false;
}
}
#elif defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
#include <ppp/app/client/route/LinuxRoutePlatform.h>
namespace ppp::app::client::route {
bool LinuxRoutePlatform::RecoverRouteJournalEntry(std::string_view) noexcept {
    return false;
}
}
#elif defined(_MACOS)
#include <ppp/app/client/route/DarwinRoutePlatform.h>
namespace ppp::app::client::route {
bool DarwinRoutePlatform::RecoverRouteJournalEntry(std::string_view) noexcept {
    return false;
}
}
#endif

#pragma once

#include <boost/asio/ip/address.hpp>
#include <ppp/net/native/rib.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;

            class ClientBypassRouteLoader {
            public:
                static bool RejectsBypassBeforeTapLookup(const boost::asio::ip::address& ip) noexcept {
                    if (!ip.is_v4()) {
                        return true;
                    }

                    if (ip.is_unspecified()) {
                        return true;
                    }

                    if (ip.is_multicast()) {
                        return true;
                    }

                    return false;
                }

#if !defined(_ANDROID) && !defined(_IPHONE)
                static bool IsRouteListPathEmpty(const ppp::string& path) noexcept {
                    return path.empty();
                }
#endif

                void Bind(VEthernetNetworkSwitcher* owner) noexcept;

#if defined(_ANDROID) || defined(_IPHONE)
                void SetBypassIpList(ppp::string&& bypass_ip_list) noexcept;
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
                bool AddLoadIPList(
                    const ppp::string& path,
#if defined(_LINUX)
                    const ppp::string& nic,
#endif
                    const boost::asio::ip::address& gw,
                    const ppp::string& url) noexcept;

                bool AddLoadIPListText(
                    const ppp::string& text,
#if defined(_LINUX)
                    const ppp::string& nic,
#endif
                    const boost::asio::ip::address& gw) noexcept;

                bool LoadAllIPListWithFilePaths(const boost::asio::ip::address& gw) noexcept;
#endif

                bool IsBypassIpAddress(const boost::asio::ip::address& ip) noexcept;

            private:
#if !defined(_ANDROID) && !defined(_IPHONE)
                struct TextSource final {
                    ppp::string text;
                    uint32_t ngw = 0;
                };

                struct SourceOrder final {
                    bool text = false;
                    std::size_t index = 0;
                };

                ppp::vector<TextSource> text_sources_;
                ppp::vector<SourceOrder> source_order_;
#endif
                VEthernetNetworkSwitcher* owner_ = nullptr;
            };
        }
    }
}

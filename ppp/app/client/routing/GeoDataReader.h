#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ppp::app::client::routing {

    enum class GeoDataReadStatus {
        Success,
        FileMissing,
        SelectorMissing,
        Malformed,
    };

    struct GeoDataCidr final {
        std::vector<std::uint8_t> address;
        std::uint8_t prefix_length = 0;
        std::string cidr;
        std::size_t line = 0;
    };

    enum class GeoDataDomainType : std::uint8_t {
        Plain = 0,
        Regex = 1,
        Domain = 2,
        Full = 3,
    };

    struct GeoDataDomain final {
        GeoDataDomainType type = GeoDataDomainType::Plain;
        std::string value;
        std::size_t line = 0;
    };

    struct GeoIpReadResult final {
        GeoDataReadStatus status = GeoDataReadStatus::Malformed;
        std::string diagnostic;
        std::vector<GeoDataCidr> entries;
        std::size_t skipped = 0;
        std::size_t ipv4_entries = 0;
        std::size_t ipv6_entries = 0;

        bool Succeeded() const noexcept { return status == GeoDataReadStatus::Success; }
    };

    struct GeoSiteReadResult final {
        GeoDataReadStatus status = GeoDataReadStatus::Malformed;
        std::string diagnostic;
        std::vector<GeoDataDomain> entries;
        std::size_t skipped = 0;

        bool Succeeded() const noexcept { return status == GeoDataReadStatus::Success; }
    };

    class GeoDataReader final {
    public:
        // Reads v2ray/Xray/MetaCubeX protobuf dat files and selects one category.
        static GeoIpReadResult ReadGeoIp(
            std::string_view path,
            std::string_view selector) noexcept;
        static GeoSiteReadResult ReadGeoSite(
            std::string_view path,
            std::string_view selector) noexcept;

        // Reads the existing line-oriented source formats. Invalid data lines are
        // skipped and counted; file access and stream errors are structured statuses.
        static GeoIpReadResult ReadGeoIpText(std::string_view path) noexcept;
        static GeoSiteReadResult ReadGeoSiteText(std::string_view path) noexcept;

        // Compatibility adapters for callers that predate the structured result API.
        static bool ReadGeoIp(
            const std::string& path,
            const std::string& selector,
            std::vector<GeoDataCidr>& entries,
            bool& selector_found,
            std::string& diagnostic) noexcept;
        static bool ReadGeoSite(
            const std::string& path,
            const std::string& selector,
            std::vector<GeoDataDomain>& entries,
            bool& selector_found,
            std::string& diagnostic) noexcept;
    };

} // namespace ppp::app::client::routing

#include <ppp/app/client/routing/GeoDataReader.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <sstream>
#include <utility>

namespace ppp::app::client::routing {
namespace {

    enum class WireStep {
        Field,
        End,
        Invalid,
    };

    struct WireField final {
        std::uint32_t number = 0;
        std::uint8_t type = 0;
        std::uint64_t varint = 0;
        const std::uint8_t* data = nullptr;
        std::size_t size = 0;
    };

    class WireReader final {
    public:
        WireReader(const std::uint8_t* data, std::size_t size) noexcept
            : begin_(data), current_(data), end_(size == 0 ? data : data + size) {
        }

        WireStep Next(WireField& field, std::string& diagnostic) noexcept {
            if (current_ == end_) {
                return WireStep::End;
            }

            const std::size_t key_offset = Offset();
            std::uint64_t key = 0;
            const VarintResult key_result = ReadVarint(key);
            if (key_result != VarintResult::Success) {
                diagnostic = key_result == VarintResult::Truncated
                    ? "truncated protobuf key varint at byte " + std::to_string(key_offset)
                    : "invalid protobuf key varint at byte " + std::to_string(key_offset);
                return WireStep::Invalid;
            }

            const std::uint64_t field_number = key >> 3u;
            const std::uint8_t wire_type = static_cast<std::uint8_t>(key & 0x07u);
            if (field_number == 0 || field_number > 0x1fffffffu) {
                diagnostic = "invalid protobuf field number at byte " + std::to_string(key_offset);
                return WireStep::Invalid;
            }

            field = WireField{};
            field.number = static_cast<std::uint32_t>(field_number);
            field.type = wire_type;
            switch (wire_type) {
            case 0: {
                const std::size_t value_offset = Offset();
                const VarintResult value_result = ReadVarint(field.varint);
                if (value_result != VarintResult::Success) {
                    diagnostic = value_result == VarintResult::Truncated
                        ? "truncated protobuf varint at byte " + std::to_string(value_offset)
                        : "invalid protobuf varint at byte " + std::to_string(value_offset);
                    return WireStep::Invalid;
                }
                return WireStep::Field;
            }
            case 1:
                return SkipFixed(8, diagnostic) ? WireStep::Field : WireStep::Invalid;
            case 2: {
                const std::size_t length_offset = Offset();
                std::uint64_t length = 0;
                const VarintResult length_result = ReadVarint(length);
                if (length_result != VarintResult::Success) {
                    diagnostic = length_result == VarintResult::Truncated
                        ? "truncated protobuf length at byte " + std::to_string(length_offset)
                        : "invalid protobuf length at byte " + std::to_string(length_offset);
                    return WireStep::Invalid;
                }
                const std::uint64_t remaining = static_cast<std::uint64_t>(end_ - current_);
                if (length > remaining || length > std::numeric_limits<std::size_t>::max()) {
                    diagnostic = "truncated length-delimited field at byte " +
                        std::to_string(length_offset);
                    return WireStep::Invalid;
                }
                field.data = current_;
                field.size = static_cast<std::size_t>(length);
                current_ += field.size;
                return WireStep::Field;
            }
            case 5:
                return SkipFixed(4, diagnostic) ? WireStep::Field : WireStep::Invalid;
            default:
                diagnostic = "invalid protobuf wire type " + std::to_string(wire_type) +
                    " at byte " + std::to_string(key_offset);
                return WireStep::Invalid;
            }
        }

    private:
        enum class VarintResult {
            Success,
            Truncated,
            Invalid,
        };

        std::size_t Offset() const noexcept {
            return static_cast<std::size_t>(current_ - begin_);
        }

        VarintResult ReadVarint(std::uint64_t& value) noexcept {
            value = 0;
            for (unsigned int index = 0; index < 10; ++index) {
                if (current_ == end_) {
                    return VarintResult::Truncated;
                }
                const std::uint8_t byte = *current_++;
                if (index == 9 && (byte & 0xfeu) != 0) {
                    return VarintResult::Invalid;
                }
                value |= static_cast<std::uint64_t>(byte & 0x7fu) << (index * 7u);
                if ((byte & 0x80u) == 0) {
                    return VarintResult::Success;
                }
            }
            return VarintResult::Invalid;
        }

        bool SkipFixed(std::size_t size, std::string& diagnostic) noexcept {
            if (static_cast<std::size_t>(end_ - current_) < size) {
                diagnostic = "truncated fixed-width field at byte " + std::to_string(Offset());
                return false;
            }
            current_ += size;
            return true;
        }

    private:
        const std::uint8_t* begin_;
        const std::uint8_t* current_;
        const std::uint8_t* end_;
    };

    struct MessageSlice final {
        const std::uint8_t* data = nullptr;
        std::size_t size = 0;
    };

    std::string Trim(std::string value) {
        std::size_t begin = 0;
        while (begin < value.size() &&
               std::isspace(static_cast<unsigned char>(value[begin]))) {
            ++begin;
        }
        std::size_t end = value.size();
        while (end > begin &&
               std::isspace(static_cast<unsigned char>(value[end - 1]))) {
            --end;
        }
        return value.substr(begin, end - begin);
    }

    std::string ToLowerAscii(std::string value) {
        for (char& ch : value) {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        return value;
    }

    std::string NormalizeCategory(std::string_view value) {
        std::string normalized = ToLowerAscii(Trim(std::string(value)));
        if (normalized.compare(0, 6, "geoip:") == 0) {
            normalized = Trim(normalized.substr(6));
        }
        if (normalized.compare(0, 8, "geosite:") == 0) {
            normalized = Trim(normalized.substr(8));
        }
        return normalized;
    }

    std::string NormalizeSelector(std::string_view selector) {
        std::string normalized = NormalizeCategory(selector);
        return normalized.empty() ? "cn" : normalized;
    }

    std::string FieldString(const WireField& field) {
        if (field.data == nullptr || field.size == 0) {
            return {};
        }
        return std::string(reinterpret_cast<const char*>(field.data), field.size);
    }

    bool ReadFile(std::string_view path, std::vector<std::uint8_t>& bytes,
                  GeoDataReadStatus& status, std::string& diagnostic) {
        const std::string file_path(path);
        if (file_path.empty()) {
            status = GeoDataReadStatus::FileMissing;
            diagnostic = "source path is empty";
            return false;
        }

        std::ifstream stream(file_path, std::ios::binary);
        if (!stream) {
            status = GeoDataReadStatus::FileMissing;
            diagnostic = "source file not found or cannot be opened: " + file_path;
            return false;
        }

        bytes.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
        if (stream.bad()) {
            status = GeoDataReadStatus::Malformed;
            diagnostic = "unable to read source file: " + file_path;
            bytes.clear();
            return false;
        }
        return true;
    }

    void MaskAddress(std::vector<std::uint8_t>& address, unsigned int prefix_length) noexcept {
        const unsigned int full_bytes = prefix_length / 8u;
        const unsigned int remaining_bits = prefix_length % 8u;
        if (remaining_bits != 0 && full_bytes < address.size()) {
            address[full_bytes] &= static_cast<std::uint8_t>(0xffu << (8u - remaining_bits));
        }
        const std::size_t zero_from = full_bytes + (remaining_bits == 0 ? 0u : 1u);
        for (std::size_t index = zero_from; index < address.size(); ++index) {
            address[index] = 0;
        }
    }

    std::string FormatIpv4(const std::vector<std::uint8_t>& address) {
        return std::to_string(address[0]) + "." + std::to_string(address[1]) + "." +
            std::to_string(address[2]) + "." + std::to_string(address[3]);
    }

    std::string FormatIpv6(const std::vector<std::uint8_t>& address) {
        std::array<std::uint16_t, 8> words{};
        for (std::size_t index = 0; index < words.size(); ++index) {
            words[index] = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(address[index * 2]) << 8u) |
                address[index * 2 + 1]);
        }

        std::size_t best_start = words.size();
        std::size_t best_length = 0;
        for (std::size_t index = 0; index < words.size();) {
            if (words[index] != 0) {
                ++index;
                continue;
            }
            const std::size_t start = index;
            while (index < words.size() && words[index] == 0) {
                ++index;
            }
            const std::size_t length = index - start;
            if (length >= 2 && length > best_length) {
                best_start = start;
                best_length = length;
            }
        }

        std::ostringstream output;
        output << std::hex << std::nouppercase;
        for (std::size_t index = 0; index < words.size();) {
            if (index == best_start) {
                output << "::";
                index += best_length;
                continue;
            }
            if (index > 0 && index != best_start + best_length) {
                output << ':';
            }
            output << words[index];
            ++index;
        }
        return output.str();
    }

    std::string FormatCidr(const std::vector<std::uint8_t>& address,
                           unsigned int prefix_length) {
        const std::string ip = address.size() == 4 ? FormatIpv4(address) : FormatIpv6(address);
        return ip + "/" + std::to_string(prefix_length);
    }

    bool ParseDatCidr(const MessageSlice& slice, GeoDataCidr& cidr,
                      bool& usable, std::string& diagnostic) {
        WireReader reader(slice.data, slice.size);
        std::vector<std::uint8_t> address;
        std::uint64_t prefix = 0;
        bool has_prefix = false;

        for (;;) {
            WireField field;
            const WireStep step = reader.Next(field, diagnostic);
            if (step == WireStep::End) {
                break;
            }
            if (step == WireStep::Invalid) {
                diagnostic = "malformed GeoIP CIDR message: " + diagnostic;
                return false;
            }
            if (field.number == 1 && field.type == 2) {
                address.assign(field.data, field.data + field.size);
            }
            else if (field.number == 2 && field.type == 0) {
                prefix = field.varint;
                has_prefix = true;
            }
        }

        usable = address.size() == 4 || address.size() == 16;
        if (!usable) {
            return true;
        }
        const unsigned int maximum_prefix = address.size() == 4 ? 32u : 128u;
        if (!has_prefix) {
            prefix = maximum_prefix;
        }
        if (prefix > maximum_prefix) {
            usable = false;
            return true;
        }

        MaskAddress(address, static_cast<unsigned int>(prefix));
        cidr.address = std::move(address);
        cidr.prefix_length = static_cast<std::uint8_t>(prefix);
        cidr.cidr = FormatCidr(cidr.address, static_cast<unsigned int>(prefix));
        return true;
    }

    bool ParseGeoIpEntry(const MessageSlice& slice, const std::string& selector,
                         GeoIpReadResult& result, bool& selector_found,
                         std::string& diagnostic) {
        WireReader reader(slice.data, slice.size);
        std::string country;
        std::vector<MessageSlice> cidr_messages;

        for (;;) {
            WireField field;
            const WireStep step = reader.Next(field, diagnostic);
            if (step == WireStep::End) {
                break;
            }
            if (step == WireStep::Invalid) {
                diagnostic = "malformed GeoIP entry: " + diagnostic;
                return false;
            }
            if (field.number == 1 && field.type == 2) {
                country = NormalizeCategory(FieldString(field));
            }
            else if (field.number == 2 && field.type == 2) {
                cidr_messages.push_back(MessageSlice{ field.data, field.size });
            }
        }

        if (country != selector) {
            return true;
        }
        selector_found = true;
        for (const MessageSlice& cidr_message : cidr_messages) {
            GeoDataCidr cidr;
            bool usable = false;
            if (!ParseDatCidr(cidr_message, cidr, usable, diagnostic)) {
                return false;
            }
            if (!usable) {
                ++result.skipped;
                continue;
            }
            if (cidr.address.size() == 4) {
                ++result.ipv4_entries;
            }
            else {
                ++result.ipv6_entries;
            }
            result.entries.emplace_back(std::move(cidr));
        }
        return true;
    }

    bool ParseGeoIpList(const std::vector<std::uint8_t>& bytes,
                        const std::string& selector, GeoIpReadResult& result) {
        WireReader reader(bytes.data(), bytes.size());
        bool selector_found = false;
        std::string diagnostic;

        for (;;) {
            WireField field;
            const WireStep step = reader.Next(field, diagnostic);
            if (step == WireStep::End) {
                break;
            }
            if (step == WireStep::Invalid) {
                result.diagnostic = "malformed GeoIP list: " + diagnostic;
                return false;
            }
            if (field.number == 1 && field.type == 2 &&
                !ParseGeoIpEntry(MessageSlice{ field.data, field.size }, selector,
                                 result, selector_found, diagnostic)) {
                result.diagnostic = std::move(diagnostic);
                return false;
            }
        }

        if (!selector_found) {
            result.status = GeoDataReadStatus::SelectorMissing;
            result.diagnostic = "GeoIP selector not found: " + selector;
            return true;
        }
        result.status = GeoDataReadStatus::Success;
        return true;
    }

    bool ParseDatDomain(const MessageSlice& slice, GeoDataDomain& domain,
                        bool& usable, std::string& diagnostic) {
        WireReader reader(slice.data, slice.size);
        std::uint64_t type = 0;
        std::string value;

        for (;;) {
            WireField field;
            const WireStep step = reader.Next(field, diagnostic);
            if (step == WireStep::End) {
                break;
            }
            if (step == WireStep::Invalid) {
                diagnostic = "malformed GeoSite domain message: " + diagnostic;
                return false;
            }
            if (field.number == 1 && field.type == 0) {
                type = field.varint;
            }
            else if (field.number == 2 && field.type == 2) {
                value = FieldString(field);
            }
        }

        usable = type <= static_cast<std::uint64_t>(GeoDataDomainType::Full) &&
            !Trim(value).empty();
        if (usable) {
            domain.type = static_cast<GeoDataDomainType>(type);
            domain.value = std::move(value);
        }
        return true;
    }

    bool ParseGeoSiteEntry(const MessageSlice& slice, const std::string& selector,
                           GeoSiteReadResult& result, bool& selector_found,
                           std::string& diagnostic) {
        WireReader reader(slice.data, slice.size);
        std::string country;
        std::vector<MessageSlice> domain_messages;

        for (;;) {
            WireField field;
            const WireStep step = reader.Next(field, diagnostic);
            if (step == WireStep::End) {
                break;
            }
            if (step == WireStep::Invalid) {
                diagnostic = "malformed GeoSite entry: " + diagnostic;
                return false;
            }
            if (field.number == 1 && field.type == 2) {
                country = NormalizeCategory(FieldString(field));
            }
            else if (field.number == 2 && field.type == 2) {
                domain_messages.push_back(MessageSlice{ field.data, field.size });
            }
        }

        if (country != selector) {
            return true;
        }
        selector_found = true;
        for (const MessageSlice& domain_message : domain_messages) {
            GeoDataDomain domain;
            bool usable = false;
            if (!ParseDatDomain(domain_message, domain, usable, diagnostic)) {
                return false;
            }
            if (!usable) {
                ++result.skipped;
                continue;
            }
            result.entries.emplace_back(std::move(domain));
        }
        return true;
    }

    bool ParseGeoSiteList(const std::vector<std::uint8_t>& bytes,
                          const std::string& selector, GeoSiteReadResult& result) {
        WireReader reader(bytes.data(), bytes.size());
        bool selector_found = false;
        std::string diagnostic;

        for (;;) {
            WireField field;
            const WireStep step = reader.Next(field, diagnostic);
            if (step == WireStep::End) {
                break;
            }
            if (step == WireStep::Invalid) {
                result.diagnostic = "malformed GeoSite list: " + diagnostic;
                return false;
            }
            if (field.number == 1 && field.type == 2 &&
                !ParseGeoSiteEntry(MessageSlice{ field.data, field.size }, selector,
                                   result, selector_found, diagnostic)) {
                result.diagnostic = std::move(diagnostic);
                return false;
            }
        }

        if (!selector_found) {
            result.status = GeoDataReadStatus::SelectorMissing;
            result.diagnostic = "GeoSite selector not found: " + selector;
            return true;
        }
        result.status = GeoDataReadStatus::Success;
        return true;
    }

    bool ParseIpv4(std::string_view text, std::array<std::uint8_t, 4>& bytes) noexcept {
        std::size_t offset = 0;
        for (std::size_t octet = 0; octet < bytes.size(); ++octet) {
            const std::size_t separator = text.find('.', offset);
            const std::size_t end = separator == std::string_view::npos ? text.size() : separator;
            if (end == offset || (octet < 3 && separator == std::string_view::npos) ||
                (octet == 3 && separator != std::string_view::npos)) {
                return false;
            }
            unsigned int value = 0;
            for (std::size_t index = offset; index < end; ++index) {
                const unsigned char ch = static_cast<unsigned char>(text[index]);
                if (!std::isdigit(ch)) {
                    return false;
                }
                value = value * 10u + static_cast<unsigned int>(ch - '0');
                if (value > 255u) {
                    return false;
                }
            }
            bytes[octet] = static_cast<std::uint8_t>(value);
            offset = end + 1;
        }
        return true;
    }

    bool ParseHexWord(std::string_view text, std::uint16_t& word) noexcept {
        if (text.empty() || text.size() > 4) {
            return false;
        }
        unsigned int value = 0;
        for (char raw_ch : text) {
            const unsigned char ch = static_cast<unsigned char>(raw_ch);
            unsigned int digit = 0;
            if (ch >= '0' && ch <= '9') {
                digit = ch - '0';
            }
            else if (ch >= 'a' && ch <= 'f') {
                digit = ch - 'a' + 10u;
            }
            else if (ch >= 'A' && ch <= 'F') {
                digit = ch - 'A' + 10u;
            }
            else {
                return false;
            }
            value = value * 16u + digit;
        }
        word = static_cast<std::uint16_t>(value);
        return true;
    }

    bool ParseIpv6Part(std::string_view part, bool may_have_ipv4,
                       std::vector<std::uint16_t>& words) noexcept {
        if (part.empty()) {
            return true;
        }
        std::size_t offset = 0;
        while (offset <= part.size()) {
            const std::size_t separator = part.find(':', offset);
            const std::size_t end = separator == std::string_view::npos ? part.size() : separator;
            const std::string_view token = part.substr(offset, end - offset);
            if (token.empty()) {
                return false;
            }
            if (token.find('.') != std::string_view::npos) {
                if (!may_have_ipv4 || end != part.size()) {
                    return false;
                }
                std::array<std::uint8_t, 4> ipv4{};
                if (!ParseIpv4(token, ipv4)) {
                    return false;
                }
                words.push_back(static_cast<std::uint16_t>(
                    (static_cast<std::uint16_t>(ipv4[0]) << 8u) | ipv4[1]));
                words.push_back(static_cast<std::uint16_t>(
                    (static_cast<std::uint16_t>(ipv4[2]) << 8u) | ipv4[3]));
            }
            else {
                std::uint16_t word = 0;
                if (!ParseHexWord(token, word)) {
                    return false;
                }
                words.push_back(word);
            }
            if (separator == std::string_view::npos) {
                break;
            }
            offset = separator + 1;
        }
        return true;
    }

    bool ParseIpv6(std::string_view text, std::vector<std::uint8_t>& address) noexcept {
        if (text.empty() || text.find('%') != std::string_view::npos) {
            return false;
        }
        const std::size_t compression = text.find("::");
        if (compression != std::string_view::npos &&
            text.find("::", compression + 2) != std::string_view::npos) {
            return false;
        }

        std::vector<std::uint16_t> left;
        std::vector<std::uint16_t> right;
        if (compression == std::string_view::npos) {
            if (!ParseIpv6Part(text, true, left) || left.size() != 8) {
                return false;
            }
        }
        else {
            if (!ParseIpv6Part(text.substr(0, compression), false, left) ||
                !ParseIpv6Part(text.substr(compression + 2), true, right) ||
                left.size() + right.size() >= 8) {
                return false;
            }
            left.resize(8 - right.size(), 0);
            left.insert(left.end(), right.begin(), right.end());
        }

        address.resize(16);
        for (std::size_t index = 0; index < left.size(); ++index) {
            address[index * 2] = static_cast<std::uint8_t>(left[index] >> 8u);
            address[index * 2 + 1] = static_cast<std::uint8_t>(left[index] & 0xffu);
        }
        return true;
    }

    bool ParseTextCidr(std::string value, GeoDataCidr& cidr) {
        value = Trim(std::move(value));
        const std::string lower = ToLowerAscii(value);
        if (lower.compare(0, 6, "geoip:") == 0) {
            value = Trim(value.substr(6));
        }

        const std::size_t slash = value.find('/');
        if (slash != std::string::npos && value.find('/', slash + 1) != std::string::npos) {
            return false;
        }
        const std::string address_text = slash == std::string::npos
            ? value : value.substr(0, slash);

        std::vector<std::uint8_t> address;
        std::array<std::uint8_t, 4> ipv4{};
        unsigned int maximum_prefix = 128;
        if (ParseIpv4(address_text, ipv4)) {
            address.assign(ipv4.begin(), ipv4.end());
            maximum_prefix = 32;
        }
        else if (!ParseIpv6(address_text, address)) {
            return false;
        }

        unsigned int prefix = maximum_prefix;
        if (slash != std::string::npos) {
            const std::string prefix_text = value.substr(slash + 1);
            if (prefix_text.empty()) {
                return false;
            }
            prefix = 0;
            for (char raw_ch : prefix_text) {
                const unsigned char ch = static_cast<unsigned char>(raw_ch);
                if (!std::isdigit(ch)) {
                    return false;
                }
                prefix = prefix * 10u + static_cast<unsigned int>(ch - '0');
                if (prefix > maximum_prefix) {
                    return false;
                }
            }
        }

        MaskAddress(address, prefix);
        cidr.address = std::move(address);
        cidr.prefix_length = static_cast<std::uint8_t>(prefix);
        cidr.cidr = FormatCidr(cidr.address, prefix);
        return true;
    }

    bool ParseTextDomain(std::string value, GeoDataDomain& domain) {
        value = Trim(std::move(value));
        const std::string lower = ToLowerAscii(value);
        std::size_t prefix_length = 0;
        if (lower.compare(0, 6, "plain:") == 0) {
            domain.type = GeoDataDomainType::Plain;
            prefix_length = 6;
        }
        else if (lower.compare(0, 7, "regexp:") == 0) {
            domain.type = GeoDataDomainType::Regex;
            prefix_length = 7;
        }
        else if (lower.compare(0, 6, "regex:") == 0) {
            domain.type = GeoDataDomainType::Regex;
            prefix_length = 6;
        }
        else if (lower.compare(0, 5, "full:") == 0) {
            domain.type = GeoDataDomainType::Full;
            prefix_length = 5;
        }
        else if (lower.compare(0, 7, "domain:") == 0 ||
             lower.compare(0, 7, "suffix:") == 0) {
            domain.type = GeoDataDomainType::Domain;
            prefix_length = 7;
        }
        else {
            domain.type = GeoDataDomainType::Domain;
        }

        value = Trim(value.substr(prefix_length));
        if (domain.type == GeoDataDomainType::Domain && !value.empty() && value.front() == '.') {
            value.erase(value.begin());
            value = Trim(std::move(value));
        }
        if (value.empty()) {
            return false;
        }
        domain.value = std::move(value);
        return true;
    }

    template <typename TParseLine>
    bool ReadTextLines(std::string_view path, GeoDataReadStatus& status,
                       std::string& diagnostic, std::size_t& skipped,
                       TParseLine&& parse_line) {
        const std::string file_path(path);
        if (file_path.empty()) {
            status = GeoDataReadStatus::FileMissing;
            diagnostic = "source path is empty";
            return false;
        }
        std::ifstream stream(file_path, std::ios::binary);
        if (!stream) {
            status = GeoDataReadStatus::FileMissing;
            diagnostic = "source file not found or cannot be opened: " + file_path;
            return false;
        }

        std::string raw_line;
        std::size_t line_number = 0;
        while (std::getline(stream, raw_line)) {
            ++line_number;
            if (!raw_line.empty() && raw_line.back() == '\r') {
                raw_line.pop_back();
            }
            const std::size_t comment = raw_line.find('#');
            if (comment != std::string::npos) {
                raw_line.erase(comment);
            }
            std::string line = Trim(std::move(raw_line));
            if (line.empty()) {
                continue;
            }
            if (!parse_line(std::move(line), line_number)) {
                ++skipped;
                if (diagnostic.empty()) {
                    diagnostic = "skipped malformed text entry at line " +
                        std::to_string(line_number);
                }
            }
        }
        if (stream.bad()) {
            status = GeoDataReadStatus::Malformed;
            diagnostic = "unable to read source file: " + file_path;
            return false;
        }
        status = GeoDataReadStatus::Success;
        return true;
    }

} // namespace

GeoIpReadResult GeoDataReader::ReadGeoIp(
    std::string_view path,
    std::string_view selector) noexcept {
    GeoIpReadResult result;
    try {
        std::vector<std::uint8_t> bytes;
        if (!ReadFile(path, bytes, result.status, result.diagnostic)) {
            return result;
        }
        if (!ParseGeoIpList(bytes, NormalizeSelector(selector), result)) {
            result.status = GeoDataReadStatus::Malformed;
            result.entries.clear();
            result.ipv4_entries = 0;
            result.ipv6_entries = 0;
        }
    }
    catch (const std::exception& exception) {
        result = GeoIpReadResult{};
        result.status = GeoDataReadStatus::Malformed;
        result.diagnostic = exception.what();
    }
    catch (...) {
        result = GeoIpReadResult{};
        result.status = GeoDataReadStatus::Malformed;
        result.diagnostic = "unknown GeoIP reader failure";
    }
    return result;
}

GeoSiteReadResult GeoDataReader::ReadGeoSite(
    std::string_view path,
    std::string_view selector) noexcept {
    GeoSiteReadResult result;
    try {
        std::vector<std::uint8_t> bytes;
        if (!ReadFile(path, bytes, result.status, result.diagnostic)) {
            return result;
        }
        if (!ParseGeoSiteList(bytes, NormalizeSelector(selector), result)) {
            result.status = GeoDataReadStatus::Malformed;
            result.entries.clear();
        }
    }
    catch (const std::exception& exception) {
        result = GeoSiteReadResult{};
        result.status = GeoDataReadStatus::Malformed;
        result.diagnostic = exception.what();
    }
    catch (...) {
        result = GeoSiteReadResult{};
        result.status = GeoDataReadStatus::Malformed;
        result.diagnostic = "unknown GeoSite reader failure";
    }
    return result;
}

GeoIpReadResult GeoDataReader::ReadGeoIpText(std::string_view path) noexcept {
    GeoIpReadResult result;
    try {
        ReadTextLines(path, result.status, result.diagnostic, result.skipped,
            [&result](std::string value, std::size_t line) {
                GeoDataCidr cidr;
                if (!ParseTextCidr(std::move(value), cidr)) {
                    return false;
                }
                cidr.line = line;
                if (cidr.address.size() == 4) {
                    ++result.ipv4_entries;
                }
                else {
                    ++result.ipv6_entries;
                }
                result.entries.emplace_back(std::move(cidr));
                return true;
            });
    }
    catch (const std::exception& exception) {
        result = GeoIpReadResult{};
        result.status = GeoDataReadStatus::Malformed;
        result.diagnostic = exception.what();
    }
    catch (...) {
        result = GeoIpReadResult{};
        result.status = GeoDataReadStatus::Malformed;
        result.diagnostic = "unknown GeoIP text reader failure";
    }
    return result;
}

GeoSiteReadResult GeoDataReader::ReadGeoSiteText(std::string_view path) noexcept {
    GeoSiteReadResult result;
    try {
        ReadTextLines(path, result.status, result.diagnostic, result.skipped,
            [&result](std::string value, std::size_t line) {
                GeoDataDomain domain;
                if (!ParseTextDomain(std::move(value), domain)) {
                    return false;
                }
                domain.line = line;
                result.entries.emplace_back(std::move(domain));
                return true;
            });
    }
    catch (const std::exception& exception) {
        result = GeoSiteReadResult{};
        result.status = GeoDataReadStatus::Malformed;
        result.diagnostic = exception.what();
    }
    catch (...) {
        result = GeoSiteReadResult{};
        result.status = GeoDataReadStatus::Malformed;
        result.diagnostic = "unknown GeoSite text reader failure";
    }
    return result;
}

bool GeoDataReader::ReadGeoIp(
    const std::string& path,
    const std::string& selector,
    std::vector<GeoDataCidr>& entries,
    bool& selector_found,
    std::string& diagnostic) noexcept {
    GeoIpReadResult result = ReadGeoIp(std::string_view(path), std::string_view(selector));
    entries = std::move(result.entries);
    selector_found = result.status == GeoDataReadStatus::Success;
    diagnostic = std::move(result.diagnostic);
    return result.status == GeoDataReadStatus::Success ||
        result.status == GeoDataReadStatus::SelectorMissing;
}

bool GeoDataReader::ReadGeoSite(
    const std::string& path,
    const std::string& selector,
    std::vector<GeoDataDomain>& entries,
    bool& selector_found,
    std::string& diagnostic) noexcept {
    GeoSiteReadResult result = ReadGeoSite(std::string_view(path), std::string_view(selector));
    entries = std::move(result.entries);
    selector_found = result.status == GeoDataReadStatus::Success;
    diagnostic = std::move(result.diagnostic);
    return result.status == GeoDataReadStatus::Success ||
        result.status == GeoDataReadStatus::SelectorMissing;
}

} // namespace ppp::app::client::routing

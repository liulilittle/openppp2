#include "ProtocolSniffer.h"

#include <algorithm>
#include <cctype>
#include <limits>
#include <string_view>

namespace ppp::app::client::routing {
    namespace {
        constexpr std::size_t kMaxTlsRecordPayload = 16 * 1024;
        constexpr std::size_t kMaxHostnameWireLength = 254;

        ProtocolSnifferResult MakeResult(ProtocolSnifferStatus status) {
            ProtocolSnifferResult result;
            result.status = status;
            return result;
        }

        ProtocolSnifferResult MakeComplete(
            std::string domain, ProtocolSnifferSource source) {
            ProtocolSnifferResult result;
            result.status = ProtocolSnifferStatus::Complete;
            result.domain = std::move(domain);
            result.source = source;
            return result;
        }

        bool ReadU16(const std::vector<std::uint8_t>& bytes,
            std::size_t& offset, std::size_t limit, std::uint16_t& value) {
            if (offset > limit || limit - offset < 2) {
                return false;
            }
            value = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(bytes[offset]) << 8) |
                static_cast<std::uint16_t>(bytes[offset + 1]));
            offset += 2;
            return true;
        }

        bool Skip(std::size_t& offset, std::size_t count, std::size_t limit) {
            if (offset > limit || count > limit - offset) {
                return false;
            }
            offset += count;
            return true;
        }

        bool IsAsciiAlphaNumeric(unsigned char value) {
            return (value >= 'a' && value <= 'z') ||
                (value >= 'A' && value <= 'Z') ||
                (value >= '0' && value <= '9');
        }

        bool IsTokenCharacter(unsigned char value) {
            if (IsAsciiAlphaNumeric(value)) {
                return true;
            }
            switch (value) {
            case '!': case '#': case '$': case '%': case '&': case '\'':
            case '*': case '+': case '-': case '.': case '^': case '_':
            case '`': case '|': case '~':
                return true;
            default:
                return false;
            }
        }

        bool NormalizeDomain(std::string_view value, std::string& normalized) {
            if (value.empty() || value.size() > kMaxHostnameWireLength) {
                return false;
            }

            normalized.assign(value.begin(), value.end());
            if (!normalized.empty() && normalized.back() == '.') {
                normalized.pop_back();
            }
            if (normalized.empty() || normalized.size() > 253) {
                return false;
            }

            std::size_t label_start = 0;
            for (std::size_t i = 0; i <= normalized.size(); ++i) {
                if (i != normalized.size() && normalized[i] != '.') {
                    const unsigned char character =
                        static_cast<unsigned char>(normalized[i]);
                    if (!IsAsciiAlphaNumeric(character) && character != '-') {
                        return false;
                    }
                    if (character >= 'A' && character <= 'Z') {
                        normalized[i] = static_cast<char>(character + ('a' - 'A'));
                    }
                    continue;
                }

                const std::size_t label_length = i - label_start;
                if (label_length == 0 || label_length > 63 ||
                    normalized[label_start] == '-' || normalized[i - 1] == '-') {
                    return false;
                }
                label_start = i + 1;
            }
            return true;
        }

        bool ParsePort(std::string_view value) {
            if (value.empty() || value.size() > 5) {
                return false;
            }
            unsigned int port = 0;
            for (const unsigned char character : value) {
                if (character < '0' || character > '9') {
                    return false;
                }
                port = port * 10 + static_cast<unsigned int>(character - '0');
            }
            return port <= 65535;
        }

        bool ParseIpv4Address(std::string_view value) {
            int component_count = 0;
            while (!value.empty()) {
                const std::size_t separator = value.find('.');
                const std::string_view component = value.substr(0, separator);
                if (component.empty() || component.size() > 3) {
                    return false;
                }
                unsigned int number = 0;
                for (const unsigned char character : component) {
                    if (character < '0' || character > '9') {
                        return false;
                    }
                    number = number * 10 + static_cast<unsigned int>(character - '0');
                }
                if (number > 255 || ++component_count > 4) {
                    return false;
                }
                if (separator == std::string_view::npos) {
                    value = {};
                }
                else {
                    value.remove_prefix(separator + 1);
                }
            }
            return component_count == 4;
        }

        bool CountIpv6Groups(std::string_view value, int& groups) {
            while (!value.empty()) {
                const std::size_t separator = value.find(':');
                const std::string_view group = value.substr(0, separator);
                if (group.empty()) {
                    return false;
                }
                if (group.find('.') != std::string_view::npos) {
                    if (separator != std::string_view::npos || !ParseIpv4Address(group)) {
                        return false;
                    }
                    groups += 2;
                    return true;
                }
                if (group.size() > 4) {
                    return false;
                }
                for (const unsigned char character : group) {
                    const bool hex_digit = (character >= '0' && character <= '9') ||
                        (character >= 'a' && character <= 'f') ||
                        (character >= 'A' && character <= 'F');
                    if (!hex_digit) {
                        return false;
                    }
                }
                ++groups;
                if (separator == std::string_view::npos) {
                    return true;
                }
                if (separator + 1 == value.size()) {
                    return false;
                }
                value.remove_prefix(separator + 1);
            }
            return true;
        }

        bool IsIpv6Address(std::string_view value) {
            if (value.empty()) {
                return false;
            }
            const std::size_t compression = value.find("::");
            if (compression != std::string_view::npos &&
                value.find("::", compression + 2) != std::string_view::npos) {
                return false;
            }

            int groups = 0;
            if (compression == std::string_view::npos) {
                return CountIpv6Groups(value, groups) && groups == 8;
            }
            const std::string_view left = value.substr(0, compression);
            const std::string_view right = value.substr(compression + 2);
            return CountIpv6Groups(left, groups) && CountIpv6Groups(right, groups) &&
                groups < 8;
        }

        std::string_view TrimOptionalWhitespace(std::string_view value) {
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
                value.remove_prefix(1);
            }
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
                value.remove_suffix(1);
            }
            return value;
        }
    }

    ProtocolSnifferResult ProtocolSniffer::Feed(
        const void* data, std::size_t length) {
        if (result_.status != ProtocolSnifferStatus::NeedMore) {
            return result_;
        }
        if (length != 0 && data == nullptr) {
            result_ = MakeResult(ProtocolSnifferStatus::Malformed);
            return result_;
        }
        if (length > MaxInputSize - input_.size()) {
            result_ = MakeResult(ProtocolSnifferStatus::LimitExceeded);
            input_.clear();
            return result_;
        }

        if (length != 0) {
            const auto* bytes = static_cast<const std::uint8_t*>(data);
            input_.insert(input_.end(), bytes, bytes + length);
        }
        result_ = Parse();
        if (result_.status == ProtocolSnifferStatus::NeedMore &&
            input_.size() == MaxInputSize) {
            result_ = MakeResult(ProtocolSnifferStatus::LimitExceeded);
        }
        if (result_.status != ProtocolSnifferStatus::NeedMore) {
            input_.clear();
            input_.shrink_to_fit();
        }
        return result_;
    }

    const ProtocolSnifferResult& ProtocolSniffer::GetResult() const noexcept {
        return result_;
    }

    ProtocolSnifferResult ProtocolSniffer::Parse() const {
        if (input_.empty()) {
            return MakeResult(ProtocolSnifferStatus::NeedMore);
        }
        if (input_.front() == 0x16) {
            return ParseTls();
        }

        const unsigned char first = input_.front();
        if (first >= 'A' && first <= 'Z') {
            return ParseHttp();
        }
        return MakeResult(ProtocolSnifferStatus::Unsupported);
    }

    ProtocolSnifferResult ProtocolSniffer::ParseTls() const {
        std::vector<std::uint8_t> handshake;
        handshake.reserve(input_.size());
        std::size_t input_offset = 0;
        std::size_t record_count = 0;
        std::size_t handshake_size = std::numeric_limits<std::size_t>::max();

        while (input_offset < input_.size()) {
            if (record_count == MaxTlsRecordCount) {
                return MakeResult(ProtocolSnifferStatus::LimitExceeded);
            }
            if (input_.size() - input_offset < 5) {
                return MakeResult(ProtocolSnifferStatus::NeedMore);
            }
            if (input_[input_offset] != 0x16 || input_[input_offset + 1] != 0x03 ||
                input_[input_offset + 2] > 0x04) {
                return MakeResult(ProtocolSnifferStatus::Malformed);
            }
            const std::size_t record_length =
                (static_cast<std::size_t>(input_[input_offset + 3]) << 8) |
                static_cast<std::size_t>(input_[input_offset + 4]);
            if (record_length == 0 || record_length > kMaxTlsRecordPayload) {
                return MakeResult(ProtocolSnifferStatus::Malformed);
            }
            if (input_.size() - input_offset - 5 < record_length) {
                return MakeResult(ProtocolSnifferStatus::NeedMore);
            }

            const std::size_t payload_offset = input_offset + 5;
            handshake.insert(handshake.end(), input_.begin() + payload_offset,
                input_.begin() + payload_offset + record_length);
            ++record_count;
            input_offset = payload_offset + record_length;

            if (handshake.size() >= 4 &&
                handshake_size == std::numeric_limits<std::size_t>::max()) {
                if (handshake[0] != 0x01) {
                    return MakeResult(ProtocolSnifferStatus::Unsupported);
                }
                handshake_size = 4 +
                    (static_cast<std::size_t>(handshake[1]) << 16) +
                    (static_cast<std::size_t>(handshake[2]) << 8) +
                    static_cast<std::size_t>(handshake[3]);
                if (handshake_size > MaxInputSize) {
                    return MakeResult(ProtocolSnifferStatus::Malformed);
                }
            }
            if (handshake_size != std::numeric_limits<std::size_t>::max() &&
                handshake.size() >= handshake_size) {
                break;
            }
        }

        if (handshake_size == std::numeric_limits<std::size_t>::max() ||
            handshake.size() < handshake_size) {
            return MakeResult(ProtocolSnifferStatus::NeedMore);
        }

        const std::size_t limit = handshake_size;
        std::size_t offset = 4;
        if (!Skip(offset, 2 + 32, limit)) {
            return MakeResult(ProtocolSnifferStatus::Malformed);
        }
        if (offset >= limit) {
            return MakeResult(ProtocolSnifferStatus::Malformed);
        }
        const std::size_t session_id_length = handshake[offset++];
        if (session_id_length > 32 || !Skip(offset, session_id_length, limit)) {
            return MakeResult(ProtocolSnifferStatus::Malformed);
        }

        std::uint16_t cipher_suites_length = 0;
        if (!ReadU16(handshake, offset, limit, cipher_suites_length) ||
            cipher_suites_length == 0 || (cipher_suites_length & 1) != 0 ||
            !Skip(offset, cipher_suites_length, limit)) {
            return MakeResult(ProtocolSnifferStatus::Malformed);
        }
        if (offset >= limit) {
            return MakeResult(ProtocolSnifferStatus::Malformed);
        }
        const std::size_t compression_methods_length = handshake[offset++];
        if (compression_methods_length == 0 ||
            !Skip(offset, compression_methods_length, limit)) {
            return MakeResult(ProtocolSnifferStatus::Malformed);
        }
        if (offset == limit) {
            return MakeResult(ProtocolSnifferStatus::Unsupported);
        }

        std::uint16_t extensions_length = 0;
        if (!ReadU16(handshake, offset, limit, extensions_length) ||
            extensions_length != limit - offset) {
            return MakeResult(ProtocolSnifferStatus::Malformed);
        }
        const std::size_t extensions_end = offset + extensions_length;
        bool saw_server_name = false;
        std::string domain;

        while (offset < extensions_end) {
            std::uint16_t extension_type = 0;
            std::uint16_t extension_length = 0;
            if (!ReadU16(handshake, offset, extensions_end, extension_type) ||
                !ReadU16(handshake, offset, extensions_end, extension_length) ||
                extension_length > extensions_end - offset) {
                return MakeResult(ProtocolSnifferStatus::Malformed);
            }
            const std::size_t extension_end = offset + extension_length;
            if (extension_type != 0) {
                offset = extension_end;
                continue;
            }
            if (saw_server_name) {
                return MakeResult(ProtocolSnifferStatus::Malformed);
            }
            saw_server_name = true;

            std::uint16_t names_length = 0;
            if (!ReadU16(handshake, offset, extension_end, names_length) ||
                names_length != extension_end - offset) {
                return MakeResult(ProtocolSnifferStatus::Malformed);
            }
            bool saw_host_name = false;
            while (offset < extension_end) {
                if (extension_end - offset < 3) {
                    return MakeResult(ProtocolSnifferStatus::Malformed);
                }
                const std::uint8_t name_type = handshake[offset++];
                std::uint16_t name_length = 0;
                if (!ReadU16(handshake, offset, extension_end, name_length) ||
                    name_length > extension_end - offset) {
                    return MakeResult(ProtocolSnifferStatus::Malformed);
                }
                if (name_type == 0) {
                    if (saw_host_name || name_length == 0 ||
                        name_length > kMaxHostnameWireLength) {
                        return MakeResult(ProtocolSnifferStatus::Malformed);
                    }
                    saw_host_name = true;
                    const std::string_view name(
                        reinterpret_cast<const char*>(handshake.data() + offset),
                        name_length);
                    if (!NormalizeDomain(name, domain)) {
                        return MakeResult(ProtocolSnifferStatus::Malformed);
                    }
                }
                offset += name_length;
            }
            if (!saw_host_name) {
                return MakeResult(ProtocolSnifferStatus::Unsupported);
            }
        }

        if (!saw_server_name) {
            return MakeResult(ProtocolSnifferStatus::Unsupported);
        }
        return MakeComplete(std::move(domain), ProtocolSnifferSource::TlsSni);
    }

    ProtocolSnifferResult ProtocolSniffer::ParseHttp() const {
        const std::string_view text(
            reinterpret_cast<const char*>(input_.data()), input_.size());
        const std::size_t request_line_end = text.find("\r\n");
        if (request_line_end == std::string_view::npos) {
            if (text.find('\n') != std::string_view::npos) {
                return MakeResult(ProtocolSnifferStatus::Malformed);
            }
            return MakeResult(ProtocolSnifferStatus::NeedMore);
        }

        const std::string_view request_line = text.substr(0, request_line_end);
        const std::size_t first_space = request_line.find(' ');
        const std::size_t second_space = first_space == std::string_view::npos
            ? std::string_view::npos
            : request_line.find(' ', first_space + 1);
        if (first_space == std::string_view::npos) {
            return MakeResult(ProtocolSnifferStatus::Unsupported);
        }
        if (first_space == 0 || second_space == std::string_view::npos ||
            second_space == first_space + 1 ||
            request_line.find(' ', second_space + 1) != std::string_view::npos) {
            return MakeResult(ProtocolSnifferStatus::Malformed);
        }
        for (const unsigned char character : request_line.substr(0, first_space)) {
            if (!IsTokenCharacter(character)) {
                return MakeResult(ProtocolSnifferStatus::Malformed);
            }
        }
        const std::string_view version = request_line.substr(second_space + 1);
        if (version != "HTTP/1.0" && version != "HTTP/1.1") {
            return MakeResult(ProtocolSnifferStatus::Unsupported);
        }

        const std::size_t headers_end = text.find("\r\n\r\n", request_line_end);
        if (headers_end == std::string_view::npos) {
            return MakeResult(ProtocolSnifferStatus::NeedMore);
        }

        bool saw_host = false;
        bool ipv6_host = false;
        std::string domain;
        std::size_t line_start = request_line_end + 2;
        while (line_start < headers_end) {
            const std::size_t line_end = text.find("\r\n", line_start);
            if (line_end == std::string_view::npos || line_end > headers_end) {
                return MakeResult(ProtocolSnifferStatus::Malformed);
            }
            const std::string_view line = text.substr(line_start, line_end - line_start);
            if (line.empty() || line.front() == ' ' || line.front() == '\t') {
                return MakeResult(ProtocolSnifferStatus::Malformed);
            }
            const std::size_t colon = line.find(':');
            if (colon == std::string_view::npos || colon == 0) {
                return MakeResult(ProtocolSnifferStatus::Malformed);
            }
            for (const unsigned char character : line.substr(0, colon)) {
                if (!IsTokenCharacter(character)) {
                    return MakeResult(ProtocolSnifferStatus::Malformed);
                }
            }

            std::string header_name(line.substr(0, colon));
            std::transform(header_name.begin(), header_name.end(), header_name.begin(),
                [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
            if (header_name == "host") {
                if (saw_host) {
                    return MakeResult(ProtocolSnifferStatus::Malformed);
                }
                saw_host = true;
                std::string_view host = TrimOptionalWhitespace(line.substr(colon + 1));
                if (host.empty()) {
                    return MakeResult(ProtocolSnifferStatus::Malformed);
                }
                if (host.front() == '[') {
                    const std::size_t close = host.find(']');
                    if (close == std::string_view::npos || close == 1 ||
                        !IsIpv6Address(host.substr(1, close - 1))) {
                        return MakeResult(ProtocolSnifferStatus::Malformed);
                    }
                    if (close + 1 < host.size() &&
                        (host[close + 1] != ':' || !ParsePort(host.substr(close + 2)))) {
                        return MakeResult(ProtocolSnifferStatus::Malformed);
                    }
                    ipv6_host = true;
                }
                else {
                    const std::size_t host_colon = host.find(':');
                    if (host_colon != std::string_view::npos) {
                        if (host.find(':', host_colon + 1) != std::string_view::npos ||
                            !ParsePort(host.substr(host_colon + 1))) {
                            return MakeResult(ProtocolSnifferStatus::Malformed);
                        }
                        host = host.substr(0, host_colon);
                    }
                    if (!NormalizeDomain(host, domain)) {
                        return MakeResult(ProtocolSnifferStatus::Malformed);
                    }
                }
            }
            line_start = line_end + 2;
        }

        if (!saw_host || ipv6_host) {
            return MakeResult(ProtocolSnifferStatus::Unsupported);
        }
        return MakeComplete(std::move(domain), ProtocolSnifferSource::HttpHost);
    }

} // namespace ppp::app::client::routing

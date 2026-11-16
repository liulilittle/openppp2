#include <ppp/stdafx.h>
#include <ppp/app/client/WindowsIPv6Snapshot.h>

#include <algorithm>
#include <array>
#include <limits>

namespace ppp::app::client {
namespace {
constexpr std::array<char, 4> kMagic{{'O', 'P', '6', 'S'}};
constexpr std::uint32_t kVersion = 1;
constexpr std::size_t kHeaderSize = 12;
constexpr std::uint32_t kMaxString = 16u * 1024u;
constexpr std::uint32_t kMaxServers = 8;

void Put32(std::string& out, std::uint32_t value) {
    out.push_back(static_cast<char>((value >> 24) & 0xff));
    out.push_back(static_cast<char>((value >> 16) & 0xff));
    out.push_back(static_cast<char>((value >> 8) & 0xff));
    out.push_back(static_cast<char>(value & 0xff));
}
void Put64(std::string& out, std::uint64_t value) {
    Put32(out, static_cast<std::uint32_t>(value >> 32));
    Put32(out, static_cast<std::uint32_t>(value));
}
bool PutString(std::string& out, const std::string& value) {
    if (value.size() > kMaxString || value.size() > std::numeric_limits<std::uint32_t>::max()) return false;
    Put32(out, static_cast<std::uint32_t>(value.size()));
    out.append(value);
    return true;
}
void PutHeader(std::string& out) {
    out.append(kMagic.data(), kMagic.size());
    Put32(out, kVersion);
    out.append(4, '\0');
}

class Reader final {
public:
    explicit Reader(std::string_view input) noexcept
        : data_(reinterpret_cast<const unsigned char*>(input.data())), size_(input.size()) {}
    bool Header() noexcept {
        if (size_ < kHeaderSize || !std::equal(kMagic.begin(), kMagic.end(), data_)) return false;
        position_ = 4;
        std::uint32_t version = 0;
        if (!U32(version) || version != kVersion || position_ + 4 > size_ ||
            data_[position_] || data_[position_ + 1] || data_[position_ + 2] || data_[position_ + 3]) return false;
        position_ += 4;
        return true;
    }
    bool U8(std::uint8_t& value) noexcept {
        if (position_ >= size_) return false;
        value = data_[position_++]; return true;
    }
    bool Bool(bool& value) noexcept {
        std::uint8_t byte = 0; if (!U8(byte) || byte > 1) return false;
        value = byte != 0; return true;
    }
    bool U32(std::uint32_t& value) noexcept {
        if (position_ + 4 > size_) return false;
        value = (static_cast<std::uint32_t>(data_[position_]) << 24) |
            (static_cast<std::uint32_t>(data_[position_ + 1]) << 16) |
            (static_cast<std::uint32_t>(data_[position_ + 2]) << 8) |
            static_cast<std::uint32_t>(data_[position_ + 3]);
        position_ += 4; return true;
    }
    bool ReadU64(std::uint64_t& value) noexcept {
        std::uint32_t hi = 0, lo = 0; if (!U32(hi) || !U32(lo)) return false;
        value = (static_cast<std::uint64_t>(hi) << 32) | lo; return true;
    }
    bool String(std::string& value) noexcept {
        std::uint32_t length = 0;
        if (!U32(length) || length > kMaxString || position_ + length > size_) return false;
        try { value.assign(reinterpret_cast<const char*>(data_ + position_), length); }
        catch (...) { return false; }
        position_ += length; return true;
    }
    bool End() const noexcept { return position_ == size_; }
private:
    const unsigned char* data_ = nullptr; std::size_t size_ = 0; std::size_t position_ = 0;
};

bool Strings(std::string& out, const std::vector<std::string>& values) {
    if (values.size() > kMaxServers) return false;
    Put32(out, static_cast<std::uint32_t>(values.size()));
    for (const auto& value : values) if (!PutString(out, value)) return false;
    return true;
}
bool ReadStrings(Reader& reader, std::vector<std::string>& values) {
    std::uint32_t count = 0; if (!reader.U32(count) || count > kMaxServers) return false;
    values.clear(); values.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) { std::string value; if (!reader.String(value)) return false; values.emplace_back(std::move(value)); }
    return true;
}
}

bool SerializeWindowsIPv6Snapshot(const WindowsIPv6Snapshot& snapshot, std::string& serialized) noexcept {
    try {
        serialized.clear(); PutHeader(serialized);
        Put32(serialized, snapshot.interface_index);
        if (!PutString(serialized, snapshot.interface_luid) || !PutString(serialized, snapshot.interface_guid) ||
            !PutString(serialized, snapshot.address)) return false;
        serialized.push_back(static_cast<char>(snapshot.address_prefix_length));
        if (!PutString(serialized, snapshot.gateway) || !PutString(serialized, snapshot.subnet_prefix)) return false;
        serialized.push_back(static_cast<char>(snapshot.subnet_prefix_length));
        if (!PutString(serialized, snapshot.subnet_gateway)) return false;
        serialized.push_back(static_cast<char>(snapshot.mode));
        Put64(serialized, snapshot.neighbor_interface_luid); Put32(serialized, snapshot.neighbor_interface_index);
        serialized.push_back(snapshot.address_owned); serialized.push_back(snapshot.neighbor_owned);
        serialized.push_back(snapshot.subnet_owned); serialized.push_back(snapshot.dns_applied);
        serialized.push_back(snapshot.original_dns_automatic);
        return Strings(serialized, snapshot.dns_servers) && Strings(serialized, snapshot.original_dns_servers);
    } catch (...) { serialized.clear(); return false; }
}

bool DeserializeWindowsIPv6Snapshot(std::string_view serialized, WindowsIPv6Snapshot& snapshot) noexcept {
    try {
        Reader reader(serialized); WindowsIPv6Snapshot decoded;
        if (!reader.Header() || !reader.U32(decoded.interface_index) ||
            !reader.String(decoded.interface_luid) || !reader.String(decoded.interface_guid) ||
            !reader.String(decoded.address) || !reader.U8(decoded.address_prefix_length) ||
            !reader.String(decoded.gateway) || !reader.String(decoded.subnet_prefix) ||
            !reader.U8(decoded.subnet_prefix_length) || !reader.String(decoded.subnet_gateway) ||
            !reader.U8(decoded.mode) || !reader.ReadU64(decoded.neighbor_interface_luid) ||
            !reader.U32(decoded.neighbor_interface_index) || !reader.Bool(decoded.address_owned) ||
            !reader.Bool(decoded.neighbor_owned) || !reader.Bool(decoded.subnet_owned) ||
            !reader.Bool(decoded.dns_applied) || !reader.Bool(decoded.original_dns_automatic) ||
            !ReadStrings(reader, decoded.dns_servers) || !ReadStrings(reader, decoded.original_dns_servers) || !reader.End()) return false;
        snapshot = std::move(decoded); return true;
    } catch (...) { return false; }
}

bool VerifyWindowsIPv6Identity(const WindowsIPv6Snapshot& expected, std::uint32_t interface_index,
    std::string_view interface_luid, std::string_view interface_guid) noexcept {
    return expected.interface_index == interface_index && !expected.interface_luid.empty() &&
        !expected.interface_guid.empty() && !interface_luid.empty() && !interface_guid.empty() &&
        expected.interface_luid == interface_luid && expected.interface_guid == interface_guid;
}
} // namespace ppp::app::client

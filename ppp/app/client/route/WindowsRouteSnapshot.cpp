#include <ppp/stdafx.h>
#include <ppp/app/client/route/WindowsRouteSnapshot.h>

#include <algorithm>
#include <array>
#include <limits>

namespace ppp::app::client::route {
namespace {

constexpr std::array<char, 4> kMagic{{'O', 'P', 'R', 'S'}};
constexpr std::size_t kHeaderSize = 12;
constexpr std::uint32_t kMaxStringSize = 16u * 1024u;

void AppendU32(std::string& output, std::uint32_t value) {
    output.push_back(static_cast<char>((value >> 24) & 0xffu));
    output.push_back(static_cast<char>((value >> 16) & 0xffu));
    output.push_back(static_cast<char>((value >> 8) & 0xffu));
    output.push_back(static_cast<char>(value & 0xffu));
}

bool AppendString(std::string& output, const std::string& value) {
    if (value.size() > kMaxStringSize ||
        value.size() > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    AppendU32(output, static_cast<std::uint32_t>(value.size()));
    output.append(value);
    return true;
}

void AppendHeader(std::string& output, WindowsRouteSnapshotKind kind) {
    output.append(kMagic.data(), kMagic.size());
    AppendU32(output, WindowsRouteSnapshotSchemaVersion);
    output.push_back(static_cast<char>(kind));
    output.append(3, '\0');
}

class Reader final {
public:
    explicit Reader(std::string_view input) noexcept
        : data_(reinterpret_cast<const unsigned char*>(input.data())),
          size_(input.size()) {
    }

    bool Header(WindowsRouteSnapshotKind expected_kind) noexcept {
        if (size_ < kHeaderSize ||
            !std::equal(kMagic.begin(), kMagic.end(), data_)) {
            return false;
        }
        position_ = 4;
        std::uint32_t version = 0;
        if (!U32(version) || version != WindowsRouteSnapshotSchemaVersion) {
            return false;
        }
        if (position_ + 4 > size_ ||
            static_cast<WindowsRouteSnapshotKind>(data_[position_]) !=
                expected_kind || data_[position_ + 1] != 0 ||
            data_[position_ + 2] != 0 || data_[position_ + 3] != 0) {
            return false;
        }
        position_ += 4;
        return true;
    }

    bool U32(std::uint32_t& value) noexcept {
        if (position_ + 4 > size_) {
            return false;
        }
        value = (static_cast<std::uint32_t>(data_[position_]) << 24) |
            (static_cast<std::uint32_t>(data_[position_ + 1]) << 16) |
            (static_cast<std::uint32_t>(data_[position_ + 2]) << 8) |
            static_cast<std::uint32_t>(data_[position_ + 3]);
        position_ += 4;
        return true;
    }

    bool String(std::string& value) noexcept {
        std::uint32_t length = 0;
        if (!U32(length) || length > kMaxStringSize ||
            position_ + length > size_) {
            return false;
        }
        try {
            value.assign(reinterpret_cast<const char*>(data_ + position_), length);
        } catch (...) {
            return false;
        }
        position_ += length;
        return true;
    }

    bool End() const noexcept { return position_ == size_; }

private:
    const unsigned char* data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t position_ = 0;
};

bool SerializeRowFields(
    const WindowsRouteRowSnapshot& snapshot,
    std::string& output) {
    const std::array<std::uint32_t, 14> fields{{
        snapshot.destination,
        snapshot.mask,
        snapshot.policy,
        snapshot.next_hop,
        snapshot.interface_index,
        snapshot.type,
        snapshot.proto,
        snapshot.age,
        snapshot.next_hop_as,
        snapshot.metric1,
        snapshot.metric2,
        snapshot.metric3,
        snapshot.metric4,
        snapshot.metric5,
    }};
    for (const std::uint32_t value : fields) {
        AppendU32(output, value);
    }
    return AppendString(output, snapshot.interface_luid) &&
        AppendString(output, snapshot.interface_guid);
}

bool DeserializeRowFields(Reader& reader, WindowsRouteRowSnapshot& snapshot) {
    std::array<std::uint32_t, 14> fields{};
    for (std::uint32_t& value : fields) {
        if (!reader.U32(value)) {
            return false;
        }
    }
    snapshot.destination = fields[0];
    snapshot.mask = fields[1];
    snapshot.policy = fields[2];
    snapshot.next_hop = fields[3];
    snapshot.interface_index = fields[4];
    snapshot.type = fields[5];
    snapshot.proto = fields[6];
    snapshot.age = fields[7];
    snapshot.next_hop_as = fields[8];
    snapshot.metric1 = fields[9];
    snapshot.metric2 = fields[10];
    snapshot.metric3 = fields[11];
    snapshot.metric4 = fields[12];
    snapshot.metric5 = fields[13];
    return reader.String(snapshot.interface_luid) &&
        reader.String(snapshot.interface_guid);
}

} // namespace

bool SerializeWindowsRouteSnapshot(
    const WindowsRouteRowSnapshot& snapshot,
    std::string& serialized) noexcept {
    try {
        serialized.clear();
        serialized.reserve(kHeaderSize + 14u * 4u + 8u +
            snapshot.interface_luid.size() + snapshot.interface_guid.size());
        AppendHeader(serialized, WindowsRouteSnapshotKind::RouteRow);
        return SerializeRowFields(snapshot, serialized);
    } catch (...) {
        serialized.clear();
        return false;
    }
}

bool SerializeWindowsGatewaySnapshot(
    const WindowsGatewaySnapshotData& snapshot,
    std::string& serialized) noexcept {
    try {
        serialized.clear();
        serialized.reserve(kHeaderSize + 4u + 12u + snapshot.interface_luid.size() +
            snapshot.interface_guid.size() + snapshot.gateway.size());
        AppendHeader(serialized, WindowsRouteSnapshotKind::Gateway);
        AppendU32(serialized, snapshot.interface_index);
        if (!AppendString(serialized, snapshot.interface_luid) ||
            !AppendString(serialized, snapshot.interface_guid) ||
            !AppendString(serialized, snapshot.gateway)) {
            serialized.clear();
            return false;
        }
        return true;
    } catch (...) {
        serialized.clear();
        return false;
    }
}

bool DeserializeWindowsRouteSnapshot(
    std::string_view serialized,
    WindowsRouteRowSnapshot& snapshot) noexcept {
    try {
        Reader reader(serialized);
        WindowsRouteRowSnapshot decoded;
        if (!reader.Header(WindowsRouteSnapshotKind::RouteRow) ||
            !DeserializeRowFields(reader, decoded) || !reader.End()) {
            return false;
        }
        snapshot = std::move(decoded);
        return true;
    } catch (...) {
        return false;
    }
}

bool DeserializeWindowsGatewaySnapshot(
    std::string_view serialized,
    WindowsGatewaySnapshotData& snapshot) noexcept {
    try {
        Reader reader(serialized);
        WindowsGatewaySnapshotData decoded;
        if (!reader.Header(WindowsRouteSnapshotKind::Gateway) ||
            !reader.U32(decoded.interface_index) ||
            !reader.String(decoded.interface_luid) ||
            !reader.String(decoded.interface_guid) ||
            !reader.String(decoded.gateway) || !reader.End()) {
            return false;
        }
        snapshot = std::move(decoded);
        return true;
    } catch (...) {
        return false;
    }
}

bool SameWindowsRouteSnapshot(
    const WindowsRouteRowSnapshot& left,
    const WindowsRouteRowSnapshot& right) noexcept {
    return left.destination == right.destination && left.mask == right.mask &&
        left.policy == right.policy && left.next_hop == right.next_hop &&
        left.interface_index == right.interface_index &&
        left.type == right.type && left.proto == right.proto &&
        left.age == right.age && left.next_hop_as == right.next_hop_as &&
        left.metric1 == right.metric1 && left.metric2 == right.metric2 &&
        left.metric3 == right.metric3 && left.metric4 == right.metric4 &&
        left.metric5 == right.metric5 &&
        left.interface_luid == right.interface_luid &&
        left.interface_guid == right.interface_guid;
}

bool SameWindowsGatewaySnapshot(
    const WindowsGatewaySnapshotData& left,
    const WindowsGatewaySnapshotData& right) noexcept {
    return left.interface_index == right.interface_index &&
        left.gateway == right.gateway &&
        left.interface_luid == right.interface_luid &&
        left.interface_guid == right.interface_guid;
}

bool VerifyWindowsRouteSnapshot(
    const WindowsRouteRowSnapshot& expected,
    const WindowsRouteRowSnapshot& actual) noexcept {
    // dwForwardAge is maintained by the IP helper and changes while a route
    // remains installed.  It is serialized for forensic completeness, but it
    // is not an ownership attribute and must not turn an otherwise exact
    // compare-and-restore into a false conflict.
    // A durable route claim is unsafe without both stable adapter
    // identifiers.  Empty values are an unknown identity, never a wildcard.
    return !expected.interface_luid.empty() &&
        !expected.interface_guid.empty() &&
        !actual.interface_luid.empty() &&
        !actual.interface_guid.empty() &&
        expected.destination == actual.destination &&
        expected.mask == actual.mask && expected.policy == actual.policy &&
        expected.next_hop == actual.next_hop &&
        expected.interface_index == actual.interface_index &&
        expected.type == actual.type && expected.proto == actual.proto &&
        expected.next_hop_as == actual.next_hop_as &&
        expected.metric1 == actual.metric1 &&
        expected.metric2 == actual.metric2 &&
        expected.metric3 == actual.metric3 &&
        expected.metric4 == actual.metric4 &&
        expected.metric5 == actual.metric5 &&
        expected.interface_luid == actual.interface_luid &&
        expected.interface_guid == actual.interface_guid;
}

bool VerifyWindowsGatewaySnapshot(
    const WindowsGatewaySnapshotData& expected,
    const WindowsGatewaySnapshotData& actual) noexcept {
    return !expected.interface_luid.empty() &&
        !expected.interface_guid.empty() &&
        !actual.interface_luid.empty() &&
        !actual.interface_guid.empty() &&
        SameWindowsGatewaySnapshot(expected, actual);
}

} // namespace ppp::app::client::route

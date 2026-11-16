#include <ppp/app/client/WindowsIPv6Snapshot.h>

#include <cassert>
#include <string>

using ppp::app::client::DeserializeWindowsIPv6Snapshot;
using ppp::app::client::SerializeWindowsIPv6Snapshot;
using ppp::app::client::VerifyWindowsIPv6Identity;
using ppp::app::client::WindowsIPv6Snapshot;

int main() {
    WindowsIPv6Snapshot original;
    original.interface_index = 42;
    original.interface_luid = "0x1234";
    original.interface_guid = "{tap-guid}";
    original.address = "2001:db8::2";
    original.address_prefix_length = 128;
    original.gateway = "2001:db8::1";
    original.subnet_prefix = "fd00::";
    original.subnet_prefix_length = 64;
    original.subnet_gateway = "fd00::1";
    original.mode = 1;
    original.neighbor_interface_luid = 0x9988;
    original.neighbor_interface_index = 42;
    original.address_owned = true;
    original.neighbor_owned = true;
    original.subnet_owned = true;
    original.dns_applied = true;
    original.original_dns_automatic = false;
    original.dns_servers = {"2001:4860:4860::8888", "2001:4860:4860::8844"};
    original.original_dns_servers = {"::1"};

    std::string encoded;
    assert(SerializeWindowsIPv6Snapshot(original, encoded));
    assert(encoded.rfind("OP6S", 0) == 0);
    WindowsIPv6Snapshot decoded;
    assert(DeserializeWindowsIPv6Snapshot(encoded, decoded));
    assert(decoded.interface_guid == original.interface_guid);
    assert(decoded.interface_luid == original.interface_luid);
    assert(decoded.address == original.address);
    assert(decoded.dns_servers == original.dns_servers);
    assert(VerifyWindowsIPv6Identity(decoded, 42, "0x1234", "{tap-guid}"));
    assert(!VerifyWindowsIPv6Identity(decoded, 43, "0x1234", "{tap-guid}"));
    assert(!VerifyWindowsIPv6Identity(decoded, 42, "0x9999", "{tap-guid}"));
    assert(!VerifyWindowsIPv6Identity(decoded, 42, "0x1234", "{other}"));

    std::string truncated = encoded.substr(0, encoded.size() - 1);
    assert(!DeserializeWindowsIPv6Snapshot(truncated, decoded));
    encoded[0] = 'X';
    assert(!DeserializeWindowsIPv6Snapshot(encoded, decoded));
    return 0;
}

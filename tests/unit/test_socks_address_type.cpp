#include <gtest/gtest.h>

#include <ppp/app/client/proxys/SocksAddressType.h>

namespace {

using ppp::app::client::proxys::detail::TryParseSocksAddressType;
using ppp::app::protocol::AddressType;

TEST(SocksAddressType, ParsesWireTypesIndependentlyFromInternalValues) {
    AddressType address_type = AddressType::None;
    int address_length = -1;

    EXPECT_TRUE(TryParseSocksAddressType(1, address_type, address_length));
    EXPECT_EQ(AddressType::IPv4, address_type);
    EXPECT_EQ(4, address_length);

    EXPECT_TRUE(TryParseSocksAddressType(3, address_type, address_length));
    EXPECT_EQ(AddressType::Domain, address_type);
    EXPECT_EQ(0, address_length);

    EXPECT_TRUE(TryParseSocksAddressType(4, address_type, address_length));
    EXPECT_EQ(AddressType::IPv6, address_type);
    EXPECT_EQ(16, address_length);
}

TEST(SocksAddressType, RejectsUnsupportedWireType) {
    AddressType address_type = AddressType::None;
    int address_length = -1;

    EXPECT_FALSE(TryParseSocksAddressType(2, address_type, address_length));
    EXPECT_EQ(AddressType::None, address_type);
    EXPECT_EQ(-1, address_length);
}

} // namespace

#include <ppp/app/client/udp/UdpFlowPolicy.h>
#include <iostream>
#include <stdexcept>

using namespace ppp::app::client::udp;
namespace {
void Require(bool ok, const char* why) { if (!ok) throw std::runtime_error(why); }
}
int main() {
    try {
        Require(UdpFlowQueueLimit::Allows(0, 0, 65507), "Largest IPv4 UDP accepted");
        Require(!UdpFlowQueueLimit::Allows(0, 0, 65508), "Oversized IPv4 UDP rejected");
        Require(!UdpFlowQueueLimit::Allows(0, 0, 0), "Empty payload rejected");
        Require(UdpFlowQueueLimit::Allows(31, 65535, 1), "Inclusive packet/byte boundary");
        Require(!UdpFlowQueueLimit::Allows(32, 1, 1), "Packet limit enforced");
        Require(!UdpFlowQueueLimit::Allows(1, 65536, 1), "Byte limit enforced");
        Require(!UdpFlowQueueLimit::Allows(1, static_cast<std::size_t>(-1), 1), "Overflow cannot admit bytes");
        Require(NormalizeUdpFlowDomain("A.Example.TEST.") == "a.example.test", "Domain identity normalizes DNS case/dot");
        Require(NormalizeUdpFlowDomain("a.test") != NormalizeUdpFlowDomain("b.test"), "Shared IP domains retain identity");
        Require(NormalizeUdpFlowDomain("").empty(), "IP-only flow does not invent domain");
        std::uint64_t sequence = 65534;
        std::uint32_t first_address, second_address;
        std::uint16_t first_port, second_port;
        Require(UdpRelayIdentity::Next(sequence, first_address, first_port), "First relay identity allocation");
        Require(UdpRelayIdentity::Next(sequence, second_address, second_port), "Relay rollover allocation");
        Require(first_address != second_address && first_port == 65535 && second_port == 1,
            "Retired relay endpoint reused on 16-bit port wrap");
        Require(UdpRelayIdentity::IsIdentity(first_address) && UdpRelayIdentity::IsIdentity(second_address),
            "Relay namespace recognition");
        sequence = 0xffffffffu;
        Require(!UdpRelayIdentity::Next(sequence, second_address, second_port), "Exhausted relay identities wrap");
        std::cout << "UDP direct flow policy tests passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    return 0;
}

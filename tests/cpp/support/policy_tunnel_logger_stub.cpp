// The offline connector fixture never supplies a logger. Resolve the optional
// call without linking file rotation and transport RTTI into this partial binary.
#include <ppp/app/protocol/VirtualEthernetLogger.h>

namespace ppp::app::protocol {
bool VirtualEthernetLogger::Connect(
    Int128, const std::shared_ptr<ppp::transmissions::ITransmission>&,
    const boost::asio::ip::tcp::endpoint&, const boost::asio::ip::tcp::endpoint&,
    const ppp::string&) noexcept {
    return false;
}
}

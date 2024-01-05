#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/io/Stream.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/checksum.h>
#include <ppp/coroutines/asio/asio.h>

namespace ppp {
    namespace app {
        namespace protocol {
            typedef ppp::io::Stream                                     Stream;
            typedef ppp::io::MemoryStream                               MemoryStream;
            typedef ppp::net::Ipep                                      Ipep;
            typedef ppp::net::AddressFamily                             AddressFamily;
            typedef ppp::net::IPEndPoint                                IPEndPoint;
            typedef VirtualEthernetLinklayer::ITransmissionPtr          ITransmissionPtr;
            typedef VirtualEthernetLinklayer::YieldContext              YieldContext;
            typedef VirtualEthernetLinklayer::PacketAction              PacketAction;

            namespace checksum = ppp::net::native;
            namespace global {
                template<class TProtocol>
                static boost::asio::ip::basic_endpoint<TProtocol>       PACKET_IPEndPoint(const std::shared_ptr<ppp::net::Firewall>& firewall, Byte*& stream, int& packet_length, YieldContext& y) noexcept {
                    /* ACTION(1BYTE) ADDR_LEN(1BYTE) ... PORT_LEN(1BYTE) ... */
                    if (--packet_length < 0) {
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    int address_length = *stream++;
                    if (address_length > packet_length) {
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    ppp::string hostname = ppp::string((char*)stream, address_length);
                    if (hostname.empty()) {
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    stream += address_length;
                    packet_length -= address_length + 1;
                    if (packet_length < 0) {
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    int port_length = *stream++;
                    if (port_length > packet_length) {
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    int port = atoi(ppp::string((char*)stream, port_length).data());
                    if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                        port = IPEndPoint::MinPort;
                    }

                    if (NULL != firewall) {
                        if (firewall->IsDropNetworkPort(port, std::is_same<boost::asio::ip::tcp, TProtocol>::value)) {
                            return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                        }
                    }

                    stream += port_length;
                    packet_length -= port_length;

                    boost::system::error_code ec;
                    boost::asio::ip::address address = boost::asio::ip::address::from_string(hostname.data(), ec);
                    if (ec) {
                        if (NULL != firewall) {
                            if (firewall->IsDropNetworkDomains(hostname)) {
                                return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                            }
                        }

                        if (y) {
                            boost::asio::ip::basic_resolver<TProtocol> resolver(y.GetContext());
                            return ppp::coroutines::asio::GetAddressByHostName(resolver, hostname.data(), port, y);
                        }
                        else {
                            return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                        }
                    }
                    else {
                        if (NULL != firewall) {
                            if (firewall->IsDropNetworkSegment(address)) {
                                return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                            }
                        }

                        return boost::asio::ip::basic_endpoint<TProtocol>(address, port);
                    }
                }

                static int                                              PACKET_ConnectId(Byte*& stream, int& packet_length) noexcept {
                    /* ACTION(1BYTE) CONNECT_ID(3BYTE) */
                    int remainder_length = packet_length - 3;
                    if (remainder_length < 0) {
                        return 0;
                    }

                    int connect_id = stream[0] << 16 | stream[1] << 8 | stream[2];
                    stream += 3;
                    packet_length -= 3;
                    return connect_id;
                }

                static bool                                             PACKET_ConnectId(Stream& stream, PacketAction packet_action, int connection_id, Byte* packet, int packet_length) noexcept {
                    if (packet_length < 0 || (NULL == packet && packet_length != 0)) {
                        return false;
                    }

                    if (connection_id == 0) {
                        return false;
                    }

                    Byte packet_header[4] = {
                        (Byte)(packet_action),
                        (Byte)(connection_id >> 16),
                        (Byte)(connection_id >> 8),
                        (Byte)(connection_id)
                    };

                    bool ok = stream.Write(packet_header, 0, sizeof(packet_header));
                    if (ok) {
                        ok = stream.Write(packet, 0, packet_length);
                    }
                    return ok;
                }

                static bool                                             PACKET_Push(PacketAction packet_action, const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept {
                    if (NULL == transmission) {
                        return false;
                    }

                    MemoryStream ms;
                    if (!PACKET_ConnectId(ms, packet_action, connection_id, packet, packet_length)) {
                        return false;
                    }

                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                }

                template<class TProtocol>
                static bool                                             PACKET_IPEndPoint(const boost::asio::ip::basic_endpoint<TProtocol>& destinationEP) noexcept {
                    int destinationPort = destinationEP.port();
                    if (destinationPort <= IPEndPoint::MinPort || destinationPort > IPEndPoint::MaxPort) {
                        return false;
                    }

                    boost::asio::ip::address destinationIP = destinationEP.address();
                    if (destinationIP.is_v4() || destinationIP.is_v6()) {
                        if (destinationIP.is_unspecified()) {
                            return false;
                        }

                        if (destinationIP.is_multicast()) {
                            return false;
                        }

                        if (std::is_same<TProtocol, boost::asio::ip::tcp>::value) {
                            IPEndPoint ep = IPEndPoint::ToEndPoint(destinationEP);
                            if (ep.IsBroadcast()) {
                                return false;
                            }
                        }

                        return true;
                    }
                    return false;
                }

                template<class TString>
                static bool                                             PACKET_IPEndPoint(Stream& stream, const TString& address_string, int address_port) noexcept {
                    if (address_port <= IPEndPoint::MinPort || address_port > IPEndPoint::MaxPort) {
                        return false;
                    }

                    if (address_string.empty()) {
                        return false;
                    }

                    if (stream.WriteByte((Byte)address_string.size())) {
                        if (stream.Write(address_string.data(), 0, (int)address_string.size())) {
                            char address_port_string[16];
                            int address_port_string_size = std::_snprintf(address_port_string, sizeof(address_port_string), "%d", address_port);
                            if (address_port_string_size < 1) {
                                return false;
                            }

                            if (stream.WriteByte((Byte)address_port_string_size)) {
                                return stream.Write(address_port_string, 0, address_port_string_size);
                            }
                        }
                    }
                    return false;
                }

                template<class TProtocol>
                static bool                                             PACKET_IPEndPoint(Stream& stream, const boost::asio::ip::basic_endpoint<TProtocol>& destinationEP) noexcept {
                    if (!PACKET_IPEndPoint<TProtocol>(destinationEP)) {
                        return false;
                    }

                    return PACKET_IPEndPoint(stream, Ipep::ToAddressString<ppp::string>(destinationEP), destinationEP.port());
                }
            
                static bool                                             PACKET_DoConnect(
                    const ITransmissionPtr&                             transmission,
                    int                                                 connection_id,
                    const boost::asio::ip::tcp::endpoint*               destinationEP,
                    const ppp::string&                                  hostname,
                    int                                                 port,
                    YieldContext&                                       y) noexcept {
                    typedef VirtualEthernetLinklayer PakcetAction;

                    if (NULL == transmission || connection_id == 0) {
                        return false;
                    }

                    MemoryStream ms;
                    if (NULL != destinationEP) {
                        if (!PACKET_IPEndPoint(ms, *destinationEP)) {
                            return false;
                        }
                    }
                    else {
                        if (!PACKET_IPEndPoint(ms, hostname, port)) {
                            return false;
                        }
                    }

                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                    return PACKET_Push(PakcetAction::PacketAction_SYN, transmission, connection_id, buffer.get(), ms.GetPosition(), y);
                }

                static bool                                             PACKET_Push(PacketAction packet_action, const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                    if (NULL == packet || packet_length < 1) {
                        return false;
                    }
                    
                    if (NULL == transmission) {
                        return false;
                    }

                    MemoryStream ms;
                    if (ms.WriteByte((Byte)packet_action)) {
                        if (ms.Write(packet, 0, packet_length)) {
                            std::shared_ptr<Byte> buffer = ms.GetBuffer();
                            return transmission->Write(y, buffer.get(), ms.GetPosition());
                        }
                    }
                    return false;
                }
            }

            VirtualEthernetLinklayer::VirtualEthernetLinklayer(
                const AppConfigurationPtr&                              configuration, 
                const ContextPtr&                                       context,
                const Int128&                                           id) noexcept
                : context_(context)
                , disposed_(false)
                , id_(id)
                , configuration_(configuration) {

            }

            int VirtualEthernetLinklayer::NewId() noexcept {
                static std::atomic<unsigned short> aid = /*ATOMIC_FLAG_INIT*/RandomNext();
                static constexpr int max_aid = (1 << 24) - 1;

                for (;;) {
                    int id = ++aid;
                    if (id < 0) {
                        aid = 0;
                        continue;
                    }

                    if (id > max_aid) {
                        aid = 0;
                        continue;
                    }

                    return id;
                }
            }

            Int128 VirtualEthernetLinklayer::GetId() noexcept {
                return id_;
            }

            std::shared_ptr<VirtualEthernetLinklayer> VirtualEthernetLinklayer::GetReference() noexcept {
                return shared_from_this();
            }
            
            VirtualEthernetLinklayer::ContextPtr VirtualEthernetLinklayer::GetContext() noexcept {
                return context_;
            }

            std::shared_ptr<ppp::net::Firewall> VirtualEthernetLinklayer::GetFirewall() noexcept {
                return NULL;
            }

            bool VirtualEthernetLinklayer::Run(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (NULL == transmission) {
                    return false;
                }

                bool ok = false;
                while (!disposed_) {
                    int packet_length = 0;
                    std::shared_ptr<Byte> packet = transmission->Read(y, packet_length);
                    if (NULL == packet || packet_length < 1) {
                        break;
                    }

                    if (!PacketInput(transmission, packet.get(), packet_length, y)) {
                        break;
                    }
                    else {
                        ok = true;
                    }
                }
                return ok;
            }

            bool VirtualEthernetLinklayer::PacketInput(const ITransmissionPtr& transmission, Byte* p, int packet_length, YieldContext& y) noexcept {
                // Pointer access and iteration GUN GCC/G++ and clang++ compiler compatibility.
                // *--p and *p++ expressions, and follow the C/C++ language standard VC++ 2012, C# native-access not is different.
                PacketAction packet_action = (PacketAction)*p;
                p++;
                packet_length--;

                // Dealing with the operation protocol under different actions, here is not made into a variety 
                // of different action callback functions and C/C++ action parameter anemia model template, 
                // the reason: reduce the size of the stack space, 
                // and improve efficiency, allowing the sacrifice of a certain code readability, 
                // because the part of the code is very fixed, so this is a slightly feasible.
                if (packet_action == PacketAction_PSH) {
                    int connection_id = global::PACKET_ConnectId(p, packet_length);
                    if (connection_id && packet_length > 0) {
                        return OnPush(transmission, connection_id, p, packet_length, y);
                    }
                }
                elif(packet_action == PacketAction_SYN) {
                    int connection_id = global::PACKET_ConnectId(p, packet_length);
                    if (connection_id) {
                        boost::asio::ip::tcp::endpoint destinationEP = global::PACKET_IPEndPoint<boost::asio::ip::tcp>(GetFirewall(), p, packet_length, y);
                        if (destinationEP.port()) {
                            return OnConnect(transmission, connection_id, destinationEP, y);
                        }
                    }
                }
                elif(packet_action == PacketAction_SYNOK) {
                    int connection_id = global::PACKET_ConnectId(p, packet_length);
                    if (connection_id && packet_length > 0) {
                        Byte error_code = *p;
                        p++;
                        return OnConnectOK(transmission, connection_id, error_code, y);
                    }
                }
                elif(packet_action == PacketAction_FIN) {
                    int connection_id = global::PACKET_ConnectId(p, packet_length);
                    if (connection_id) {
                        return OnDisconnect(transmission, connection_id, y);
                    }
                }
                elif(packet_action == PacketAction_SENDTO) {
                    boost::asio::ip::udp::endpoint destinationEP = global::PACKET_IPEndPoint<boost::asio::ip::udp>(GetFirewall(), p, packet_length, y);
                    if (destinationEP.port()) {
                        boost::asio::ip::udp::endpoint sourceEP = global::PACKET_IPEndPoint<boost::asio::ip::udp>(GetFirewall(), p, packet_length, y);
                        if (sourceEP.port() && packet_length > -1) {
                            return OnSendTo(transmission, sourceEP, destinationEP, p, packet_length, y);
                        }
                    }
                }
                elif(packet_action == PacketAction_ECHO) {
                    if (packet_length > 0) {
                        return OnEcho(transmission, p, packet_length, y);
                    }
                }
                elif(packet_action == PacketAction_ECHOACK) {
                    int ack_id = global::PACKET_ConnectId(p, packet_length);
                    if (ack_id) {
                        return OnEcho(transmission, ack_id, y);
                    }
                }
                elif(packet_action == PacketAction_INFO) {
                    if (packet_length >= sizeof(VirtualEthernetInformation)) {
                        VirtualEthernetInformation info = *reinterpret_cast<VirtualEthernetInformation*>(p);
                        info.BandwidthQoS = ntohl(info.BandwidthQoS);
                        info.ExpiredTime = ntohl(info.ExpiredTime);
                        info.IncomingTraffic = checksum::ntohll(info.IncomingTraffic);
                        info.OutgoingTraffic = checksum::ntohll(info.OutgoingTraffic);
                        return OnInformation(transmission, info, y);
                    }
                }
                return false;
            }

            bool VirtualEthernetLinklayer::DoInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept {
                if (disposed_) {
                    return false;
                }

                VirtualEthernetInformation info;
                info.BandwidthQoS = htonl(information.BandwidthQoS);
                info.ExpiredTime = htonl(information.ExpiredTime);
                info.IncomingTraffic = checksum::htonll(information.IncomingTraffic);
                info.OutgoingTraffic = checksum::htonll(information.OutgoingTraffic);
                return global::PACKET_Push(PacketAction_INFO, transmission, (Byte*)&info, sizeof(info), y);
            }

            bool VirtualEthernetLinklayer::DoConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept {
                if (disposed_) {
                    return false;
                }

                return global::PACKET_DoConnect(transmission, connection_id, addressof(destinationEP), ppp::string(), IPEndPoint::MinPort, y);
            }

            bool VirtualEthernetLinklayer::DoConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& hostname, int port, YieldContext& y) noexcept {
                if (disposed_) {
                    return false;
                }
                
                return global::PACKET_DoConnect(transmission, connection_id, NULL, hostname, port, y);
            }

            bool VirtualEthernetLinklayer::DoConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept {
                if (disposed_) {
                    return false;
                }
                
                return global::PACKET_Push(PacketAction_SYNOK, transmission, connection_id, &error_code, sizeof(error_code), y);
            }

            bool VirtualEthernetLinklayer::DoPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                return global::PACKET_Push(PacketAction_PSH, transmission, connection_id, packet, packet_length, y);
            }

            bool VirtualEthernetLinklayer::DoDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept {
                if (disposed_) {
                    return false;
                }

                return global::PACKET_Push(PacketAction_FIN, transmission, connection_id, NULL, 0, y);
            }

            bool VirtualEthernetLinklayer::DoSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
                if (NULL == packet && packet_length != 0) {
                    return false;
                }

                if (packet_length < 0) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                if (NULL == transmission) {
                    return false;
                }

                MemoryStream ms;
                if (ms.WriteByte((Byte)PacketAction_SENDTO)) {
                    if (global::PACKET_IPEndPoint(ms, destinationEP)) {
                        if (global::PACKET_IPEndPoint(ms, sourceEP)) {
                            if (ms.Write(packet, 0, packet_length)) {
                                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                return transmission->Write(y, buffer.get(), ms.GetPosition());
                            }
                        }
                    }
                }
                return false;
            }

            bool VirtualEthernetLinklayer::DoEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept {
                if (disposed_) {
                    return false;
                }

                return global::PACKET_Push(PacketAction_ECHOACK, transmission, ack_id, NULL, 0, y);
            }

            bool VirtualEthernetLinklayer::DoEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                if (disposed_) {
                    return false;
                }

                return global::PACKET_Push(PacketAction_ECHO, transmission, packet, packet_length, y);
            }

            bool VirtualEthernetLinklayer::OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept {
                return true;
            }

            bool VirtualEthernetLinklayer::OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept {
                return true;
            }

            bool VirtualEthernetLinklayer::OnEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                return true;
            }

            bool VirtualEthernetLinklayer::OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
                return true;
            }

            bool VirtualEthernetLinklayer::OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept {
                return true;
            }

            bool VirtualEthernetLinklayer::OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept {
                return true;
            }

            bool VirtualEthernetLinklayer::OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept {
                return true;
            }

            bool VirtualEthernetLinklayer::OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept {
                return true;
            }

            VirtualEthernetLinklayer::AppConfigurationPtr VirtualEthernetLinklayer::GetConfiguration() noexcept {
                return configuration_;
            }
        }
    }
}
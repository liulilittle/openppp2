#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/io/Stream.h>
#include <ppp/io/BinaryReader.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/checksum.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>

namespace ppp {
    namespace app {
        namespace protocol {
            typedef ppp::io::Stream                                     Stream;
            typedef ppp::io::BinaryReader                               BinaryReader;
            typedef ppp::io::MemoryStream                               MemoryStream;
            typedef ppp::net::Ipep                                      Ipep;
            typedef ppp::net::AddressFamily                             AddressFamily;
            typedef ppp::net::IPEndPoint                                IPEndPoint;
            typedef VirtualEthernetLinklayer::ITransmissionPtr          ITransmissionPtr;
            typedef VirtualEthernetLinklayer::YieldContext              YieldContext;
            typedef VirtualEthernetLinklayer::PacketAction              PacketAction;
            typedef ppp::threading::Executors                           Executors;

            namespace checksum = ppp::net::native;
            namespace global {
                template <class TProtocol>
                static boost::asio::ip::basic_endpoint<TProtocol>       PACKET_IPEndPoint(const std::shared_ptr<ppp::net::Firewall>& firewall, Byte*& stream, int& packet_length, YieldContext& y, ppp::string& hostname) noexcept {
                    /* ACTION(1BYTE) ADDR_LEN(1BYTE) ... PORT_LEN(1BYTE) ... */
                    if (--packet_length < 0) {
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    int address_length = *stream++;
                    if (address_length > packet_length) {
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    hostname = ppp::string((char*)stream, address_length);
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
                    boost::asio::ip::address address = StringToAddress(hostname.data(), ec);
                    if (ec) {
                        if (NULL != firewall) {
                            if (firewall->IsDropNetworkDomains(hostname)) {
                                return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                            }
                        }

                        if (y) {
                            return ppp::coroutines::asio::GetAddressByHostName<TProtocol>(hostname.data(), port, y);
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

                static int                                              PACKET_Dword(Byte*& stream, int& packet_length) noexcept {
                    int remainder_length = packet_length - 4;
                    if (remainder_length < 0) {
                        return 0;
                    }

                    int connect_id = stream[0] << 24 | stream[1] << 16 | stream[2] << 8 | stream[3];
                    stream += 4;
                    packet_length -= 4;
                    return connect_id;
                }

                static bool                                             PACKET_Dword(Stream& stream, int value) noexcept {
                    Byte buf[4] = {
                        (Byte)(value >> 24),
                        (Byte)(value >> 16),
                        (Byte)(value >> 8),
                        (Byte)(value)
                    };

                    return stream.Write(buf, 0, sizeof(buf));
                }

                static int                                              PACKET_Word(Byte*& stream, int& packet_length) noexcept {
                    int remainder_length = packet_length - 2;
                    if (remainder_length < 0) {
                        return 0;
                    }

                    int word_value = stream[0] << 8 | stream[1];
                    stream += 2;
                    packet_length -= 2;
                    return word_value;
                }

                static bool                                             PACKET_Word(Stream& stream, int value) noexcept {
                    Byte buf[2] = {
                        (Byte)(value >> 8),
                        (Byte)(value)
                    };

                    return stream.Write(buf, 0, sizeof(buf));
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

                template <class TProtocol>
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

                template <class TString>
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

                template <class TProtocol>
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
                , id_(id)
                , configuration_(configuration) {

                last_ = Executors::GetTickCount();
                last_ka_ = last_;
            }

            int VirtualEthernetLinklayer::NewId() noexcept {
                static std::atomic<unsigned int> aid = /*ATOMIC_FLAG_INIT*/RandomNext();
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

            std::shared_ptr<ppp::net::Firewall> VirtualEthernetLinklayer::GetFirewall() noexcept {
                return NULL;
            }

            bool VirtualEthernetLinklayer::Run(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (NULL == transmission) {
                    return false;
                }

                bool ok = false;
                last_ = Executors::GetTickCount();
                last_ka_ = last_;

                for (;;) {
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
                        last_ = Executors::GetTickCount();
                    }
                }

                return ok;
            }

#pragma pack(push, 1)
            typedef struct 
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed)) 
#endif
            {
                Byte                            il;
                uint16_t                        vlan;
                uint16_t                        max_connections;
                Byte                            acceleration;
            } VirtualEthernetLinklayer_MUX_IL;

            typedef struct 
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed)) 
#endif
            {
                Byte                            il;
                uint16_t                        vlan;
                uint32_t                        seq;
                uint32_t                        ack;
            } VirtualEthernetLinklayer_MUXON_IL;
#pragma pack(pop)

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
                elif(packet_action == PacketAction_NAT) {
                    if (packet_length > 0) {
                        return OnNat(transmission, p, packet_length, y);
                    }
                }
                elif(packet_action == PacketAction_SENDTO) {
                    ppp::string destinationHost;
                    boost::asio::ip::udp::endpoint destinationEP = global::PACKET_IPEndPoint<boost::asio::ip::udp>(GetFirewall(), p, packet_length, y, destinationHost);
                    if (destinationEP.port()) {
                        ppp::string sourceHost;
                        boost::asio::ip::udp::endpoint sourceEP = global::PACKET_IPEndPoint<boost::asio::ip::udp>(GetFirewall(), p, packet_length, y, sourceHost);
                        if (sourceEP.port() && packet_length > -1) {
                            return OnPreparedSendTo(transmission, sourceHost, sourceEP, destinationHost, destinationEP, p, packet_length, y) && OnSendTo(transmission, sourceEP, destinationEP, p, packet_length, y);
                        }
                    }
                }
                elif(packet_action == PacketAction_FRP_PUSH) {
                    if (packet_length > 0) {
                        int connection_id = global::PACKET_Dword(p, packet_length);
                        if (connection_id && packet_length > 0) {
                            bool in = *p != 0;
                            p++;
                            packet_length--;

                            int remote_port = global::PACKET_Word(p, packet_length);
                            if (remote_port && packet_length > 0) {
                                return OnFrpPush(transmission, connection_id, in, remote_port, p, packet_length);
                            }
                        }
                    }
                }
                elif(packet_action == PacketAction_FRP_SENDTO) {
                    ppp::string destinationHost;
                    boost::asio::ip::udp::endpoint destinationEP = global::PACKET_IPEndPoint<boost::asio::ip::udp>(GetFirewall(), p, packet_length, y, destinationHost);
                    if (destinationEP.port() && packet_length > 0) {
                        bool in = *p != 0;
                        p++;
                        packet_length--;

                        int remote_port = global::PACKET_Word(p, packet_length);
                        if (remote_port && packet_length > 0) {
                            return OnFrpSendTo(transmission, in, remote_port, destinationEP, p, packet_length, y);
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
                    return OnEcho(transmission, ack_id, y);
                }
                elif(packet_action == PacketAction_SYN) {
                    int connection_id = global::PACKET_ConnectId(p, packet_length);
                    if (connection_id) {
                        ppp::string destinationHost;
                        boost::asio::ip::tcp::endpoint destinationEP = global::PACKET_IPEndPoint<boost::asio::ip::tcp>(GetFirewall(), p, packet_length, y, destinationHost);
                        if (destinationEP.port()) {
                            return OnPreparedConnect(transmission, connection_id, destinationHost, destinationEP, y) && OnConnect(transmission, connection_id, destinationEP, y);
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
                elif(packet_action == PacketAction_LAN) {
                    if (packet_length >= sizeof(uint32_t) << 1) {
                        uint32_t* addresses = reinterpret_cast<uint32_t*>(p);
                        return OnLan(transmission, addresses[0], addresses[1], y);
                    }
                }
                elif(packet_action == PacketAction_FRP_DISCONNECT) {
                    if (packet_length > 0) {
                        int connection_id = global::PACKET_Dword(p, packet_length);
                        if (connection_id && packet_length > 0) {
                            bool in = *p != 0;
                            p++;
                            packet_length--;

                            int remote_port = global::PACKET_Word(p, packet_length);
                            if (remote_port) {
                                return OnFrpDisconnect(transmission, connection_id, in, remote_port);
                            }
                        }
                    }
                }
                elif(packet_action == PacketAction_FRP_CONNECT) {
                    if (packet_length > 0) {
                        int connection_id = global::PACKET_Dword(p, packet_length);
                        if (connection_id && packet_length > 0) {
                            bool in = *p != 0;
                            p++;
                            packet_length--;

                            if (packet_length > 0) {
                                int remote_port = global::PACKET_Word(p, packet_length);
                                if (remote_port) {
                                    return OnFrpConnect(transmission, connection_id, in, remote_port, y);
                                }
                            }
                        }
                    }
                }
                elif(packet_action == PacketAction_FRP_CONNECTOK) {
                    if (packet_length > 0) {
                        int connection_id = global::PACKET_Dword(p, packet_length);
                        if (connection_id && packet_length > 0) {
                            bool in = *p != 0;
                            p++;
                            packet_length--;

                            int remote_port = global::PACKET_Word(p, packet_length);
                            if (remote_port && packet_length > 0) {
                                Byte error_code = *p;
                                p++;
                                packet_length--;

                                return OnFrpConnectOK(transmission, connection_id, in, remote_port, error_code, y);
                            }
                        }
                    }
                }
                elif(packet_action == PacketAction_INFO) {
                    if (packet_length >= sizeof(VirtualEthernetInformation)) {
                        VirtualEthernetInformation info = *reinterpret_cast<VirtualEthernetInformation*>(p);
                        info.BandwidthQoS = ppp::net::Ipep::NetworkToHostOrder(info.BandwidthQoS);
                        info.ExpiredTime = ntohl(info.ExpiredTime);
                        info.IncomingTraffic = ppp::net::Ipep::NetworkToHostOrder(info.IncomingTraffic);
                        info.OutgoingTraffic = ppp::net::Ipep::NetworkToHostOrder(info.OutgoingTraffic);
                        return OnInformation(transmission, info, y);
                    }
                }
                elif(packet_action == PacketAction_FRP_ENTRY) {
                    if (packet_length > 0) {
                        bool tcp = *p != 0;
                        p++;
                        packet_length--;

                        if (packet_length > 0) {
                            bool in = *p != 0;
                            p++;
                            packet_length--;

                            int remote_port = global::PACKET_Word(p, packet_length);
                            if (remote_port) {
                                return OnFrpEntry(transmission, tcp, in, remote_port, y);
                            }
                        }
                    }
                }
                elif(packet_action == PacketAction_STATIC) {
                    return OnStatic(transmission, y);
                }
                elif(packet_action == PacketAction_STATICACK) {
                    int session_id = global::PACKET_Dword(p, packet_length);
                    if (packet_length > 0) {
                        int remote_port = global::PACKET_Word(p, packet_length);
                        if (packet_length > -1) {
                            return OnStatic(transmission, session_id, remote_port, y);
                        }
                    }
                }
                elif(packet_action == PacketAction_MUX) {
                    static constexpr int MUX_IL_REFT = sizeof(VirtualEthernetLinklayer_MUX_IL) - 1;

                    if (packet_length >= MUX_IL_REFT) {
                        VirtualEthernetLinklayer_MUX_IL* pil = (VirtualEthernetLinklayer_MUX_IL*)(p - 1);
                        return OnMux(transmission, ntohs(pil->vlan), ntohs(pil->max_connections), pil->acceleration != 0, y);
                    }
                }
                elif(packet_action == PacketAction_MUXON) {
                    static constexpr int MUXON_IL_REF = sizeof(VirtualEthernetLinklayer_MUXON_IL) - 1;

                    if (packet_length >= MUXON_IL_REF) {
                        VirtualEthernetLinklayer_MUXON_IL* pil = (VirtualEthernetLinklayer_MUXON_IL*)(p - 1);
                        return OnMuxON(transmission, ntohs(pil->vlan), ntohl(pil->seq), ntohl(pil->ack), y);
                    }
                }
                elif(packet_action == PacketAction_KEEPALIVED) {
                    last_ = Executors::GetTickCount();
                    return true;
                }

                return false;
            }

            bool VirtualEthernetLinklayer::DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept {
                static constexpr int MAX_RANDOM_BUFFER_SIZE = ppp::tap::ITap::Mtu;
                static constexpr int MILLISECONDS_TO_SECONDS = 1000;
                static constexpr int MIN_TIMEOUT_SECONDS = 5;
                static constexpr int EXTRA_FAULT_TOLERANT_TIME = MIN_TIMEOUT_SECONDS * MILLISECONDS_TO_SECONDS;

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (NULL == configuration) {
                    return false;
                }

                const int max_timeout = std::max(MIN_TIMEOUT_SECONDS, 
                    std::min(configuration->tcp.connect.timeout << 1, configuration->tcp.inactive.timeout)) * MILLISECONDS_TO_SECONDS;
                if (uint64_t last = last_; (last + static_cast<uint64_t>(max_timeout + EXTRA_FAULT_TOLERANT_TIME)) <= now) {
                    return false;
                }

                if (NULL != transmission) {
                    uint64_t last = last_ka_; 
                    if ((last + static_cast<uint64_t>(RandomNext(1000, max_timeout))) <= now) {
                        Byte buf[MAX_RANDOM_BUFFER_SIZE];
                        last_ka_ = now;

                        int len = RandomNext(1, MAX_RANDOM_BUFFER_SIZE);
                        for (int i = 0; i < len; i++) {
                            buf[i] = RandomNext('\x20', '\x7e');
                        }

                        return global::PACKET_Push(PacketAction_KEEPALIVED, transmission, buf, len, nullof<YieldContext>());
                    }
                }

                return true;
            }

            bool VirtualEthernetLinklayer::DoLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept {
                uint32_t addresses[] = { ip, mask };
                return global::PACKET_Push(PacketAction_LAN, transmission, reinterpret_cast<Byte*>(addresses), sizeof(addresses), y);
            }

            bool VirtualEthernetLinklayer::DoNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                return global::PACKET_Push(PacketAction_NAT, transmission, packet, packet_length, y);
            }

            bool VirtualEthernetLinklayer::DoInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept {
                VirtualEthernetInformation info;
                info.BandwidthQoS = ppp::net::Ipep::NetworkToHostOrder(information.BandwidthQoS);
                info.ExpiredTime = htonl(information.ExpiredTime);
                info.IncomingTraffic = ppp::net::Ipep::HostToNetworkOrder(information.IncomingTraffic);
                info.OutgoingTraffic = ppp::net::Ipep::HostToNetworkOrder(information.OutgoingTraffic);
                return global::PACKET_Push(PacketAction_INFO, transmission, (Byte*)&info, sizeof(info), y);
            }

            bool VirtualEthernetLinklayer::DoConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept {
                return global::PACKET_DoConnect(transmission, connection_id, addressof(destinationEP), ppp::string(), IPEndPoint::MinPort, y);
            }

            bool VirtualEthernetLinklayer::DoConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& hostname, int port, YieldContext& y) noexcept {
                return global::PACKET_DoConnect(transmission, connection_id, NULL, hostname, port, y);
            }

            bool VirtualEthernetLinklayer::DoConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept {
                return global::PACKET_Push(PacketAction_SYNOK, transmission, connection_id, &error_code, sizeof(error_code), y);
            }

            bool VirtualEthernetLinklayer::DoPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                return global::PACKET_Push(PacketAction_PSH, transmission, connection_id, packet, packet_length, y);
            }

            bool VirtualEthernetLinklayer::DoDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept {
                return global::PACKET_Push(PacketAction_FIN, transmission, connection_id, NULL, 0, y);
            }

            bool VirtualEthernetLinklayer::DoSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
                if (NULL == packet && packet_length != 0) {
                    return false;
                }

                if (packet_length < 0) {
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
                return global::PACKET_Push(PacketAction_ECHOACK, transmission, ack_id, NULL, 0, y);
            }

            bool VirtualEthernetLinklayer::DoEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                return global::PACKET_Push(PacketAction_ECHO, transmission, packet, packet_length, y);
            }

            bool VirtualEthernetLinklayer::DoStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                MemoryStream ms;
                if (ms.WriteByte((Byte)PacketAction_STATIC)) {
                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                }

                return false;
            }

            bool VirtualEthernetLinklayer::DoStatic(const ITransmissionPtr& transmission, int session_id, int remote_port, YieldContext& y) noexcept {
                MemoryStream ms;
                if (ms.WriteByte((Byte)PacketAction_STATICACK)) {
                    if (global::PACKET_Dword(ms, session_id)) {
                        if (global::PACKET_Word(ms, remote_port)) {
                            std::shared_ptr<Byte> buffer = ms.GetBuffer();
                            return transmission->Write(y, buffer.get(), ms.GetPosition());
                        }
                    }
                }

                return false;
            }

            bool VirtualEthernetLinklayer::DoMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept {
                MemoryStream ms;
                VirtualEthernetLinklayer_MUX_IL data;

                data.il                   = (Byte)PacketAction_MUX;
                data.vlan                 = htons(vlan);
                data.max_connections      = htons(max_connections);
                data.acceleration         = acceleration ? 1 : 0;

                if (ms.Write(&data, 0, sizeof(data))) {
                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                }

                return false;
            }

            bool VirtualEthernetLinklayer::DoMuxON(const ITransmissionPtr& transmission, uint16_t vlan, uint32_t seq, uint32_t ack, YieldContext& y) noexcept {
                MemoryStream ms;
                VirtualEthernetLinklayer_MUXON_IL data;

                data.il = (Byte)PacketAction_MUXON;
                data.vlan = htons(vlan);
                data.seq = htonl(seq);
                data.ack = htonl(ack);

                if (ms.Write(&data, 0, sizeof(data))) {
                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                }

                return false;
            }

            bool VirtualEthernetLinklayer::DoFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept {
                MemoryStream ms;
                if (ms.WriteByte((Byte)PacketAction_FRP_ENTRY)) {
                    Byte b = tcp ? 1 : 0;
                    if (ms.WriteByte(b)) {
                        b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                return transmission->Write(y, buffer.get(), ms.GetPosition());
                            }
                        }
                    }
                }
                return false;
            }

            bool VirtualEthernetLinklayer::DoFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                MemoryStream ms;
                if (ms.WriteByte((Byte)PacketAction_FRP_SENDTO)) {
                    if (global::PACKET_IPEndPoint(ms, sourceEP)) {
                        Byte b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                if (ms.Write(packet, 0, packet_length)) {
                                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                                }
                            }
                        }
                    }
                }
                return false;
            }

            bool VirtualEthernetLinklayer::DoFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept {
                MemoryStream ms;
                if (ms.WriteByte((Byte)PacketAction_FRP_CONNECT)) {
                    if (global::PACKET_Dword(ms, connection_id)) {
                        Byte b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                return transmission->Write(y, buffer.get(), ms.GetPosition());
                            }
                        }
                    }
                }
                return false;
            }

            bool VirtualEthernetLinklayer::DoFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept {
                MemoryStream ms;
                if (ms.WriteByte((Byte)PacketAction_FRP_CONNECTOK)) {
                    if (global::PACKET_Dword(ms, connection_id)) {
                        Byte b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                if (ms.WriteByte(error_code)) {
                                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                                }
                            }
                        }
                    }
                }
                return false;
            }

            bool VirtualEthernetLinklayer::DoFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept {
                MemoryStream ms;
                if (ms.WriteByte((Byte)PacketAction_FRP_DISCONNECT)) {
                    if (global::PACKET_Dword(ms, connection_id)) {
                        Byte b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                return transmission->Write(y, buffer.get(), ms.GetPosition());
                            }
                        }
                    }
                }
                return false;
            }

            bool VirtualEthernetLinklayer::DoFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length, YieldContext& y) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                MemoryStream ms;
                if (ms.WriteByte((Byte)PacketAction_FRP_PUSH)) {
                    if (global::PACKET_Dword(ms, connection_id)) {
                        Byte b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                if (ms.Write(packet, 0, packet_length)) {
                                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                                }
                            }
                        }
                    }
                }
                return false;
            }
        }
    }
}
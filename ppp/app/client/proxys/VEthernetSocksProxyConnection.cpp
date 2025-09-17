#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/proxys/VEthernetSocksProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetSocksProxyConnection.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                static constexpr int SOCKS_VER                  = 5;
                static constexpr int SOCKS_METHOD_NONE          = 0;
                static constexpr int SOCKS_METHOD_AUTH          = 2;
                static constexpr int SOCKS_METHOD_RSVD          = 255;
                static constexpr int SOCKS_ERR_ER               = -1;
                static constexpr int SOCKS_ERR_OK               = 0;
                static constexpr int SOCKS_ERR_NO               = 1;
                static constexpr int SOCKS_ERR_CMD              = 7;
                static constexpr int SOCKS_ERR_ATYPE            = 8;
                static constexpr int SOCKS_ERR_FF               = 255;
                static constexpr int SOCKS_PROTO_AUTH           = 1;
                static constexpr int SOCKS_ATYPE_IPV4           = 1;
                static constexpr int SOCKS_ATYPE_IPV6           = 4;
                static constexpr int SOCKS_ATYPE_DOMAIN         = 3;
                static constexpr int SOCKS_CMD_CONNECT          = 1;
                static constexpr int SOCKS_CMD_UDP              = 3;

                VEthernetSocksProxyConnection::VEthernetSocksProxyConnection(
                    const VEthernetSocksProxySwitcherPtr&                           proxy,
                    const VEthernetExchangerPtr&                                    exchanger, 
                    const std::shared_ptr<boost::asio::io_context>&                 context,
                    const ppp::threading::Executors::StrandPtr&                     strand,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept 
                    : VEthernetLocalProxyConnection(proxy, exchanger, context, strand, socket) {
                        
                }
                
                bool VEthernetSocksProxyConnection::Handshake(YieldContext& y) noexcept {
                    int method = SOCKS_METHOD_NONE;
                    int status = SelectMethod(y, method); 
                    if (status <= SOCKS_ERR_ER) {
                        return false;
                    }
                    elif(status >= SOCKS_ERR_NO) {
                        Replay(y, SOCKS_VER, SOCKS_METHOD_RSVD);
                        return false;
                    }
                    elif(!Replay(y, SOCKS_VER, method)) {
                        return false;
                    }
                    elif(method == SOCKS_METHOD_AUTH) {
                        status = Authentication(y);
                        if (status <= SOCKS_ERR_ER) {
                            return false;
                        }
                        elif(status >= SOCKS_ERR_NO) {
                            Replay(y, SOCKS_PROTO_AUTH, SOCKS_ERR_FF);
                            return false;
                        }
                        elif(!Replay(y, SOCKS_PROTO_AUTH, SOCKS_ERR_OK)) {
                            return false;
                        }
                    }

                    int port = ppp::net::IPEndPoint::MinPort;
                    ppp::string host;
                    ppp::app::protocol::AddressType address_type = ppp::app::protocol::AddressType::Domain;

                    if (!Requirement(y, host, port, address_type)) {
                        return false;
                    }

                    std::shared_ptr<ppp::app::protocol::AddressEndPoint> address_endpoint = make_shared_object<ppp::app::protocol::AddressEndPoint>();
                    if (NULL == address_endpoint) {
                        return false;
                    }

                    address_endpoint->Type = address_type;
                    address_endpoint->Host = host;
                    address_endpoint->Port = port;

                    return ConnectBridgeToPeer(address_endpoint, y);
                }

                int VEthernetSocksProxyConnection::Authentication(YieldContext& y) noexcept {
                    std::shared_ptr<boost::asio::ip::tcp::socket>& socket = GetSocket();
                    if (NULL == socket || !socket->is_open()) {
                        return SOCKS_ERR_ER;
                    }

                    if (IsDisposed()) {
                        return SOCKS_ERR_ER;
                    }

                    AppConfigurationPtr& configuration = GetConfiguration();
                    auto& socks_proxy = configuration->client.socks_proxy;

                    Byte data[256];
                    if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 1), y)) {
                        return SOCKS_ERR_ER;
                    }

                    if (data[0] != SOCKS_PROTO_AUTH) {
                        return SOCKS_ERR_NO;
                    }

                    ppp::string strings[2];
                    for (int i = 0; i < arraysizeof(strings); i++) {
                        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 1), y)) {
                            return SOCKS_ERR_ER;
                        }

                        int string_size = data[0];
                        if (string_size > 0) {
                            if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, string_size), y)) {
                                return SOCKS_ERR_ER;
                            }

                            data[string_size] = '\x0';
                            strings[i] = reinterpret_cast<char*>(data);
                        }
                    }

                    if (socks_proxy.username != strings[0] && socks_proxy.password != strings[1]) {
                        return SOCKS_ERR_NO;
                    }

                    return SOCKS_ERR_OK;
                }

                bool VEthernetSocksProxyConnection::Replay(YieldContext& y, int k, int v) noexcept {
                    std::shared_ptr<boost::asio::ip::tcp::socket>& socket = GetSocket();
                    if (NULL == socket || !socket->is_open()) {
                        return false;
                    }

                    if (IsDisposed()) {
                        return false;
                    }

                    Byte data[2] = { (Byte)k, (Byte)v };
                    return ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(data, sizeof(data)), y);
                }

                int VEthernetSocksProxyConnection::SelectMethod(YieldContext& y, int& method) noexcept {
                    std::shared_ptr<boost::asio::ip::tcp::socket>& socket = GetSocket();
                    method = SOCKS_METHOD_NONE;

                    if (NULL == socket || !socket->is_open()) {
                        return SOCKS_ERR_ER;
                    }

                    if (IsDisposed()) {
                        return SOCKS_ERR_ER;
                    }

                    Byte data[256];
                    if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 2), y)) {
                        return SOCKS_ERR_ER;
                    }

                    int nver = data[0];
                    if (nver != SOCKS_VER) {
                        return SOCKS_ERR_NO;
                    }

                    int nmethod = data[1];
                    AppConfigurationPtr& configuration = GetConfiguration();
                    auto& socks_proxy = configuration->client.socks_proxy;
                    bool no_auth = socks_proxy.username.empty() && socks_proxy.password.empty();

                    if (nmethod == SOCKS_METHOD_NONE) {
                        return no_auth ? SOCKS_ERR_OK : SOCKS_ERR_NO;
                    }
                    elif(nmethod < SOCKS_METHOD_NONE) {
                        return SOCKS_ERR_NO;
                    }

                    if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, nmethod), y)) {
                        return SOCKS_ERR_ER;
                    }

                    for (int i = 0; i < nmethod; i++) {
                        Byte m = data[i];
                        if (m == SOCKS_METHOD_RSVD) {
                            continue;
                        }
                        elif(m == SOCKS_METHOD_NONE) {
                            if (no_auth) {
                                return SOCKS_ERR_OK;
                            }
                        }
                        elif(m == SOCKS_METHOD_AUTH) {
                            if (!no_auth) {
                                method = m;
                            }

                            return SOCKS_ERR_OK;
                        }
                    }

                    return no_auth ? SOCKS_ERR_OK : SOCKS_ERR_NO;
                }
            
                bool VEthernetSocksProxyConnection::Requirement(YieldContext& y, ppp::string& address, int& port, ppp::app::protocol::AddressType& address_type) noexcept {
                    std::shared_ptr<boost::asio::ip::tcp::socket>& socket = GetSocket();
                    address.clear();

                    port = ppp::net::IPEndPoint::MinPort;
                    address_type = ppp::app::protocol::AddressType::Domain;

                    if (NULL == socket || !socket->is_open()) {
                        return false;
                    }

                    if (IsDisposed()) {
                        return false;
                    }
                    
                    Byte cmd = SOCKS_ERR_CMD;
                    Byte data[256];

                    for (;;) {
                        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 4), y)) {
                            return false;
                        }

                        if (data[0] != SOCKS_VER) {
                            break;
                        }

                        if (data[1] != SOCKS_CMD_CONNECT) {
                            break;
                        }

                        int address_type = data[3];
                        int address_length = 0;
                        if (address_type == SOCKS_ATYPE_IPV4) {
                            address_length = 4;
                            address_type = ppp::app::protocol::AddressType::IPv4;
                        }
                        elif(address_type == SOCKS_ATYPE_IPV6) {
                            address_length = 16;
                            address_type = ppp::app::protocol::AddressType::IPv6;
                        }
                        elif(address_type == SOCKS_ATYPE_DOMAIN) {
                            if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 1), y)) {
                                return false;
                            }

                            address_length = data[0];
                            address_type = ppp::app::protocol::AddressType::Domain;
                        }
                        else {
                            cmd = SOCKS_ERR_ATYPE;
                            break;
                        }

                        if (address_length < 1) {
                            break;
                        }

                        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, address_length), y)) {
                            return false;
                        }

                        switch (address_type) {
                        case SOCKS_ATYPE_IPV4: {
                                boost::asio::ip::address_v4::bytes_type bytes;
                                memset(bytes.data(), 0, bytes.size());
                                memcpy(bytes.data(), data, address_length);

                                address = boost::asio::ip::address_v4(bytes).to_string();
                            }
                            break;
                        case SOCKS_ATYPE_IPV6: {
                                boost::asio::ip::address_v6::bytes_type bytes;
                                memset(bytes.data(), 0, bytes.size());
                                memcpy(bytes.data(), data, address_length);

                                address = boost::asio::ip::address_v6(bytes).to_string();
                            }
                            break;
                        default: {
                                data[address_length] = '\x0';
                                address = reinterpret_cast<char*>(data);
                            }
                            break;
                        };

                        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 2), y)) {
                            return false;
                        }

                        cmd = SOCKS_ERR_OK;
                        port = data[0] << 8 | data[1];
                        break;
                    }

                    for (;;) {
                        int packet_length = 0;
                        data[packet_length++] = SOCKS_VER;
                        data[packet_length++] = cmd;
                        data[packet_length++] = 0;

                        boost::system::error_code ec;
                        boost::asio::ip::tcp::endpoint local_endpoint = socket->local_endpoint(ec);
                        if (ec) {
                            return false;
                        }
                        else {
                            local_endpoint = ppp::net::Ipep::V6ToV4(local_endpoint);
                        }
                    
                        boost::asio::ip::address local_ip = local_endpoint.address();
                        if (local_ip.is_v4()) {
                            data[packet_length++] = SOCKS_ATYPE_IPV4;

                            boost::asio::ip::address_v4 in4 = local_ip.to_v4();
                            boost::asio::ip::address_v4::bytes_type bytes = in4.to_bytes();
                            memcpy(data + packet_length, bytes.data(), bytes.size());

                            packet_length += bytes.size();
                        }
                        elif(local_ip.is_v6()) {
                            data[packet_length++] = SOCKS_ATYPE_IPV6;

                            boost::asio::ip::address_v6 in6 = local_ip.to_v6();
                            boost::asio::ip::address_v6::bytes_type bytes = in6.to_bytes();
                            memcpy(data + packet_length, bytes.data(), bytes.size());
                            
                            packet_length += bytes.size();
                        }
                        else {
                            return false;
                        }

                        int local_port = local_endpoint.port();
                        data[packet_length++] = (Byte)(local_port >> 8);
                        data[packet_length++] = (Byte)(local_port);

                        return ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(data, packet_length), y);
                    }
                }
            }
        }
    }
}
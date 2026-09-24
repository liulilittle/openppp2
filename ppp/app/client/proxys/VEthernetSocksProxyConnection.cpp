#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/proxys/VEthernetSocksProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetSocksProxyConnection.h>
#include <ppp/app/client/proxys/SocksAddressType.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Socket.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file VEthernetSocksProxyConnection.cpp
 * @brief Implements SOCKS5 handshake and request processing for local proxy clients.
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                /**
                 * @brief SOCKS5 protocol version.
                 */
                static constexpr int SOCKS_VER                  = 5;
                /**
                 * @brief SOCKS5 "no authentication" method id.
                 */
                static constexpr int SOCKS_METHOD_NONE          = 0;
                /**
                 * @brief SOCKS5 username/password authentication method id.
                 */
                static constexpr int SOCKS_METHOD_AUTH          = 2;
                /**
                 * @brief SOCKS5 "no acceptable methods" marker.
                 */
                static constexpr int SOCKS_METHOD_RSVD          = 255;
                /**
                 * @brief Internal error return code for transport failures.
                 */
                static constexpr int SOCKS_ERR_ER               = -1;
                /**
                 * @brief Success return code.
                 */
                static constexpr int SOCKS_ERR_OK               = 0;
                /**
                 * @brief Generic protocol rejection return code.
                 */
                static constexpr int SOCKS_ERR_NO               = 1;
                /**
                 * @brief SOCKS reply code for unsupported command.
                 */
                static constexpr int SOCKS_ERR_CMD              = 7;
                /**
                 * @brief SOCKS reply code for unsupported address type.
                 */
                static constexpr int SOCKS_ERR_ATYPE            = 8;
                /**
                 * @brief Username/password sub-protocol failure status.
                 */
                static constexpr int SOCKS_ERR_FF               = 255;
                /**
                 * @brief Username/password sub-protocol version.
                 */
                static constexpr int SOCKS_PROTO_AUTH           = 1;
                /**
                 * @brief SOCKS address type id for IPv4 addresses.
                 */
                static constexpr int SOCKS_ATYPE_IPV4           = 1;
                /**
                 * @brief SOCKS address type id for IPv6 addresses.
                 */
                static constexpr int SOCKS_ATYPE_IPV6           = 4;
                /**
                 * @brief SOCKS address type id for domain names.
                 */
                static constexpr int SOCKS_ATYPE_DOMAIN         = 3;
                /**
                 * @brief SOCKS command id for CONNECT.
                 */
                static constexpr int SOCKS_CMD_CONNECT          = 1;
                /**
                 * @brief SOCKS command id for UDP ASSOCIATE.
                 */
                static constexpr int SOCKS_CMD_UDP              = 3;
                /**
                 * @brief Minimum SOCKS5 UDP request header size for IPv4 targets.
                 */
                static constexpr int SOCKS_UDP_MIN_PACKET_SIZE  = 10;

                static int PublishSocketReadFailure(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept {
                    if (NULLPTR == socket) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    }
                    elif(socket->is_open()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                    }

                    return SOCKS_ERR_ER;
                }

                static bool PublishSocketWriteFailure(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept {
                    if (NULLPTR == socket) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    }
                    elif(socket->is_open()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                    }

                    return false;
                }

                /**
                 * @brief Constructs a SOCKS proxy connection instance.
                 * @param proxy Parent SOCKS switcher that owns this connection.
                 * @param exchanger Shared exchanger used to establish remote bridge channels.
                 * @param context I/O context used by asynchronous operations.
                 * @param strand Strand that serializes callbacks.
                 * @param socket Accepted client TCP socket.
                 */
                VEthernetSocksProxyConnection::VEthernetSocksProxyConnection(
                    const VEthernetSocksProxySwitcherPtr&                           proxy,
                    const VEthernetExchangerPtr&                                    exchanger, 
                    const std::shared_ptr<boost::asio::io_context>&                 context,
                    const ppp::threading::Executors::StrandPtr&                     strand,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept 
                    : VEthernetLocalProxyConnection(proxy, exchanger, context, strand, socket) {
                
                }
                
                /**
                 * @brief Sends a SOCKS5 request-reply packet containing local bind endpoint.
                 * @param socket Connected client socket.
                 * @param rep SOCKS reply code.
                 * @param y Coroutine yield context.
                 * @return true if the packet is written successfully; otherwise false.
                 * @note The address in the reply is derived from the socket local endpoint.
                 */
                static bool SendSocksRequestReply(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, Byte rep, ppp::coroutines::YieldContext& y) noexcept {
                    if (NULLPTR == socket) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    }

                    if (!socket->is_open()) {
                        return false;
                    }

                    Byte data[32];
                    int packet_length = 0;
                    data[packet_length++] = SOCKS_VER;
                    data[packet_length++] = rep;
                    data[packet_length++] = 0;

                    boost::system::error_code ec;
                    boost::asio::ip::tcp::endpoint local_endpoint = socket->local_endpoint(ec);
                    if (ec) {
                        local_endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::any(), 0);
                    }
                    else {
                        local_endpoint = ppp::net::Ipep::V6ToV4(local_endpoint);
                    }

                    boost::asio::ip::address local_ip = local_endpoint.address();
                    if (local_ip.is_v4()) {
                        data[packet_length++] = SOCKS_ATYPE_IPV4;
                        auto bytes = local_ip.to_v4().to_bytes();
                        memcpy(data + packet_length, bytes.data(), bytes.size());
                        packet_length += bytes.size();
                    }
                    elif(local_ip.is_v6()) {
                        data[packet_length++] = SOCKS_ATYPE_IPV6;
                        auto bytes = local_ip.to_v6().to_bytes();
                        memcpy(data + packet_length, bytes.data(), bytes.size());
                        packet_length += bytes.size();
                    }
                    else {
                        data[packet_length++] = SOCKS_ATYPE_IPV4;
                        memset(data + packet_length, 0, 4);
                        packet_length += 4;
                    }

                    int local_port = local_endpoint.port();
                    data[packet_length++] = (Byte)(local_port >> 8);
                    data[packet_length++] = (Byte)(local_port);

                    bool ok = ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(data, packet_length), y);
                    return ok ? true : PublishSocketWriteFailure(socket);
                }

                VEthernetSocksProxyConnection::~VEthernetSocksProxyConnection() noexcept {
                    VEthernetExchangerPtr exchanger = GetExchanger();
                    if (NULLPTR != exchanger && udp_client_ep_.port() > ppp::net::IPEndPoint::MinPort) {
                        exchanger->ReleaseDatagramHandler(udp_client_ep_);
                    }

                    ppp::net::Socket::Closesocket(udp_socket_);
                }

                /** @brief Sends a SOCKS5 request reply with an explicit UDP bind endpoint. */
                static bool SendSocksRequestReply(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, Byte rep, const boost::asio::ip::udp::endpoint& bind_endpoint, ppp::coroutines::YieldContext& y) noexcept {
                    if (NULLPTR == socket) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    }

                    if (!socket->is_open()) {
                        return false;
                    }

                    Byte data[32];
                    int packet_length = 0;
                    data[packet_length++] = SOCKS_VER;
                    data[packet_length++] = rep;
                    data[packet_length++] = 0;

                    boost::asio::ip::address local_ip = bind_endpoint.address();
                    if (local_ip.is_v4()) {
                        data[packet_length++] = SOCKS_ATYPE_IPV4;
                        auto bytes = local_ip.to_v4().to_bytes();
                        memcpy(data + packet_length, bytes.data(), bytes.size());
                        packet_length += bytes.size();
                    }
                    elif(local_ip.is_v6()) {
                        data[packet_length++] = SOCKS_ATYPE_IPV6;
                        auto bytes = local_ip.to_v6().to_bytes();
                        memcpy(data + packet_length, bytes.data(), bytes.size());
                        packet_length += bytes.size();
                    }
                    else {
                        data[packet_length++] = SOCKS_ATYPE_IPV4;
                        memset(data + packet_length, 0, 4);
                        packet_length += 4;
                    }

                    int local_port = bind_endpoint.port();
                    data[packet_length++] = (Byte)(local_port >> 8);
                    data[packet_length++] = (Byte)(local_port);

                    bool ok = ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(data, packet_length), y);
                    return ok ? true : PublishSocketWriteFailure(socket);
                }

                /**
                 * @brief Executes the full SOCKS5 handshake and target bridge setup.
                 * @param y Coroutine yield context.
                 * @return true when handshake and bridge connection both succeed.
                 */
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
                    int command = SOCKS_CMD_CONNECT;
                    ppp::string host;
                    ppp::app::protocol::AddressType address_type = ppp::app::protocol::AddressType::Domain;

                    int command_status = Requirement(y, host, port, address_type, command);
                    if (command_status != SOCKS_ERR_OK) {
                        if (command_status == SOCKS_ERR_ATYPE) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocksAddressTypeUnsupported);
                        }
                        elif(command_status == SOCKS_ERR_CMD) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocksCommandUnsupported);
                        }
                        elif(command_status > SOCKS_ERR_OK) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketAddressInvalid);
                        }

                        SendSocksRequestReply(GetSocket(), (Byte)command_status, y);
                        return false;
                    }

                    if (command == SOCKS_CMD_UDP) {
                        if (!OpenUdpAssociate(y)) {
                            SendSocksRequestReply(GetSocket(), SOCKS_ERR_NO, y);
                            return false;
                        }

                        boost::system::error_code ec;
                        boost::asio::ip::udp::endpoint local_endpoint = udp_socket_->local_endpoint(ec);
                        if (ec) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketAddressInvalid);
                            SendSocksRequestReply(GetSocket(), SOCKS_ERR_NO, y);
                            return false;
                        }

                        return SendSocksRequestReply(GetSocket(), SOCKS_ERR_OK, local_endpoint, y);
                    }

                    std::shared_ptr<ppp::app::protocol::AddressEndPoint> address_endpoint = make_shared_object<ppp::app::protocol::AddressEndPoint>();
                    if (NULLPTR == address_endpoint) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    address_endpoint->Type = address_type;
                    address_endpoint->Host = host;
                    address_endpoint->Port = port;

                    if (!ConnectBridgeToPeer(address_endpoint, y)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpConnectFailed);
                        SendSocksRequestReply(GetSocket(), SOCKS_ERR_NO, y);
                        return false;
                    }

                    return SendSocksRequestReply(GetSocket(), SOCKS_ERR_OK, y);
                }

                /**
                 * @brief Validates SOCKS username/password credentials.
                 * @param y Coroutine yield context.
                 * @return SOCKS_ERR_OK when credentials match configuration; otherwise an error code.
                 * @note Credentials are read using SOCKS5 username/password sub-negotiation framing.
                 */
                int VEthernetSocksProxyConnection::Authentication(YieldContext& y) noexcept {
                    std::shared_ptr<boost::asio::ip::tcp::socket>& socket = GetSocket();
                    if (NULLPTR == socket) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                        return SOCKS_ERR_ER;
                    }

                    if (!socket->is_open()) {
                        return SOCKS_ERR_ER;
                    }

                    if (IsDisposed()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return SOCKS_ERR_ER;
                    }

                    AppConfigurationPtr& configuration = GetConfiguration();
                    if (NULLPTR == configuration) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
                        return SOCKS_ERR_ER;
                    }

                    auto& socks_proxy = configuration->client.socks_proxy;

                    Byte data[256];
                    if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 1), y)) {
                        return PublishSocketReadFailure(socket);
                    }

                    if (data[0] != SOCKS_PROTO_AUTH) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AuthChallengeFailed);
                        return SOCKS_ERR_NO;
                    }

                    ppp::string strings[2];
                    for (int i = 0; i < arraysizeof(strings); i++) {
                        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 1), y)) {
                            return PublishSocketReadFailure(socket);
                        }

                        int string_size = data[0];
                        if (string_size > 0) {
                            if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, string_size), y)) {
                                return PublishSocketReadFailure(socket);
                            }

                            data[string_size] = '\x0';
                            strings[i] = reinterpret_cast<char*>(data);
                        }
                    }

                    if (socks_proxy.username != strings[0] || socks_proxy.password != strings[1]) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AuthCredentialInvalid);
                        return SOCKS_ERR_NO;
                    }

                    return SOCKS_ERR_OK;
                }

                /**
                 * @brief Sends a two-byte protocol reply message.
                 * @param y Coroutine yield context.
                 * @param k First reply byte.
                 * @param v Second reply byte.
                 * @return true if write succeeds; otherwise false.
                 */
                bool VEthernetSocksProxyConnection::Replay(YieldContext& y, int k, int v) noexcept {
                    std::shared_ptr<boost::asio::ip::tcp::socket>& socket = GetSocket();
                    if (NULLPTR == socket) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    }

                    if (!socket->is_open()) {
                        return false;
                    }

                    if (IsDisposed()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                    }

                    Byte data[2] = { (Byte)k, (Byte)v };
                    bool ok = ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(data, sizeof(data)), y);
                    return ok ? true : PublishSocketWriteFailure(socket);
                }

                /**
                 * @brief Negotiates SOCKS5 authentication method with the client.
                 * @param y Coroutine yield context.
                 * @param method Output negotiated method.
                 * @return SOCKS status code for success, protocol rejection, or transport error.
                 */
                int VEthernetSocksProxyConnection::SelectMethod(YieldContext& y, int& method) noexcept {
                    std::shared_ptr<boost::asio::ip::tcp::socket>& socket = GetSocket();
                    method = SOCKS_METHOD_NONE;

                    if (NULLPTR == socket) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                        return SOCKS_ERR_ER;
                    }

                    if (!socket->is_open()) {
                        return SOCKS_ERR_ER;
                    }

                    if (IsDisposed()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return SOCKS_ERR_ER;
                    }

                    Byte data[256];
                    if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 2), y)) {
                        return PublishSocketReadFailure(socket);
                    }

                    int nver = data[0];
                    if (nver != SOCKS_VER) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                        return SOCKS_ERR_NO;
                    }

                    int nmethod = data[1];
                    AppConfigurationPtr& configuration = GetConfiguration();
                    if (NULLPTR == configuration) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
                        return SOCKS_ERR_ER;
                    }

                    auto& socks_proxy = configuration->client.socks_proxy;
                    bool no_auth = socks_proxy.username.empty() && socks_proxy.password.empty();

                    if (nmethod == SOCKS_METHOD_NONE) {
                        if (!no_auth) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocksMethodUnsupported);
                        }
                        return no_auth ? SOCKS_ERR_OK : SOCKS_ERR_NO;
                    }
                    elif(nmethod < SOCKS_METHOD_NONE) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                        return SOCKS_ERR_NO;
                    }

                    if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, nmethod), y)) {
                        return PublishSocketReadFailure(socket);
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

                    if (!no_auth) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocksMethodUnsupported);
                        return SOCKS_ERR_NO;
                    }

                    return SOCKS_ERR_OK;
                }
            
                /**
                 * @brief Parses SOCKS5 CONNECT or UDP ASSOCIATE request.
                 * @param y Coroutine yield context.
                 * @param address Output destination host string.
                 * @param port Output destination port in host order.
                 * @param address_type Output parsed address type.
                 * @return SOCKS status code indicating request parse result.
                 */
                int VEthernetSocksProxyConnection::Requirement(YieldContext& y, ppp::string& address, int& port, ppp::app::protocol::AddressType& address_type, int& command) noexcept {
                    std::shared_ptr<boost::asio::ip::tcp::socket>& socket = GetSocket();
                    address.clear();

                    port = ppp::net::IPEndPoint::MinPort;
                    address_type = ppp::app::protocol::AddressType::Domain;
                    command = SOCKS_CMD_CONNECT;

                    if (NULLPTR == socket) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                        return SOCKS_ERR_ER;
                    }

                    if (!socket->is_open()) {
                        return SOCKS_ERR_ER;
                    }

                    if (IsDisposed()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return SOCKS_ERR_ER;
                    }
                    
                    Byte cmd = SOCKS_ERR_CMD;
                    Byte data[256];

                    /**
                     * @brief Parse request header, destination address, and destination port.
                     */
                    for (;;) {
                        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 4), y)) {
                            return PublishSocketReadFailure(socket);
                        }

                        if (data[0] != SOCKS_VER) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                            return SOCKS_ERR_CMD;
                        }

                        command = data[1];
                        if (command != SOCKS_CMD_CONNECT && command != SOCKS_CMD_UDP) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                            return SOCKS_ERR_CMD;
                        }

                        const int wire_address_type = data[3];
                        int address_length = 0;
                        if (!detail::TryParseSocksAddressType(wire_address_type, address_type, address_length)) {
                            cmd = SOCKS_ERR_ATYPE;
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocksAddressTypeUnsupported);
                            return SOCKS_ERR_ATYPE;
                        }

                        if (wire_address_type == SOCKS_ATYPE_DOMAIN) {
                            if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 1), y)) {
                                return PublishSocketReadFailure(socket);
                            }

                            address_length = data[0];
                        }

                        if (address_length < 1) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocksAddressTypeUnsupported);
                            return SOCKS_ERR_ATYPE;
                        }

                        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, address_length), y)) {
                            return PublishSocketReadFailure(socket);
                        }

                        switch (wire_address_type) {
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
                        case SOCKS_ATYPE_DOMAIN: {
                                data[address_length] = '\x0';
                                address = reinterpret_cast<char*>(data);
                            }
                            break;
                        };

                        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 2), y)) {
                            return PublishSocketReadFailure(socket);
                        }

                        cmd = SOCKS_ERR_OK;
                        port = data[0] << 8 | data[1];
                        break;
                    }

                    return SOCKS_ERR_OK;
                }

                /** @brief Opens and binds the local UDP socket for SOCKS5 UDP ASSOCIATE. */
                bool VEthernetSocksProxyConnection::OpenUdpAssociate(YieldContext& y) noexcept {
                    std::shared_ptr<boost::asio::io_context>& context = GetContext();
                    std::shared_ptr<boost::asio::ip::tcp::socket>& tcp_socket = GetSocket();
                    if (NULLPTR == context || NULLPTR == tcp_socket) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    }

                    if (!tcp_socket->is_open()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                    }

                    if (IsDisposed()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::tcp::endpoint local_tcp_endpoint = tcp_socket->local_endpoint(ec);
                    if (ec) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketAddressInvalid);
                    }

                    boost::asio::ip::address bind_ip = ppp::net::Ipep::V6ToV4(local_tcp_endpoint).address();
                    if (bind_ip.is_unspecified()) {
                        bind_ip = bind_ip.is_v6() ? boost::asio::ip::address(boost::asio::ip::address_v6::any()) : boost::asio::ip::address(boost::asio::ip::address_v4::any());
                    }

                    std::shared_ptr<boost::asio::ip::udp::socket> udp_socket = make_shared_object<boost::asio::ip::udp::socket>(*context);
                    if (NULLPTR == udp_socket) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    if (!ppp::net::Socket::OpenSocket(*udp_socket, bind_ip, ppp::net::IPEndPoint::MinPort)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                    }

                    udp_buffer_ = Executors::GetCachedBuffer(context);
                    if (NULLPTR == udp_buffer_) {
                        ppp::net::Socket::Closesocket(udp_socket);
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    udp_socket_ = std::move(udp_socket);

                    return UdpAssociateLoopback();
                }

                /** @brief Schedules one SOCKS5 UDP ASSOCIATE receive operation. */
                bool VEthernetSocksProxyConnection::UdpAssociateLoopback() noexcept {
                    std::shared_ptr<boost::asio::ip::udp::socket> udp_socket = udp_socket_;
                    std::shared_ptr<Byte> udp_buffer = udp_buffer_;
                    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                    std::shared_ptr<boost::asio::io_context> context = GetContext();
                    if (NULLPTR == udp_socket || NULLPTR == udp_buffer) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    }

                    if (NULLPTR == allocator || NULLPTR == context) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
                    }

                    if (!udp_socket->is_open()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                    }

                    if (IsDisposed()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                    }

                    auto self = std::dynamic_pointer_cast<VEthernetSocksProxyConnection>(shared_from_this());
                    udp_socket->async_receive_from(boost::asio::buffer(udp_buffer.get(), PPP_BUFFER_SIZE), udp_remote_ep_,
                        [self, this, udp_socket, udp_buffer, allocator, context](const boost::system::error_code& ec, std::size_t sz) noexcept {
                            bool disposing = false;
                            if (ec == boost::system::errc::success) {
                                if (sz > 0) {
                                    std::shared_ptr<Byte> packet = ppp::net::asio::IAsynchronousWriteIoQueue::Copy(allocator, udp_buffer, udp_buffer.get(), (int)sz);
                                    if (NULLPTR == packet) {
                                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                                    }
                                    else {
                                        boost::asio::ip::udp::endpoint sourceEP = udp_remote_ep_;
                                        auto self_yield = self;
                                        bool spawned = YieldContext::Spawn(allocator.get(), *context,
                                            [self_yield, packet, sourceEP, sz](YieldContext& y) noexcept {
                                                if (self_yield) {
                                                    self_yield->ForwardUdpAssociatePacket(y, packet.get(), (int)sz, sourceEP);
                                                }
                                            });

                                        if (!spawned) {
                                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineSpawnFailed);
                                        }
                                    }
                                }
                            }
                            elif(ec == boost::system::errc::operation_canceled) {
                                disposing = true;
                            }
                            else {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpRelayFailed);
                                disposing = true;
                            }

                            if (disposing) {
                                Dispose();
                            }
                            elif(!IsDisposed()) {
                                UdpAssociateLoopback();
                            }
                        });
                    return true;
                }

                /** @brief Maintains the SOCKS5 TCP control channel for UDP ASSOCIATE. */
                bool VEthernetSocksProxyConnection::RunAfterHandshakeWithoutBridge(YieldContext& y) noexcept {
                    std::shared_ptr<boost::asio::ip::udp::socket> udp_socket = udp_socket_;
                    if (NULLPTR == udp_socket || !udp_socket->is_open()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket>& socket = GetSocket();
                    if (NULLPTR == socket || !socket->is_open()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                    }

                    Byte data = 0;
                    for (;;) {
                        if (IsDisposed()) {
                            return false;
                        }

                        bool ok = ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(&data, 1), y);
                        if (!ok) {
                            return false;
                        }
                    }
                }

                /** @brief Parses and forwards a SOCKS5 UDP request datagram. */
                bool VEthernetSocksProxyConnection::ForwardUdpAssociatePacket(YieldContext& y, Byte* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                    if (NULLPTR == packet || packet_length < SOCKS_UDP_MIN_PACKET_SIZE) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    }

                    if (packet[0] != 0 || packet[1] != 0 || packet[2] != 0) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    }

                    int offset = 3;
                    int atyp = packet[offset++];
                    boost::asio::ip::address destination_address;
                    if (atyp == SOCKS_ATYPE_IPV4) {
                        if (packet_length < offset + 4 + 2) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                        }

                        boost::asio::ip::address_v4::bytes_type bytes;
                        memcpy(bytes.data(), packet + offset, bytes.size());
                        destination_address = boost::asio::ip::address_v4(bytes);
                        offset += bytes.size();
                    }
                    elif(atyp == SOCKS_ATYPE_IPV6) {
                        if (packet_length < offset + 16 + 2) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                        }

                        boost::asio::ip::address_v6::bytes_type bytes;
                        memcpy(bytes.data(), packet + offset, bytes.size());
                        destination_address = boost::asio::ip::address_v6(bytes);
                        offset += bytes.size();
                    }
                    elif(atyp == SOCKS_ATYPE_DOMAIN) {
                        if (packet_length < offset + 1 + 2) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                        }

                        int address_length = packet[offset++];
                        if (address_length < 1 || packet_length < offset + address_length + 2) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                        }

                        ppp::string host(reinterpret_cast<char*>(packet + offset), address_length);
                        offset += address_length;
                        int port = (packet[offset] << 8) | packet[offset + 1];
                        if (port <= ppp::net::IPEndPoint::MinPort || port > ppp::net::IPEndPoint::MaxPort) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                        }

                        destination_address = ppp::coroutines::asio::GetAddressByHostName<boost::asio::ip::udp>(host.data(), port, y).address();
                        if (ppp::net::IPEndPoint::IsInvalid(destination_address)) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                        }
                    }
                    else {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocksAddressTypeUnsupported);
                    }

                    int destination_port = (packet[offset] << 8) | packet[offset + 1];
                    offset += 2;
                    if (destination_port <= ppp::net::IPEndPoint::MinPort || destination_port > ppp::net::IPEndPoint::MaxPort) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                    }

                    int payload_length = packet_length - offset;
                    if (payload_length < 1) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    }

                    boost::asio::ip::udp::endpoint destinationEP(destination_address, destination_port);
                    if (ppp::net::IPEndPoint::IsInvalid(destination_address)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    }

                    udp_client_ep_ = sourceEP;
                    udp_destination_clients_[destinationEP] = sourceEP;

                    VEthernetExchangerPtr exchanger = GetExchanger();
                    if (NULLPTR == exchanger) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    }

                    auto self = std::dynamic_pointer_cast<VEthernetSocksProxyConnection>(shared_from_this());
                    exchanger->RegisterDatagramHandler(sourceEP,
                        [self](const boost::asio::ip::udp::endpoint& replySourceEP, const boost::asio::ip::udp::endpoint& relaySourceEP, void* responsePacket, int responsePacketLength) noexcept -> bool {
                            if (NULLPTR == self || NULLPTR == responsePacket || responsePacketLength < 1) {
                                return false;
                            }

                            return self->SendUdpAssociatePacketToClient(replySourceEP, relaySourceEP, responsePacket, responsePacketLength);
                        });

                    return exchanger->SendTo(sourceEP, destinationEP, packet + offset, payload_length);
                }

                /** @brief Encodes and sends a SOCKS5 UDP response datagram to the local client. */
                bool VEthernetSocksProxyConnection::SendUdpAssociatePacketToClient(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_length) noexcept {
                    std::shared_ptr<boost::asio::ip::udp::socket> udp_socket = udp_socket_;
                    if (NULLPTR == udp_socket || !udp_socket->is_open()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                    }

                    if (NULLPTR == packet || packet_length < 1) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    }

                    Byte buffer[PPP_BUFFER_SIZE + 32];
                    int packet_offset = 0;
                    buffer[packet_offset++] = 0;
                    buffer[packet_offset++] = 0;
                    buffer[packet_offset++] = 0;

                    boost::asio::ip::address source_address = sourceEP.address();
                    if (source_address.is_v4()) {
                        buffer[packet_offset++] = SOCKS_ATYPE_IPV4;
                        auto bytes = source_address.to_v4().to_bytes();
                        memcpy(buffer + packet_offset, bytes.data(), bytes.size());
                        packet_offset += bytes.size();
                    }
                    elif(source_address.is_v6()) {
                        buffer[packet_offset++] = SOCKS_ATYPE_IPV6;
                        auto bytes = source_address.to_v6().to_bytes();
                        memcpy(buffer + packet_offset, bytes.data(), bytes.size());
                        packet_offset += bytes.size();
                    }
                    else {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    }

                    int source_port = sourceEP.port();
                    buffer[packet_offset++] = (Byte)(source_port >> 8);
                    buffer[packet_offset++] = (Byte)(source_port);

                    if (packet_length > (int)sizeof(buffer) - packet_offset) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    }

                    memcpy(buffer + packet_offset, packet, packet_length);
                    packet_offset += packet_length;

                    boost::system::error_code ec;
                    udp_socket->send_to(boost::asio::buffer(buffer, packet_offset), destinationEP, boost::asio::socket_base::message_end_of_record, ec);
                    if (ec) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpSendFailed);
                    }

                    return true;
                }
            }
        }
    }
}

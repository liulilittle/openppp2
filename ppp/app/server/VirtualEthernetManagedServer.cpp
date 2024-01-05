#include <ppp/app/server/VirtualEthernetManagedServer.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/auxiliary/JsonAuxiliary.h>
#include <ppp/auxiliary/UriAuxiliary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Timer.h>

using ppp::threading::Executors;
using ppp::auxiliary::UriAuxiliary;
using ppp::auxiliary::JsonAuxiliary;
using ppp::auxiliary::StringAuxiliary;
using ppp::net::Socket;
using ppp::net::IPEndPoint;
using ppp::threading::Timer;

namespace ppp {
    namespace app {
        namespace server {
            enum {
                PACKET_CMD_CONNECT = 1001,
                PACKET_CMD_AUTHENTICATION = 1002,
                PACKET_CMD_TRAFFIC = 1003,

                PACKET_TIMEOUT_AUTHENTICATION = 5000,
                PACKET_TIMEOUT_CONNECT = 5000,
                PACKET_TIMEOUT_RECONNECT = 5000,

                PACKET_TIMEOUT_TRAFFIC = 10000,
            };

            VirtualEthernetManagedServer::VirtualEthernetManagedServer(const std::shared_ptr<VirtualEthernetSwitcher>& switcher) noexcept
                : disposed_(false)
                , traffics_next_(0)
                , switcher_(switcher) {
                context_ = switcher->GetContext();
                configuration_ = switcher->GetConfiguration();
                allocator_ = configuration_->GetBufferAllocator();
            }

            bool VirtualEthernetManagedServer::ConnectToManagedServer(const ppp::string& url) noexcept {
                return false;
            }

            bool VirtualEthernetManagedServer::AuthenticationToManagedServer(const ppp::Int128& session_id, const AuthenticationToManagedServerAsyncCallback& ac) noexcept {
                if (disposed_) {
                    return false;
                }

                if (NULL == ac) {
                    return false;
                }

                UInt64 next = Executors::GetTickCount() + PACKET_TIMEOUT_AUTHENTICATION; {
                    SynchronizedObjectScope scope(syncobj_);
                    if (authentications_.find(session_id) != authentications_.end()) {
                        return false;
                    }

                    authentications_.emplace(session_id, AuthenticationWaitable{ next, ac });
                }

                if (SendToManagedServer(session_id, PACKET_CMD_AUTHENTICATION)) {
                    return true;
                }

                DeleteAuthenticationToManagedServer(session_id);
                return false;
            }

            VirtualEthernetManagedServer::AuthenticationToManagedServerAsyncCallback VirtualEthernetManagedServer::DeleteAuthenticationToManagedServer(const ppp::Int128& session_id) noexcept {
                AuthenticationToManagedServerAsyncCallback f; {
                    SynchronizedObjectScope scope(syncobj_);
                    auto tail = authentications_.find(session_id);
                    auto endl = authentications_.end();
                    if (tail != endl) {
                        auto& aw = tail->second;
                        f = std::move(aw.ac);
                        aw.ac.reset();
                        authentications_.erase(tail);
                    }
                }
                return f;
            }

            void VirtualEthernetManagedServer::TickAllAuthenticationToManagedServer(UInt64 now) noexcept {
                typedef struct {
                    ppp::Int128 k;
                    AuthenticationToManagedServerAsyncCallback f;
                } ReleaseInfo;

                ppp::vector<ReleaseInfo> releases; {
                    SynchronizedObjectScope scope(syncobj_);
                    for (auto&& kv : authentications_) {
                        auto& aw = kv.second;
                        if (now >= aw.timeout) {
                            releases.emplace_back(ReleaseInfo{ kv.first, std::move(aw.ac) });
                            aw.ac.reset();
                        }
                    }
                }

                for (ReleaseInfo& ri : releases) {
                    ri.f(false, NULL);
                }
            }

            std::shared_ptr<VirtualEthernetManagedServer> VirtualEthernetManagedServer::GetReference() noexcept {
                return shared_from_this();
            }

            VirtualEthernetManagedServer::AppConfigurationPtr VirtualEthernetManagedServer::GetConfiguration() noexcept {
                return configuration_;
            }

            std::shared_ptr<ppp::threading::BufferswapAllocator> VirtualEthernetManagedServer::GetBufferswapAllocator() noexcept {
                return allocator_;
            }

            VirtualEthernetManagedServer::SynchronizedObject& VirtualEthernetManagedServer::GetSynchronizedObject() noexcept {
                return syncobj_;
            }

            bool VirtualEthernetManagedServer::LinkIsAvailable() noexcept {
                WebSocketPtr websocket = server_;
                if (NULL == websocket) {
                    return false;
                }

                if (websocket->IsDisposed()) {
                    return false;
                }

                return true;
            }

            void VirtualEthernetManagedServer::Update(UInt64 now) noexcept {
                TickAllAuthenticationToManagedServer(now);
                TickAllUploadTrafficToManagedServer(now);
            }

            template <typename TWebSocket, typename TWebSocketPtr, typename TData>
            static bool PACKET_SendToManagedServer(int node, TWebSocketPtr websocket, const ppp::Int128& session_id, int cmd, const TData& data) noexcept {
                if (NULL == websocket) {
                    return false;
                }

                if (websocket->IsDisposed()) {
                    return false;
                }

                Json::Value messages;
                messages["node"] = node;
                messages["guid"] = StringAuxiliary::Int128ToGuidString(session_id);
                messages["cmd"] = cmd;
                messages["data"] = data;

                auto packet = make_shared_object<ppp::string>(JsonAuxiliary::ToString(messages));
                auto cb = make_shared_object<typename TWebSocket::AsynchronousWriteCallback>(
                    [websocket, packet](bool ok) noexcept -> void {
                        if (!ok) {
                            websocket->Dispose();
                        }
                    });
                return websocket->Write(packet->data(), 0, packet->size(), cb);
            }

            template <typename TWebSocketPtr>
            static std::shared_ptr<Byte> PACKET_ReadBinaryPacket(std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, TWebSocketPtr& websocket, int& packet_length, ppp::coroutines::YieldContext& y) noexcept {
                char length_hex[8];
                if (!websocket->Read(length_hex, 0, sizeof(length_hex), y)) {
                    return NULL;
                }

                int length_num = (int)Int128::Parse<ppp::string>(ppp::string(length_hex, sizeof(length_hex)), 16);
                if (length_num < 1) {
                    return NULL;
                }

                std::shared_ptr<Byte> packet = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, length_num);
                if (NULL == packet) {
                    return NULL;
                }

                if (!websocket->Read(packet.get(), 0, length_num, y)) {
                    return NULL;
                }

                packet_length = length_num;
                return packet;
            }

            template <typename TWebSocketPtr>
            static bool PACKET_ReadJsonPacket(std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, TWebSocketPtr& websocket, Json::Value& json, ppp::coroutines::YieldContext& y) noexcept {
                int packet_length = 0;
                std::shared_ptr<Byte> packet = PACKET_ReadBinaryPacket(allocator, websocket, packet_length, y);
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                json = JsonAuxiliary::FromString((char*)packet.get(), packet_length);
                return json.isObject();
            }

            bool VirtualEthernetManagedServer::SendToManagedServer(const ppp::Int128& session_id, int cmd) noexcept {
                return SendToManagedServer(session_id, cmd, ppp::string());
            }

            bool VirtualEthernetManagedServer::SendToManagedServer(const ppp::Int128& session_id, int cmd, const Json::Value& data) noexcept {
                return PACKET_SendToManagedServer<WebSocket>(switcher_->GetNodeId(), server_, session_id, cmd, data);
            }

            bool VirtualEthernetManagedServer::SendToManagedServer(const ppp::Int128& session_id, int cmd, const ppp::string& data) noexcept {
                return PACKET_SendToManagedServer<WebSocket>(switcher_->GetNodeId(), server_, session_id, cmd, data);
            }

            bool VirtualEthernetManagedServer::TryVerifyUriAsync(const ppp::string& url, const TryVerifyUriAsyncCallback& ac) noexcept {
                if (disposed_) {
                    return false;
                }

                if (url.empty()) {
                    return false;
                }

                if (NULL == ac) {
                    return false;
                }

                auto self = shared_from_this();
                return YieldContext::Spawn(*context_,
                    [self, this, ac, url](YieldContext& y) noexcept {
                        ppp::string host;
                        ppp::string path;
                        boost::asio::ip::tcp::endpoint remoteEP;
                        auto& context = y.GetContext();
                        auto verify_ok = TryGetManagedServerEndPoint(url, host, path, remoteEP, y);
                        context.post(
                            [verify_ok, ac]() noexcept {
                                ac(verify_ok);
                            });
                    });
            }

            bool VirtualEthernetManagedServer::TryGetManagedServerEndPoint(const ppp::string& url, ppp::string& host, ppp::string& path, boost::asio::ip::tcp::endpoint& remoteEP, YieldContext& y) noexcept {
                using ProtocolType = UriAuxiliary::ProtocolType;

                if (disposed_) {
                    return false;
                }

                if (url.empty()) {
                    return false;
                }

                ppp::string address;
                ppp::string server;
                int port;
                ProtocolType protocol_type = ProtocolType::ProtocolType_Http;

                ppp::string url_new = UriAuxiliary::Parse(url, host, address, path, port, protocol_type, y);
                if (url_new.empty()) {
                    return false;
                }

                if (host.empty()) {
                    return false;
                }

                if (address.empty()) {
                    return false;
                }

                if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    return false;
                }

                if (protocol_type != ProtocolType::ProtocolType_Http && protocol_type != ProtocolType::ProtocolType_WebSocket) {
                    return false;
                }

                IPEndPoint ipep(address.data(), port);
                if (IPEndPoint::IsInvalid(ipep)) {
                    return false;
                }

                return disposed_ ? false : true;
            }

            void VirtualEthernetManagedServer::RunInner(const ppp::string& url, YieldContext& y) noexcept {
                while (!disposed_) {
                    WebSocketPtr websocket = NewWebSocketConnectToManagedServer2(url, y);
                    if (websocket) {
                        server_ = websocket; {
                            Run(websocket, y); {
                                server_.reset();
                            }
                        }
                        websocket->Dispose();
                    }

                    ppp::coroutines::asio::async_sleep(y, context_, PACKET_TIMEOUT_RECONNECT);
                }
            }

            void VirtualEthernetManagedServer::Run(WebSocketPtr& websocket, YieldContext& y) noexcept {
                int node = switcher_->GetNodeId();
                while (!disposed_) {
                    Json::Value json;
                    if (!PACKET_ReadJsonPacket(allocator_, websocket, json, y)) {
                        break;
                    }

                    if (JsonAuxiliary::AsValue<int>(json["node"]) != node) {
                        break;
                    }

                    int cmd = JsonAuxiliary::AsValue<int>(json["cmd"]);
                    if (cmd == PACKET_CMD_AUTHENTICATION) {
                        AckAuthenticationToManagedServer(json);
                    }
                    elif(cmd == PACKET_CMD_TRAFFIC) {
                        AckAllUploadTrafficToManagedServer(json);
                    }
                    else {
                        break;
                    }
                }
            }

            bool VirtualEthernetManagedServer::AckAllUploadTrafficToManagedServer(Json::Value& json) noexcept {
                Json::Value json_array = json["data"];
                if (!json_array.isArray()) {
                    return false;
                }

                Json::ArrayIndex json_array_size = json_array.size();
                UInt32 now = (UInt32)(ppp::threading::Executors::GetTickCount() / 1000);
         
                bool any = false;
                for (Json::ArrayIndex json_array_index = 0; json_array_index < json_array_size; json_array_index++) {
                    Json::Value& json_object = json_array[json_array_index];
                    if (!json_object.isObject()) {
                        continue;
                    }

                    ppp::string guid = JsonAuxiliary::ToString(json["guid"]);
                    if (guid.empty()) {
                        return false;
                    }

                    Int128 session_id = StringAuxiliary::GuidStringToInt128(guid);
                    any |= switcher_->OnInformation(session_id, VirtualEthernetInformation::FromJson(json["data"]));
                }
                return any;
            }

            bool VirtualEthernetManagedServer::AckAuthenticationToManagedServer(Json::Value& json) noexcept {
                ppp::string guid = JsonAuxiliary::ToString(json["guid"]);
                if (guid.empty()) {
                    return false;
                }

                Int128 session_id = StringAuxiliary::GuidStringToInt128(guid);
                AuthenticationToManagedServerAsyncCallback f = DeleteAuthenticationToManagedServer(session_id);
                if (!f) {
                    return false;
                }

                std::shared_ptr<VirtualEthernetInformation> i = VirtualEthernetInformation::FromJson(json["data"]);
                if (!i) {
                    f(false, NULL);
                    return true;
                }

                UInt32 now = (UInt32)(ppp::threading::Executors::GetTickCount() / 1000);
                if ((i->IncomingTraffic > 0 && i->OutgoingTraffic > 0) || (now >= i->ExpiredTime)) {
                    f(true, i.get());
                }
                else {
                    f(false, i.get());
                }
                return true;
            }

            void VirtualEthernetManagedServer::UploadTrafficToManagedServer(const ppp::Int128& session_id, int64_t in, int64_t out) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                UploadTrafficTask& task = traffics_[session_id];
                task.in += in;
                task.out += out;
            }
 
            void VirtualEthernetManagedServer::TickAllUploadTrafficToManagedServer(UInt64 now) noexcept {
                if (now >= traffics_next_) {
                    Json::Value json;
                    UploadTrafficTaskTable traffics; {
                        SynchronizedObjectScope scope(syncobj_);
                        traffics = std::move(traffics_);
                        traffics_.clear();
                    }

                    for (auto&& kv : traffics) {
                        UploadTrafficTask& task = kv.second;
                        json["guid"] = StringAuxiliary::Int128ToGuidString(kv.first);
                        json["in"] = std::to_string(task.in).data();
                        json["out"] = std::to_string(task.out).data();
                    }

                    traffics_next_ = now + PACKET_TIMEOUT_TRAFFIC;
                    SendToManagedServer(0, PACKET_CMD_TRAFFIC, json);
                }
            }

            VirtualEthernetManagedServer::WebSocketPtr VirtualEthernetManagedServer::NewWebSocketConnectToManagedServer2(const ppp::string& url, YieldContext& y) noexcept {
                WebSocketPtr websocket = NewWebSocketConnectToManagedServer(url, y);
                if (NULL == websocket) {
                    return NULL;
                }

                int node = switcher_->GetNodeId();
                bool ok = PACKET_SendToManagedServer<WebSocket>(node, websocket, 0, PACKET_CMD_CONNECT, ppp::string());
                if (!ok) {
                    return NULL;
                }

                auto self = shared_from_this();
                std::shared_ptr<Timer> timeout = Timer::Timeout(context_, PACKET_TIMEOUT_CONNECT,
                    make_shared_object<Timer::TimeoutEventHandler>(
                        [self, this, websocket]() noexcept {
                            websocket->Dispose();
                        }));
                if (NULL == timeout) {
                    return NULL;
                }

                Json::Value json;
                ok = PACKET_ReadJsonPacket(allocator_, websocket, json, y);
                timeout->Dispose();
                if (!ok) {
                    return NULL;
                }

                if (disposed_) {
                    return NULL;
                }

                int cmd = JsonAuxiliary::AsValue<int>(json["cmd"]);
                if (cmd != PACKET_CMD_CONNECT) {
                    return NULL;
                }

                if (JsonAuxiliary::AsValue<int>(json["node"]) != node) {
                    return NULL;
                }

                return websocket;
            }

            VirtualEthernetManagedServer::WebSocketPtr VirtualEthernetManagedServer::NewWebSocketConnectToManagedServer(const ppp::string& url, YieldContext& y) noexcept {
                ppp::string host;
                ppp::string path;
                boost::asio::ip::tcp::endpoint remoteEP;

                auto verify_ok = TryGetManagedServerEndPoint(url, host, path, remoteEP, y);
                if (!verify_ok) {
                    return NULL;
                }

                auto socket = make_shared_object<boost::asio::ip::tcp::socket>(*context_);
                if (NULL == socket) {
                    return NULL;
                }

                boost::system::error_code ec;
                socket->open(remoteEP.protocol(), ec);
                if (ec) {
                    return NULL;
                }
                else {
                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                    ppp::net::Socket::AdjustSocketOptional(*socket, configuration->tcp.fast_open, configuration->tcp.turbo);
                }

                bool binary = false;
                auto websocket = make_shared_object<WebSocket>(context_, socket, binary);
                if (!websocket->Run(WebSocket::HandshakeType_Client, host, path, y)) {
                    return NULL;
                }

                if (disposed_) {
                    websocket->Dispose();
                    return NULL;
                }
                else {
                    return websocket;
                }
            }
        }
    }
}
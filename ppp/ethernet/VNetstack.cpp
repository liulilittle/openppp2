#include <ppp/ethernet/VNetstack.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/coroutines/asio/asio.h>
#include <libtcpip/netstack.h>

typedef ppp::net::AddressFamily                                 AddressFamily;
typedef ppp::net::Socket                                        Socket;
typedef ppp::tap::ITap                                          ITap;
typedef ppp::threading::Executors                               Executors;
typedef ppp::net::IPEndPoint                                    IPEndPoint;
typedef ppp::net::native::ip_hdr                                ip_hdr;
typedef ppp::net::native::tcp_hdr                               tcp_hdr;
typedef tcp_hdr::tcp_flags                                      TcpFlags;
typedef tcp_hdr::tcp_state                                      TcpState;
typedef ppp::collections::Dictionary                            Dictionary;

namespace ppp {
    namespace ethernet {
        static Int128 LAN2WAN_KEY(uint32_t src_ip, uint16_t src_port, uint16_t dst_ip, uint16_t dst_port) noexcept {
            uint64_t src_ep = MAKE_QWORD(src_ip, src_port);
            uint64_t dst_ep = MAKE_QWORD(dst_ip, dst_port);

            return MAKE_OWORD(dst_ep, src_ep);
        }

        VNetstack::TapTcpLink::TapTcpLink() noexcept {
            this->dstAddr = 0;
            this->dstPort = 0;
            this->srcAddr = 0;
            this->srcPort = 0;
            this->natPort = 0;
            this->lwip = false;
            this->state = TcpState::TCP_STATE_CLOSED;
            this->socket = NULL;
            this->lastTime = Executors::GetTickCount();
        }

        VNetstack::TapTcpLink::~TapTcpLink() noexcept {
            Release();
        }

        void VNetstack::TapTcpLink::Update() noexcept {
            this->lastTime = Executors::GetTickCount();
        }

        void VNetstack::TapTcpLink::Release() noexcept {
            TapTcpLink* p = this;
            std::shared_ptr<TapTcpClient> m = std::move(p->socket);
            if (NULL != m) {
                p->socket.reset();
                m->Dispose();
            }

            p->state = TcpState::TCP_STATE_CLOSED;
            p->Update();
        }

        void VNetstack::TapTcpLink::Dispose() noexcept {
            Release();
        }

        std::shared_ptr<VNetstack::TapTcpLink> VNetstack::FindTcpLink(int key) noexcept {
#ifndef _WIN32
            SynchronizedObjectScope scope(syncobj_);
#endif
            auto& map = this->wan2lan_;
            auto tail = map.find(key);
            auto endl = map.end();
            if (tail == endl) {
                return NULL;
            }
            else {
                return tail->second;
            }
        }

        std::shared_ptr<VNetstack::TapTcpLink> VNetstack::FindTcpLink(const Int128& key) noexcept {
#ifndef _WIN32
            SynchronizedObjectScope scope(syncobj_);
#endif
            auto& map = this->lan2wan_;
            auto tail = map.find(key);
            auto endl = map.end();
            if (tail == endl) {
                return NULL;
            }
            else {
                return tail->second;
            }
        }

        std::shared_ptr<VNetstack::TapTcpLink> VNetstack::AllocTcpLink(UInt32 src_ip, int src_port, UInt32 dst_ip, int dst_port) noexcept {
            auto key = LAN2WAN_KEY(src_ip, src_port, dst_ip, dst_port);
            std::shared_ptr<TapTcpLink> link = this->FindTcpLink(key);
            if (link != NULL) {
                return link;
            }

            int newPort = 0;
#ifndef _WIN32
            SynchronizedObjectScope scope(syncobj_);
#endif
            for (int traversePort = IPEndPoint::MinPort; traversePort < IPEndPoint::MaxPort; traversePort++) {
                newPort = IPEndPoint::MinPort;
                for (int c = IPEndPoint::MinPort; c <= IPEndPoint::MaxPort; c++) {
                    int localPort = ++this->ap_;
                    if (localPort <= IPEndPoint::MinPort || localPort > IPEndPoint::MaxPort) {
                        this->ap_ = IPEndPoint::MinPort;
                    }

                    if (localPort == this->listenEP_.Port) {
                        continue;
                    }

                    auto tail = this->lan2wan_.find(key);
                    auto endl = this->lan2wan_.end();
                    if (tail == endl) {
                        newPort = localPort;
                        break;
                    }
                }

                if (newPort == IPEndPoint::MinPort) {
                    break;
                }

                link = make_shared_object<TapTcpLink>();
                if (NULL == link) {
                    break;
                }

                link->dstAddr = dst_ip;
                link->dstPort = dst_port;
                link->srcAddr = src_ip;
                link->srcPort = src_port;
                link->natPort = newPort;
                link->state = TcpState::TCP_STATE_SYN_RECEIVED;

                this->lan2wan_[key] = link;
                this->wan2lan_[newPort] = link;
                break;
            }

            if (NULL != link) {
                link->Update();
            }

            return link;
        }

        std::shared_ptr<VNetstack> VNetstack::GetReference() noexcept {
            return shared_from_this();
        }

#ifndef _WIN32
        VNetstack::SynchronizedObject& VNetstack::GetSynchronizedObject() noexcept {
            return syncobj_;
        }
#endif

        VNetstack::VNetstack() noexcept
            : ap_(RandomNext(IPEndPoint::MinPort, IPEndPoint::MaxPort))
            , lwip_(false) {

        }

        VNetstack::~VNetstack() noexcept {
            ReleaseAllResources();
        }

        bool VNetstack::Constructor(bool lwip, const int& localPort) noexcept {
            if (localPort < IPEndPoint::MinPort || localPort > IPEndPoint::MaxPort) {
                return false;
            }

            std::shared_ptr<ITap> tap = this->Tap;
            if (NULL == tap) {
                return false;
            }
            else {
                Release();
            }

            std::shared_ptr<SocketAcceptor> acceptor = SocketAcceptor::New();
            if (NULL == acceptor) {
                return false;
            }
            else {
                ppp::string bindIP = ppp::net::Ipep::ToAddressString<ppp::string>(boost::asio::ip::address_v4::any());
                if (!acceptor->Open(bindIP.data(), localPort, PPP_LISTEN_BACKLOG)) {
                    acceptor->Dispose();
                    return false;
                }
                else {
                    int handle = acceptor->GetHandle();
                    ppp::net::Socket::AdjustDefaultSocketOptional(handle, false);
                    ppp::net::Socket::SetTypeOfService(handle);
                    ppp::net::Socket::SetSignalPipeline(handle, false);
                    
                    listenEP_ = IPEndPoint::ToEndPoint(Socket::GetLocalEndPoint(acceptor->GetHandle()));
                    constantof(localPort) = listenEP_.Port;
                }
            }

            std::shared_ptr<VNetstack> self = shared_from_this();
            auto fx = make_shared_object<SocketAcceptor::AcceptSocketEventHandler>(
                [self, this](SocketAcceptor*, SocketAcceptor::AcceptSocketEventArgs& e) noexcept {
                    this->ProcessAcceptSocket(e.Socket);
                });
            if (NULL == fx) {
                return false;
            }

            acceptor->AcceptSocket = fx;
            lwip_ = lwip;
            acceptor_ = acceptor;

            lwip::netstack::Localhost = localPort;
            return true;
        }

        void VNetstack::Release() noexcept {
            ReleaseAllResources();
        }

        void VNetstack::ReleaseAllResources() noexcept {
            std::shared_ptr<SocketAcceptor> acceptor;
            WAN2LANTABLE wan2lan;
            LAN2WANTABLE lan2wan; {
#ifndef _WIN32
                SynchronizedObjectScope scope(syncobj_);
#endif
                acceptor = std::move(acceptor_);
                acceptor_.reset();

                wan2lan = std::move(wan2lan_);
                wan2lan_.clear();

                lan2wan = std::move(lan2wan_);
                lan2wan_.clear();
            }

            if (NULL != acceptor) {
                acceptor->Dispose();
            }

            Dictionary::ReleaseAllObjects(wan2lan);
            Dictionary::ReleaseAllObjects(lan2wan);

            listenEP_ = IPEndPoint();
            lwip_ = false;
            ap_ = RandomNext(IPEndPoint::MinPort, IPEndPoint::MaxPort);
        }

        bool VNetstack::Input(ip_hdr* ip, tcp_hdr* tcp, int tcp_len) noexcept {
            if (NULL == ip || NULL == tcp || tcp_len < 1) {
                return false;
            }

            std::shared_ptr<ITap> tap = this->Tap;
            if (NULL == tap) {
                return false;
            }

            TcpFlags flags = (TcpFlags)tcp_hdr::TCPH_FLAGS(tcp);
            bool lan2wan = true;
            std::shared_ptr<TapTcpLink> link;

            if (ip->dest == tap->GatewayServer) { // V->Local 
                link = this->FindTcpLink(tcp->dest);
                if (NULL == link) {
                    this->RST(ip, tcp, tcp_len);
                    return false;
                }
                else {
                    link->Update();
                    ip->src = link->dstAddr;
                    tcp->src = link->dstPort;
                    ip->dest = link->srcAddr;
                    tcp->dest = link->srcPort;
                }
                lan2wan = false;
            }
            elif(flags == TcpFlags::TCP_SYN) { // SYN
                link = this->AllocTcpLink(ip->src, tcp->src, ip->dest, tcp->dest);
                if (NULL == link) {
                    this->RST(ip, tcp, tcp_len);
                    return false;
                }

                if (link->state != TcpState::TCP_STATE_SYN_RECEIVED) {
                    this->CloseTcpLink(link);
                    return this->Input(ip, tcp, tcp_len);
                }

                boost::asio::ip::tcp::endpoint localEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(ip->src, ntohs(tcp->src));
                boost::asio::ip::tcp::endpoint remoteEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(ip->dest, ntohs(tcp->dest));

                std::shared_ptr<TapTcpClient> socket = this->BeginAcceptClient(localEP, remoteEP);
                if (NULL == socket) {
                    this->CloseTcpLink(link);
                    return false;
                }

                if (!socket->BeginAccept()) {
                    this->CloseTcpLink(link);
                    return false;
                }

                link->socket = std::move(socket);
                ip->src = tap->GatewayServer;
                tcp->src = link->natPort;
                ip->dest = tap->IPAddress;
                tcp->dest = ntohs(this->listenEP_.Port);
            }
            else { // Local->V
                link = this->FindTcpLink(LAN2WAN_KEY(ip->src, tcp->src, ip->dest, tcp->dest));
                if (NULL == link) {
                    this->RST(ip, tcp, tcp_len);
                    return false;
                }
                else {
                    link->Update();
                    ip->src = tap->GatewayServer;
                    tcp->src = link->natPort;
                    ip->dest = tap->IPAddress;
                    tcp->dest = ntohs(this->listenEP_.Port);
                }
            }

            if (flags & TcpFlags::TCP_RST) {
                link->state = TcpState::TCP_STATE_CLOSED;
            }
            elif((flags & TcpFlags::TCP_SYN) && (flags & TcpFlags::TCP_ACK)) {
                if (link->state == TcpState::TCP_STATE_SYN_RECEIVED) {
                    link->state = TcpState::TCP_STATE_ESTABLISHED;
                }
            }
            elif((flags & TcpFlags::TCP_FIN) && (flags & TcpFlags::TCP_ACK)) {
                if (link->state == TcpState::TCP_STATE_ESTABLISHED) {
                    link->state = TcpState::TCP_STATE_CLOSE_WAIT;
                }
                elif(link->state == TcpState::TCP_STATE_LAST_ACK) {
                    link->state = TcpState::TCP_STATE_CLOSED;
                }
            }
            elif(flags & TcpFlags::TCP_ACK) {
                if (link->state == TcpState::TCP_STATE_CLOSE_WAIT) {
                    link->state = TcpState::TCP_STATE_LAST_ACK;
                }
            }

            return this->Output(lan2wan, ip, tcp, tcp_len);
        }

        uint64_t VNetstack::GetMaxConnectTimeout() noexcept {
            return 10000;
        }

        uint64_t VNetstack::GetMaxFinalizeTimeout() noexcept {
            return 20000;
        }

        uint64_t VNetstack::GetMaxEstablishedTimeout() noexcept {
            return 72000;;
        }

        bool VNetstack::Update(uint64_t now) noexcept {
            const uint64_t MaxEstablishedTimeout = GetMaxEstablishedTimeout();
            const uint64_t MaxFinalizeTimeout = GetMaxFinalizeTimeout();
            const uint64_t MaxConnectTimeout = GetMaxConnectTimeout();

            ppp::vector<TapTcpLink::Ptr> releases; {
#ifndef _WIN32
                SynchronizedObjectScope scope(syncobj_);
#endif
                for (auto tail = this->wan2lan_.begin(); tail != this->wan2lan_.end();) {
                    std::shared_ptr<TapTcpLink> link = tail->second;
                    if (NULL == link) {
                        tail = this->wan2lan_.erase(tail);
                        continue;
                    }
                    else {
                        tail++;
                    }

                    UInt64 deltaTime = now - link->lastTime;
                    if (link->lwip) {
                        std::shared_ptr<TapTcpClient> socket = link->socket;
                        if (NULL == socket) {
                            bool syn = link->state == TcpState::TCP_STATE_SYN_SENT || link->state == TcpState::TCP_STATE_SYN_RECEIVED;
                            if (!syn) {
                                releases.emplace_back(link);
                            }
                        }
                        elif(socket->IsDisposed()) {
                            releases.emplace_back(link);
                        }
                        else {
                            uint64_t maxTimeout = link->state == TcpState::TCP_STATE_ESTABLISHED ? MaxEstablishedTimeout : MaxFinalizeTimeout;
                            if (deltaTime >= maxTimeout) {
                                releases.emplace_back(link);
                            }
                        }
                    }
                    elif(link->state == TcpState::TCP_STATE_ESTABLISHED) {
                        goto TCP_STATE_INACTIVE;
                    }
                    elif(link->state == TcpState::TCP_STATE_CLOSED) {
                        releases.emplace_back(link);
                    }
                    elif(link->state > TcpState::TCP_STATE_ESTABLISHED) {
                        if (deltaTime >= MaxFinalizeTimeout) {
                            releases.emplace_back(link);
                        }
                    }
                    elif(link->state == TcpState::TCP_STATE_SYN_SENT || link->state == TcpState::TCP_STATE_SYN_RECEIVED) {
                        if (deltaTime >= MaxConnectTimeout) {
                            releases.emplace_back(link);
                        }
                    }
                    else {
                    TCP_STATE_INACTIVE:
                        if (deltaTime >= MaxEstablishedTimeout) {
                            releases.emplace_back(link);
                        }
                    }
                }
            }

            for (const std::shared_ptr<TapTcpLink>& link : releases) {
                if (NULL != link) {
                    this->CloseTcpLink(link);
                }
            }
            return true;
        }

        bool VNetstack::RST(ip_hdr* iphdr, tcp_hdr* ip, int tcp_len) noexcept {
            uint32_t dstAddr = iphdr->dest;
            uint16_t dstPort = ip->dest;
            uint32_t srcAddr = iphdr->src;
            uint16_t srcPort = ip->src;
            uint32_t seqNo = ip->seqno;
            uint32_t ackNo = ip->ackno;

            uint32_t hdrlen_bytes = tcp_hdr::TCPH_HDRLEN_BYTES(ip);
            uint32_t tcplen = tcp_len - hdrlen_bytes;
            if (tcp_hdr::TCPH_FLAGS(ip) & (TcpFlags::TCP_FIN | TcpFlags::TCP_SYN)) {
                tcplen++;
            }

            tcp_len = tcp_hdr::TCP_HLEN;
            iphdr->src = dstAddr;
            ip->src = dstPort;
            iphdr->dest = srcAddr;
            ip->dest = srcPort;
            ip->ackno = seqNo + tcplen;
            ip->seqno = ackNo;
            ip->hdrlen_rsvd_flags = 0;
            ip->urgp = 0;

            tcp_hdr::TCPH_HDRLEN_BYTES_SET(ip, tcp_len);
            tcp_hdr::TCPH_FLAGS_SET(ip, TcpFlags::TCP_RST | TcpFlags::TCP_ACK);

            return this->Output(false, iphdr, ip, tcp_len);
        }

        bool VNetstack::Output(bool lan2wan, ip_hdr* ip, tcp_hdr* tcp, int tcp_len) noexcept {
            std::shared_ptr<ITap> tap = this->Tap;
            if (NULL == tap) {
                return false;
            }

            tcp->chksum = 0;
            tcp->chksum = ppp::net::native::inet_chksum_pseudo((unsigned char*)tcp,
                (unsigned int)ip_hdr::IP_PROTO_TCP,
                (unsigned int)tcp_len,
                ip->src,
                ip->dest);
            if (tcp->chksum == 0) {
                tcp->chksum = 0xffff;
            }

            int iphdr_len = (char*)tcp - (char*)ip;
            ip->chksum = 0;
            ip->chksum = ppp::net::native::inet_chksum(ip, iphdr_len);
            if (ip->chksum == 0) {
                ip->chksum = 0xffff;
            }

            int ippkg_len = ((char*)tcp + tcp_len) - (char*)ip;
            return tap->Output(ip, ippkg_len);
        }

        bool VNetstack::CloseTcpLink(const std::shared_ptr<TapTcpLink>& link, bool fin) noexcept {
            if (NULL == link) {
                return false;
            }

            std::shared_ptr<ITap> tap = this->Tap;
            if (NULL == tap) {
                return false;
            }

            if (!fin) {
#ifndef _WIN32
                SynchronizedObjectScope scope(syncobj_);
#endif
                auto tail_wan2lan = this->wan2lan_.find(link->natPort);
                auto endl_wan2lan = this->wan2lan_.end();
                if (tail_wan2lan != endl_wan2lan) {
                    this->wan2lan_.erase(tail_wan2lan);
                }

                auto key = LAN2WAN_KEY(link->srcAddr, link->srcPort, link->dstAddr, link->dstPort);
                auto tail_lan2wan = this->lan2wan_.find(key);
                auto endl_lan2wan = this->lan2wan_.end();
                if (tail_lan2wan != endl_lan2wan) {
                    this->lan2wan_.erase(tail_lan2wan);
                }
            }

            link->Release();
            return true;
        }

        std::shared_ptr<ppp::threading::BufferswapAllocator> VNetstack::GetBufferAllocator() noexcept {
            std::shared_ptr<ITap> tap = this->Tap;
            if (NULL == tap) {
                return NULL;
            }
            else {
                return tap->BufferAllocator;
            }
        }

        std::shared_ptr<VNetstack::TapTcpClient> VNetstack::BeginAcceptClient(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
            std::shared_ptr<TapTcpClient> socket = make_shared_object<TapTcpClient>(Executors::GetCurrent());
            if (NULL == socket) {
                return NULL;
            }
            else {
                socket->Constructor(localEP, remoteEP);
                return socket;
            }
        }

        bool VNetstack::ProcessAcceptSocket(int sockfd) noexcept {
            std::shared_ptr<boost::asio::ip::tcp::socket> socket;
            do {
                std::shared_ptr<ITap> tap = this->Tap;
                if (NULL == tap) {
                    break;
                }

                boost::asio::ip::tcp::endpoint natEP = Socket::GetRemoteEndPoint(sockfd);
                IPEndPoint remoteEP = IPEndPoint::V6ToV4(IPEndPoint::ToEndPoint(natEP));
                if (lwip_) {
                    if (remoteEP.GetAddress() != htonl(IPEndPoint::LoopbackAddress)) {
                        break;
                    }
                }
                elif(remoteEP.GetAddress() != tap->GatewayServer) {
                    break;
                }

                if (remoteEP.Port <= IPEndPoint::MinPort || remoteEP.Port > IPEndPoint::MaxPort) {
                    break;
                }

                std::shared_ptr<TapTcpLink> link = this->AcceptTcpLink(htons(remoteEP.Port));
                if (NULL == link) {
                    break;
                }

                std::shared_ptr<TapTcpClient> pcb = link->socket;
                if (NULL == pcb) {
                    if (link->state != TcpState::TCP_STATE_CLOSED) {
                        link->state = TcpState::TCP_STATE_CLOSED;
                    }
                    break;
                }

                socket = pcb->NewAsynchronousSocket(sockfd, natEP);
                if (NULL == socket) {
                    break;
                }

                bool ok = pcb->EndAccept(socket, natEP);
                if (ok) {
                    link->Update();
                }
                else {
                    link->Release();
                }
                return ok;
            } while (false);

            if (NULL == socket) {
                Socket::Closesocket(sockfd);
            }
            return false;
        }

        std::shared_ptr<VNetstack::TapTcpLink> VNetstack::AcceptTcpLink(int key) noexcept {
            if (key <= IPEndPoint::MinPort || key >= IPEndPoint::MaxPort) {
                return NULL;
            }
            elif(!this->lwip_) {
                return this->FindTcpLink(key);
            }
            else {
                key = ntohs(key);
            }

            uint32_t srcAddr;
            uint32_t dstAddr;
            int      srcPort;
            int      dstPort;
            if (!lwip::netstack::link(key, srcAddr, srcPort, dstAddr, dstPort)) {
                return NULL;
            }

            boost::asio::ip::tcp::endpoint localEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(srcAddr, srcPort);
            boost::asio::ip::tcp::endpoint remoteEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(dstAddr, dstPort);

            std::shared_ptr<TapTcpLink> link;
            do {
#ifndef _WIN32
                SynchronizedObjectScope scope(syncobj_);
#endif
                auto tail = this->wan2lan_.find(key);
                auto endl = this->wan2lan_.end();
                if (tail != endl) {
                    return NULL;
                }

                link = make_shared_object<TapTcpLink>();
                if (NULL == link) {
                    return NULL;
                }
                
                link->dstAddr = dstAddr;
                link->dstPort = ntohs(dstPort);
                link->srcAddr = srcAddr;
                link->srcPort = ntohs(srcPort);
                link->natPort = key;
                link->lwip = true;
                link->state = TcpState::TCP_STATE_ESTABLISHED;
                this->wan2lan_[key] = link;
            } while (false);

            std::shared_ptr<TapTcpClient> socket = this->BeginAcceptClient(localEP, remoteEP);
            if (NULL == socket) {
                this->CloseTcpLink(link);
                return NULL;
            }

            socket->lwip_ = key;
            socket->link_ = link;
            if (!socket->BeginAccept()) {
                this->CloseTcpLink(link);
                return NULL;
            }

            link->socket = std::move(socket);
            return link;
        }

        VNetstack::TapTcpClient::TapTcpClient(const std::shared_ptr<boost::asio::io_context>& context) noexcept
            : lwip_(false)
            , disposed_(false)
            , context_(context) {

        }

        VNetstack::TapTcpClient::~TapTcpClient() noexcept {
            Finalize();
        }

        void VNetstack::TapTcpClient::Constructor(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
            this->localEP_ = localEP;
            this->remoteEP_ = remoteEP;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> VNetstack::TapTcpClient::NewAsynchronousSocket(int sockfd, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
            std::shared_ptr<boost::asio::ip::tcp::socket> socket = make_shared_object<boost::asio::ip::tcp::socket>(*context_);
            if (NULL == socket) {
                return NULL;
            }

            boost::system::error_code ec = boost::asio::error::operation_aborted;
            try {
                socket->assign(remoteEP.protocol(), sockfd, ec);
            }
            catch (const std::exception&) {}

            if (ec) {
                return NULL;
            }
            else {
                return socket;
            }
        }

        bool VNetstack::TapTcpClient::IsDisposed() noexcept {
            return disposed_;
        }

        void VNetstack::TapTcpClient::Dispose() noexcept {
            auto self = shared_from_this();
            context_->post(
                [self, this]() noexcept {
                    Finalize();
                });
        }

        void VNetstack::TapTcpClient::Finalize() noexcept {
            disposed_ = true; {
                std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::move(socket_);
                if (NULL != socket) {
                    socket_.reset();
                    Socket::Closesocket(socket);
                }

                std::shared_ptr<TapTcpLink> link = std::move(link_);
                if (NULL != link) {
                    link_.reset();
                    if (lwip_) {
                        link->Release();
                    }
                }
            }
        }

        bool VNetstack::TapTcpClient::BeginAccept() noexcept {
            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
            if (disposed_) {
                return false;
            }
            else {
                return NULL == socket;
            }
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> VNetstack::TapTcpClient::GetSocket() noexcept {
            return socket_;
        }

        std::shared_ptr<boost::asio::io_context>& VNetstack::TapTcpClient::GetContext() noexcept {
            return context_;
        }

        const boost::asio::ip::tcp::endpoint& VNetstack::TapTcpClient::GetLocalEndPoint() const noexcept {
            return this->localEP_;
        }

        const boost::asio::ip::tcp::endpoint& VNetstack::TapTcpClient::GetNatEndPoint() const noexcept {
            return this->natEP_;
        }

        const boost::asio::ip::tcp::endpoint& VNetstack::TapTcpClient::GetRemoteEndPoint() const noexcept {
            return this->remoteEP_;
        }

        bool VNetstack::TapTcpClient::EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) noexcept {
            if (NULL == socket) {
                return false;
            }

            std::shared_ptr<boost::asio::io_context> context = this->context_;
            if (NULL == context) {
                return false;
            }

            this->natEP_ = natEP;
            this->socket_ = socket;
            return this->Establish();
        }

        bool VNetstack::TapTcpClient::Establish() noexcept {
            return true;
        }

        bool VNetstack::TapTcpClient::Update() noexcept {
            if (disposed_) {
                return false;
            }

            std::shared_ptr<TapTcpLink> link = link_;
            if (NULL == link) {
                return false;
            }

            link->Update();
            return true;
        }
    }
}
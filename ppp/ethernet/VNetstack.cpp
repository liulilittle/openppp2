#include <ppp/ethernet/VNetstack.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/tcp.h>
#include <ppp/net/native/udp.h>
#include <ppp/net/native/icmp.h>
#include <ppp/net/packet/IPFrame.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>

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
            this->closed = false;
            this->state = TcpState::TCP_STATE_CLOSED;
            this->socket = NULL;
            this->lastTime = Executors::GetTickCount();
        }

        void VNetstack::TapTcpLink::Release() noexcept {
            this->Closing();

            this->state = TcpState::TCP_STATE_CLOSED;
            this->Update();
        }

        void VNetstack::TapTcpLink::Closing() noexcept {
            std::shared_ptr<TapTcpClient> c = std::move(this->socket); 
            this->closed = true;
            this->socket.reset();

            if (NULL != c) {
                c->Dispose();
            }
        }

        std::shared_ptr<VNetstack::TapTcpLink> VNetstack::FindTcpLink(int key) noexcept {
            SynchronizedObjectScope scope(syncobj_);

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
            SynchronizedObjectScope scope(syncobj_);

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
            else {
                int newPort = 0;
                SynchronizedObjectScope scope(syncobj_);

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
            }

            if (NULL != link) {
                link->Update();
            }

            return link;
        }

        VNetstack::VNetstack() noexcept
            : ap_(RandomNext(IPEndPoint::MinPort, IPEndPoint::MaxPort))
            , lwip_(false) {

        }

        VNetstack::~VNetstack() noexcept {
            ReleaseAllResources();
        }

        bool VNetstack::Open(bool lwip, const int& localPort) noexcept {
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
            acceptor->AcceptSocket = 
                [self, this](SocketAcceptor*, SocketAcceptor::AcceptSocketEventArgs& e) noexcept {
                    this->ProcessAcceptSocket(e.Socket);
                };

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
            LAN2WANTABLE lan2wan; 
            
            for (;;) {
                SynchronizedObjectScope scope(syncobj_);

                acceptor = std::move(acceptor_);
                acceptor_.reset();

                wan2lan = std::move(wan2lan_);
                wan2lan_.clear();

                lan2wan = std::move(lan2wan_);
                lan2wan_.clear();
                break;
            }

            if (NULL != acceptor) {
                acceptor->Dispose();
            }

            Dictionary::ReleaseAllObjects(wan2lan);
            Dictionary::ReleaseAllObjects(lan2wan);

            listenEP_ = IPEndPoint();
            lwip_ = IPEndPoint::MinPort;
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
            bool rst = true;
            std::shared_ptr<TapTcpLink> link;
            std::shared_ptr<TapTcpClient> c;

            if (ip->dest == tap->GatewayServer) { // V->Local 
                if ((link = this->FindTcpLink(tcp->dest))) {
                    link->Update();
                    lan2wan = false;
                    rst = false;
                    ip->src = link->dstAddr;
                    tcp->src = link->dstPort;
                    ip->dest = link->srcAddr;
                    tcp->dest = link->srcPort;
                }
            }
            elif(flags != TcpFlags::TCP_SYN) { // Local->V
                if ((link = this->FindTcpLink(LAN2WAN_KEY(ip->src, tcp->src, ip->dest, tcp->dest)))) {
                    link->Update();
                    rst = false;
                    ip->src = tap->GatewayServer;
                    tcp->src = link->natPort;
                    ip->dest = tap->IPAddress;
                    tcp->dest = ntohs(this->listenEP_.Port);
                }
            }
            elif((link = this->AllocTcpLink(ip->src, tcp->src, ip->dest, tcp->dest))) { // SYN
                for (;;) {
                    if (link->closed || link->state != TcpState::TCP_STATE_SYN_RECEIVED) {
                        break;
                    }
                    else {
                        c = link->socket;
                        if (NULL != c) {
                            rst = c->IsDisposed();
                            break;
                        }
                    }

                    boost::asio::ip::tcp::endpoint localEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(ip->src, ntohs(tcp->src));
                    boost::asio::ip::tcp::endpoint remoteEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(ip->dest, ntohs(tcp->dest));

                    c = this->BeginAcceptClient(localEP, remoteEP);
                    if (NULL == c || !c->BeginAccept()) {
                        break;
                    }

                    rst = false;
                    c->link_ = link;
                    link->socket = c;
                    ip->src = tap->GatewayServer;
                    tcp->src = link->natPort;
                    ip->dest = tap->IPAddress;
                    tcp->dest = ntohs(this->listenEP_.Port);
                    break;
                }
            }

            if (rst) {
                this->RST(ip, tcp, tcp_len);
                return false;
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

            return this->Output(lan2wan, ip, tcp, tcp_len, c.get());
        }

        uint64_t VNetstack::GetMaxConnectTimeout() noexcept {
            return 10000;
        }

        uint64_t VNetstack::GetMaxFinalizeTimeout() noexcept {
            return 20000;
        }

        uint64_t VNetstack::GetMaxEstablishedTimeout() noexcept {
            return 72000;
        }

        bool VNetstack::Update(uint64_t now) noexcept {
            const uint64_t MaxEstablishedTimeout = GetMaxEstablishedTimeout();
            const uint64_t MaxFinalizeTimeout = GetMaxFinalizeTimeout();
            const uint64_t MaxConnectTimeout = GetMaxConnectTimeout();

            std::shared_ptr<TapTcpClient> socket;
            std::shared_ptr<TapTcpLink> link;

            ppp::vector<TapTcpLink::Ptr> releases; {
                SynchronizedObjectScope scope(syncobj_);

                auto tail = this->wan2lan_.begin(); 
                auto endl = this->wan2lan_.end();
                while (tail != endl) {
                    link = tail->second;
                    if (NULL == link) {
                        tail = this->wan2lan_.erase(tail);
                        continue;
                    }
                    else {
                        tail++;
                    }

                    UInt64 deltaTime = now - link->lastTime;
                    if (link->lwip) {
                        socket = link->socket;
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
                    TCP_STATE_FINALIZE:
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
                        socket = link->socket;
                        if (NULL == socket || socket->IsDisposed()) {
                            goto TCP_STATE_FINALIZE;
                        }

                        if (deltaTime >= MaxEstablishedTimeout) {
                            releases.emplace_back(link);
                        }
                    }
                }
            }

            for (const std::shared_ptr<TapTcpLink>& i : releases) {
                if (NULL != i) {
                    this->CloseTcpLink(i);
                }
            }

            return true;
        }

        bool VNetstack::RST(ip_hdr* iphdr, tcp_hdr* tcp, int tcp_len) noexcept {
            uint32_t dstAddr = iphdr->dest;
            uint16_t dstPort = tcp->dest;
            uint32_t srcAddr = iphdr->src;
            uint16_t srcPort = tcp->src;
            uint32_t seqNo = tcp->seqno;
            uint32_t ackNo = tcp->ackno;

            uint32_t hdrlen_bytes = tcp_hdr::TCPH_HDRLEN_BYTES(tcp);
            uint32_t tcplen = tcp_len - hdrlen_bytes;
            uint8_t tcp_flags = tcp_hdr::TCPH_FLAGS(tcp);
            if (tcp_flags & (TcpFlags::TCP_FIN | TcpFlags::TCP_SYN)) {
                tcplen++;
            }

            tcp_len = tcp_hdr::TCP_HLEN;
            iphdr->src = dstAddr;
            tcp->src = dstPort;
            iphdr->dest = srcAddr;
            tcp->dest = srcPort;
            tcp->ackno = seqNo + tcplen;
            tcp->seqno = ackNo;
            tcp->urgp = 0;
            tcp->wnd = 0;
            tcp->hdrlen_rsvd_flags = 0;

            tcp_hdr::TCPH_HDRLEN_BYTES_SET(tcp, tcp_len);
            tcp_hdr::TCPH_FLAGS_SET(tcp, TcpFlags::TCP_RST);

            return this->Output(false, iphdr, tcp, tcp_len, NULL);
        }

        bool VNetstack::Output(bool lan2wan, ip_hdr* ip, tcp_hdr* tcp, int tcp_len, TapTcpClient* c) noexcept {
            std::shared_ptr<ITap> tap = this->Tap;
            if (NULL == tap) {
                return false;
            }

            if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                ip->tos = std::max<Byte>(ip->tos, ppp::net::packet::IPFrame::DefaultFlashTypeOfService());
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
            if (NULL == c) {
                return tap->Output(ip, ippkg_len);
            }

            std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
            std::shared_ptr<Byte> packet = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, ippkg_len);
            if (NULL == packet) {
                return false;
            }
            else {
                memcpy(packet.get(), ip, ippkg_len);
            }

            c->sync_ack_tap_driver_ = tap;
            c->sync_ack_byte_array_ = packet;
            c->sync_ack_bytes_size_ = ippkg_len;
            return true;
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
                SynchronizedObjectScope scope(syncobj_);

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

        bool VNetstack::ProcessAcceptSocket(int sockfd) noexcept {
            std::shared_ptr<boost::asio::ip::tcp::socket> socket;
            std::shared_ptr<TapTcpLink> link;
            std::shared_ptr<TapTcpClient> pcb;
            std::shared_ptr<ITap> tap;

            do {
                tap = this->Tap;
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

                link = this->AcceptTcpLink(htons(remoteEP.Port));
                if (NULL == link) {
                    break;
                }

                pcb = link->socket;
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

            bool blwip = this->lwip_;
            if (!blwip) {
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
                SynchronizedObjectScope scope(syncobj_);
                
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
                link->closed = false;
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

            bool bok = socket->BeginAccept();
            if (!bok) {
                this->CloseTcpLink(link);
                return NULL;
            }

            link->socket = std::move(socket);
            return link;
        }

        VNetstack::TapTcpClient::TapTcpClient(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand) noexcept
            : lwip_(IPEndPoint::MinPort)
            , disposed_(FALSE)
            , context_(context)
            , strand_(strand) {
            socket_ = strand ? 
                make_shared_object<boost::asio::ip::tcp::socket>(*strand) : make_shared_object<boost::asio::ip::tcp::socket>(*context);
        }

        VNetstack::TapTcpClient::~TapTcpClient() noexcept {
            Finalize();
        }

        void VNetstack::TapTcpClient::Open(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
            this->localEP_ = localEP;
            this->remoteEP_ = remoteEP;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> VNetstack::TapTcpClient::NewAsynchronousSocket(int sockfd, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
            if (disposed_) {
                return NULL;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
            if (NULL == socket) {
                return NULL;
            }

            if (socket->is_open()) {
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

        void VNetstack::TapTcpClient::Dispose() noexcept {
            std::shared_ptr<TapTcpClient> self = shared_from_this();
            ppp::threading::Executors::ContextPtr context = context_;
            ppp::threading::Executors::StrandPtr strand = strand_;

            auto finalize = 
                [self, this, context, strand]() noexcept {
                    Finalize();
                };

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_; 
            if (NULL != socket) {
                boost::asio::post(socket->get_executor(), finalize);
            }
            else {
                ppp::threading::Executors::Post(context, strand, finalize);
            }
        }

        void VNetstack::TapTcpClient::Finalize() noexcept {
            std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::move(socket_);
            socket_.reset();

            std::shared_ptr<TapTcpLink> link = std::move(link_);
            link_.reset();

            if (!disposed_.exchange(TRUE)) {
                if (lwip_) {
                    lwip::netstack::close(lwip_);
                }
            }

            if (NULL != socket) {
                Socket::Closesocket(socket);
            }

            if (NULL != link) {
                if (lwip_) {
                    link->Release();
                }
                else {
                    link->Closing();
                }
            }
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

            this->sync_ack_byte_array_.reset();
            this->sync_ack_bytes_size_ = 0;
            this->sync_ack_tap_driver_.reset();
            return this->Establish();
        }

        bool VNetstack::TapTcpClient::AckAccept() noexcept {
            if (disposed_) {
                return false;
            }

            std::shared_ptr<Byte> packet = std::move(this->sync_ack_byte_array_);
            this->sync_ack_byte_array_.reset();

            std::shared_ptr<ITap> tap = std::move(this->sync_ack_tap_driver_);
            this->sync_ack_tap_driver_.reset();

            int packet_length = this->sync_ack_bytes_size_;
            if (packet_length < 1) {
                return false;
            }

            if (NULL == tap) {
                return false;
            }

            if (NULL == packet) {
                return false;
            }

            return tap->Output(packet, packet_length);
        }
    }
}
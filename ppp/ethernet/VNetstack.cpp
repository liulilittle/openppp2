#include <ppp/ethernet/VNetstack.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/LinkTelemetry.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/diagnostics/DatapathPerfJson.h>
/**
 * @file VNetstack.cpp
 * @brief Implements virtual TCP NAT mapping, accept bridge, and flow lifecycle.
 */
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/tcp.h>
#include <ppp/net/native/udp.h>
#include <ppp/net/native/icmp.h>
#include <ppp/net/packet/IPFrame.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>
#include <ppp/io/File.h>

#include <ppp/collections/Dictionary.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/coroutines/asio/asio.h>

#include <chrono>
#include <vector>

#include <libtcpip/netstack.h>

#ifdef SYSNAT
#include <linux/ppp/tap/TapLinux.h>
#endif

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
    using ppp::telemetry::Level;
    /**
     * @brief SYN/ACK handshake state values used by TapTcpClient.
     */
    static constexpr Byte VNETSTACK_SYNC_ACK_STATE_CLOSED    = 0;
    static constexpr Byte VNETSTACK_SYNC_ACK_STATE_SYN_SENT  = 1;
    static constexpr Byte VNETSTACK_SYNC_ACK_STATE_SYN_RECVD = 2;

    namespace ethernet {
#ifdef SYSNAT
        /**
         * @brief Returns process-wide lock for SYSNAT driver API calls.
         */
        static VNetstack::SynchronizedObject& openppp2_sysnat_syncobj() noexcept {
            static VNetstack::SynchronizedObject lock_obj;
            return lock_obj;
        }
#endif

        /**
         * @brief Builds LAN-to-WAN flow key from endpoint tuple.
         */
        static Int128 LAN2WAN_KEY(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port) noexcept {
            uint64_t src_ep = MAKE_QWORD(src_ip, src_port);
            uint64_t dst_ep = MAKE_QWORD(dst_ip, dst_port);

            return MAKE_OWORD(dst_ep, src_ep);
        }

        /**
         * @brief Initializes a fresh TCP link record.
         */
        VNetstack::TapTcpLink::TapTcpLink() noexcept {
            this->dstAddr = 0;
            this->dstPort = 0;
            this->srcAddr = 0;
            this->srcPort = 0;
            this->natPort = 0;
            this->lwip = false;
            this->accepting.store(false, std::memory_order_relaxed);
            this->closed.store(false, std::memory_order_relaxed);
            this->state.store((Byte)TcpState::TCP_STATE_CLOSED, std::memory_order_relaxed);
            this->socket = NULLPTR;
            this->lastTime.store(Executors::GetTickCount(), std::memory_order_relaxed);
        }

        /**
         * @brief Releases link resources and resets to closed state.
         */
        void VNetstack::TapTcpLink::Release() noexcept {
            if (this->closed.load(std::memory_order_acquire)) {
                return;
            }

            this->Closing();

            this->state.store((Byte)TcpState::TCP_STATE_CLOSED, std::memory_order_relaxed);
            this->Update();
        }

        /**
         * @brief Closes and disposes the associated TAP TCP client.
         */
        void VNetstack::TapTcpLink::Closing() noexcept {
            if (this->closed.exchange(true, std::memory_order_acq_rel)) {
                return;
            }

            this->state.store((Byte)TcpState::TCP_STATE_CLOSED, std::memory_order_relaxed);

            std::shared_ptr<TapTcpClient> c = std::atomic_exchange(&this->socket, std::shared_ptr<TapTcpClient>());

            if (NULLPTR != c) {
                c->Dispose();
            }
        }

        /**
         * @brief Finds link by NAT-side lookup key.
         */
        std::shared_ptr<VNetstack::TapTcpLink> VNetstack::FindTcpLink(int key) noexcept {
            SynchronizedObjectScope scope(syncobj_);

            auto& map = this->wan2lan_;
            auto tail = map.find(key);
            auto endl = map.end();
            if (tail == endl) {
                return NULLPTR;
            }
            else {
                return tail->second;
            }
        }

        /**
         * @brief Finds link by LAN-to-WAN 4-tuple key.
         */
        std::shared_ptr<VNetstack::TapTcpLink> VNetstack::FindTcpLink(const Int128& key) noexcept {
            SynchronizedObjectScope scope(syncobj_);

            auto& map = this->lan2wan_;
            auto tail = map.find(key);
            auto endl = map.end();
            if (tail == endl) {
                return NULLPTR;
            }
            else {
                return tail->second;
            }
        }

        /**
         * @brief Allocates or returns NAT mapping for a new LAN-originated flow.
         */
        std::shared_ptr<VNetstack::TapTcpLink> VNetstack::AllocTcpLink(UInt32 src_ip, int src_port, UInt32 dst_ip, int dst_port) noexcept {
            auto key = LAN2WAN_KEY(src_ip, src_port, dst_ip, dst_port);
            std::shared_ptr<TapTcpLink> link = this->FindTcpLink(key);
            if (NULLPTR != link) {
                std::shared_ptr<TapTcpClient> socket = std::atomic_load(&link->socket);
                TcpState state = (TcpState)link->state.load(std::memory_order_relaxed);
                bool stale_link = link->closed.load(std::memory_order_acquire) || state == TcpState::TCP_STATE_CLOSED || (NULLPTR != socket && socket->IsDisposed());
                if (!stale_link) {
                    return link;
                }

                ppp::telemetry::Count("vnetstack.native_accept.stale", 1);
                ppp::telemetry::Log(Level::kInfo, "vnetstack", "native accept stale link lan=%s:%u wan=%s:%u state=%u closed=%d", IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->srcAddr, ntohs(link->srcPort)).address().to_string().c_str(), ntohs(link->srcPort), IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->dstAddr, ntohs(link->dstPort)).address().to_string().c_str(), ntohs(link->dstPort), (unsigned int)state, link->closed.load(std::memory_order_relaxed) ? 1 : 0);
                this->CloseTcpLink(link);
                link = NULLPTR;
            }

            std::shared_ptr<TapTcpLink> stale;
            {
                int newPort = 0;
                SynchronizedObjectScope scope(syncobj_);

                /**
                 * @brief TOCTOU guard: re-check for an existing entry inside the lock.
                 *
                 * A concurrent thread may have inserted the same key between the unlocked
                 * FindTcpLink() call above and this lock acquisition.  Without this check,
                 * two threads could both pass the unlocked read (both see no entry), then
                 * both insert — producing duplicate NAT mappings and state corruption for
                 * the same source flow.
                 */
                {
                    auto existing_tail = lan2wan_.find(key);
                    if (existing_tail != lan2wan_.end()) {
                        link = existing_tail->second;
                        if (NULLPTR != link) {
                            std::shared_ptr<TapTcpClient> socket = std::atomic_load(&link->socket);
                            TcpState state = (TcpState)link->state.load(std::memory_order_relaxed);
                            bool closed = link->closed.load(std::memory_order_acquire);
                            bool stale_link = closed || state == TcpState::TCP_STATE_CLOSED || (NULLPTR != socket && socket->IsDisposed());
                            if (stale_link) {
                                ppp::telemetry::Count("vnetstack.native_accept.stale", 1);
                                ppp::telemetry::Log(Level::kInfo, "vnetstack", "native accept stale link lan=%s:%u wan=%s:%u state=%u closed=%d", IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->srcAddr, ntohs(link->srcPort)).address().to_string().c_str(), ntohs(link->srcPort), IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->dstAddr, ntohs(link->dstPort)).address().to_string().c_str(), ntohs(link->dstPort), (unsigned int)state, closed ? 1 : 0);

                                auto tail_wan2lan = wan2lan_.find(Int128(link->natPort));
                                if (tail_wan2lan != wan2lan_.end() && tail_wan2lan->second == link) {
                                    wan2lan_.erase(tail_wan2lan);
                                }

                                lan2wan_.erase(existing_tail);
                                stale = link;
                                link = NULLPTR;
                            }
                        }
                    }
                }

                /**
                 * @brief Port scan: find one free NAT port and allocate the link.
                 *        The outer for-loop that previously wrapped this block always broke
                 *        on its first iteration; it has been removed (L4-5) to eliminate the
                 *        dead O(N²) shell.  The inner scan is preserved as-is.
                 */
                if (NULLPTR == link) {
                    for (int c = 0; c <= IPEndPoint::MaxPort; c++) {
                        int localPort = ++this->ap_;
                        if (localPort <= IPEndPoint::MinPort || localPort > IPEndPoint::MaxPort) {
                            this->ap_ = IPEndPoint::MinPort + 1;
                            localPort = this->ap_;
                        }

                        if (localPort == this->listenEP_.Port) {
                            continue;
                        }

                        auto tail = this->wan2lan_.find(localPort);
                        auto endl = this->wan2lan_.end();
                        if (tail == endl) {
                            newPort = localPort;
                            break;
                        }
                    }

                    if (0 != newPort) {
                        link = make_shared_object<TapTcpLink>();
                        if (NULLPTR != link) {
                            link->dstAddr = dst_ip;
                            link->dstPort = dst_port;
                            link->srcAddr = src_ip;
                            link->srcPort = src_port;
                            link->natPort = newPort;
                            // Native ctcp defers SYN-ACK until VPN peer connect completes; keep
                            // the link in SYN_SENT until AckAccept() emits SYN-ACK.
                            link->state.store((Byte)TcpState::TCP_STATE_SYN_SENT, std::memory_order_relaxed);

                            this->lan2wan_[key]     = link;
                            this->wan2lan_[newPort] = link;
                        }
                    }
                }
            }

            if (NULLPTR != stale) {
                stale->Release();
            }

            if (NULLPTR != link) {
                link->Update();
            }

            return link;
        }

        /**
         * @brief Constructs stack with randomized NAT port cursor.
         */
        VNetstack::VNetstack() noexcept
            : ap_(RandomNext(IPEndPoint::MinPort, IPEndPoint::MaxPort))
            , lwip_(false) {

        }

        /**
         * @brief Destroys stack and releases all runtime resources.
         */
        VNetstack::~VNetstack() noexcept {
            ReleaseAllResources();
        }

#ifdef SYSNAT
        /**
         * @brief Mounts SYSNAT and attaches it to current TAP interface.
         */
        static bool SysnatAttachDriver(const std::shared_ptr<ITap>& tap, ppp::string& interface_name) noexcept {
            ppp::telemetry::SpanScope span("vnetstack.sysnat.attach");
            if (NULLPTR == tap) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
            }

            VNetstack::SynchronizedObjectScope __SCOPE__(openppp2_sysnat_syncobj());
            auto started_at = std::chrono::steady_clock::now();
            if (0 != openppp2_sysnat_mount()) {
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                ppp::telemetry::Histogram("vnetstack.sysnat.attach.us", elapsed);
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
            }

            ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
            if (NULLPTR == linux_tap) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceUnsupported);
            }

            int64_t h = reinterpret_cast<int64_t>(linux_tap->GetHandle());
            if (!linux_tap->GetInterfaceName(static_cast<int>(h), interface_name)) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
            }

            int attach_status = openppp2_sysnat_attach(interface_name.data());
            if (0 != attach_status) {
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                ppp::telemetry::Histogram("vnetstack.sysnat.attach.us", elapsed);
                openppp2_sysnat_publish_error(attach_status);
                return false;
            }

            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
            ppp::telemetry::Histogram("vnetstack.sysnat.attach.us", elapsed);
            return true;
        }
#endif

        /**
         * @brief Opens listener, initializes accept callback, and sets runtime mode.
         */
        bool VNetstack::Open(bool lwip, const int& localPort) noexcept {
            struct ScopedConnectHistogram final {
                std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();

                ~ScopedConnectHistogram() noexcept {
                    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                    ppp::telemetry::Histogram("vnetstack.connect.us", elapsed);
                }
            } connect_histogram;

            int bindPort = localPort;
            if (bindPort < IPEndPoint::MinPort || bindPort > IPEndPoint::MaxPort) {
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "vnetstack", "network port invalid in Open local_port=%d", bindPort);
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
            }

            std::shared_ptr<ITap> tap = this->Tap;
            if (NULLPTR == tap) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
            }

            std::shared_ptr<SocketAcceptor> acceptor = SocketAcceptor::New();
            if (NULLPTR == acceptor) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
            }
            else {
                std::shared_ptr<VNetstack> self = shared_from_this();
                acceptor->AcceptSocket =
                    [self](SocketAcceptor*, SocketAcceptor::AcceptSocketEventArgs& e) noexcept {
                        self->ProcessAcceptSocket(e.Socket);
                    };

                ppp::string bindIP = ppp::net::Ipep::ToAddressString<ppp::string>(boost::asio::ip::address_v4::any());
                if (!acceptor->Open(bindIP.data(), bindPort, PPP_LISTEN_BACKLOG)) {
                    acceptor->Dispose();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketListenFailed);
                }
                else {
                    int handle = acceptor->GetHandle();
                    ppp::net::Socket::AdjustDefaultSocketOptional(handle, false);
                    ppp::net::Socket::SetTypeOfService(handle);
                    ppp::net::Socket::SetSignalPipeline(handle, false);

                    listenEP_ = IPEndPoint::ToEndPoint(Socket::GetLocalEndPoint(acceptor->GetHandle()));
                    bindPort = listenEP_.Port;
                    listenPort_.store(listenEP_.Port, std::memory_order_release);
                }
            }

            lwip_ = lwip;
            acceptor_ = acceptor;

            lwip::netstack::Localhost = bindPort;
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "vnetstack", "open listener lwip=%d requested_port=%d bound_port=%d", lwip ? 1 : 0, localPort, bindPort);
#ifdef SYSNAT
            sysnat_ = SysnatAttachDriver(tap, sysnat_interface_name_);
#endif
            return true;
        }

        boost::asio::ip::tcp::endpoint VNetstack::GetLocalListenerEndpoint() noexcept {
            const int port = listenPort_.load(std::memory_order_acquire);
            if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                return boost::asio::ip::tcp::endpoint();
            }
            return boost::asio::ip::tcp::endpoint(
                boost::asio::ip::address_v4::loopback(), static_cast<uint16_t>(port));
        }

        bool VNetstack::RegisterExternalClient(uint16_t source_port,
            uint64_t runtime_generation, uint64_t flow_generation,
            const std::shared_ptr<TapTcpClient>& client) noexcept {
            if (source_port <= IPEndPoint::MinPort || runtime_generation == 0 ||
                flow_generation == 0 || NULLPTR == client || client->IsDisposed()) {
                return false;
            }
            SynchronizedObjectScope scope(syncobj_);
            if (NULLPTR == acceptor_ || external_clients_.find(source_port) != external_clients_.end()) {
                return false;
            }
            client->external_ = true;
            ExternalClient entry;
            entry.runtime_generation = runtime_generation;
            entry.flow_generation = flow_generation;
            entry.client = client;
            return external_clients_.emplace(source_port, std::move(entry)).second;
        }

        bool VNetstack::CompleteExternalAcceptWithFd(uint16_t source_port,
            uint64_t runtime_generation, int fd,
            const boost::asio::ip::tcp::endpoint& natEP) noexcept {
            if (fd < 0) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceOpenFailed);
            }
            const auto close_unadopted_fd = [fd]() noexcept {
                Socket::Closesocket(fd);
            };
            std::shared_ptr<TapTcpClient> pcb;
            bool registered = false;
            {
                SynchronizedObjectScope scope(syncobj_);
                const auto found = external_clients_.find(source_port);
                if (found != external_clients_.end() &&
                    found->second.runtime_generation == runtime_generation) {
                    pcb = std::move(found->second.client);
                    external_clients_.erase(found);
                    registered = true;
                }
            }
            if (!registered) {
                close_unadopted_fd();
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceOpenFailed);
            }
            if (NULLPTR == pcb || pcb->IsDisposed()) {
                close_unadopted_fd();
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceOpenFailed);
            }
            std::shared_ptr<boost::asio::ip::tcp::socket> socket = pcb->NewAsynchronousSocket(fd, natEP);
            if (NULLPTR == socket) {
                close_unadopted_fd();
                pcb->Dispose();
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceOpenFailed);
            }
            bool ok = pcb->EndAccept(socket, natEP);
            if (ok) {
                ok = pcb->BeginAccept();
            }
            if (!ok) {
                ppp::telemetry::Count("vnetstack.accept.fail.end_accept", 1);
                pcb->Dispose();
                return false;
            }
            ppp::telemetry::Count("vnetstack.accept.external_fd", 1);
            return true;
        }

        void VNetstack::CancelExternalClient(uint16_t source_port,
            uint64_t runtime_generation) noexcept {
            std::shared_ptr<TapTcpClient> client;
            {
                SynchronizedObjectScope scope(syncobj_);
                const auto found = external_clients_.find(source_port);
                if (found == external_clients_.end() ||
                    found->second.runtime_generation != runtime_generation) {
                    return;
                }
                client = std::move(found->second.client);
                external_clients_.erase(found);
            }
            if (NULLPTR != client) {
                client->Dispose();
            }
        }

        /**
         * @brief Public release entry that frees all resources.
         */
        void VNetstack::Release() noexcept {
            ReleaseAllResources();
        }

        /**
         * @brief Releases acceptor, flow tables, and SYSNAT binding state.
         */
        void VNetstack::ReleaseAllResources() noexcept {
            std::shared_ptr<SocketAcceptor> acceptor;
            WAN2LANTABLE wan2lan;
            LAN2WANTABLE lan2wan;
            ExternalClientTable external_clients;

            for (;;) {
                SynchronizedObjectScope scope(syncobj_);
                acceptor = std::move(acceptor_);

                wan2lan = std::move(wan2lan_);
                wan2lan_.clear();

                lan2wan = std::move(lan2wan_);
                lan2wan_.clear();

                external_clients = std::move(external_clients_);
                external_clients_.clear();

                // Reset these fields INSIDE the lock so that concurrent SSMT Input() threads
                // that read listenPort_ (lock-free) observe the cleared value only after the
                // tables are already empty — preventing a window where a packet arrives after
                // the tables are cleared but before listenPort_ reads return MinPort.
                listenPort_.store(IPEndPoint::MinPort, std::memory_order_release);
                listenEP_ = IPEndPoint();
                lwip_     = false;
                ap_       = RandomNext(IPEndPoint::MinPort, IPEndPoint::MaxPort);
                break;
            }

            if (NULLPTR != acceptor) {
                acceptor->Dispose();
            }

            Dictionary::ReleaseAllObjects(wan2lan);
            Dictionary::ReleaseAllObjects(lan2wan);
            for (auto& entry : external_clients) {
                if (NULLPTR != entry.second.client) {
                    entry.second.client->Dispose();
                }
            }
            external_clients.clear();

#ifdef SYSNAT
            if (!sysnat_interface_name_.empty()) {
                VNetstack::SynchronizedObjectScope __SCOPE__(openppp2_sysnat_syncobj());

                int detach_status = openppp2_sysnat_detach(sysnat_interface_name_.data());
                if (0 != detach_status && ERR_NOT_ATTACHED != detach_status) {
                    openppp2_sysnat_publish_error(detach_status);
                }
                sysnat_interface_name_.clear();
            }
#endif
        }

        /**
         * @brief Processes one TCP packet through NAT mapping and state machine.
         */
        bool VNetstack::Input(ip_hdr* ip, tcp_hdr* tcp, int tcp_len) noexcept {
            // Lab-only JSONL: TCP segment call/byte count and whole-function time.
            ppp::diagnostics::datapath_perf::VnetInputScope perf_scope(tcp_len);
            if (NULLPTR == ip || NULLPTR == tcp || tcp_len < 1) {
                ppp::telemetry::Log(Level::kInfo, "vnetstack", "null packet input");
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VNetstackNullPacketInput);
            }

            std::shared_ptr<ITap> tap = this->Tap;
            if (NULLPTR == tap) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
            }

            ppp::telemetry::Count("vnetstack.input", 1);
            TcpFlags flags = (TcpFlags)tcp_hdr::TCPH_FLAGS(tcp);
            UInt32 original_src_addr = ip->src;
            UInt32 original_dst_addr = ip->dest;
            UInt16 original_src_port = tcp->src;
            UInt16 original_dst_port = tcp->dest;
            bool syn_only = (flags & TcpFlags::TCP_SYN) && !(flags & TcpFlags::TCP_ACK);
            if (syn_only) {
                ppp::telemetry::Log(Level::kDebug, "vnetstack", "TCP SYN input src=%s:%u dst=%s:%u len=%d",
                    IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(original_src_addr, ntohs(original_src_port)).address().to_string().c_str(),
                    ntohs(original_src_port),
                    IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(original_dst_addr, ntohs(original_dst_port)).address().to_string().c_str(),
                    ntohs(original_dst_port),
                    tcp_len);
            }
            bool lan2wan = true;
            bool rst = true;
            std::shared_ptr<TapTcpLink> link;
            std::shared_ptr<TapTcpClient> c;

            /**
             * @brief Packet direction handling.
             * - Gateway destination packets are NAT return traffic (V->Local).
             * - Non-SYN packets from LAN reuse existing mapping (Local->V).
             * - SYN packets allocate mapping and start accept path.
             */
            if (ip->dest == tap->GatewayServer) { // V->Local
                if ((link = this->FindTcpLink(ntohs(tcp->dest)))) {
                    link->Update();
                    lan2wan = false;
                    rst = false;

                    ip->src = link->dstAddr;
                    tcp->src = link->dstPort;
                    ip->dest = link->srcAddr;
                    tcp->dest = link->srcPort;
                }
            }
            elif(!(flags & TcpFlags::TCP_SYN)) { // Local->V
                if ((link = this->FindTcpLink(LAN2WAN_KEY(ip->src, tcp->src, ip->dest, tcp->dest)))) {
                    link->Update();
                    rst = false;

#if defined(_IPHONE) || defined(IPHONE)
                    if (!lwip_) {
                        return this->DeliverNativeLoopback(link, tcp, tcp_len);
                    }
#endif

                    ip->src = tap->GatewayServer;
                    tcp->src = htons(link->natPort);
                    ip->dest = tap->IPAddress;
                    tcp->dest = htons((UInt16)this->listenPort_.load(std::memory_order_acquire));
                }
            }
            elif((link = this->AllocTcpLink(ip->src, tcp->src, ip->dest, tcp->dest))) { // SYN
                link->clientSeqno = tcp->seqno;
                for (;;) {
                    TcpState ls = (TcpState)link->state.load(std::memory_order_relaxed);
                    if (ls == TcpState::TCP_STATE_CLOSED) {
                        break;
                    }
                    else {
                        c = std::atomic_load(&link->socket);
                        if (NULLPTR != c) {
                            bool disposed = c->IsDisposed();
                            bool pending = ls == TcpState::TCP_STATE_SYN_RECEIVED || ls == TcpState::TCP_STATE_SYN_SENT;
                            if (!disposed && pending) {
                                ppp::telemetry::Count("vnetstack.native_syn.duplicate", 1);
                                link->Update();
                                return true;
                            }

                            if (disposed) {
                                rst = true;
                            }
                            break;
                        }
                    }

                    if (ls != TcpState::TCP_STATE_SYN_RECEIVED && ls != TcpState::TCP_STATE_SYN_SENT) {
                        /**
                         * @brief Keep handshake links pending to allow retransmission retry.
                         */
                        link->Update();
                        return true;
                    }

                    /**
                     * @brief CAS guard: only the SSMT thread that wins this exchange may call
                     *        BeginAcceptClient().  Concurrent SYN retransmissions on other threads
                     *        lose the CAS and defer, preventing duplicate clients for the same flow.
                     */
                    bool expected_accepting = false;
                    if (!link->accepting.compare_exchange_strong(expected_accepting, true, std::memory_order_acq_rel)) {
                        link->Update();
                        return true;
                    }

                    boost::asio::ip::tcp::endpoint localEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(ip->src, ntohs(tcp->src));
                    boost::asio::ip::tcp::endpoint remoteEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(ip->dest, ntohs(tcp->dest));

                    c = this->BeginAcceptClient(localEP, remoteEP);
                    if (NULLPTR == c) {
                        ppp::telemetry::Count("vnetstack.connect.fail.begin_client", 1);
                        ppp::telemetry::Log(Level::kInfo, "vnetstack", "TCP connect failed: stage=begin_client local=%s:%u remote=%s:%u error=%d", localEP.address().to_string().c_str(), localEP.port(), remoteEP.address().to_string().c_str(), remoteEP.port(), (int)ppp::diagnostics::GetLastErrorCode());
                        /**
                         * @brief Defer failure; reset accepting so the next retransmission may retry.
                         */
                        link->accepting.store(false, std::memory_order_release);
                        link->Update();
                        return true;
                    }
                    ppp::telemetry::Log(Level::kDebug, "vnetstack", "TCP begin client ok local=%s:%u remote=%s:%u nat=%u listen=%u",
                        localEP.address().to_string().c_str(),
                        localEP.port(),
                        remoteEP.address().to_string().c_str(),
                        remoteEP.port(),
                        (unsigned int)link->natPort,
                        (unsigned int)listenPort_.load(std::memory_order_acquire));

                    c->sync_ack_state_ = VNETSTACK_SYNC_ACK_STATE_SYN_SENT;
#ifdef SYSNAT
                    for (SynchronizedObjectScope _(c->sysnat_synbobj_);;) {
                        c->listenPort_ = this->listenPort_.load(std::memory_order_acquire);
                        c->sysnat_status_ = this->sysnat_ ? 0 : -1;
                        break;
                    }
#endif

                    c->link_ = link;
                    c->owner_ = shared_from_this();
                    std::atomic_store(&link->socket, c);

                    if (!c->BeginAccept()) {
                        ppp::telemetry::Count("vnetstack.connect.fail.begin_accept", 1);
                        ppp::telemetry::Log(Level::kInfo, "vnetstack", "TCP connect failed: stage=begin_accept local=%s:%u remote=%s:%u error=%d", localEP.address().to_string().c_str(), localEP.port(), remoteEP.address().to_string().c_str(), remoteEP.port(), (int)ppp::diagnostics::GetLastErrorCode());
                        /**
                         * @brief Preserve pending SYN while outbound connect is transiently unavailable.
                         *        Reset accepting so that the next retransmission may retry.
                         */
                        link->accepting.store(false, std::memory_order_release);
                        link->Update();
                        return true;
                    }
                    ppp::telemetry::Log(Level::kDebug, "vnetstack", "TCP begin accept posted local=%s:%u remote=%s:%u", localEP.address().to_string().c_str(), localEP.port(), remoteEP.address().to_string().c_str(), remoteEP.port());

                    ppp::telemetry::Count("vnetstack.connect", 1);
                    ppp::telemetry::Log(Level::kDebug, "vnetstack", "TCP connect begin local=%s:%u remote=%s:%u", localEP.address().to_string().c_str(), localEP.port(), remoteEP.address().to_string().c_str(), remoteEP.port());
                    rst = false;
#if !defined(_IPHONE) && !defined(IPHONE)
                    ip->src = tap->GatewayServer;
                    tcp->src = htons(link->natPort);
                    ip->dest = tap->IPAddress;
                    tcp->dest = htons((UInt16)this->listenPort_.load(std::memory_order_acquire));
#endif
                    break;
                }
            }

            /**
             * @brief If mapping is unresolved, send RST and abort processing.
             */
            if (rst) {
                boost::asio::ip::tcp::endpoint srcEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(ip->src, ntohs(tcp->src));
                boost::asio::ip::tcp::endpoint dstEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(ip->dest, ntohs(tcp->dest));
                ppp::telemetry::Log(Level::kInfo, "vnetstack", "link input error: unresolved mapping src=%s:%u dst=%s:%u flags=0x%02x gateway=%s", srcEP.address().to_string().c_str(), srcEP.port(), dstEP.address().to_string().c_str(), dstEP.port(), (unsigned int)flags, ip->dest == tap->GatewayServer ? "yes" : "no");
                if (!(flags & TcpFlags::TCP_RST)) {
                    this->RST(ip, tcp, tcp_len);
                }
                return false;
            }

            /**
             * @brief Advance simplified TCP state for timeout management.
             */
            if (flags & TcpFlags::TCP_RST) {
                TcpState prev_state = (TcpState)link->state.load(std::memory_order_relaxed);
                link->state.store((Byte)TcpState::TCP_STATE_CLOSED, std::memory_order_relaxed);

                /**
                 * @brief Link telemetry: unexpected RST received on an established connection.
                 *
                 * An RST on an ESTABLISHED connection is an unexpected interruption.
                 * RST on other states (SYN_RECEIVED, etc.) is a normal connection rejection
                 * and does not count as a link fault.
                 *
                 * Also: RST received through the underlying link (when the EC triggers it)
                 * should be recorded as a fault. Other RSTs (e.g., destination unreachable)
                 * are not link faults.
                 */
                if (prev_state == TcpState::TCP_STATE_ESTABLISHED) {
                    ppp::telemetry::Count("vnetstack.unexpected_rst", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "unexpected RST on established connection src=%s:%u dst=%s:%u lan=%s:%u wan=%s:%u flags=0x%02x", IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(ip->src, ntohs(tcp->src)).address().to_string().c_str(), ntohs(tcp->src), IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(ip->dest, ntohs(tcp->dest)).address().to_string().c_str(), ntohs(tcp->dest), IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->srcAddr, ntohs(link->srcPort)).address().to_string().c_str(), ntohs(link->srcPort), IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->dstAddr, ntohs(link->dstPort)).address().to_string().c_str(), ntohs(link->dstPort), (unsigned int)flags);
                }
                else {
                    ppp::telemetry::Count("vnetstack.rst_pre_established", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "RST in non-established state lan=%s:%u wan=%s:%u prev_state=%u flags=0x%02x lwip=%s dir=%s pkt_src=%s:%u pkt_dst=%s:%u", IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->srcAddr, ntohs(link->srcPort)).address().to_string().c_str(), ntohs(link->srcPort), IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->dstAddr, ntohs(link->dstPort)).address().to_string().c_str(), ntohs(link->dstPort), (unsigned int)prev_state, (unsigned int)flags, link->lwip ? "yes" : "no", lan2wan ? "lan2wan" : "wan2lan", IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(original_src_addr, ntohs(original_src_port)).address().to_string().c_str(), ntohs(original_src_port), IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(original_dst_addr, ntohs(original_dst_port)).address().to_string().c_str(), ntohs(original_dst_port));
                }
            }
            elif((flags & TcpFlags::TCP_SYN) && (flags & TcpFlags::TCP_ACK)) {
                if ((TcpState)link->state.load(std::memory_order_relaxed) == TcpState::TCP_STATE_SYN_RECEIVED) {
                    link->state.store((Byte)TcpState::TCP_STATE_ESTABLISHED, std::memory_order_relaxed);
                }
            }
            elif((flags & TcpFlags::TCP_FIN) && (flags & TcpFlags::TCP_ACK)) {
                TcpState ls2 = (TcpState)link->state.load(std::memory_order_relaxed);
                if (ls2 == TcpState::TCP_STATE_ESTABLISHED) {
                    link->state.store((Byte)TcpState::TCP_STATE_CLOSE_WAIT, std::memory_order_relaxed);

                    /**
                     * @brief Link telemetry: clean FIN received on an established connection.
                     *
                     * A FIN+ACK on an ESTABLISHED connection with no error is a graceful close.
                     * Per specification, FIN with 0 bytes is NOT an error.
                     * Record as success (clean close).
                     */
                    ppp::diagnostics::LinkTelemetryGlobal::GetInstance().GetTotal().RecordSuccess();
                    ppp::telemetry::Count("vnetstack.clean_fin", 1);
                    ppp::telemetry::Log(Level::kDebug, "vnetstack", "clean FIN lan=%s:%u wan=%s:%u lwip=%s", IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->srcAddr, ntohs(link->srcPort)).address().to_string().c_str(), ntohs(link->srcPort), IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->dstAddr, ntohs(link->dstPort)).address().to_string().c_str(), ntohs(link->dstPort), link->lwip ? "yes" : "no");
                }
                elif(ls2 == TcpState::TCP_STATE_SYN_SENT || ls2 == TcpState::TCP_STATE_SYN_RECEIVED) {
                    /**
                     * @brief Diagnostic: FIN+ACK before flow ever reached ESTABLISHED.
                     *        Indicates lwIP/NAT or peer prematurely closed before connect-back.
                     */
                    ppp::telemetry::Count("vnetstack.fin_before_established", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "FIN before established lan=%s:%u wan=%s:%u prev_state=%u flags=0x%02x lwip=%s", IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->srcAddr, ntohs(link->srcPort)).address().to_string().c_str(), ntohs(link->srcPort), IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->dstAddr, ntohs(link->dstPort)).address().to_string().c_str(), ntohs(link->dstPort), (unsigned int)ls2, (unsigned int)flags, link->lwip ? "yes" : "no");
                }
                elif(ls2 == TcpState::TCP_STATE_LAST_ACK) {
                    link->state.store((Byte)TcpState::TCP_STATE_CLOSED, std::memory_order_relaxed);
                }
            }
            elif(flags & TcpFlags::TCP_ACK) {
                if ((TcpState)link->state.load(std::memory_order_relaxed) == TcpState::TCP_STATE_CLOSE_WAIT) {
                    link->state.store((Byte)TcpState::TCP_STATE_LAST_ACK, std::memory_order_relaxed);
                }
            }

            bool output = this->Output(lan2wan, ip, tcp, tcp_len, c.get());
            if (syn_only || (flags & TcpFlags::TCP_SYN) || (flags & TcpFlags::TCP_RST)) {
                ppp::telemetry::Log(output ? Level::kDebug : Level::kInfo, "vnetstack", "TCP output result ok=%d dir=%s flags=0x%02x src=%s:%u dst=%s:%u",
                    output ? 1 : 0,
                    lan2wan ? "lan2wan" : "wan2lan",
                    (unsigned int)flags,
                    IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(ip->src, ntohs(tcp->src)).address().to_string().c_str(),
                    ntohs(tcp->src),
                    IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(ip->dest, ntohs(tcp->dest)).address().to_string().c_str(),
                    ntohs(tcp->dest));
            }
            if ((flags & TcpFlags::TCP_RST) && NULLPTR != link && !link->lwip) {
                this->CloseTcpLink(link);
            }

            return output;
        }

        /**
         * @brief Returns connect-phase timeout in milliseconds.
         */
        uint64_t VNetstack::GetMaxConnectTimeout() noexcept {
#if defined(_IPHONE)
            // ctcp child connects may queue for a transmission slot during speed tests.
            return 30000;
#else
            return 10000;
#endif
        }

        /**
         * @brief Returns finalize-phase timeout in milliseconds.
         */
        uint64_t VNetstack::GetMaxFinalizeTimeout() noexcept {
            return 20000;
        }

        /**
         * @brief Returns established idle timeout in milliseconds.
         */
        uint64_t VNetstack::GetMaxEstablishedTimeout() noexcept {
            return 72000;
        }

        /**
         * @brief Performs periodic flow timeout scan and cleanup.
         *
         * The wan2lan_ table is scanned under syncobj_ and stale entries are erased
         * in-place. Link disposal runs after the lock is released.
         */
        bool VNetstack::Update(uint64_t now) noexcept {
            const uint64_t MaxEstablishedTimeout = GetMaxEstablishedTimeout();
            const uint64_t MaxFinalizeTimeout    = GetMaxFinalizeTimeout();
            const uint64_t MaxConnectTimeout     = GetMaxConnectTimeout();

            /**
             * Step 1+2+3 combined: iterate the map under one lock pass,
             * collect stale entries, erase them, then release the lock.
             * This eliminates the O(N) shared_ptr copy that previously blocked
             * FindTcpLink() / ProcessAcceptSocket() on the accept loop thread.
             *
             * Disposal of stale links happens outside the lock.
             */
            ppp::vector<TapTcpLink::Ptr> releases;
            {
                SynchronizedObjectScope scope(syncobj_);
                if (wan2lan_.empty()) {
                    return true;
                }

                std::shared_ptr<TapTcpClient> socket;

                for (auto it = wan2lan_.begin(); it != wan2lan_.end();) {
                    TapTcpLink::Ptr& entry = it->second;
                    TapTcpLink* link = entry.get();
                    if (NULLPTR == link) {
                        it = wan2lan_.erase(it);
                        continue;
                    }

                    UInt64 deltaTime = now - link->lastTime.load(std::memory_order_relaxed);
                    bool should_release = false;

                    if (link->lwip) {
                        socket = std::atomic_load(&link->socket);
                        if (NULLPTR == socket) {
                            TcpState ls0 = (TcpState)link->state.load(std::memory_order_relaxed);
                            bool syn = ls0 == TcpState::TCP_STATE_SYN_SENT || ls0 == TcpState::TCP_STATE_SYN_RECEIVED;
                            if (!syn) {
                                should_release = true;
                            }
                        }
                        elif(socket->IsDisposed()) {
                            should_release = true;
                        }
                        else {
                            uint64_t maxTimeout = (TcpState)link->state.load(std::memory_order_relaxed) == TcpState::TCP_STATE_ESTABLISHED ? MaxEstablishedTimeout : MaxFinalizeTimeout;
                            if (deltaTime >= maxTimeout) {
                                should_release = true;
                            }
                        }

                        if (should_release) {
                            releases.emplace_back(entry);
                            // Erase from lan2wan_ if present.
                            auto key = LAN2WAN_KEY(link->srcAddr, link->srcPort, link->dstAddr, link->dstPort);
                            auto tail_lan2wan = lan2wan_.find(key);
                            if (tail_lan2wan != lan2wan_.end() && tail_lan2wan->second.get() == link) {
                                lan2wan_.erase(tail_lan2wan);
                            }
                            it = wan2lan_.erase(it);
                        } else {
                            ++it;
                        }
                        continue;
                    }
#ifdef SYSNAT
                    else {
                        socket = std::atomic_load(&link->socket);
                        if (NULL != socket) {
                            if (socket->sysnat_status_.load(std::memory_order_acquire) > 0) {
                                ++it;
                                continue;
                            }
                        }
                    }
#endif
                    TcpState lsn = (TcpState)link->state.load(std::memory_order_relaxed);
                    if (lsn == TcpState::TCP_STATE_ESTABLISHED) {
                        socket = std::atomic_load(&link->socket);
                        if (NULLPTR == socket || socket->IsDisposed()) {
                            if (deltaTime >= MaxFinalizeTimeout) {
                                should_release = true;
                            }
                        } else if (deltaTime >= MaxEstablishedTimeout) {
                            should_release = true;
                        }
                    }
                    elif(lsn == TcpState::TCP_STATE_CLOSED) {
                        should_release = true;
                    }
                    elif(lsn > TcpState::TCP_STATE_ESTABLISHED) {
                        if (deltaTime >= MaxFinalizeTimeout) {
                            should_release = true;
                        }
                    }
                    elif(lsn == TcpState::TCP_STATE_SYN_SENT || lsn == TcpState::TCP_STATE_SYN_RECEIVED) {
                        if (deltaTime >= MaxConnectTimeout) {
                            should_release = true;
                        }
                    }

                    if (should_release) {
                        releases.emplace_back(entry);
                        auto key = LAN2WAN_KEY(link->srcAddr, link->srcPort, link->dstAddr, link->dstPort);
                        auto tail_lan2wan = lan2wan_.find(key);
                        if (tail_lan2wan != lan2wan_.end() && tail_lan2wan->second.get() == link) {
                            lan2wan_.erase(tail_lan2wan);
                        }
                        it = wan2lan_.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
            // syncobj_ is released here.

            // Step 4: Dispose stale links outside the lock.
            for (const TapTcpLink::Ptr& i : releases) {
                if (NULLPTR != i) {
                    i->Release();
                }
            }

            return true;
        }

        /**
         * @brief Rewrites packet as TCP RST response and outputs it.
         */
        bool VNetstack::RST(ip_hdr* iphdr, tcp_hdr* tcp, int tcp_len) noexcept {
            uint32_t dstAddr = iphdr->dest;
            uint16_t dstPort = tcp->dest;
            uint32_t srcAddr = iphdr->src;
            uint16_t srcPort = tcp->src;
            uint32_t seqNo   = tcp->seqno;
            uint32_t ackNo   = tcp->ackno;

            uint32_t hdrlen_bytes = tcp_hdr::TCPH_HDRLEN_BYTES(tcp);
            uint32_t tcplen = tcp_len - hdrlen_bytes;
            uint8_t tcp_flags = tcp_hdr::TCPH_FLAGS(tcp);
            if (tcp_flags & (TcpFlags::TCP_FIN | TcpFlags::TCP_SYN)) {
                tcplen++;
            }

            tcp_len                 = tcp_hdr::TCP_HLEN;
            iphdr->src              = dstAddr;
            tcp->src                = dstPort;
            iphdr->dest             = srcAddr;
            tcp->dest               = srcPort;
            tcp->ackno              = seqNo + tcplen;
            tcp->seqno              = ackNo;
            tcp->urgp               = 0;
            tcp->wnd                = 0;
            tcp->hdrlen_rsvd_flags  = 0;

            tcp_hdr::TCPH_HDRLEN_BYTES_SET(tcp, tcp_len);
            tcp_hdr::TCPH_FLAGS_SET(tcp, TcpFlags::TCP_RST);

            int iphdr_len = (char*)tcp - (char*)iphdr;
            iphdr->len = htons(iphdr_len + tcp_len);

            return this->Output(false, iphdr, tcp, tcp_len, NULLPTR);
        }

        /**
         * @brief Recomputes checksums and sends packet to TAP or SYN/ACK cache.
         */
        bool VNetstack::Output(bool lan2wan, ip_hdr* ip, tcp_hdr* tcp, int tcp_len, TapTcpClient* c) noexcept {
            // Lab-only JSONL: whole Output time; direct is TAP output, cached is SYN/ACK retention.
            ppp::diagnostics::datapath_perf::VnetOutputScope perf_scope(NULLPTR == c, tcp_len);
            std::shared_ptr<ITap> tap = this->Tap;
            if (NULLPTR == tap) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
            }

            ppp::telemetry::Count("vnetstack.output", 1);
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
            perf_scope.SetBytes(ippkg_len);
            if (NULLPTR == c) {
                bool ok = tap->Output(ip, ippkg_len);
                if (!ok) {
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "tap output direct bytes=%d ok=%d", ippkg_len, 0);
                }
                return ok;
            }

            std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
            std::shared_ptr<Byte> packet = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, ippkg_len);
            if (NULLPTR == packet) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
            }
            else {
                memcpy(packet.get(), ip, ippkg_len);
            }

            /** @brief Atomic stores prevent a data race with the SYN-ACK retry timer callback running on context_. */
            std::atomic_store(&c->sync_ack_tap_driver_, tap);
            std::atomic_store(&c->sync_ack_byte_array_, packet);
            c->sync_ack_bytes_size_.store(ippkg_len, std::memory_order_release);
            ppp::telemetry::Log(Level::kDebug, "vnetstack", "sync-ack cached bytes=%d", ippkg_len);
            return true;
        }

        /**
         * @brief Removes flow tables entry and closes linked client.
         */
        bool VNetstack::CloseTcpLink(const std::shared_ptr<TapTcpLink>& link) noexcept {
            if (NULLPTR == link) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VNetstackNullLinkInput);
            }

            std::shared_ptr<ITap> tap = this->Tap;
            if (NULLPTR == tap) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
            }
            else {
                SynchronizedObjectScope scope(syncobj_);

                // Use the full Int128 key for lwIP-path links; the lower-16-bit natPort for standard NAT.
                Int128 wan_key = (Int128(0) != link->lwipKey) ? link->lwipKey : Int128(link->natPort);
                auto tail_wan2lan = this->wan2lan_.find(wan_key);
                auto endl_wan2lan = this->wan2lan_.end();
                if (tail_wan2lan != endl_wan2lan && tail_wan2lan->second == link) {
                    this->wan2lan_.erase(tail_wan2lan);
                }

                auto key = LAN2WAN_KEY(link->srcAddr, link->srcPort, link->dstAddr, link->dstPort);
                auto tail_lan2wan = this->lan2wan_.find(key);
                auto endl_lan2wan = this->lan2wan_.end();
                if (tail_lan2wan != endl_lan2wan && tail_lan2wan->second == link) {
                    this->lan2wan_.erase(tail_lan2wan);
                }
            }

            link->Release();
            return true;
        }

        /**
         * @brief Resolves accepted socket to pending flow and finalizes accept.
         */
        bool VNetstack::ProcessAcceptSocket(int sockfd) noexcept {
            ppp::telemetry::Count("vnetstack.accept.entry", 1);
            ppp::telemetry::Log(Level::kDebug, "vnetstack", "accept entry sockfd=%d", sockfd);
            std::shared_ptr<boost::asio::ip::tcp::socket> socket;
            std::shared_ptr<TapTcpLink> link;
            std::shared_ptr<TapTcpClient> pcb;
            std::shared_ptr<ITap> tap;
            bool external = false;

            do {
                tap = this->Tap;
                if (NULLPTR == tap) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
                    ppp::telemetry::Count("vnetstack.accept.fail.tap", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: tap missing");
                    break;
                }

                boost::asio::ip::tcp::endpoint natEP = Socket::GetRemoteEndPoint(sockfd);
                IPEndPoint remoteEP = IPEndPoint::V6ToV4(IPEndPoint::ToEndPoint(natEP));
                const bool loopback = remoteEP.GetAddress() == htonl(IPEndPoint::LoopbackAddress);
                if (loopback && remoteEP.Port > IPEndPoint::MinPort &&
                    remoteEP.Port <= IPEndPoint::MaxPort) {
                    SynchronizedObjectScope scope(syncobj_);
                    const auto registered = external_clients_.find(static_cast<uint16_t>(remoteEP.Port));
                    if (registered != external_clients_.end()) {
                        pcb = std::move(registered->second.client);
                        external_clients_.erase(registered);
                        external = NULLPTR != pcb;
                    }
                }

                if (!external) {
                    if (lwip_) {
                        if (!loopback) {
                            ppp::telemetry::Count("vnetstack.accept.fail.endpoint", 1);
                            ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: lwip endpoint mismatch nat=%s:%u", natEP.address().to_string().c_str(), natEP.port());
                            break;
                        }
                    }
                    elif(remoteEP.GetAddress() != tap->GatewayServer) {
#if defined(_IPHONE) || defined(IPHONE)
                        if (!loopback) {
#endif
                            ppp::telemetry::Count("vnetstack.accept.fail.endpoint", 1);
                            ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: endpoint mismatch nat=%s:%u", natEP.address().to_string().c_str(), natEP.port());
                            break;
#if defined(_IPHONE) || defined(IPHONE)
                        }
#endif
                    }

                    if (remoteEP.Port <= IPEndPoint::MinPort || remoteEP.Port > IPEndPoint::MaxPort) {
                        ppp::telemetry::Count("vnetstack.accept.fail.port", 1);
                        ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: invalid port nat=%s:%u", natEP.address().to_string().c_str(), natEP.port());
                        break;
                    }

                    if (lwip_) {
                        uint32_t srcAddr;
                        uint32_t dstAddr;
                        int srcPort;
                        int dstPort;
                        if (!lwip::netstack::link(remoteEP.Port, srcAddr, srcPort, dstAddr, dstPort)) {
                            ppp::telemetry::Count("vnetstack.accept.fail.lwip_link", 1);
                            ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: lwip link missing nat=%s:%u", natEP.address().to_string().c_str(), natEP.port());
                            break;
                        }
                        link = this->LwIpAcceptLink(srcAddr, dstAddr, srcPort, dstPort);
                    }
                    else {
                        link = this->FindTcpLink(remoteEP.Port);
                    }

                    if (NULLPTR == link) {
                        ppp::telemetry::Count("vnetstack.accept.fail.link", 1);
                        ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: link missing nat=%s:%u", natEP.address().to_string().c_str(), natEP.port());
                        break;
                    }
                    pcb = std::atomic_load(&link->socket);
                }

                if (NULLPTR == pcb) {
                    if (NULLPTR != link && (TcpState)link->state.load(std::memory_order_relaxed) != TcpState::TCP_STATE_CLOSED) {
                        link->state.store((Byte)TcpState::TCP_STATE_CLOSED, std::memory_order_relaxed);
                    }
                    ppp::telemetry::Count("vnetstack.accept.fail.pcb", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: pcb missing nat=%s:%u", natEP.address().to_string().c_str(), natEP.port());
                    break;
                }

                socket = pcb->NewAsynchronousSocket(sockfd, natEP);
                if (NULLPTR == socket) {
                    ppp::telemetry::Count("vnetstack.accept.fail.socket", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: socket wrap failed nat=%s:%u", natEP.address().to_string().c_str(), natEP.port());
                    break;
                }

                bool ok = pcb->EndAccept(socket, natEP);
                if (ok && external) {
                    ok = pcb->BeginAccept();
                }
                if (ok) {
                    ppp::telemetry::Count(external ? "vnetstack.accept.external" : "vnetstack.accept", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "socket accepted external=%d nat=%s:%u local=%s:%u remote=%s:%u", external ? 1 : 0, natEP.address().to_string().c_str(), natEP.port(), pcb->GetLocalEndPoint().address().to_string().c_str(), pcb->GetLocalEndPoint().port(), pcb->GetRemoteEndPoint().address().to_string().c_str(), pcb->GetRemoteEndPoint().port());
                    if (NULLPTR != link) {
                        link->Update();
                    }
                }
                else {
                    ppp::telemetry::Count("vnetstack.accept.fail.end_accept", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: end accept failed external=%d nat=%s:%u local=%s:%u remote=%s:%u error=%d", external ? 1 : 0, natEP.address().to_string().c_str(), natEP.port(), pcb->GetLocalEndPoint().address().to_string().c_str(), pcb->GetLocalEndPoint().port(), pcb->GetRemoteEndPoint().address().to_string().c_str(), pcb->GetRemoteEndPoint().port(), (int)ppp::diagnostics::GetLastErrorCode());
                    if (external) {
                        pcb->Dispose();
                    }
                    else {
                        this->CloseTcpLink(link);
                    }
                }

                return ok;
            } while (false);

            if (NULLPTR == socket) {
                Socket::Closesocket(sockfd);
            }

            return false;
        }

#if defined(_IPHONE) || defined(IPHONE)
        /**
         * @brief Starts the iOS ctcp relay that writes client payload to rinetd remote.
         */
        bool VNetstack::EnsureNativeInject(const std::shared_ptr<TapTcpLink>& link, const std::shared_ptr<boost::asio::io_context>& context) noexcept {
            (void)context;
            if (NULLPTR == link || lwip_ || link->lwip) {
                return false;
            }

            if (link->nativeInjectReady.load(std::memory_order_acquire)) {
                return true;
            }

            bool relay_started = false;
            if (!link->nativeRelayStarted.compare_exchange_strong(relay_started, true, std::memory_order_acq_rel)) {
                return link->nativeInjectReady.load(std::memory_order_acquire);
            }

            std::shared_ptr<TapTcpClient> pcb = std::atomic_load(&link->socket);
            if (NULLPTR == pcb) {
                link->nativeRelayStarted.store(false, std::memory_order_release);
                ppp::telemetry::Log(Level::kInfo, "vnetstack", "native inject relay failed: pcb missing nat=%u", (unsigned int)link->natPort);
                return false;
            }

            if (!pcb->StartNativeRelay()) {
                link->nativeRelayStarted.store(false, std::memory_order_release);
                ppp::telemetry::Log(Level::kInfo, "vnetstack", "native inject relay start failed nat=%u", (unsigned int)link->natPort);
                return false;
            }

            link->nativeInjectReady.store(true, std::memory_order_release);
            ppp::telemetry::Log(Level::kDebug, "vnetstack", "native inject ready nat=%u lan=%s:%u wan=%s:%u",
                (unsigned int)link->natPort,
                IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->srcAddr, ntohs(link->srcPort)).address().to_string().c_str(),
                ntohs(link->srcPort),
                IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->dstAddr, ntohs(link->dstPort)).address().to_string().c_str(),
                ntohs(link->dstPort));
            return true;
        }

        /**
         * @brief Forwards client TCP payload through the iOS native relay path.
         */
        bool VNetstack::DeliverNativeLoopback(const std::shared_ptr<TapTcpLink>& link, tcp_hdr* tcp, int tcp_len) noexcept {
            if (NULLPTR == link || NULLPTR == tcp || tcp_len < 1) {
                return false;
            }

            const uint32_t hdrlen_bytes = tcp_hdr::TCPH_HDRLEN_BYTES(tcp);
            if (tcp_len < (int)hdrlen_bytes) {
                return false;
            }

            const int payload_len = tcp_len - (int)hdrlen_bytes;
            const uint8_t flags = tcp_hdr::TCPH_FLAGS(tcp);

            if (!link->nativeInjectReady.load(std::memory_order_acquire)) {
                std::shared_ptr<TapTcpClient> pcb = std::atomic_load(&link->socket);
                if (NULLPTR != pcb) {
                    std::shared_ptr<boost::asio::io_context> context = pcb->GetContext();
                    this->EnsureNativeInject(link, context);
                }
            }

            if (!link->nativeInjectReady.load(std::memory_order_acquire)) {
                if (payload_len > 0) {
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "native inject not ready payload refused nat=%u flags=0x%02x payload=%d",
                        (unsigned int)link->natPort,
                        (unsigned int)flags,
                        payload_len);
                    return false;
                }
                link->Update();
                return true;
            }

            if (flags & TcpFlags::TCP_ACK) {
                TcpState ls = (TcpState)link->state.load(std::memory_order_relaxed);
                std::shared_ptr<TapTcpClient> established_pcb = std::atomic_load(&link->socket);
                // Only treat client ACK as handshake completion after we have emitted SYN-ACK.
                // Premature ACK handling races with deferred AckAccept() and yields ack accept result=0.
                if (NULLPTR != established_pcb
                    && established_pcb->sync_ack_state_.load(std::memory_order_acquire) >= VNETSTACK_SYNC_ACK_STATE_SYN_RECVD
                    && (ls == TcpState::TCP_STATE_SYN_RECEIVED || ls == TcpState::TCP_STATE_SYN_SENT)) {
                    link->state.store((Byte)TcpState::TCP_STATE_ESTABLISHED, std::memory_order_relaxed);

                    established_pcb->CancelSyncAckRetry();
                    std::atomic_store(&established_pcb->sync_ack_byte_array_, std::shared_ptr<Byte>());
                    established_pcb->sync_ack_bytes_size_.store(0, std::memory_order_release);
                    std::atomic_store(&established_pcb->sync_ack_tap_driver_, std::shared_ptr<ITap>());
                    established_pcb->sync_ack_state_ = VNETSTACK_SYNC_ACK_STATE_CLOSED;

                    ppp::telemetry::Log(Level::kDebug, "vnetstack", "native client ack established nat=%u flags=0x%02x payload=%d",
                        (unsigned int)link->natPort,
                        (unsigned int)flags,
                        payload_len);
                }
            }

#if !defined(_IPHONE) && !defined(IPHONE)
            if (payload_len > 0) {
                ppp::telemetry::Log(Level::kInfo, "vnetstack", "native inject client payload nat=%u flags=0x%02x payload=%d",
                    (unsigned int)link->natPort,
                    (unsigned int)flags,
                    payload_len);
            }
#endif

            std::shared_ptr<TapTcpClient> pcb = std::atomic_load(&link->socket);
            if (NULLPTR == pcb) {
                return false;
            }

            if (!pcb->DeliverNativePayload(tcp, tcp_len)) {
                ppp::telemetry::Log(Level::kInfo, "vnetstack", "native inject write failed nat=%u flags=0x%02x len=%d",
                    (unsigned int)link->natPort,
                    (unsigned int)tcp_hdr::TCPH_FLAGS(tcp),
                    tcp_len);
                return false;
            }

            link->Update();
            return true;
        }

        /**
         * @brief Emits server payload to the TUN client as TCP PSH|ACK segment(s).
         *
         * VPN reads can return multi-kilobyte chunks, but iOS utun rejects writes
         * larger than the tunnel MTU (typically 1400). Split into MSS-sized segments.
         */
        bool VNetstack::EmitNativeToClient(const std::shared_ptr<TapTcpLink>& link, const void* payload, int payload_len) noexcept {
            return EmitNativeToClient(link, payload, payload_len, TcpFlags::TCP_ACK);
        }

        bool VNetstack::EmitNativeToClient(const std::shared_ptr<TapTcpLink>& link, const void* payload, int payload_len, int tcp_flags) noexcept {
            if (NULLPTR == link || payload_len < 0) {
                return false;
            }

            if (NULLPTR == payload && payload_len > 0) {
                return false;
            }

            std::shared_ptr<ITap> tap = this->Tap;
            if (NULLPTR == tap) {
                return false;
            }

#if defined(_IPHONE) || defined(IPHONE)
            static constexpr int kNativeMaxTcpPayload = 1360; // 1400 MTU - IPv4(20) - TCP(20)
#else
            static constexpr int kNativeMaxTcpPayload = ITap::Mtu - ip_hdr::IP_HLEN - tcp_hdr::TCP_HLEN;
#endif

            const uint8_t* bytes = (const uint8_t*)payload;
            int offset = 0;
            bool all_ok = true;

            do {
                const int chunk_len = payload_len == 0
                    ? 0
                    : std::min(payload_len - offset, kNativeMaxTcpPayload);
                const bool final_segment = payload_len == 0 || (offset + chunk_len) >= payload_len;
                const int outlen = ip_hdr::IP_HLEN + tcp_hdr::TCP_HLEN + chunk_len;
                std::shared_ptr<Byte> packet = ppp::make_shared_alloc<Byte>(outlen);
                if (NULLPTR == packet) {
                    return false;
                }

                ip_hdr* iphdr = (ip_hdr*)packet.get();
                iphdr->src    = link->dstAddr;
                iphdr->dest   = link->srcAddr;
                iphdr->ttl    = ip_hdr::IP_DFT_TTL;
                iphdr->proto  = ip_hdr::IP_PROTO_TCP;
                iphdr->v_hl   = 4 << 4 | ip_hdr::IP_HLEN >> 2;
                iphdr->tos    = 0;
                iphdr->len    = htons((uint16_t)outlen);
                iphdr->id     = ntohs(ip_hdr::NewId());
                iphdr->flags  = htons(ip_hdr::IP_DF);
                iphdr->chksum = 0;
                iphdr->chksum = ppp::net::native::inet_chksum(iphdr, ip_hdr::IP_HLEN);
                if (iphdr->chksum == 0) {
                    iphdr->chksum = 0xffff;
                }

                tcp_hdr* tcphdr = (tcp_hdr*)(iphdr + 1);
                tcphdr->src               = link->dstPort;
                tcphdr->dest              = link->srcPort;
                tcphdr->seqno             = link->serverSeqno;
                tcphdr->ackno             = link->clientAckno;
                tcphdr->wnd               = htons(65535);
                tcphdr->urgp              = 0;
                tcphdr->chksum            = 0;
                tcphdr->hdrlen_rsvd_flags = 0;
                tcp_hdr::TCPH_HDRLEN_BYTES_SET(tcphdr, tcp_hdr::TCP_HLEN);

                TcpFlags out_flags = (TcpFlags)(tcp_flags | TcpFlags::TCP_ACK);
                if (chunk_len > 0) {
                    out_flags = (TcpFlags)(out_flags | TcpFlags::TCP_PSH);
                }
                if (!final_segment) {
                    out_flags = (TcpFlags)(out_flags & ~(TcpFlags::TCP_FIN | TcpFlags::TCP_RST));
                }
                tcp_hdr::TCPH_FLAGS_SET(tcphdr, out_flags);

                if (chunk_len > 0) {
                    memcpy((uint8_t*)tcphdr + tcp_hdr::TCP_HLEN, bytes + offset, (size_t)chunk_len);
                }

                tcphdr->chksum = ppp::net::native::inet_chksum_pseudo((unsigned char*)tcphdr,
                    (unsigned int)ip_hdr::IP_PROTO_TCP,
                    (unsigned int)(tcp_hdr::TCP_HLEN + chunk_len),
                    iphdr->src,
                    iphdr->dest);
                if (tcphdr->chksum == 0) {
                    tcphdr->chksum = 0xffff;
                }

                uint32_t seq_delta = (uint32_t)chunk_len;
                if (final_segment && (out_flags & TcpFlags::TCP_FIN)) {
                    seq_delta++;
                    link->state.store((Byte)TcpState::TCP_STATE_FIN_WAIT1, std::memory_order_relaxed);
                }

                uint32_t next_seq = ntohl(link->serverSeqno) + seq_delta;
                link->serverSeqno = htonl(next_seq);
                link->Update();

                bool ok = tap->Output(packet, outlen);
                all_ok = all_ok && ok;
#if defined(_IPHONE) || defined(IPHONE)
                if (!ok) {
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "native inject emit client failed nat=%u payload=%d chunk=%d offset=%d",
                        (unsigned int)link->natPort,
                        payload_len,
                        chunk_len,
                        offset);
                }
                elif (payload_len == 0 && (out_flags & TcpFlags::TCP_FIN)) {
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "native inject remote fin nat=%u seq=%u ackno=%u ok=%d",
                        (unsigned int)link->natPort,
                        (unsigned int)ntohl(link->serverSeqno),
                        (unsigned int)ntohl(link->clientAckno),
                        ok ? 1 : 0);
                }
                elif (payload_len == 0) {
                    ppp::telemetry::Log(Level::kDebug, "vnetstack", "native upload ack nat=%u ackno=%u ok=%d",
                        (unsigned int)link->natPort,
                        (unsigned int)ntohl(link->clientAckno),
                        ok ? 1 : 0);
                }
                elif(payload_len > 0 && offset == 0) {
                    ppp::telemetry::Log(Level::kDebug, "vnetstack", "native inject emit client nat=%u payload=%d chunk=%d ok=%d",
                        (unsigned int)link->natPort,
                        payload_len,
                        chunk_len,
                        ok ? 1 : 0);
                }
#else
                if (payload_len > 0) {
                    ppp::telemetry::Log(ok ? Level::kDebug : Level::kInfo, "vnetstack", "native inject emit client nat=%u payload=%d chunk=%d offset=%d ok=%d",
                        (unsigned int)link->natPort,
                        payload_len,
                        chunk_len,
                        offset,
                        ok ? 1 : 0);
                }
#endif

                if (!ok) {
                    return false;
                }

                offset += chunk_len;
            } while (payload_len > 0 && offset < payload_len);

            return all_ok;
        }
#endif

        /**
         * @brief Handles lwIP accept callback and prepares SYN/ACK packet state.
         */
        int VNetstack::LwIpBeginAccept(boost::asio::ip::tcp::endpoint& dest, boost::asio::ip::tcp::endpoint& src, uint32_t seq, uint32_t ack, uint16_t wnd) noexcept {
            // Guard against non-IPv4 endpoints: lwIP is inherently IPv4-only and
            // to_v4() would throw (or cause std::terminate in a noexcept function)
            // if called on an IPv6 address, e.g. from a dual-stack listener.
            if (!dest.address().is_v4() || !src.address().is_v4()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6AddressInvalid);
                return -1;
            }

            const uint32_t dest_ip = *(uint32_t*)dest.address().to_v4().to_bytes().data();
            const uint32_t src_ip = *(uint32_t*)src.address().to_v4().to_bytes().data();

            const int dest_port = dest.port();
            const int src_port = src.port();

            std::shared_ptr<TapTcpLink> link = this->LwIpAcceptLink(src_ip, dest_ip, src_port, dest_port);
            if (NULLPTR == link) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceOpenFailed);
                return -1;
            }

            std::shared_ptr<TapTcpClient> pcb = std::atomic_load(&link->socket);
            if (NULLPTR == pcb) {
                if ((TcpState)link->state.load(std::memory_order_relaxed) == TcpState::TCP_STATE_SYN_SENT) {
                    boost::asio::ip::tcp::endpoint localEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(src_ip, src_port);
                    boost::asio::ip::tcp::endpoint remoteEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(dest_ip, dest_port);

                    pcb = this->BeginAcceptClient(localEP, remoteEP);
                    if (NULLPTR != pcb) {
                        pcb->lwip_ = link->lwipKey;   // Non-zero key marks this TapTcpClient as lwIP-path.
                        pcb->link_ = link;
                        pcb->owner_ = shared_from_this();
                        std::atomic_store(&pcb->sync_ack_tap_driver_, this->Tap);
                        std::atomic_store(&link->socket, pcb);
                    }
                }

                if (NULLPTR == pcb) {
                    link->Update();
                    return 0;
                }
            }

            Byte sync_ack_state = VNETSTACK_SYNC_ACK_STATE_CLOSED;
            if (pcb->sync_ack_state_.compare_exchange_strong(sync_ack_state, VNETSTACK_SYNC_ACK_STATE_SYN_SENT)) {
                int sync_packet_size = 0;
                link->Update();
                ppp::telemetry::Log(Level::kDebug, "vnetstack", "lwip sync-ack begin");

                pcb->sync_ack_bytes_size_.store(0, std::memory_order_relaxed);
                std::atomic_store(&pcb->sync_ack_tap_driver_, this->Tap);
                std::atomic_store(&pcb->sync_ack_byte_array_, lwip::netstack_wrap_ipv4_tcp_syn_packet(dest, src, wnd, ack, seq, sync_packet_size));

                if (NULLPTR != std::atomic_load(&pcb->sync_ack_byte_array_)) {
                    pcb->sync_ack_bytes_size_.store(sync_packet_size, std::memory_order_release);
                    return 1;
                }
                else {
                    this->CloseTcpLink(link);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return -1;
                }
            }

            return pcb->sync_ack_state_.load() >= VNETSTACK_SYNC_ACK_STATE_SYN_RECVD ? 0 : 1;
        }

        /**
         * @brief Finds or creates lwIP flow link and starts accept workflow.
         */
        std::shared_ptr<VNetstack::TapTcpLink> VNetstack::LwIpAcceptLink(uint32_t srcAddr, uint32_t dstAddr, int srcPort, int dstPort) noexcept {
            ppp::telemetry::SpanScope span("vnetstack.connect");
            Int128 key = LAN2WAN_KEY(srcAddr, srcPort, dstAddr, dstPort);
            std::shared_ptr<TapTcpLink> link;
            std::shared_ptr<TapTcpLink> stale;

            for (SynchronizedObjectScope scope(syncobj_);;) {
                WAN2LANTABLE::iterator tail = this->wan2lan_.find(key);
                WAN2LANTABLE::iterator endl = this->wan2lan_.end();
                if (tail != endl) {
                    std::shared_ptr<TapTcpLink> existing = tail->second;
                    if (NULLPTR != existing) {
                        TcpState state = (TcpState)existing->state.load(std::memory_order_relaxed);
                        std::shared_ptr<TapTcpClient> socket = std::atomic_load(&existing->socket);
                        bool closed = existing->closed.load(std::memory_order_acquire);
                        bool disposed = NULLPTR != socket && socket->IsDisposed();
                        bool reusable = !closed && NULLPTR != socket && !disposed &&
                            (state == TcpState::TCP_STATE_SYN_SENT || state == TcpState::TCP_STATE_SYN_RECEIVED);
                        if (reusable) {
                            ppp::telemetry::Count("vnetstack.lwip_accept.reused", 1);
                            ppp::telemetry::Log(Level::kDebug, "vnetstack", "lwip accept reused link lan=%s:%u wan=%s:%u state=%u closed=%d", IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(existing->srcAddr, ntohs(existing->srcPort)).address().to_string().c_str(), ntohs(existing->srcPort), IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(existing->dstAddr, ntohs(existing->dstPort)).address().to_string().c_str(), ntohs(existing->dstPort), (unsigned int)state, closed ? 1 : 0);
                            return existing;
                        }

                        ppp::telemetry::Count("vnetstack.lwip_accept.stale", 1);
                        ppp::telemetry::Log(Level::kInfo, "vnetstack", "lwip accept replaced stale link lan=%s:%u wan=%s:%u state=%u closed=%d socket=%d disposed=%d", IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(existing->srcAddr, ntohs(existing->srcPort)).address().to_string().c_str(), ntohs(existing->srcPort), IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(existing->dstAddr, ntohs(existing->dstPort)).address().to_string().c_str(), ntohs(existing->dstPort), (unsigned int)state, closed ? 1 : 0, NULLPTR != socket ? 1 : 0, disposed ? 1 : 0);
                        stale = existing;
                    }

                    this->wan2lan_.erase(tail);
                    auto tail_lan2wan = this->lan2wan_.find(key);
                    if (tail_lan2wan != this->lan2wan_.end() && tail_lan2wan->second == existing) {
                        this->lan2wan_.erase(tail_lan2wan);
                    }
                }

                link = make_shared_object<TapTcpLink>();
                if (NULLPTR == link) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return NULLPTR;
                }

                link->dstAddr = dstAddr;
                link->dstPort = ntohs(dstPort);
                link->srcAddr = srcAddr;
                link->srcPort = ntohs(srcPort);
                link->natPort = 0;       // Not used as a real NAT port in the lwIP path.
                link->lwipKey = key;     // Store full Int128 key for wan2lan_ lookup on close.
                link->lwip = true;
                link->closed.store(false, std::memory_order_relaxed);
                link->state.store((Byte)TcpState::TCP_STATE_SYN_SENT, std::memory_order_relaxed);

                this->wan2lan_[key] = link;
                break;
            }

            if (NULLPTR != stale) {
                stale->Release();
            }

            boost::asio::ip::tcp::endpoint localEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(srcAddr, srcPort);
            boost::asio::ip::tcp::endpoint remoteEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(dstAddr, dstPort);

            std::shared_ptr<TapTcpClient> socket = this->BeginAcceptClient(localEP, remoteEP);
            if (NULLPTR == socket) {
                /**
                 * @brief Keep pending SYN link alive for retransmission-driven retry.
                 */
                link->Update();
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceOpenFailed);
                return NULLPTR;
            }

            socket->lwip_ = key;
            socket->link_ = link;
            socket->owner_ = shared_from_this();

#ifdef SYSNAT
            for (SynchronizedObjectScope _(socket->sysnat_synbobj_);;) {
                socket->listenPort_ = this->listenPort_.load(std::memory_order_acquire);
                socket->sysnat_status_ = this->sysnat_ ? 0 : -1;
                break;
            }
#endif

            bool bok = socket->BeginAccept();
            if (!bok) {
                /** @brief Preserve pending SYN until next retransmission window. */
                link->Update();
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceOpenFailed);
                return NULLPTR;
            }

            ppp::telemetry::Count("vnetstack.connect", 1);
            ppp::telemetry::Log(Level::kDebug, "vnetstack", "TCP connect begin");
            std::atomic_store(&link->socket, socket);
            return link;
        }

        /**
         * @brief Creates a TCP client wrapper for one accepted flow.
         */
        VNetstack::TapTcpClient::TapTcpClient(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand) noexcept
            : lwip_(IPEndPoint::MinPort)
            , disposed_(FALSE)
            , context_(context)
            , strand_(strand)
            , sync_ack_state_(VNETSTACK_SYNC_ACK_STATE_CLOSED)
            , sync_ack_bytes_size_(0) {
            ppp::telemetry::Log(Level::kInfo, "vnetstack", "socket created");
            socket_ = strand ?
                make_shared_object<boost::asio::ip::tcp::socket>(*strand) : make_shared_object<boost::asio::ip::tcp::socket>(*context);
        }

        /**
         * @brief Finalizes and releases TCP client state.
         */
        VNetstack::TapTcpClient::~TapTcpClient() noexcept {
            Finalize();
        }

        /**
         * @brief Stores endpoint metadata for this client.
         */
        void VNetstack::TapTcpClient::Open(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
            this->localEP_ = localEP;
            this->remoteEP_ = remoteEP;
        }

        /**
         * @brief Wraps accepted native socket handle into client socket.
         */
        std::shared_ptr<boost::asio::ip::tcp::socket> VNetstack::TapTcpClient::NewAsynchronousSocket(int sockfd, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
            if (disposed_) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                return NULLPTR;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
            if (NULLPTR == socket) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                return NULLPTR;
            }

            if (socket->is_open()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                return NULLPTR;
            }

            boost::system::error_code ec = boost::asio::error::operation_aborted;
            try {
                socket->assign(remoteEP.protocol(), sockfd, ec);
            }
            catch (const std::exception&) {}

            if (ec) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                return NULLPTR;
            }
            else {
                return socket;
            }
        }

        /**
         * @brief Schedules asynchronous finalization on socket executor.
         */
        void VNetstack::TapTcpClient::Dispose() noexcept {
            if (disposed_.exchange(TRUE, std::memory_order_acq_rel) != FALSE) {
                return;
            }

            ppp::telemetry::Log(Level::kInfo, "vnetstack", "socket disposed");
            std::shared_ptr<TapTcpClient> self = shared_from_this();
            ppp::threading::Executors::ContextPtr context = context_;
            ppp::threading::Executors::StrandPtr strand = strand_;

            auto finalize =
                [self, this, context, strand]() noexcept {
                    Finalize();
                };

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
            if (NULLPTR != socket) {
                boost::asio::post(socket->get_executor(), finalize);
            }
            else {
                ppp::threading::Executors::Post(context, strand, finalize);
            }
        }

        /**
         * @brief Resets handshake state, closes socket, and releases link.
         */
        void VNetstack::TapTcpClient::Finalize() noexcept {
            disposed_.store(TRUE, std::memory_order_release);

            this->CancelSyncAckRetry();

            std::atomic_store(&this->sync_ack_byte_array_, std::shared_ptr<Byte>());
            this->sync_ack_bytes_size_.store(0, std::memory_order_release);
            std::atomic_store(&this->sync_ack_tap_driver_, std::shared_ptr<ITap>());
            this->sync_ack_retry_count_ = 0;
            this->sync_ack_state_ = VNETSTACK_SYNC_ACK_STATE_CLOSED;

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::move(socket_);
            std::shared_ptr<TapTcpLink> link = std::move(link_);
            std::shared_ptr<VNetstack> owner = owner_.lock();
            owner_.reset();

            if (NULLPTR != socket) {
                Socket::Closesocket(socket);
            }

            if (NULLPTR != link) {
                bool closed_by_owner = NULLPTR != owner && owner->CloseTcpLink(link);
                if (!closed_by_owner && lwip_) {
                    link->Release();
                }
                elif(!closed_by_owner) {
                    link->Closing();
                }
            }

#ifdef SYSNAT
            {
                SynchronizedObjectScope scope(sysnat_synbobj_);
                int _ = 1;
                if (sysnat_status_.compare_exchange_strong(_, -1)) {
                    SynchronizedObjectScope __SCOPE__(openppp2_sysnat_syncobj());
                    openppp2_sysnat_del_rule(&forward_key_);
                    openppp2_sysnat_del_rule(&backward_key_);
                }
            }

            /**
             * @brief Virtual Update() calls run outside sysnat_synbobj_ to prevent
             *        lock-order inversion: a subclass override of Update() may acquire
             *        its own mutex, and acquiring that mutex while holding sysnat_synbobj_
             *        would create a deadlock if another thread acquires them in reverse order.
             */
            Update();
            if (NULL != link) {
                link->Update();
            }
#endif
        }

        /**
         * @brief Refreshes linked flow activity timestamp.
         */
        bool VNetstack::TapTcpClient::Update() noexcept {
            if (disposed_) {
                return false;
            }

            std::shared_ptr<TapTcpLink> link = link_;
            if (NULLPTR != link) {
                link->Update();
                return true;
            }
            else {
                return false;
            }
        }

#if defined(_IPHONE) || defined(IPHONE)
        /**
         * @brief Updates iOS native relay client sequence tracking from a TUN packet.
         */
        bool VNetstack::TapTcpClient::UpdateNativeClientAck(tcp_hdr* tcp, int tcp_len) noexcept {
            if (NULLPTR == tcp || tcp_len < 1) {
                return false;
            }

            std::shared_ptr<TapTcpLink> link = link_;
            if (NULLPTR == link) {
                return false;
            }

            const uint32_t hdrlen_bytes = tcp_hdr::TCPH_HDRLEN_BYTES(tcp);
            if (tcp_len < (int)hdrlen_bytes) {
                return false;
            }

            const int payload_len = tcp_len - (int)hdrlen_bytes;
            const uint8_t tcp_flags = tcp_hdr::TCPH_FLAGS(tcp);
            uint32_t client_seq = ntohl(tcp->seqno);
            uint32_t client_end = client_seq + (uint32_t)payload_len;
            if (tcp_flags & (TcpFlags::TCP_SYN | TcpFlags::TCP_FIN)) {
                client_end++;
            }

            link->clientAckno = htonl(client_end);
            link->Update();
            return true;
        }

        /**
         * @brief Emits iOS native relay upstream payload back to the TUN client.
         */
        bool VNetstack::TapTcpClient::EmitNativeToClient(const void* payload, int payload_len) noexcept {
            return EmitNativeToClient(payload, payload_len, TcpFlags::TCP_ACK);
        }

        bool VNetstack::TapTcpClient::EmitNativeToClient(const void* payload, int payload_len, int tcp_flags) noexcept {
            std::shared_ptr<TapTcpLink> link = link_;
            std::shared_ptr<VNetstack> owner = owner_.lock();
            if (NULLPTR == link || NULLPTR == owner) {
                return false;
            }

            return owner->EmitNativeToClient(link, payload, payload_len, tcp_flags);
        }
#endif

        /**
         * @brief Binds accepted NAT endpoint and transitions into established flow.
         */
        bool VNetstack::TapTcpClient::EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) noexcept {
            if (NULLPTR == socket) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VNetstackNullSocketInput);
            }

            std::shared_ptr<boost::asio::io_context> context = this->context_;
            if (NULLPTR == context) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
            }

            this->natEP_ = natEP;
            this->socket_ = socket;

            this->CancelSyncAckRetry();

            std::atomic_store(&this->sync_ack_byte_array_, std::shared_ptr<Byte>());
            this->sync_ack_bytes_size_.store(0, std::memory_order_release);
            std::atomic_store(&this->sync_ack_tap_driver_, std::shared_ptr<ITap>());
            this->sync_ack_retry_count_ = 0;
            this->sync_ack_state_ = VNETSTACK_SYNC_ACK_STATE_CLOSED;

            std::shared_ptr<TapTcpLink> link = this->link_;
            if (NULLPTR == link) {
                if (external_) {
                    return true;
                }
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::InternalLogicNullPointer);
            }

            link->state.store((Byte)TcpState::TCP_STATE_ESTABLISHED, std::memory_order_relaxed);
            link->Update();

            return this->Establish();
        }

        namespace {
#if defined(_IPHONE) || defined(IPHONE)
            /**
             * @brief Builds a client-facing SYN/ACK for the native (ctcp) dataplane.
             *
             * The lan2wan rewrite cached during SYN handling targets the VPN listener and
             * must not be written back to the TUN device on iOS/Android.
             */
            std::shared_ptr<Byte> BuildNativeSynAckPacket(
                uint32_t remote_ip,
                uint16_t remote_port,
                uint32_t local_ip,
                uint16_t local_port,
                uint32_t ack_seq,
                uint32_t seq_num,
                int&                                 outlen) noexcept {
                outlen = ip_hdr::IP_HLEN + tcp_hdr::TCP_HLEN;

                std::shared_ptr<Byte> packet = ppp::make_shared_alloc<Byte>(outlen);
                if (NULLPTR == packet) {
                    outlen = 0;
                    return NULLPTR;
                }

                ip_hdr* iphdr = (ip_hdr*)packet.get();
                iphdr->src    = remote_ip;
                iphdr->dest   = local_ip;
                iphdr->ttl    = ip_hdr::IP_DFT_TTL;
                iphdr->proto  = ip_hdr::IP_PROTO_TCP;
                iphdr->v_hl   = 4 << 4 | ip_hdr::IP_HLEN >> 2;
                iphdr->tos    = 0;
                iphdr->len    = htons(outlen);
                iphdr->id     = ntohs(ip_hdr::NewId());
                iphdr->flags  = htons(ip_hdr::IP_DF);
                iphdr->chksum = 0;
                iphdr->chksum = ppp::net::native::inet_chksum(iphdr, ip_hdr::IP_HLEN);
                if (iphdr->chksum == 0) {
                    iphdr->chksum = 0xffff;
                }

                tcp_hdr* tcphdr = (tcp_hdr*)(iphdr + 1);
                tcphdr->src               = remote_port;
                tcphdr->dest              = local_port;
                tcphdr->seqno             = htonl(seq_num);
                tcphdr->ackno             = htonl(ack_seq);
                tcphdr->wnd               = htons(65535);
                tcphdr->urgp              = 0;
                tcphdr->chksum            = 0;
                tcphdr->hdrlen_rsvd_flags = 0;
                tcp_hdr::TCPH_HDRLEN_BYTES_SET(tcphdr, tcp_hdr::TCP_HLEN);
                tcp_hdr::TCPH_FLAGS_SET(tcphdr, TcpFlags::TCP_SYN | TcpFlags::TCP_ACK);
                tcphdr->chksum = ppp::net::native::inet_chksum_pseudo((unsigned char*)tcphdr,
                    (unsigned int)ip_hdr::IP_PROTO_TCP,
                    (unsigned int)tcp_hdr::TCP_HLEN,
                    iphdr->src,
                    iphdr->dest);
                if (tcphdr->chksum == 0) {
                    tcphdr->chksum = 0xffff;
                }

                return packet;
            }
#endif
        }

        /**
         * @brief Sends SYN/ACK once and schedules retransmission when needed.
         */
        bool VNetstack::TapTcpClient::AckAccept() noexcept {
            if (disposed_) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                return false;
            }

            std::shared_ptr<Byte> packet = std::atomic_load(&this->sync_ack_byte_array_);
            std::shared_ptr<ITap> tap    = std::atomic_load(&this->sync_ack_tap_driver_);

            int packet_length = this->sync_ack_bytes_size_.load(std::memory_order_acquire);

            Byte sync_ack_state = this->sync_ack_state_.load(std::memory_order_acquire);
            if (sync_ack_state == VNETSTACK_SYNC_ACK_STATE_SYN_RECVD) {
                ppp::telemetry::Log(Level::kDebug, "vnetstack", "sync-ack already sent");
                return true;
            }

            sync_ack_state = VNETSTACK_SYNC_ACK_STATE_SYN_SENT;
            if (!this->sync_ack_state_.compare_exchange_strong(sync_ack_state, VNETSTACK_SYNC_ACK_STATE_SYN_RECVD)) {
                if (sync_ack_state == VNETSTACK_SYNC_ACK_STATE_SYN_RECVD) {
                    return true;
                }

                ppp::telemetry::Log(Level::kInfo, "vnetstack", "sync-ack invalid state=%u", (unsigned int)sync_ack_state);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VNetstackSyncAckInvalidState);
                return false;
            }

            auto rollback_sync_ack_state = [this]() noexcept {
                this->sync_ack_state_.store(VNETSTACK_SYNC_ACK_STATE_SYN_SENT, std::memory_order_release);
            };

            ppp::telemetry::Log(Level::kDebug, "vnetstack", "sync-ack accepted");
            std::shared_ptr<TapTcpLink> link = this->link_;
            if (NULLPTR != link) {
                link->Update();
            }

            if (NULLPTR == tap) {
                ppp::telemetry::Log(Level::kInfo, "vnetstack", "sync-ack failed: tap missing");
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
                rollback_sync_ack_state();
                return false;
            }

            if (!lwip_) {
                if (NULLPTR == link || link->clientSeqno == 0) {
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "sync-ack failed: native link missing or client seq unset");
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VNetstackSyncAckInvalidState);
                    rollback_sync_ack_state();
                    return false;
                }

#if defined(_IPHONE) || defined(IPHONE)
                std::shared_ptr<VNetstack> owner = this->owner_.lock();
                if (NULLPTR == owner || !owner->EnsureNativeInject(link, this->context_)) {
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "sync-ack failed: native relay not ready nat=%u",
                        (unsigned int)link->natPort);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    rollback_sync_ack_state();
                    return false;
                }

                const uint32_t ack_seq = ntohl(link->clientSeqno) + 1;
                const uint32_t seq_num = static_cast<uint32_t>(ip_hdr::NewId());
                packet = BuildNativeSynAckPacket(
                    link->dstAddr,
                    link->dstPort,
                    link->srcAddr,
                    link->srcPort,
                    ack_seq,
                    seq_num,
                    packet_length);
                if (NULLPTR == packet || packet_length < 1) {
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "sync-ack failed: native packet build failed");
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    rollback_sync_ack_state();
                    return false;
                }

                ppp::telemetry::Log(Level::kDebug, "vnetstack", "native sync-ack built remote=%s:%u local=%s:%u bytes=%d",
                    IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->dstAddr, ntohs(link->dstPort)).address().to_string().c_str(),
                    ntohs(link->dstPort),
                    IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(link->srcAddr, ntohs(link->srcPort)).address().to_string().c_str(),
                    ntohs(link->srcPort),
                    packet_length);
#else
                if (packet_length < 1) {
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "sync-ack invalid: packet_length=%d", packet_length);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VNetstackSyncAckInvalidState);
                    rollback_sync_ack_state();
                    return false;
                }
#endif
            }
            elif(packet_length < 1) {
                ppp::telemetry::Log(Level::kInfo, "vnetstack", "sync-ack invalid: packet_length=%d", packet_length);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VNetstackSyncAckInvalidState);
                rollback_sync_ack_state();
                return false;
            }

            if (lwip_) {
                if (NULLPTR == link) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::InternalLogicNullPointer);
                    rollback_sync_ack_state();
                    return false;
                }

                link->state.store((Byte)TcpState::TCP_STATE_SYN_RECEIVED, std::memory_order_relaxed);
                bool ok = lwip::netstack::input(packet.get(), packet_length);
                ppp::telemetry::Log(Level::kInfo, "vnetstack", "lwip sync input bytes=%d ok=%d", packet_length, ok ? 1 : 0);
                if (!ok) {
                    rollback_sync_ack_state();
                }
                return ok;
            }

            if (NULLPTR == packet) {
                ppp::telemetry::Log(Level::kInfo, "vnetstack", "sync-ack failed: packet missing");
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryBufferNull);
                rollback_sync_ack_state();
                return false;
            }

#ifdef SYSNAT
            for (int _ = 0;;) {
                std::shared_ptr<TapTcpLink> link = this->link_;
                if (NULLPTR == link) {
                    break;
                }

                SynchronizedObjectScope scope(sysnat_synbobj_);
                if (!sysnat_status_.compare_exchange_strong(_, 1)) {
                    break;
                }

                uint32_t inner_src   = link->srcAddr;
                uint16_t inner_sport = link->srcPort;
                uint32_t outer_dst   = link->dstAddr;
                uint16_t outer_dport = link->dstPort;

                uint32_t nat_ip      = tap->GatewayServer;
                uint16_t nat_port    = link->natPort;
                uint32_t local_ip    = tap->IPAddress;
                uint16_t listen_port = htons(listenPort_);

                forward_key_.src_ip   = inner_src;
                forward_key_.src_port = (inner_sport);
                forward_key_.dst_ip   = outer_dst;
                forward_key_.dst_port = (outer_dport);
                forward_key_.proto    = IPPROTO_TCP;

                struct openppp2_sysnat_value forward_val;
                forward_val.new_src_addr     = nat_ip;
                forward_val.new_src_port     = nat_port;
                forward_val.new_dst_addr     = local_ip;
                forward_val.new_dst_port     = listen_port;
                forward_val.redirect_ifindex = 0;

                backward_key_.src_ip   = local_ip;
                backward_key_.src_port = listen_port;
                backward_key_.dst_ip   = nat_ip;
                backward_key_.dst_port = nat_port;
                backward_key_.proto    = IPPROTO_TCP;

                struct openppp2_sysnat_value backward_val;
                backward_val.new_src_addr     = outer_dst;
                backward_val.new_src_port     = outer_dport;
                backward_val.new_dst_addr     = inner_src;
                backward_val.new_dst_port     = inner_sport;
                backward_val.redirect_ifindex = 0;

                SynchronizedObjectScope __SCOPE__(openppp2_sysnat_syncobj());
                int forward_add_status = openppp2_sysnat_add_rule(&forward_key_, &forward_val);
                if (0 == forward_add_status) {
                    int backward_add_status = openppp2_sysnat_add_rule(&backward_key_, &backward_val);
                    if (0 != backward_add_status) {
                        /**
                         * @brief Roll back forward SYSNAT rule when backward install fails.
                         */
                        openppp2_sysnat_del_rule(&forward_key_);

                        _ = 1;
                        sysnat_status_.compare_exchange_strong(_, -1);
                        openppp2_sysnat_publish_error(backward_add_status);
                    }
                }
                else {
                    _ = 1;
                    sysnat_status_.compare_exchange_strong(_, -1);
                    openppp2_sysnat_publish_error(forward_add_status);
                }

                break;
            }
#endif

            std::atomic_store(&this->sync_ack_byte_array_, packet);
            this->sync_ack_bytes_size_.store(packet_length, std::memory_order_release);
            this->sync_ack_retry_count_ = 0;
            this->ScheduleSyncAckRetry(200);

            bool ok = tap->Output(packet, packet_length);
            ppp::telemetry::Log(ok ? Level::kDebug : Level::kInfo, "vnetstack", "sync-ack write bytes=%d ok=%d", packet_length, ok ? 1 : 0);

            if (ok && !lwip_) {
                std::shared_ptr<TapTcpLink> inject_link = this->link_;
                if (NULLPTR != inject_link && NULLPTR != packet) {
                    const ip_hdr* iphdr = (const ip_hdr*)packet.get();
                    const tcp_hdr* tcphdr = (const tcp_hdr*)(iphdr + 1);
                    inject_link->state.store((Byte)TcpState::TCP_STATE_SYN_RECEIVED, std::memory_order_relaxed);
                    inject_link->serverSeqno = htonl(ntohl(tcphdr->seqno) + 1);
                    inject_link->clientAckno = tcphdr->ackno;
                    inject_link->Update();
                }

#if defined(_IPHONE) || defined(IPHONE)
                std::shared_ptr<VNetstack> owner = this->owner_.lock();
                if (NULLPTR != inject_link && NULLPTR != owner) {
                    owner->EnsureNativeInject(inject_link, this->context_);
                }
#endif
            }

            if (!ok) {
                // Retry timer will retransmit; returning true avoids tearing down the flow.
                return true;
            }

            return ok;
        }

        /**
         * @brief Cancels pending SYN/ACK retry timer if present.
         *
         * The cancel is serialized through the same strand that owns the socket and the
         * retry timer, so it can never run concurrently with the timer handler; the
         * retry counter is reset inside that serial domain as well.
         */
        void VNetstack::TapTcpClient::CancelSyncAckRetry() noexcept {
            ppp::threading::Executors::StrandPtr strand = this->strand_;
            std::shared_ptr<TapTcpClient> self = weak_from_this().lock();
            if (NULLPTR == strand || NULLPTR == self) {
                /**
                 * @brief Without a strand there is no second serial domain to marshal to.
                 *        A null self means the object is being destroyed; a pending
                 *        async_wait always holds a reference, so no handler can be in
                 *        flight concurrently here.
                 */
                std::shared_ptr<boost::asio::steady_timer> timer = std::move(this->sync_ack_retry_timer_);
                if (NULLPTR != timer) {
                    timer->cancel();
                }

                this->sync_ack_retry_count_ = 0;
                return;
            }

            boost::asio::post(*strand,
                [self]() noexcept {
                    std::shared_ptr<boost::asio::steady_timer> timer = std::move(self->sync_ack_retry_timer_);
                    if (NULLPTR != timer) {
                        timer->cancel();
                    }

                    self->sync_ack_retry_count_ = 0;
                });
        }

        /**
         * @brief Arms SYN/ACK retransmission timer with exponential-like schedule.
         *
         * The timer is created on (and the arming is posted to) the same strand executor
         * that owns the socket, so the wait handler, sync_ack_retry_timer_ and
         * sync_ack_retry_count_ are only ever touched inside that serial domain.
         */
        void VNetstack::TapTcpClient::ScheduleSyncAckRetry(uint64_t delay_ms) noexcept {
            if (disposed_ || delay_ms == 0) {
                return;
            }

            std::shared_ptr<boost::asio::io_context> context = this->context_;
            if (NULLPTR == context) {
                return;
            }

            std::shared_ptr<TapTcpClient> self = shared_from_this();
            ppp::threading::Executors::StrandPtr strand = this->strand_;

            auto do_schedule =
                [self, strand, context, delay_ms]() noexcept {
                    if (self->disposed_) {
                        return;
                    }

                    std::shared_ptr<boost::asio::steady_timer> timer = self->sync_ack_retry_timer_;
                    if (NULLPTR == timer) {
                        timer = strand ? make_shared_object<boost::asio::steady_timer>(*strand)
                                       : make_shared_object<boost::asio::steady_timer>(*context);
                        self->sync_ack_retry_timer_ = timer;
                    }

                    if (NULLPTR == timer) {
                        return;
                    }

                    timer->expires_after(std::chrono::milliseconds(delay_ms));
                    timer->async_wait([self](const boost::system::error_code& ec) noexcept {
                        if (ec || self->disposed_) {
                            return;
                        }

                        std::shared_ptr<Byte> packet = std::atomic_load(&self->sync_ack_byte_array_);
                        std::shared_ptr<ITap> tap    = std::atomic_load(&self->sync_ack_tap_driver_);
                        int packet_length            = self->sync_ack_bytes_size_.load(std::memory_order_acquire);
                        if (NULLPTR == packet || NULLPTR == tap || packet_length < 1) {
                            return;
                        }

                        if (self->sync_ack_state_.load() != VNETSTACK_SYNC_ACK_STATE_SYN_RECVD) {
                            return;
                        }

                        /**
                         * @brief Retry delays in milliseconds for SYN/ACK retransmission.
                         */
                        static constexpr uint64_t retry_delays[] = {200, 400, 800, 1200, 1600};

                        int retry_index = self->sync_ack_retry_count_;
                        if (retry_index < 0 || retry_index >= static_cast<int>(arraysizeof(retry_delays))) {
                            return;
                        }

                        bool ok = tap->Output(packet, packet_length);
                        self->sync_ack_retry_count_ = retry_index + 1;

                        if (self->sync_ack_retry_count_ < static_cast<int>(arraysizeof(retry_delays))) {
                            self->ScheduleSyncAckRetry(retry_delays[self->sync_ack_retry_count_]);
                        }

                    });
                };

            if (NULLPTR != strand) {
                boost::asio::post(*strand, std::move(do_schedule));
            }
            else {
                boost::asio::post(*context, std::move(do_schedule));
            }
        }
    }
}

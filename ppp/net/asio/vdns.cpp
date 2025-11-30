#include <ppp/stdafx.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/collections/LinkedList.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/Timer.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/ip.h>

#include <common/dnslib/message.h>

namespace ppp {
    namespace net {
        namespace asio {
            namespace vdns {
                static constexpr int                                                            PPP_MAX_HOSTNAME_SIZE_LIMIT = 64;
                static constexpr int                                                            PPP_IP_DNS_MERGE_WAIT       = 100;
                // Linux  : systemd-resolved set 50ms               
                // glibc  : getaddrinfo set 500ms               
                // MacOS  : 50 ~ 100ms              
                // Windows: 100 ~ 300ms             

                typedef ppp::collections::Dictionary                                            Dictionary;
                typedef std::mutex                                                              SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                                     SynchronizedObjectScope;
                typedef ppp::function<void(bool,                                    
                        ppp::unordered_set<                                 
                            boost::asio::ip::address>&)>                                        DNSRequestAsynchronousCallback;
                typedef ppp::net::Socket                                                        Socket;
                typedef ppp::threading::Timer                                                   Timer;
                typedef ppp::threading::Executors                                               Executors;

                struct DNS_RequestContext final {                                   
                    boost::asio::ip::udp::endpoint                                              source;
                    boost::asio::io_context&                                                    executor;
                    std::shared_ptr<boost::asio::ip::udp::socket>                               socket;
                    boost::asio::deadline_timer                                                 timeout;
                    std::shared_ptr<boost::asio::deadline_timer>                                merge_wait;

                    struct {
                        bool                                                                    in4 = false;
                        bool                                                                    in6 = false;

                        uint16_t                                                                in4_id = 0;
                        uint16_t                                                                in6_id = 0;
                    };

                    ppp::unordered_set<boost::asio::ip::address>                                addresses;
                    DNSRequestAsynchronousCallback                                              cb;
                    ppp::string                                                                 hostname;

                    Byte                                                                        packet[PPP_MAX_DNS_PACKET_BUFFER_SIZE];

                    DNS_RequestContext(boost::asio::io_context& context) noexcept
                        : executor(context)
                        , timeout(context)
                        , in4(false)
                        , in6(false)
                        , in4_id(0)
                        , in6_id(0) {
                        socket = make_shared_object<boost::asio::ip::udp::socket>(context);
                    }
                    ~DNS_RequestContext() noexcept;
                    
                    bool                                                                        Cache() noexcept;
                    void                                                                        Event(bool timeout) noexcept;

                    static bool                                                                 ReceiveFrom(std::shared_ptr<DNS_RequestContext> request_context) noexcept;
                };              

                IPEndPointVectorPtr                                                             servers;
                bool                                                                            enabled = false;
                int                                                                             ttl     = PPP_DEFAULT_DNS_TTL;

                struct NamespaceRecord {
                    struct {
                        bool                                                                    ipv6 : 1;
                        bool                                                                    ipv4 : 7;
                    };

                    uint64_t                                                                    expired_time = 0; 
                    SynchronizedObject                                                          lockobj;
                    ppp::string                                                                 hostname;
                    ppp::unordered_set<boost::asio::ip::address>                                addresses;

                    NamespaceRecord() noexcept 
                        : ipv6(false)
                        , ipv4(false)
                        , expired_time(0) {

                    }

                    bool                                                                        Emplace(const boost::asio::ip::address& ip) noexcept;
                };
                typedef ppp::collections::LinkedListNode<NamespaceRecord>                       NamespaceRecordNode;
                typedef std::shared_ptr<NamespaceRecordNode>                                    NamespaceRecordNodePtr;

                struct internal final {
                    SynchronizedObject                                                          lockobj;
                    std::atomic<uint16_t>                                                       identification = RandomNext(1, UINT16_MAX);
                    ppp::unordered_map<ppp::string, NamespaceRecordNodePtr>                     nr_hmap;
                    ppp::collections::LinkedList<NamespaceRecord>                               nr_list;

                    static internal& c() noexcept {
                        static internal i;
                        return i;
                    }
                };

                void vdns_ctor() noexcept {
                    boost::system::error_code ec;
                    vdns::ttl = PPP_DEFAULT_DNS_TTL;

                    auto dns_servers = make_shared_object<IPEndPointVector>();
                    vdns::servers = dns_servers;

                    dns_servers->emplace_back(boost::asio::ip::udp::endpoint(StringToAddress(PPP_PREFERRED_DNS_SERVER_1, ec), PPP_DNS_SYS_PORT));
                    dns_servers->emplace_back(boost::asio::ip::udp::endpoint(StringToAddress(PPP_PREFERRED_DNS_SERVER_2, ec), PPP_DNS_SYS_PORT));
                }
                        
                static bool                                                                     DNS_SendToARequestAsync(boost::asio::io_context& context, const ppp::string& hostname, int timeout, const ppp::vector<boost::asio::ip::udp::endpoint>& destinations, const DNSRequestAsynchronousCallback& cb) noexcept {
                    if (hostname.empty()) {
                        return false;
                    }

                    std::shared_ptr<DNS_RequestContext> request_context = make_shared_object<DNS_RequestContext>(context);
                    if (NULL == request_context) {
                        return false;
                    }

                    std::shared_ptr<boost::asio::ip::udp::socket> socket = request_context->socket;
                    if (NULL == socket) {
                        return false;
                    }

                    boost::system::error_code ec;
                    socket->open(boost::asio::ip::udp::v6(), ec);
                    if (ec) {
                        return false;
                    }
                    
                    int handle = socket->native_handle();
                    request_context->cb = cb;
                    request_context->hostname = hostname;
                    
                    Socket::AdjustDefaultSocketOptional(handle, true);
                    Socket::SetTypeOfService(handle);
                    Socket::SetSignalPipeline(handle, false);
                    Socket::ReuseSocketAddress(handle, true);

                    struct {
                        uint16_t* id;
                        bool* in;
                        ::dns::RecordType rt;
                    } srs[2] = {{&request_context->in4_id, &request_context->in4, ::dns::RecordType::kA}, {&request_context->in6_id, &request_context->in6, ::dns::RecordType::kAAAA}};

                    bool any = false;
                    internal& c = internal::c();

                    for (int i = 0, j = -1; i < arraysizeof(srs); i++, j++) {
                        auto& sr = srs[i];
                        while ((*sr.id = ++c.identification) == 0 || (i > 0 && *sr.id == *srs[j].id));

                        ::dns::Message m;
                        m.mRD = 1;
                        m.mId = *sr.id;
                        m.questions.emplace_back(::dns::QuestionSection(hostname.data(), sr.rt, ::dns::RecordClass::kIN));
                        
                        size_t messages_size = 0;
                        if (m.encode(request_context->packet, PPP_MAX_DNS_PACKET_BUFFER_SIZE, messages_size) != ::dns::BufferResult::NoError) {
                            continue;
                        }

                        for (const boost::asio::ip::udp::endpoint& ep : destinations) {
                            socket->send_to(
                                boost::asio::buffer(request_context->packet, messages_size), 
                                ppp::net::Ipep::V4ToV6(ep), 
                                boost::asio::ip::udp::socket::message_end_of_record, ec);
                            if (ec == boost::system::errc::success) {
                                any = true;
                            }
                        }
                    }

                    if (!any) {
                        return false;
                    }

                    if (timeout < 1) {
                        timeout = PPP_RESOLVE_DNS_TIMEOUT;
                    }
                    
                    std::weak_ptr<DNS_RequestContext> rc_weak_ptr = request_context;
                    request_context->timeout.expires_from_now(Timer::DurationTime(timeout));
                    request_context->timeout.async_wait(
                        [rc_weak_ptr](const boost::system::error_code& ec) noexcept {
                            if (ec == boost::system::errc::operation_canceled) {
                                return;
                            }

                            std::shared_ptr<DNS_RequestContext> request_context = rc_weak_ptr.lock();
                            if (NULL != request_context) {
                                request_context->Event(true);
                            }
                        });

                    return DNS_RequestContext::ReceiveFrom(request_context);
                }

                static bool                                                                     DNS_ProcessAResponseAddresses(Byte* packet, int packet_size, ppp::unordered_set<boost::asio::ip::address>& addresses, uint16_t& ack, ppp::string* hostname_string = NULL, bool* ipv4_or_ipv6 = NULL) noexcept {
                    using IPEndPoint = ppp::net::IPEndPoint;
                    using AddressFamily = ppp::net::AddressFamily;

                    ack = 0;
                    if (NULL == packet || packet_size < 1) {
                        return false;
                    }

                    ::dns::Message m;
                    if (m.decode(packet, packet_size) != ::dns::BufferResult::NoError) {
                        return false;
                    }

                    ::dns::QuestionSection* qs = NULL;
                    if (NULL != hostname_string && !m.questions.empty()) {
                        qs = m.questions.data();
                        
                        if (IsReverseQuery(qs->mName.data())) {
                            return false;
                        }
                    }

                    for (::dns::ResourceRecord& rr : m.answers) {
                        if (rr.mClass != ::dns::RecordClass::kIN) {
                            continue;
                        }

                        IPEndPoint ep;
                        if (rr.mType == ::dns::RecordType::kA) {
                            auto in = rr.getRData<::dns::RDataA>();
                            if (NULL != in) {
                                ep = IPEndPoint(AddressFamily::InterNetwork, in->getAddress(), 4, IPEndPoint::MinPort);
                                addresses.emplace(IPEndPoint::ToEndPoint<boost::asio::ip::udp>(ep).address());
                            }
                        }
                        elif(rr.mType == ::dns::RecordType::kAAAA) {
                            auto in = rr.getRData<::dns::RDataAAAA>();
                            if (NULL != in) {
                                ep = IPEndPoint(AddressFamily::InterNetworkV6, in->getAddress(), 16, IPEndPoint::MinPort);
                                addresses.emplace(IPEndPoint::ToEndPoint<boost::asio::ip::udp>(ep).address());
                            }
                        }
                    }

                    if (NULL != hostname_string && !m.questions.empty()) {
                        if (NULL != ipv4_or_ipv6) {
                            *ipv4_or_ipv6 = qs->mType == ::dns::RecordType::kA;
                        }

                        *hostname_string = qs->mName;
                    }
                    
                    ack = m.mId;
                    return true;
                }

                DNS_RequestContext::~DNS_RequestContext() noexcept {
                    DNS_RequestContext* const rc = this;
                    rc->Event(true);
                }

                void DNS_RequestContext::Event(bool timeout) noexcept {
                    DNS_RequestContext* const rc = this;
                    DNSRequestAsynchronousCallback f = std::move(rc->cb);
                    if (f) {
                        rc->cb.reset();
                        f(rc->in4 || rc->in6, addresses);
                    }

                    if (timeout || (rc->in4 && rc->in6)) {
                        std::shared_ptr<boost::asio::deadline_timer> t = std::move(rc->merge_wait); 
                        if (NULL != t) {
                            rc->merge_wait.reset();
                            Socket::Cancel(*t);
                        }
                        
                        std::shared_ptr<boost::asio::ip::udp::socket> socket = std::move(rc->socket);
                        if (NULL != socket) {
                            rc->socket.reset();
                            Socket::Closesocket(socket);
                        }

                        Socket::Cancel(rc->timeout);
                    }

                    rc->Cache();
                }

                bool DNS_RequestContext::Cache() noexcept {
                    DNS_RequestContext* const rc = this;
                    if (!rc->in4 && !rc->in6) {
                        return false;
                    }

                    if (IsReverseQuery(rc->hostname.data())) {
                        return false;
                    }

                    int TTL = vdns::ttl;
                    if (TTL < 1) {
                        TTL = PPP_DEFAULT_DNS_TTL;
                    }

                    internal& c = internal::c();
                    TTL *= 1000;

                    NamespaceRecordNodePtr node;
                    for (SynchronizedObjectScope syncobj(c.lockobj);;) {
                        if (Dictionary::TryRemove(c.nr_hmap, rc->hostname, node)) {
                            NamespaceRecord& nr = node->Value;
                            c.nr_list.Remove(node);

                            for (const boost::asio::ip::address& ip : nr.addresses) {
                                rc->addresses.emplace(ip);
                            }
                        }

                        node = make_shared_object<NamespaceRecordNode>();
                        if (NULL == node) {
                            return false;
                        }

                        NamespaceRecord& record = node->Value;
                        record.hostname         = rc->hostname;
                        record.addresses        = rc->addresses;
                        record.expired_time     = Executors::GetTickCount() + TTL;
                        record.ipv4             = in4;
                        record.ipv6             = in6;

                        if (!Dictionary::TryAdd(c.nr_hmap, rc->hostname, node)) {
                            return false;
                        }

                        if (c.nr_list.AddLast(node)) {
                            break;
                        }

                        Dictionary::TryRemove(c.nr_hmap, rc->hostname, node);
                        return false;
                    }

                    return true;
                }

                bool DNS_RequestContext::ReceiveFrom(std::shared_ptr<DNS_RequestContext> request_context) noexcept {
                    std::shared_ptr<boost::asio::ip::udp::socket> socket = request_context->socket;
                    if (NULL == socket) {
                        request_context->Event(true);
                        return false;
                    }

                    auto processing =
                        [socket, request_context](boost::system::error_code ec, std::size_t sz) noexcept {
                            
                            uint16_t ack = 0;
                            int bytes_transferred = std::max<int>(ec ? -1 : sz, -1);

                            if (DNS_ProcessAResponseAddresses(request_context->packet, bytes_transferred, request_context->addresses, ack)) {
                                if (ack == request_context->in4_id) {
                                    request_context->in4 = true;
                                }
                                elif(ack == request_context->in6_id) {
                                    request_context->in6 = true;
                                }
                            }

                            if (request_context->in4 && request_context->in6) {
                                request_context->Event(false);
                            }
                            else {
                                while (request_context->in4 || request_context->in6) {
                                    std::shared_ptr<boost::asio::deadline_timer> t = request_context->merge_wait;
                                    if (NULL != t) {
                                        break;
                                    }

                                    t = make_shared_object<boost::asio::deadline_timer>(request_context->executor);
                                    if (NULL == t) {
                                        break;
                                    }
                                    
                                    std::weak_ptr<DNS_RequestContext> rc_weak_ptr = request_context;
                                    request_context->merge_wait = t;

                                    t->expires_from_now(Timer::DurationTime(PPP_IP_DNS_MERGE_WAIT));
                                    t->async_wait(
                                        [rc_weak_ptr](const boost::system::error_code& ec) noexcept {
                                            std::shared_ptr<DNS_RequestContext> request_context = rc_weak_ptr.lock();
                                            if (NULL == request_context) {
                                                return false;
                                            }

                                            std::shared_ptr<boost::asio::deadline_timer> t = request_context->merge_wait;
                                            if (NULL != t) {
                                                Socket::Cancel(*t);
                                            }

                                            request_context->Event(false);
                                            return true;
                                        });
                                    break;
                                }

                                DNS_RequestContext::ReceiveFrom(request_context);
                            }
                        };

                    socket->async_receive_from(boost::asio::buffer(request_context->packet, PPP_MAX_DNS_PACKET_BUFFER_SIZE), request_context->source, processing);
                    return true;
                }

                static void                                                                     DNS_ResolveEventCallback(
                    const ppp::unordered_set<boost::asio::ip::address>&                             addresses, 
                    const ppp::function<void(const boost::asio::ip::address&)>&                     one_cb,
                    const ppp::function<void(const ppp::unordered_set<boost::asio::ip::address>&)>& all_cb) noexcept {

                    if (one_cb) {
                        if (addresses.empty()) {
                            one_cb(boost::asio::ip::address_v4::any());
                            return;
                        }

                        for (const boost::asio::ip::address& i : addresses) {
                            if (i.is_v4()) {
                                one_cb(i);
                                return;
                            }
                        }
                        
                        for (const boost::asio::ip::address& i : addresses) {
                            if (i.is_v6()) {
                                one_cb(i);
                                return;
                            }
                        }
                    }
                    else {
                        all_cb(addresses);
                    }
                }

                static bool                                                                     DNS_ResolveFromCache(
                    const char*                                                                     hostname, 
                    ppp::string&                                                                    hostname_string) noexcept {

                    if (NULL == hostname || *hostname == '\x0') {
                        return false;
                    }

                    std::size_t hostname_string_size = strnlen(hostname, PPP_MAX_HOSTNAME_SIZE_LIMIT + 1);
                    if (hostname_string_size >= PPP_MAX_HOSTNAME_SIZE_LIMIT) {
                        return false;
                    }

                    hostname_string = ATrim(ppp::string(hostname, hostname_string_size));
                    if (hostname_string.empty()) {
                        return false;
                    }

                    hostname_string = ATrim(hostname_string);
                    if (hostname_string.empty()) {
                        return false;
                    }

                    hostname_string = ToLower(hostname_string);
                    return true;
                }

                static bool                                                                     DNS_ResolveFromCache(
                    const char*                                                                     hostname, 
                    ppp::string&                                                                    hostname_string,
                    NamespaceRecordNodePtr&                                                         node) noexcept {
                    
                    if (!DNS_ResolveFromCache(hostname, hostname_string)) {
                        return false;
                    }

                    internal& c = internal::c();
                    SynchronizedObjectScope syncobj(c.lockobj);

                    if (Dictionary::TryGetValue(c.nr_hmap, hostname, node)) {
                        if (NULL == node) {
                            Dictionary::TryRemove(c.nr_hmap, hostname);
                        }
                    }

                    return true;
                }

                static bool                                                                     DNS_ResolveAsync(
                    boost::asio::io_context&                                                        context, 
                    const char*                                                                     hostname, 
                    int                                                                             timeout, 
                    const ppp::vector<boost::asio::ip::udp::endpoint>&                              destinations, 
                    const ppp::function<void(const boost::asio::ip::address&)>&                     one_cb,
                    const ppp::function<void(const ppp::unordered_set<boost::asio::ip::address>&)>& all_cb) noexcept {

                    ppp::string hostname_string;
                    NamespaceRecordNodePtr node;
                    if (!DNS_ResolveFromCache(hostname, hostname_string, node)) {
                        return false;
                    }

                    if (NULL != node) {
                        boost::asio::post(context, 
                            [node, one_cb, all_cb]() noexcept {
                                ppp::unordered_set<boost::asio::ip::address>& addresses = node->Value.addresses;
                                DNS_ResolveEventCallback(addresses, one_cb, all_cb);
                            });
                        return true;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::address hostname_address = StringToAddress(hostname_string, ec);
                    if (ec == boost::system::errc::success) {
                        boost::asio::post(context, 
                            [hostname_address, one_cb, all_cb]() noexcept {
                                ppp::unordered_set<boost::asio::ip::address> addresses;
                                addresses.emplace(hostname_address);

                                DNS_ResolveEventCallback(addresses, one_cb, all_cb);
                            });
                        return true;
                    }

                    return DNS_SendToARequestAsync(context, hostname_string, timeout, destinations, 
                        [one_cb, all_cb](bool successed, ppp::unordered_set<boost::asio::ip::address>& addresses) noexcept {
                            DNS_ResolveEventCallback(addresses, one_cb, all_cb);
                        });
                }

                bool                                                                            ResolveAsync(
                    boost::asio::io_context&                                                        context, 
                    const char*                                                                     hostname, 
                    int                                                                             timeout, 
                    const ppp::vector<boost::asio::ip::udp::endpoint>&                              destinations,
                    const ppp::function<void(const boost::asio::ip::address&)>&                     cb) noexcept {

                    if (NULL == cb) {
                        return false;
                    }

                    return DNS_ResolveAsync(context, hostname, timeout, destinations, cb, NULL);
                }

                bool                                                                            ResolveAsync2(
                    boost::asio::io_context&                                                        context, 
                    const char*                                                                     hostname, 
                    int                                                                             timeout, 
                    const ppp::vector<boost::asio::ip::udp::endpoint>&                              destinations,
                    const ppp::function<void(const ppp::unordered_set<boost::asio::ip::address>&)>& cb) noexcept {

                    if (NULL == cb) {
                        return false;
                    }

                    return DNS_ResolveAsync(context, hostname, timeout, destinations, NULL, cb);
                }

                bool                                                                            QueryCache(const char* hostname, boost::asio::ip::address& address) noexcept {
                    ppp::string hostname_string;
                    address = boost::asio::ip::address_v4::any();

                    NamespaceRecordNodePtr node;
                    if (!DNS_ResolveFromCache(hostname, hostname_string, node)) {
                        return false; 
                    }

                    if (NULL == node) {
                        return false; 
                    }

                    DNS_ResolveEventCallback(node->Value.addresses, 
                        [&address](const boost::asio::ip::address& i) noexcept {
                            address = i;
                        }, NULL);

                    return !IPEndPoint::IsInvalid(address);
                }

                ppp::string                                                                     QueryCache2(const char* hostname, ::dns::Message& messsage, AddressFamily af) noexcept {
                    bool in4 = af == AddressFamily::kA;
                    bool in6 = af == AddressFamily::kAAAA;
                    if (!in4 && !in6) {
                        return ppp::string(); 
                    }

                    ppp::string hostname_string;
                    NamespaceRecordNodePtr node;
                    if (!DNS_ResolveFromCache(hostname, hostname_string, node)) {
                        return ppp::string(); 
                    }

                    if (NULL == node) {
                        return ppp::string(); 
                    }

                    NamespaceRecord& record = node->Value;
                    if (in4 && !record.ipv4) {
                        return ppp::string();  
                    }

                    if (in6 && !record.ipv6) {
                        return ppp::string();  
                    }

                    bool any = false;
                    ppp::unordered_set<boost::asio::ip::address>& addresses = record.addresses;

                    for (boost::asio::ip::address ip : addresses) {
                        if (in4 && ip.is_v4()) {
                            std::shared_ptr<::dns::RDataA> rd_a = make_shared_object<::dns::RDataA>();
                            if (NULL == rd_a) {
                                break;
                            }
                            else {
                                rd_a->setAddress((uint8_t*)ip.to_v4().to_bytes().data());
                            }

                            ::dns::ResourceRecord rr;
                            rr.mName = hostname_string;
                            rr.mClass = ::dns::RecordClass::kIN;
                            rr.mType = ::dns::RecordType::kA;
                            rr.setRData(rd_a);

                            any = true;
                            messsage.answers.emplace_back(rr);
                        }
                        elif(in6 && ip.is_v6()) {
                            std::shared_ptr<::dns::RDataAAAA> rd_aaaa = make_shared_object<::dns::RDataAAAA>();
                            if (NULL == rd_aaaa) {
                                break;
                            }
                            else {
                                rd_aaaa->setAddress((uint8_t*)ip.to_v6().to_bytes().data());
                            }

                            ::dns::ResourceRecord rr;
                            rr.mName = hostname_string;
                            rr.mClass = ::dns::RecordClass::kIN;
                            rr.mType = ::dns::RecordType::kAAAA;
                            rr.setRData(rd_aaaa);

                            any = true;
                            messsage.answers.emplace_back(rr);
                        }
                    }

                    messsage.mQr = 1;
                    messsage.mRA = 1;
                    messsage.mRCode = (uint16_t)(any ? ::dns::ResponseCode::kNOERROR : ::dns::ResponseCode::kNXDOMAIN); /* No such name. */
                    return hostname_string;
                }

                void                                                                            UpdateAsync() noexcept {
                    internal& c = internal::c();

                    NamespaceRecordNodePtr node;
                    SynchronizedObjectScope scope(c.lockobj);

                    node = c.nr_list.First();
                    if (NULL != node) {
                        uint64_t now = Executors::GetTickCount();
                        do {
                            NamespaceRecord& record = node->Value;
                            if (now < record.expired_time) {
                                break;
                            }

                            if (!Dictionary::TryRemove(c.nr_hmap, record.hostname)) {
                                break;
                            }

                            NamespaceRecordNodePtr next = node->Next;
                            c.nr_list.Remove(node);
                            node = next;
                        } while (NULL != node);
                    }
                }
            
                bool                                                                            AddCache(const Byte* packet, int packet_size) noexcept {
                    if (NULL == packet || packet_size < 1) {
                        return false;
                    }

                    uint16_t ack = 0;
                    ppp::string hostname;
                    bool ipv4_or_ipv6 = false;
                    ppp::unordered_set<boost::asio::ip::address> addresses;

                    if (!DNS_ProcessAResponseAddresses((Byte*)packet, packet_size, addresses, ack, &hostname, &ipv4_or_ipv6)) {
                        return false;
                    }

                    if (hostname.empty()) {
                        return false;
                    }

                    NamespaceRecordNodePtr node;
                    if (!DNS_ResolveFromCache(hostname.data(), hostname)) {
                        return false;
                    }
                    
                    int TTL = vdns::ttl;
                    if (TTL < 1) {
                        TTL = PPP_DEFAULT_DNS_TTL;
                    }

                    internal& c = internal::c();
                    TTL *= 1000;    

                    SynchronizedObjectScope syncobj(c.lockobj);
                    if (Dictionary::TryGetValue(c.nr_hmap, hostname, node)) {
                        if (NULL == node) {
                            Dictionary::TryRemove(c.nr_hmap, hostname);
                        }
                        else {
                            NamespaceRecord& nr = node->Value;
                            for (const boost::asio::ip::address& ip : addresses) {
                                nr.Emplace(ip);
                            }

                            c.nr_list.Remove(node);
                            Dictionary::TryRemove(c.nr_hmap, hostname);

                            nr.expired_time = Executors::GetTickCount() + TTL;
                            if (Dictionary::TryAdd(c.nr_hmap, hostname, node)) {
                                if (c.nr_list.AddLast(node)) {
                                    if (ipv4_or_ipv6) 
                                        nr.ipv4 = true;
                                    else 
                                        nr.ipv6 = true;
                                    return true;
                                }

                                Dictionary::TryRemove(c.nr_hmap, hostname);
                            }
                        }
                    }

                    node = make_shared_object<NamespaceRecordNode>();
                    if (NULL == node) {
                        return false;
                    }

                    NamespaceRecord& record = node->Value;
                    record.hostname         = hostname;
                    record.addresses        = std::move(addresses);
                    record.expired_time     = Executors::GetTickCount() + TTL;

                    if (ipv4_or_ipv6) 
                        record.ipv4 = true;
                    else 
                        record.ipv6 = true;

                    if (Dictionary::TryAdd(c.nr_hmap, hostname, node)) {
                        if (c.nr_list.AddLast(node)) {
                            return true;
                        }

                        Dictionary::TryRemove(c.nr_hmap, hostname);
                    }

                    return false;
                }
            
                bool                                                                            IsReverseQuery(const char* hostname) noexcept {
                    static constexpr char PPP_DNS_ARPA_QEURY_IPV6[] = ".ip6.arpa";
                    static constexpr char PPP_DNS_ARPA_QEURY_IPV4[] = ".in-addr.arpa";

                    if (NULL == hostname || *hostname == '\x0') {
                        return false;
                    }

                    std::size_t hostname_string_size = strnlen(hostname, PPP_MAX_HOSTNAME_SIZE_LIMIT + 1);
                    if (hostname_string_size >= PPP_MAX_HOSTNAME_SIZE_LIMIT) {
                        return false;
                    }

                    if (hostname_string_size >= sizeof(PPP_DNS_ARPA_QEURY_IPV6)) {
                        const char* p = hostname + ((hostname_string_size - sizeof(PPP_DNS_ARPA_QEURY_IPV6)) + 1);
                        if (strcmp(p, PPP_DNS_ARPA_QEURY_IPV6) == 0) {
                            return true; 
                        }
                    }

                    if (hostname_string_size >= sizeof(PPP_DNS_ARPA_QEURY_IPV4)) {
                        const char* p = hostname + ((hostname_string_size - sizeof(PPP_DNS_ARPA_QEURY_IPV4)) + 1);
                        if (strcmp(p, PPP_DNS_ARPA_QEURY_IPV4) == 0) {
                            return true; 
                        }
                    }

                    return false;
                }

                bool NamespaceRecord::Emplace(const boost::asio::ip::address& ip) noexcept {
                    SynchronizedObjectScope scope(lockobj);
                    auto r = addresses.emplace(ip);
                    return r.second;
                }
            }
        }
    }
}
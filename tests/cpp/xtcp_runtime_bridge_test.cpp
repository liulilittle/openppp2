// xtcp_runtime_bridge_test.cpp
//
// Unprivileged end-to-end tests for the XTCP runtime bridge: hand-built
// IPv4/TCP segments (valid checksums, via the pinned upstream harness) enter
// through XtcpRuntime::SubmitIPv4Tcp, the stack's L3 output is captured, and
// the second leg is a real loopback TCP echo server. Covers:
//   - endpoint byte order (10.0.0.2 must not become 2.0.0.10)
//   - full handshake + bidirectional byte-exact data
//   - bidirectional socket half-close and clean direct-bridge FIN teardown
//   - duplicate close notifications do not repeat second-leg closure
//   - RST before the first leg is ready cancels the pending flow without
//     injecting the deferred SYN
//   - connect/close churn leaves no flows behind
//   - runtime stats counters reflect the traffic

#include <ppp/app/client/xtcp/XtcpRuntime.h>
#include <ppp/app/protocol/DirectReadWaiterState.h>

#include <xtcp/buf/bufref.h>
#include <harness/raw_pkt.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <string>
#include <cstdint>

#if !defined(_WIN32)
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include <vector>

namespace {

int failures = 0;

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) {                                                  \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #condition);                                        \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

using ppp::app::client::xtcp::XtcpDirectCompletion;
using ppp::app::client::xtcp::XtcpDirectReadReservation;
using ppp::app::client::xtcp::XtcpDirectResult;
using ppp::app::client::xtcp::XtcpFirstLegHooks;
using ppp::app::client::xtcp::XtcpRuntime;
using ppp::app::client::xtcp::XtcpSecondLegHooks;
using ppp::app::protocol::DirectReadWaiterState;
using ppp::app::runtime::RuntimeXtcpStats;

constexpr std::uint8_t kFin = 0x01;
constexpr std::uint8_t kSyn = 0x02;
constexpr std::uint8_t kRst = 0x04;
constexpr std::uint8_t kAck = 0x10;

// Client (first leg) and service (second leg) addresses inside the tunnel.
constexpr std::uint32_t kClientIp = 0x0A000002u;  // 10.0.0.2
constexpr std::uint32_t kServiceIp = 0x0A000001u; // 10.0.0.1
constexpr std::uint16_t kServicePort = 80;
constexpr std::uint16_t kClientPort = 40000;

struct TcpView final {
    std::uint32_t src_ip = 0;
    std::uint32_t dst_ip = 0;
    std::uint16_t sport = 0;
    std::uint16_t dport = 0;
    std::uint32_t seq = 0;
    std::uint32_t ack = 0;
    std::uint16_t window = 0;
    std::uint8_t flags = 0;
    std::vector<Byte> payload;
};

std::uint32_t ReadBe32(const Byte* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
        (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

std::uint16_t ReadBe16(const Byte* p) noexcept {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

bool ParseTcp(const std::vector<Byte>& packet, TcpView& view) noexcept {
    if (packet.size() < 40 || (packet[0] >> 4) != 4 || packet[9] != 6) {
        return false;
    }
    const std::size_t ip_header = (packet[0] & 0x0F) * 4;
    if (packet.size() < ip_header + 20) {
        return false;
    }
    const Byte* tcp = packet.data() + ip_header;
    const std::size_t tcp_header = (tcp[12] >> 4) * 4;
    if (packet.size() < ip_header + tcp_header) {
        return false;
    }
    view.src_ip = ReadBe32(packet.data() + 12);
    view.dst_ip = ReadBe32(packet.data() + 16);
    view.sport = ReadBe16(tcp);
    view.dport = ReadBe16(tcp + 2);
    view.seq = ReadBe32(tcp + 4);
    view.ack = ReadBe32(tcp + 8);
    view.window = ReadBe16(tcp + 14);
    view.flags = tcp[13];
    view.payload.assign(tcp + tcp_header, packet.data() + packet.size());
    return true;
}

// Waits until `predicate` is true, pumping nothing (the io_context runs on
// its own thread). Returns false on timeout.
bool WaitFor(const std::function<bool()>& predicate, int timeout_ms = 5000) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return predicate();
}

// A half-close-aware loopback echo server: echoes bytes back, and when the
// peer half-closes (read EOF) it shuts down its write side after every
// received byte was echoed, then closes the socket - modelling the ppp-side
// connection object going away (Dispose closes the accepted socket).
// Accepts any number of sequential connections.
class EchoServer final : public std::enable_shared_from_this<EchoServer> {
public:
    EchoServer(boost::asio::io_context& context, std::uint16_t port)
        : acceptor_(context, boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address_v4::loopback(), port)) {
        boost::system::error_code ec;
        acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
    }

    void Start() {
        DoAccept();
    }

    boost::asio::ip::tcp::endpoint Endpoint() const {
        return acceptor_.local_endpoint();
    }

    std::uint64_t EchoedBytes() const {
        return echoed_bytes_.load(std::memory_order_relaxed);
    }

    std::uint64_t EofCount() const {
        return eof_count_.load(std::memory_order_relaxed);
    }

private:
    class Session final : public std::enable_shared_from_this<Session> {
    public:
        Session(boost::asio::ip::tcp::socket socket, EchoServer& owner)
            : socket_(std::move(socket)), owner_(owner) {}

        void Start() {
            DoRead();
        }

    private:
        void DoRead() {
            socket_.async_read_some(boost::asio::buffer(read_buffer_),
                [self = shared_from_this()](const boost::system::error_code& ec,
                    std::size_t length) noexcept {
                    if (ec == boost::asio::error::eof || (length == 0 && !ec)) {
                        self->owner_.eof_count_.fetch_add(1, std::memory_order_relaxed);
                        boost::system::error_code ignored;
                        self->socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ignored);
                        self->socket_.close(ignored);
                        return;
                    }
                    if (ec) {
                        return;
                    }
                    self->owner_.echoed_bytes_.fetch_add(length, std::memory_order_relaxed);
                    boost::system::error_code write_ec;
                    boost::asio::write(self->socket_,
                        boost::asio::buffer(self->read_buffer_.data(), length), write_ec);
                    if (write_ec) {
                        // The peer (app side) reset mid-echo; stop echoing.
                        return;
                    }
                    self->DoRead();
                });
        }

        boost::asio::ip::tcp::socket socket_;
        EchoServer& owner_;
        std::array<char, 16384> read_buffer_{};
    };

    void DoAccept() {
        acceptor_.async_accept([self = shared_from_this()](
                const boost::system::error_code& ec,
                boost::asio::ip::tcp::socket socket) noexcept {
            if (ec) {
                return;
            }
            std::make_shared<Session>(std::move(socket), *self)->Start();
            self->DoAccept();
        });
    }

    boost::asio::ip::tcp::acceptor acceptor_;
    std::atomic<std::uint64_t> echoed_bytes_{0};
    std::atomic<std::uint64_t> eof_count_{0};
};


class DirectSecondLeg final : public XtcpSecondLegHooks {
public:
    XtcpDirectResult SendToPeer(
        const std::uint8_t* data, std::uint32_t length,
        ppp::app::client::xtcp::XtcpUploadBudget::Reservation&& credit) noexcept override {
        const std::uint64_t attempt = attempts_.fetch_add(1, std::memory_order_relaxed) + 1;
        if (!accepting_.load(std::memory_order_relaxed) || attempt <= reject_attempts_) {
            std::function<void()> writable;
            {
                std::lock_guard<std::mutex> lock(sync_);
                writable = writable_before_reject_;
            }
            if (writable) {
                writable();
            }
            return XtcpDirectResult::Backpressured;
        }
        if (!data || !length || !credit || credit.Bytes() != length) {
            return XtcpDirectResult::Closed;
        }
        std::lock_guard<std::mutex> lock(sync_);
        received_.insert(received_.end(), data, data + length);
        if (hold_uploads_) {
            held_uploads_.push_back(std::make_shared<ppp::app::client::xtcp::XtcpUploadChunk>(
                data, length, std::move(credit)));
        }
        return XtcpDirectResult::Accepted;
    }

    void HoldUploads() {
        std::lock_guard<std::mutex> lock(sync_);
        hold_uploads_ = true;
    }

    void ReleaseUploads() {
        std::vector<std::shared_ptr<ppp::app::client::xtcp::XtcpUploadChunk>> released;
        {
            std::lock_guard<std::mutex> lock(sync_);
            released.swap(held_uploads_);
        }
    }

    std::uint64_t Attempts() const noexcept { return attempts_.load(std::memory_order_relaxed); }

    void OnDownloadComplete(const XtcpDirectReadReservation& reservation,
        XtcpDirectCompletion completion) noexcept override {
        try {
            std::lock_guard<std::mutex> lock(sync_);
            download_completions_.push_back({reservation, completion});
        }
        catch (...) {
        }
    }

    void ClosePeerSend() noexcept override {
        std::lock_guard<std::mutex> lock(sync_);
        received_at_close_ = received_.size();
        close_calls_.fetch_add(1, std::memory_order_relaxed);
    }

    void SetAccepting() noexcept {
        accepting_.store(true, std::memory_order_relaxed);
    }

    void RejectAttempts(std::uint64_t attempts) noexcept {
        reject_attempts_ = attempts;
        accepting_.store(true, std::memory_order_relaxed);
    }

    void WritableBeforeReject(std::function<void()> writable) {
        std::lock_guard<std::mutex> lock(sync_);
        writable_before_reject_ = std::move(writable);
    }

    std::vector<Byte> Received() const {
        std::lock_guard<std::mutex> lock(sync_);
        return received_;
    }

    std::uint64_t CloseCalls() const noexcept {
        return close_calls_.load(std::memory_order_relaxed);
    }

    std::size_t DownloadCompletionCount(const XtcpDirectReadReservation& reservation,
        XtcpDirectCompletion completion) const {
        std::lock_guard<std::mutex> lock(sync_);
        std::size_t count = 0;
        for (const DownloadCompletion& recorded : download_completions_) {
            if (recorded.reservation.IsSame(reservation) && recorded.completion == completion) {
                ++count;
            }
        }
        return count;
    }

    std::size_t DownloadCompletionCount() const {
        std::lock_guard<std::mutex> lock(sync_);
        return download_completions_.size();
    }

    std::size_t ReceivedAtClose() const noexcept {
        std::lock_guard<std::mutex> lock(sync_);
        return received_at_close_;
    }

private:
    struct DownloadCompletion final {
        XtcpDirectReadReservation reservation;
        XtcpDirectCompletion completion = XtcpDirectCompletion::Terminal;
    };

    std::atomic<bool> accepting_{false};
    std::atomic<std::uint64_t> attempts_{0};
    std::uint64_t reject_attempts_ = 0;
    std::atomic<std::uint64_t> close_calls_{0};
    mutable std::mutex sync_;
    std::function<void()> writable_before_reject_;
    std::vector<Byte> received_;
    bool hold_uploads_ = false;
    std::vector<std::shared_ptr<ppp::app::client::xtcp::XtcpUploadChunk>> held_uploads_;
    std::vector<DownloadCompletion> download_completions_;
    std::size_t received_at_close_ = 0;
};

struct AcceptedFlow final {
    boost::asio::ip::tcp::endpoint first_leg_local;   // tunnel client endpoint
    boost::asio::ip::tcp::endpoint first_leg_remote;  // tunnel service endpoint
    std::uint16_t source_port = 0;
    std::uint64_t runtime_generation = 0;
    std::uint64_t flow_generation = 0;
    std::weak_ptr<XtcpFirstLegHooks> hooks;
};

// Owns the io_context thread, the runtime under test, the captured L3 output
// and the accepted/cancelled flow records.
class Bridge final {
public:
    Bridge() {
        context_ = std::make_shared<boost::asio::io_context>();
        work_guard_ = std::make_unique<boost::asio::io_context::work>(*context_);
        io_thread_ = std::thread([this]() noexcept {
            boost::system::error_code ec;
            context_->run(ec);
        });
    }

    ~Bridge() {
        if (runtime_) {
            runtime_->Stop();
        }
        work_guard_.reset();
        context_->stop();
        if (io_thread_.joinable()) {
            io_thread_.join();
        }
    }

    bool StartRuntime(std::uint16_t echo_port) {
        echo_ = std::make_shared<EchoServer>(*context_, echo_port);
        echo_->Start();
        const auto listener_endpoint = echo_->Endpoint();
        runtime_ = std::make_shared<XtcpRuntime>(
            context_,
            [this](std::shared_ptr<Byte>&& data, int length,
                std::optional<ppp::tap::TxGsoMetadata>) noexcept {
                std::lock_guard<std::mutex> lock(output_mutex_);
                const Byte* bytes = data ? data.get() : nullptr;
                if (bytes != nullptr && length > 0) {
                    output_.emplace_back(bytes, bytes + length);
                }
                return true;
            },
            [listener_endpoint]() noexcept { return listener_endpoint; },
            [this, listener_endpoint](const boost::asio::ip::tcp::endpoint& local,
                   const boost::asio::ip::tcp::endpoint& remote,
                   std::uint16_t source_port, std::uint64_t runtime_generation,
                   std::uint64_t flow_generation,
                   const std::weak_ptr<XtcpFirstLegHooks>& hooks, int fd) noexcept {
                if (fd >= 0) {
                    // XTCP-VNET-BRIDGE-BYPASS-001: socketpair 路径 - 用阻塞双线程
                    // 中继 fd <-> echo server, 模拟 netstack 泵的 socket 语义。
                    std::thread([listener_endpoint, fd]() noexcept {
                        const int srv = ::socket(AF_INET, SOCK_STREAM, 0);
                        if (srv < 0) {
                            ::close(fd);
                            return;
                        }
                        sockaddr_in addr{};
                        addr.sin_family = AF_INET;
                        addr.sin_port = htons(static_cast<uint16_t>(listener_endpoint.port()));
                        addr.sin_addr.s_addr = htonl(0x7F000001);
                        if (::connect(srv, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
                            ::close(srv);
                            ::close(fd);
                            return;
                        }
                        struct RelaySockets final {
                            int first = -1;
                            int second = -1;
                            ~RelaySockets() {
                                if (first >= 0) ::close(first);
                                if (second >= 0) ::close(second);
                            }
                        };
                        auto sockets = std::make_shared<RelaySockets>();
                        sockets->first = fd;
                        sockets->second = srv;
                        auto pump = [](int a, int b) noexcept {
                            char buf[65536];
                            ssize_t n;
                            while ((n = ::read(a, buf, sizeof(buf))) > 0) {
                                std::size_t off = 0;
                                while (off < static_cast<std::size_t>(n)) {
                                    ssize_t w = ::send(b, buf + off, static_cast<std::size_t>(n) - off, MSG_NOSIGNAL);
                                    if (w <= 0) {
                                        ::shutdown(a, SHUT_RDWR);
                                        ::shutdown(b, SHUT_RDWR);
                                        return;
                                    }
                                    off += static_cast<std::size_t>(w);
                                }
                            }
                            ::shutdown(b, SHUT_WR);
                        };
                        // Neither pump closes a descriptor while its sibling
                        // may still use it. The detached relay owns no Bridge
                        // pointer, so teardown/restart cannot invalidate it.
                        std::thread up([pump, sockets]() noexcept { pump(sockets->first, sockets->second); });
                        std::thread down([pump, sockets]() noexcept { pump(sockets->second, sockets->first); });
                        up.detach();
                        down.detach();
                    }).detach();
                }
                std::lock_guard<std::mutex> lock(flows_mutex_);
                AcceptedFlow flow;
                flow.first_leg_local = local;
                flow.first_leg_remote = remote;
                flow.source_port = source_port;
                flow.runtime_generation = runtime_generation;
                flow.flow_generation = flow_generation;
                flow.hooks = hooks;
                accepted_.push_back(flow);
                return true;
            },
            [this](std::uint16_t source_port, std::uint64_t) noexcept {
                std::lock_guard<std::mutex> lock(flows_mutex_);
                cancelled_.push_back(source_port);
            });
        if (!runtime_->Start()) {
            return false;
        }
        runtime_->MarkReady();
        return runtime_->IsReady();
    }

    void Submit(const std::vector<Byte>& packet) {
        runtime_->SubmitIPv4Tcp(packet.data(), static_cast<int>(packet.size()));
    }

    // Pops the first captured output packet matching `predicate`.
    bool WaitOutput(const std::function<bool(const TcpView&)>& predicate, TcpView& view,
            int timeout_ms = 5000) {
        bool found = false;
        const bool ok = WaitFor([&]() {
            std::lock_guard<std::mutex> lock(output_mutex_);
            for (auto it = output_.begin(); it != output_.end(); ++it) {
                TcpView candidate;
                if (ParseTcp(*it, candidate) && predicate(candidate)) {
                    view = std::move(candidate);
                    output_.erase(it);
                    found = true;
                    return true;
                }
            }
            return false;
        }, timeout_ms);
        return ok && found;
    }

    int OutputCount() {
        std::lock_guard<std::mutex> lock(output_mutex_);
        return static_cast<int>(output_.size());
    }

    AcceptedFlow LastAccepted() {
        std::lock_guard<std::mutex> lock(flows_mutex_);
        return accepted_.back();
    }

    std::size_t AcceptedCount() {
        std::lock_guard<std::mutex> lock(flows_mutex_);
        return accepted_.size();
    }

    std::size_t CancelledCount() {
        std::lock_guard<std::mutex> lock(flows_mutex_);
        return cancelled_.size();
    }

    void ReadyLastFlow() {
        AcceptedFlow flow = LastAccepted();
        if (const std::shared_ptr<XtcpFirstLegHooks> hooks = flow.hooks.lock()) {
            hooks->OnFirstLegReady(flow.runtime_generation, flow.flow_generation);
        }
    }

    void ReadyLastFlowDirect(const std::shared_ptr<XtcpSecondLegHooks>& second_leg) {
        AcceptedFlow flow = LastAccepted();
        if (const std::shared_ptr<XtcpFirstLegHooks> hooks = flow.hooks.lock()) {
            hooks->OnFirstLegDirectReady(
                flow.runtime_generation, flow.flow_generation, second_leg);
        }
    }

    void WritableLastFlow() {
        AcceptedFlow flow = LastAccepted();
        if (const std::shared_ptr<XtcpFirstLegHooks> hooks = flow.hooks.lock()) {
            hooks->OnSecondLegWritable(flow.runtime_generation, flow.flow_generation);
        }
    }

    void WritableLastFlowStale() {
        AcceptedFlow flow = LastAccepted();
        if (const std::shared_ptr<XtcpFirstLegHooks> hooks = flow.hooks.lock()) {
            hooks->OnSecondLegWritable(flow.runtime_generation + 1, flow.flow_generation);
        }
    }

    void CloseLastFlowFirstLeg() {
        AcceptedFlow flow = LastAccepted();
        if (const std::shared_ptr<XtcpFirstLegHooks> hooks = flow.hooks.lock()) {
            hooks->OnFirstLegClosed(flow.runtime_generation, flow.flow_generation);
        }
    }

    void CloseLastFlowSecondLeg() {
        AcceptedFlow flow = LastAccepted();
        if (const std::shared_ptr<XtcpFirstLegHooks> hooks = flow.hooks.lock()) {
            hooks->OnSecondLegClosed(flow.runtime_generation, flow.flow_generation);
        }
    }

    RuntimeXtcpStats Stats() const {
        return runtime_->SnapshotStats();
    }

    bool RestartRuntime() {
        runtime_->Stop();
        if (!WaitFor([&]() { return runtime_->Start(); })) return false;
        runtime_->MarkReady();
        return true;
    }

    std::shared_ptr<EchoServer> echo_;

private:
    std::shared_ptr<boost::asio::io_context> context_;
    std::unique_ptr<boost::asio::io_context::work> work_guard_;
    std::thread io_thread_;
    std::shared_ptr<XtcpRuntime> runtime_;
    std::mutex output_mutex_;
    std::deque<std::vector<Byte>> output_;
    std::mutex flows_mutex_;
    std::vector<AcceptedFlow> accepted_;
    std::vector<std::uint16_t> cancelled_;
};

// Drives one full handshake and returns the established sequence numbers.
bool Handshake(Bridge& bridge, std::uint16_t client_port,
        std::uint32_t& client_next, std::uint32_t& server_next) {
    const std::size_t accepted_before = bridge.AcceptedCount();
    const std::uint32_t client_isn = 1000 + client_port;
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, client_port, kServicePort, client_isn, 0, kSyn));
    if (!WaitFor([&]() { return bridge.AcceptedCount() > accepted_before; })) {
        return false;
    }
    bridge.ReadyLastFlow();
    TcpView syn_ack;
    if (!bridge.WaitOutput([](const TcpView& view) {
            return (view.flags & (kSyn | kAck)) == (kSyn | kAck);
        }, syn_ack)) {
        return false;
    }
    const std::uint32_t server_isn = syn_ack.seq;
    if (syn_ack.ack != client_isn + 1) {
        return false;
    }
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, client_port, kServicePort,
        client_isn + 1, server_isn + 1, kAck));
    client_next = client_isn + 1;
    server_next = server_isn + 1;
    return true;
}

void TestEndpointByteOrder() {
    Bridge bridge;
    CHECK(bridge.StartRuntime(0));
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort, 5000, 0, kSyn));
    CHECK(WaitFor([&]() { return bridge.AcceptedCount() != 0; }));
    const AcceptedFlow flow = bridge.LastAccepted();
    // The client endpoint must read 10.0.0.2:40000, not 2.0.0.10.
    CHECK(flow.first_leg_local.address().to_string() == "10.0.0.2");
    CHECK(flow.first_leg_local.port() == kClientPort);
    CHECK(flow.first_leg_remote.address().to_string() == "10.0.0.1");
    CHECK(flow.first_leg_remote.port() == kServicePort);
    CHECK(flow.source_port != 0);
}

void TestHandshakeAndBidirectionalData() {
    Bridge bridge;
    CHECK(bridge.StartRuntime(0));
    std::uint32_t client_next = 0;
    std::uint32_t server_next = 0;
    CHECK(Handshake(bridge, kClientPort, client_next, server_next));

    const char payload[] = "hello-xtcp-bridge";
    constexpr std::uint32_t payload_len = sizeof(payload) - 1;
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_next, server_next, kAck,
        reinterpret_cast<const Byte*>(payload), payload_len));

    // The echo must come back byte-exact through the stack's L3 output.
    TcpView echo;
    CHECK(bridge.WaitOutput([&](const TcpView& view) {
        return view.dport == kClientPort && !view.payload.empty();
    }, echo));
    CHECK(echo.payload.size() == payload_len);
    CHECK(echo.payload.size() == payload_len &&
        std::memcmp(echo.payload.data(), payload, payload_len) == 0);

    const RuntimeXtcpStats stats = bridge.Stats();
    CHECK(stats.ingress_submitted >= 3);
    CHECK(stats.ingress_injected >= 3);
    CHECK(stats.flows_opened == 1);
    CHECK(stats.flows_active == 1);
    CHECK(stats.output_packets >= 2);  // SYN+ACK, echo data (ACKs may coalesce)
    CHECK(stats.connector_read_bytes == payload_len);
    CHECK(stats.connector_written_bytes == payload_len);
    // The data path is fully event-driven, so no timer may have fired yet;
    // the idle watchdog must still keep the deadline-driven poll loop alive.
    CHECK(WaitFor([&]() { return bridge.Stats().timer_polls != 0; }, 1000));
}

void TestDirectReadWaiterState() {
    const auto waiter = reinterpret_cast<ppp::coroutines::YieldContext*>(std::uintptr_t{1});
    const XtcpDirectReadReservation a{11, 22, 1, 128};
    const XtcpDirectReadReservation b{11, 22, 2, 128};
    const XtcpDirectReadReservation c{11, 22, 3, 128};

    {
        DirectReadWaiterState state;
        CHECK(state.Complete(a, XtcpDirectCompletion::Accepted) == nullptr);
        CHECK(state.Register(a, waiter) == DirectReadWaiterState::Outcome::Accepted);
        CHECK(state.Consume(a) == DirectReadWaiterState::Outcome::Accepted);
    }
    {
        DirectReadWaiterState state;
        CHECK(state.Register(b, waiter) == DirectReadWaiterState::Outcome::Pending);
        CHECK(state.Complete(a, XtcpDirectCompletion::Accepted) == nullptr);
        CHECK(state.Consume(b) == DirectReadWaiterState::Outcome::Pending);
        CHECK(state.Complete(b, XtcpDirectCompletion::Accepted) == waiter);
        CHECK(state.Consume(b) == DirectReadWaiterState::Outcome::Accepted);
    }
    {
        DirectReadWaiterState state;
        CHECK(state.Complete(a, XtcpDirectCompletion::Terminal) == nullptr);
        CHECK(state.Complete(c, XtcpDirectCompletion::Accepted) == nullptr);
        CHECK(state.Register(b, waiter) == DirectReadWaiterState::Outcome::Rejected);
        CHECK(state.Register(c, waiter) == DirectReadWaiterState::Outcome::Accepted);
        CHECK(state.Consume(c) == DirectReadWaiterState::Outcome::Accepted);
    }
    {
        DirectReadWaiterState state;
        XtcpDirectReadReservation mismatch = b;
        mismatch.length += 1;
        CHECK(state.Register(b, waiter) == DirectReadWaiterState::Outcome::Pending);
        CHECK(state.Complete(mismatch, XtcpDirectCompletion::Accepted) == nullptr);
        CHECK(state.Complete(b, XtcpDirectCompletion::Accepted) == waiter);
        CHECK(state.Complete(b, XtcpDirectCompletion::Accepted) == nullptr);
        CHECK(state.Consume(b) == DirectReadWaiterState::Outcome::Accepted);
    }
    {
        DirectReadWaiterState state;
        CHECK(state.Register(b, waiter) == DirectReadWaiterState::Outcome::Pending);
        CHECK(state.Invalidate() == waiter);
        CHECK(state.Consume(b) == DirectReadWaiterState::Outcome::Terminal);
        CHECK(state.Complete(b, XtcpDirectCompletion::Accepted) == nullptr);
    }
}

void TestDirectDownloadReservationIdentity() {
    Bridge bridge;
    CHECK(bridge.StartRuntime(0));
    const std::shared_ptr<DirectSecondLeg> second_leg =
        std::make_shared<DirectSecondLeg>();
    const std::uint32_t client_isn = 8750;
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort, client_isn, 0, kSyn));
    CHECK(WaitFor([&]() { return bridge.AcceptedCount() != 0; }));
    bridge.ReadyLastFlowDirect(second_leg);
    TcpView syn_ack;
    CHECK(bridge.WaitOutput([](const TcpView& view) {
        return (view.flags & (kSyn | kAck)) == (kSyn | kAck);
    }, syn_ack));

    const AcceptedFlow flow = bridge.LastAccepted();
    const std::shared_ptr<XtcpFirstLegHooks> hooks = flow.hooks.lock();
    CHECK(hooks != nullptr);
    const std::shared_ptr<Byte> payload(
        new Byte[8 * 1024], std::default_delete<Byte[]>());
    XtcpDirectReadReservation reservation_a;
    reservation_a.runtime_generation = flow.runtime_generation;
    reservation_a.flow_generation = flow.flow_generation;
    reservation_a.length = 8 * 1024;
    XtcpDirectReadReservation reservation_b = reservation_a;

    CHECK(hooks && hooks->OnSecondLegPayload(reservation_a, payload) ==
        XtcpDirectResult::Accepted);
    CHECK(reservation_a.token != 0);
    CHECK(hooks && hooks->OnSecondLegPayload(reservation_b, payload) ==
        XtcpDirectResult::Backpressured);
    CHECK(reservation_b.token != 0);
    CHECK(reservation_b.token != reservation_a.token);

    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_isn + 1, syn_ack.seq + 1, kAck));
    CHECK(WaitFor([&]() {
        return second_leg->DownloadCompletionCount(
            reservation_a, XtcpDirectCompletion::Accepted) == 1;
    }));

    CHECK(hooks && hooks->OnSecondLegPayload(reservation_b, payload) ==
        XtcpDirectResult::Accepted);
    CHECK(WaitFor([&]() {
        return second_leg->DownloadCompletionCount(
            reservation_b, XtcpDirectCompletion::Accepted) == 1 &&
            bridge.Stats().direct_download_writable_callbacks == 2;
    }));

    const RuntimeXtcpStats stats = bridge.Stats();
    CHECK(stats.direct_download_queue_bytes == 0);
    CHECK(stats.direct_download_chunks == 2);
    CHECK(stats.direct_download_rejected == 1);
    CHECK(stats.direct_download_accepted_bytes == 16 * 1024);
    CHECK(second_leg->DownloadCompletionCount(
        reservation_a, XtcpDirectCompletion::Accepted) == 1);
    CHECK(second_leg->DownloadCompletionCount(
        reservation_b, XtcpDirectCompletion::Accepted) == 1);
    CHECK(second_leg->DownloadCompletionCount() == 2);
}

void TestDirectBackpressureResume() {
    Bridge bridge;
    CHECK(bridge.StartRuntime(0));
    const std::shared_ptr<DirectSecondLeg> second_leg =
        std::make_shared<DirectSecondLeg>();
    second_leg->RejectAttempts(1);  // controllable cap/low-watermark equivalent
    const std::uint32_t client_isn = 9000;
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort, client_isn, 0, kSyn));
    CHECK(WaitFor([&]() { return bridge.AcceptedCount() != 0; }));
    bridge.ReadyLastFlowDirect(second_leg);
    TcpView syn_ack;
    CHECK(bridge.WaitOutput([](const TcpView& view) {
        return (view.flags & (kSyn | kAck)) == (kSyn | kAck);
    }, syn_ack));
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_isn + 1, syn_ack.seq + 1, kAck));

    // Capacity arrives before the core has latched rcv_blocked_. The first
    // detailed attempt therefore observes not_blocked; the level signal must
    // survive until the subsequent rejection is latched.
    bridge.WritableLastFlow();
    CHECK(WaitFor([&]() {
        return bridge.Stats().resume_result_not_blocked != 0 &&
            bridge.Stats().resume_pending == 0;
    }));
    bridge.WritableLastFlow();
    CHECK(WaitFor([&]() { return bridge.Stats().resume_coalesced != 0; }));

    const std::array<Byte, 16> payload = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    second_leg->WritableBeforeReject([&bridge]() { bridge.WritableLastFlow(); });
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_isn + 1, syn_ack.seq + 1, kAck,
        payload.data(), static_cast<std::uint32_t>(payload.size())));
    CHECK(WaitFor([&]() { return bridge.Stats().direct_upload_rejected == 1; }));
    TcpView reopened;
    CHECK(bridge.WaitOutput([](const TcpView& view) {
        return (view.flags & kAck) != 0 && view.window != 0;
    }, reopened));
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_isn + 1, syn_ack.seq + 1, kAck,
        payload.data(), static_cast<std::uint32_t>(payload.size())));
    CHECK(WaitFor([&]() { return second_leg->Received().size() == payload.size(); }));
    CHECK(second_leg->Received() == std::vector<Byte>(payload.begin(), payload.end()));
    CHECK(WaitFor([&]() {
        const RuntimeXtcpStats stats = bridge.Stats();
        return stats.resume_effective == 1 && stats.resume_pending == 0;
    }));
    const RuntimeXtcpStats stats = bridge.Stats();
    CHECK(stats.resume_requested >= 3);
    CHECK(stats.resume_result_not_blocked >= 1);
    CHECK(stats.resume_coalesced >= 1);
    CHECK(stats.resume_retry >= 1);
    CHECK(stats.direct_upload_rejected == 1);
    CHECK(stats.direct_upload_accepted_chunks == 1);
    CHECK(stats.direct_upload_accepted_bytes == payload.size());
    CHECK(stats.direct_upload_writable_callbacks == 3);
}

void TestDirectBackpressureFullOooWindow() {
    Bridge bridge;
    CHECK(bridge.StartRuntime(0));
    const std::shared_ptr<DirectSecondLeg> second_leg =
        std::make_shared<DirectSecondLeg>();
    second_leg->RejectAttempts(1);
    const std::uint32_t client_isn = 9050;
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort, client_isn, 0, kSyn));
    CHECK(WaitFor([&]() { return bridge.AcceptedCount() != 0; }));
    bridge.ReadyLastFlowDirect(second_leg);
    TcpView syn_ack;
    CHECK(bridge.WaitOutput([](const TcpView& view) {
        return (view.flags & (kSyn | kAck)) == (kSyn | kAck);
    }, syn_ack));
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_isn + 1, syn_ack.seq + 1, kAck));

    const std::array<Byte, 16> rejected = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_isn + 1, syn_ack.seq + 1, kAck,
        rejected.data(), static_cast<std::uint32_t>(rejected.size())));
    CHECK(WaitFor([&]() { return bridge.Stats().direct_upload_rejected == 1; }));

    // Fill the default 65535-byte XTCP receive window behind the rejected
    // in-order chunk. The subsequent writable notification must release only
    // the application latch, not remain pending forever on OOO occupancy.
    static const std::vector<Byte> ooo_a(32000, Byte{0xA1});
    static const std::vector<Byte> ooo_b(32000, Byte{0xB2});
    static const std::vector<Byte> ooo_c(1535, Byte{0xC3});
    std::uint32_t ooo_seq = client_isn + 1 + static_cast<std::uint32_t>(rejected.size());
    for (const std::vector<Byte>* payload : {&ooo_a, &ooo_b, &ooo_c}) {
        bridge.Submit(xtcp::harness::BuildIp4Tcp(
            kClientIp, kServiceIp, kClientPort, kServicePort,
            ooo_seq, syn_ack.seq + 1, kAck,
            payload->data(), static_cast<std::uint32_t>(payload->size())));
        ooo_seq += static_cast<std::uint32_t>(payload->size());
    }

    bridge.WritableLastFlow();
    constexpr std::size_t kExpectedBytes = 16 + 32000 + 32000 + 1535;
    // One writable edge must deliver the retained frontier and drain the
    // already-SACKed contiguous OOO segments without waiting for a duplicate
    // retransmission or a second application-capacity notification.
    CHECK(WaitFor([&]() { return second_leg->Received().size() == kExpectedBytes; }));
    CHECK(WaitFor([&]() {
        const RuntimeXtcpStats stats = bridge.Stats();
        return stats.resume_pending == 0 && stats.resume_effective != 0;
    }));
}

void TestDirectResumeStaleAndCloseCancellation() {
    Bridge bridge;
    CHECK(bridge.StartRuntime(0));
    const std::shared_ptr<DirectSecondLeg> second_leg =
        std::make_shared<DirectSecondLeg>();
    const std::uint32_t client_isn = 9125;
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort, client_isn, 0, kSyn));
    CHECK(WaitFor([&]() { return bridge.AcceptedCount() != 0; }));
    bridge.ReadyLastFlowDirect(second_leg);
    TcpView syn_ack;
    CHECK(bridge.WaitOutput([](const TcpView& view) {
        return (view.flags & (kSyn | kAck)) == (kSyn | kAck);
    }, syn_ack));
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_isn + 1, syn_ack.seq + 1, kAck));

    bridge.WritableLastFlowStale();
    CHECK(WaitFor([&]() { return bridge.Stats().resume_terminal != 0; }));
    bridge.CloseLastFlowSecondLeg();
    bridge.CloseLastFlowFirstLeg();
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_isn + 1, syn_ack.seq + 1, kRst));
    CHECK(WaitFor([&]() { return bridge.Stats().flows_active == 0; }));
    CHECK(bridge.Stats().resume_pending == 0);
}

void TestDirectSecondLegStrongLifetime() {
    Bridge bridge;
    CHECK(bridge.StartRuntime(0));
    std::shared_ptr<DirectSecondLeg> second_leg =
        std::make_shared<DirectSecondLeg>();
    second_leg->SetAccepting();
    const std::weak_ptr<DirectSecondLeg> lifetime = second_leg;
    const std::uint32_t client_isn = 9250;
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort, client_isn, 0, kSyn));
    CHECK(WaitFor([&]() { return bridge.AcceptedCount() != 0; }));
    bridge.ReadyLastFlowDirect(second_leg);
    TcpView syn_ack;
    CHECK(bridge.WaitOutput([](const TcpView& view) {
        return (view.flags & (kSyn | kAck)) == (kSyn | kAck);
    }, syn_ack));
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_isn + 1, syn_ack.seq + 1, kAck));

    second_leg.reset();
    CHECK(!lifetime.expired());
    const std::array<Byte, 8> payload = {7, 6, 5, 4, 3, 2, 1, 0};
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_isn + 1, syn_ack.seq + 1, kAck | kFin,
        payload.data(), static_cast<std::uint32_t>(payload.size())));
    CHECK(WaitFor([&]() {
        const std::shared_ptr<DirectSecondLeg> retained = lifetime.lock();
        return retained && retained->Received().size() == payload.size();
    }));
    CHECK(WaitFor([&]() {
        const std::shared_ptr<DirectSecondLeg> retained = lifetime.lock();
        return retained && retained->CloseCalls() == 1;
    }));
}

void TestDirectFinCloseIsIdempotent() {
    Bridge bridge;
    CHECK(bridge.StartRuntime(0));
    const std::shared_ptr<DirectSecondLeg> second_leg =
        std::make_shared<DirectSecondLeg>();
    second_leg->SetAccepting();
    const std::uint32_t client_isn = 9500;
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort, client_isn, 0, kSyn));
    CHECK(WaitFor([&]() { return bridge.AcceptedCount() != 0; }));
    bridge.ReadyLastFlowDirect(second_leg);
    TcpView syn_ack;
    CHECK(bridge.WaitOutput([](const TcpView& view) {
        return (view.flags & (kSyn | kAck)) == (kSyn | kAck);
    }, syn_ack));
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_isn + 1, syn_ack.seq + 1, kAck));

    const std::array<Byte, 8> tail = {0, 1, 2, 3, 4, 5, 6, 7};
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_isn + 1, syn_ack.seq + 1, kAck | kFin,
        tail.data(), static_cast<std::uint32_t>(tail.size())));
    CHECK(WaitFor([&]() { return second_leg->Received().size() == tail.size(); }));
    CHECK(WaitFor([&]() { return second_leg->CloseCalls() == 1; }));
    CHECK(second_leg->ReceivedAtClose() == tail.size());

    bridge.CloseLastFlowSecondLeg();
    bridge.CloseLastFlowSecondLeg();
    bridge.CloseLastFlowFirstLeg();
    bridge.CloseLastFlowFirstLeg();
    TcpView fin;
    CHECK(bridge.WaitOutput([](const TcpView& view) {
        return view.dport == kClientPort && (view.flags & kFin) != 0;
    }, fin));
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_isn + 1 + static_cast<std::uint32_t>(tail.size()) + 1,
        fin.seq + 1, kAck));

    CHECK(WaitFor([&]() { return bridge.Stats().flows_active == 0; }));
    const RuntimeXtcpStats stats = bridge.Stats();
    CHECK(second_leg->CloseCalls() == 1);
    CHECK(stats.second_leg_close_requested == 1);
    CHECK(stats.second_leg_close_duplicate_suppressed >= 1);
    CHECK(stats.degraded_half_close == 0);
    CHECK(stats.direct_upload_rejected == 0);
    CHECK(stats.direct_download_queue_bytes == 0);
    CHECK(stats.queued_bytes == 0);
    CHECK(stats.resume_pending == 0);
}

void TestHalfCloseBothDirections() {
    Bridge bridge;
    CHECK(bridge.StartRuntime(0));
    std::uint32_t client_next = 0;
    std::uint32_t server_next = 0;
    CHECK(Handshake(bridge, kClientPort, client_next, server_next));

    // data+FIN in one segment: the payload must be delivered to the second
    // leg BEFORE the EOF (shutdown SHUT_WR after the write queue drains).
    const char tail[] = "tail-bytes-before-fin";
    constexpr std::uint32_t tail_len = sizeof(tail) - 1;
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_next, server_next, kAck | kFin,
        reinterpret_cast<const Byte*>(tail), tail_len));

    CHECK(WaitFor([&]() { return bridge.echo_->EchoedBytes() == tail_len; }));
    CHECK(WaitFor([&]() { return bridge.echo_->EofCount() == 1; }));

    // After our FIN the reverse direction must still work: the echo of the
    // tail bytes arrives through the first leg.
    TcpView echo;
    CHECK(bridge.WaitOutput([&](const TcpView& view) {
        return view.dport == kClientPort && !view.payload.empty();
    }, echo));
    CHECK(echo.payload.size() == tail_len &&
        std::memcmp(echo.payload.data(), tail, tail_len) == 0);
}

void TestRstBeforeReadyCancelsFlow() {
    Bridge bridge;
    CHECK(bridge.StartRuntime(0));
    const std::uint32_t client_isn = 7000;
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort, client_isn, 0, kSyn));
    CHECK(WaitFor([&]() { return bridge.AcceptedCount() != 0; }));
    const std::uint16_t source_port = bridge.LastAccepted().source_port;

    // RST while the first leg is not ready: the pending flow is cancelled
    // and the deferred SYN must never reach the stack (no SYN+ACK output).
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort, client_isn + 1, 0, kRst));
    CHECK(WaitFor([&]() { return bridge.CancelledCount() == 1; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(bridge.OutputCount() == 0);
    const RuntimeXtcpStats stats = bridge.Stats();
    CHECK(stats.flows_opened == 1);
    CHECK(stats.flows_closed == 1);
    CHECK(stats.flows_active == 0);
    (void)source_port;
}

void TestConnectCloseChurn() {
    Bridge bridge;
    CHECK(bridge.StartRuntime(0));
    constexpr int kIterations = 256;
    for (int i = 0; i < kIterations; ++i) {
        const std::uint16_t client_port = static_cast<std::uint16_t>(41000 + i);
        std::uint32_t client_next = 0;
        std::uint32_t server_next = 0;
        CHECK(Handshake(bridge, client_port, client_next, server_next));
        if (failures != 0) {
            return;
        }
        // FIN closes the flow; the second leg half-close then lets the stack
        // run the full close handshake to kClosed/kTimeWait.
        bridge.Submit(xtcp::harness::BuildIp4Tcp(
            kClientIp, kServiceIp, client_port, kServicePort,
            client_next, server_next, kAck | kFin));
        CHECK(WaitFor([&]() { return bridge.echo_->EofCount() >= static_cast<std::uint64_t>(i + 1); }));
        // The ppp-side close notification marks the second leg gone; the echo
        // session's socket close then drives the connector to EOF and the
        // runtime closes the first leg gracefully: the stack emits its FIN
        // and the app ACKs it, completing the close handshake.
        bridge.CloseLastFlowFirstLeg();
        TcpView fin;
        CHECK(bridge.WaitOutput([&](const TcpView& view) {
            return view.dport == client_port && (view.flags & kFin) != 0;
        }, fin));
        if (failures != 0) {
            return;
        }
        bridge.Submit(xtcp::harness::BuildIp4Tcp(
            kClientIp, kServiceIp, client_port, kServicePort,
            client_next + 1, fin.seq + 1, kAck));
    }
    CHECK(WaitFor([&]() {
        const RuntimeXtcpStats stats = bridge.Stats();
        return stats.flows_opened == kIterations && stats.flows_closed == kIterations;
    }));
    const RuntimeXtcpStats stats = bridge.Stats();
    CHECK(stats.flows_active == 0);
    // Churn is a FIN-only lifecycle test (no data flows), so the queued-byte
    // ledger must simply never have been touched.
    CHECK(bridge.Stats().queued_bytes == 0);
}

// Regression for the queued-byte ledger double debit: tearing a flow down
// while a chunk is inside the in-flight async_write used to refund those
// bytes twice (teardown + late completion), wrapping the global gauge. Every
// teardown path must land the ledger back at exactly zero.
void TestQueuedBytesAccounting() {
    {
        // Normal path: after an echo completes, the ledger is drained but the
        // highwater peak proves bytes were accounted on the way through.
        Bridge bridge;
        CHECK(bridge.StartRuntime(0));
        std::uint32_t client_next = 0;
        std::uint32_t server_next = 0;
        CHECK(Handshake(bridge, kClientPort, client_next, server_next));
        const char payload[] = "accounting-probe";
        constexpr std::uint32_t payload_len = sizeof(payload) - 1;
        bridge.Submit(xtcp::harness::BuildIp4Tcp(
            kClientIp, kServiceIp, kClientPort, kServicePort,
            client_next, server_next, kAck,
            reinterpret_cast<const Byte*>(payload), payload_len));
        CHECK(WaitFor([&]() { return bridge.echo_->EchoedBytes() >= payload_len; }));
        CHECK(WaitFor([&]() { return bridge.Stats().queued_bytes == 0; }));
        CHECK(bridge.Stats().queued_bytes_highwater > 0);
    }
    {
        // Mid-flight teardown: queue a burst, then drop the second leg before
        // it drains. HandlePeerGone refunds only the unsubmitted tail and the
        // late completion debits its own chunk; the RST then closes the flow.
        Bridge bridge;
        CHECK(bridge.StartRuntime(0));
        std::uint32_t client_next = 0;
        std::uint32_t server_next = 0;
        CHECK(Handshake(bridge, kClientPort, client_next, server_next));
        static const std::vector<Byte> bulk(32000, Byte{0xAB});
        for (int i = 0; i < 18; ++i) {
            bridge.Submit(xtcp::harness::BuildIp4Tcp(
                kClientIp, kServiceIp, kClientPort, kServicePort,
                client_next, server_next, kAck, bulk.data(),
                static_cast<std::uint32_t>(bulk.size())));
            client_next += static_cast<std::uint32_t>(bulk.size());
        }
        bridge.CloseLastFlowFirstLeg();
        bridge.Submit(xtcp::harness::BuildIp4Tcp(
            kClientIp, kServiceIp, kClientPort, kServicePort, client_next, 0, kRst));
        CHECK(WaitFor([&]() { return bridge.Stats().flows_closed == 1; }));
        CHECK(WaitFor([&]() { return bridge.Stats().queued_bytes == 0; }));
        CHECK(bridge.Stats().queued_bytes_highwater > 0);
    }
}

// The external accept callback owns a non-negative bridge descriptor even
// when it rejects the flow. Replacing the closed descriptor with dup2 makes a
// second raw close deterministically observable without relying on FD reuse.
void TestRejectedExternalAcceptOwnsBridgeFd() {
    const int sentinel_source = ::open("/dev/null", O_RDONLY);
    CHECK(sentinel_source >= 0);
    if (sentinel_source < 0) {
        return;
    }

    const std::shared_ptr<boost::asio::io_context> context =
        std::make_shared<boost::asio::io_context>();
    std::unique_ptr<boost::asio::io_context::work> work_guard =
        std::make_unique<boost::asio::io_context::work>(*context);
    std::thread io_thread([context]() noexcept {
        context->run();
    });
    std::atomic<int> received_fd{-1};
    std::atomic<int> replacement_fd{-1};
    std::atomic<bool> callback_done{false};
    const std::shared_ptr<XtcpRuntime> runtime = std::make_shared<XtcpRuntime>(
        context,
        [](std::shared_ptr<Byte>&&, int,
            std::optional<ppp::tap::TxGsoMetadata>) noexcept { return true; },
        []() noexcept { return boost::asio::ip::tcp::endpoint(); },
        [sentinel_source, &received_fd, &replacement_fd, &callback_done](
            const boost::asio::ip::tcp::endpoint&,
            const boost::asio::ip::tcp::endpoint&, std::uint16_t,
            std::uint64_t, std::uint64_t,
            const std::weak_ptr<XtcpFirstLegHooks>&, int fd) noexcept {
            received_fd.store(fd, std::memory_order_relaxed);
            int replacement = -1;
            if (fd >= 0 && ::close(fd) == 0) {
                replacement = ::dup2(sentinel_source, fd);
            }
            replacement_fd.store(replacement, std::memory_order_relaxed);
            callback_done.store(true, std::memory_order_release);
            return false;
        },
        [](std::uint16_t, std::uint64_t) noexcept {});

    const bool started = runtime->Start();
    CHECK(started);
    if (started) {
        runtime->MarkReady();
        const std::vector<Byte> syn = xtcp::harness::BuildIp4Tcp(
            kClientIp, kServiceIp, kClientPort, kServicePort, 11000, 0, kSyn);
        CHECK(runtime->SubmitIPv4Tcp(syn.data(), static_cast<int>(syn.size())));
        const bool callback_called = WaitFor([&callback_done]() {
            return callback_done.load(std::memory_order_acquire);
        });
        CHECK(callback_called);
        if (callback_called) {
            CHECK(WaitFor([&runtime]() {
                return runtime->SnapshotStats().flows_closed == 1;
            }));
            const int received = received_fd.load(std::memory_order_relaxed);
            const int replacement = replacement_fd.load(std::memory_order_relaxed);
            CHECK(received >= 0);
            CHECK(replacement == received);
            const bool replacement_is_open = replacement >= 0 &&
                ::fcntl(replacement, F_GETFD) != -1;
            CHECK(replacement_is_open);
            if (replacement_is_open) {
                ::close(replacement);
            }
        }
    }

    runtime->Stop();
    work_guard.reset();
    context->stop();
    if (io_thread.joinable()) {
        io_thread.join();
    }
    ::close(sentinel_source);
}

} // namespace

void TestGlobalUploadBudgetWakesOtherFlowAndSurvivesRestart() {
    struct RestoreEnvironment final {
        bool present = ::getenv("OPENPPP2_XTCP_GLOBAL_QUEUE_BYTES") != nullptr;
        std::string value = present ? ::getenv("OPENPPP2_XTCP_GLOBAL_QUEUE_BYTES") : "";
        ~RestoreEnvironment() {
            if (present) ::setenv("OPENPPP2_XTCP_GLOBAL_QUEUE_BYTES", value.c_str(), 1);
            else ::unsetenv("OPENPPP2_XTCP_GLOBAL_QUEUE_BYTES");
        }
    } restore;
    ::setenv("OPENPPP2_XTCP_GLOBAL_QUEUE_BYTES", "32", 1);
    Bridge bridge;
    CHECK(bridge.StartRuntime(0));
    auto first = std::make_shared<DirectSecondLeg>();
    auto second = std::make_shared<DirectSecondLeg>();
    auto third = std::make_shared<DirectSecondLeg>();
    for (const auto& leg : {first, second, third}) {
        leg->SetAccepting();
        leg->HoldUploads();
    }
    auto handshake = [&](std::uint16_t port, const std::shared_ptr<DirectSecondLeg>& leg, TcpView& syn_ack) {
        const auto before = bridge.AcceptedCount();
        const std::uint32_t seq = 1000 + port;
        bridge.Submit(xtcp::harness::BuildIp4Tcp(kClientIp, kServiceIp, port, kServicePort, seq, 0, kSyn));
        if (!WaitFor([&]() { return bridge.AcceptedCount() > before; })) return false;
        bridge.ReadyLastFlowDirect(leg);
        if (!bridge.WaitOutput([&](const TcpView& view) {
                return view.dport == port && (view.flags & (kSyn | kAck)) == (kSyn | kAck);
            }, syn_ack)) return false;
        bridge.Submit(xtcp::harness::BuildIp4Tcp(kClientIp, kServiceIp, port, kServicePort,
            seq + 1, syn_ack.seq + 1, kAck));
        return true;
    };
    const std::vector<Byte> data(32, 0x5a);
    auto send = [&](std::uint16_t port, const TcpView& syn_ack, std::size_t length) {
        bridge.Submit(xtcp::harness::BuildIp4Tcp(kClientIp, kServiceIp, port, kServicePort,
            1001 + port, syn_ack.seq + 1, kAck, data.data(), static_cast<UInt32>(length)));
    };
    TcpView syn_a, syn_b, syn_c;
    CHECK(handshake(41000, first, syn_a));
    CHECK(handshake(41001, second, syn_b));
    send(41000, syn_a, 32);
    CHECK(WaitFor([&]() { return bridge.Stats().upload_budget_bytes == 32; }));
    CHECK(bridge.Stats().upload_budget_items == 1);
    send(41001, syn_b, 16);
    CHECK(WaitFor([&]() { return bridge.Stats().upload_budget_rejected == 1; }));
    CHECK(second->Attempts() == 0); // rejected before copy or second-leg dispatch
    first->ReleaseUploads();
    CHECK(WaitFor([&]() { return bridge.Stats().resume_effective == 1; }));
    CHECK(bridge.Stats().direct_upload_writable_callbacks == 0); // another flow's release woke it
    send(41001, syn_b, 16);
    CHECK(WaitFor([&]() { return second->Received().size() == 16; }));
    CHECK(bridge.Stats().upload_budget_bytes == 16);

    CHECK(bridge.RestartRuntime());
    CHECK(bridge.Stats().upload_budget_bytes == 16); // old async owner still holds credit
    CHECK(handshake(41002, third, syn_c));
    send(41002, syn_c, 32);
    CHECK(WaitFor([&]() { return bridge.Stats().upload_budget_rejected == 1; }));
    CHECK(third->Attempts() == 0);
    second->ReleaseUploads();
    CHECK(WaitFor([&]() { return bridge.Stats().resume_effective == 1; }));
    send(41002, syn_c, 32);
    CHECK(WaitFor([&]() { return third->Received().size() == 32; }));
    third->ReleaseUploads();
    CHECK(WaitFor([&]() { return bridge.Stats().upload_budget_bytes == 0; }));
    CHECK(bridge.Stats().upload_budget_items == 0);

    // A connector/fallback flow must share the very same cap, and a direct
    // flow's release must reopen its receive window as well.
    std::uint32_t connector_next = 0, server_next = 0;
    CHECK(Handshake(bridge, 41003, connector_next, server_next));
    bridge.Submit(xtcp::harness::BuildIp4Tcp(kClientIp, kServiceIp, 41002, kServicePort,
        1001 + 41002 + 32, syn_c.seq + 1, kAck, data.data(), 32));
    CHECK(WaitFor([&]() { return bridge.Stats().upload_budget_bytes == 32; }));
    bridge.Submit(xtcp::harness::BuildIp4Tcp(kClientIp, kServiceIp, 41003, kServicePort,
        connector_next, server_next, kAck, data.data(), 16));
    CHECK(WaitFor([&]() { return bridge.Stats().upload_budget_rejected == 2; }));
    CHECK(bridge.echo_->EchoedBytes() == 0);
    third->ReleaseUploads();
    TcpView reopened;
    CHECK(bridge.WaitOutput([](const TcpView& view) {
        return view.dport == 41003 && (view.flags & kAck) != 0 && view.window != 0;
    }, reopened));
    bridge.Submit(xtcp::harness::BuildIp4Tcp(kClientIp, kServiceIp, 41003, kServicePort,
        connector_next, server_next, kAck, data.data(), 16));
    CHECK(WaitFor([&]() { return bridge.echo_->EchoedBytes() == 16; }));
    CHECK(WaitFor([&]() { return bridge.Stats().upload_budget_bytes == 0; }));
    CHECK(bridge.Stats().upload_budget_items == 0);
}

int main() {
    ::setenv("OPENPPP2_XTCP_UNIX_BRIDGE", "1", 1);
    xtcp::buf::InitPools();
    TestEndpointByteOrder();
    TestHandshakeAndBidirectionalData();
    TestDirectReadWaiterState();
    TestDirectDownloadReservationIdentity();
    TestDirectBackpressureResume();
    TestGlobalUploadBudgetWakesOtherFlowAndSurvivesRestart();
    TestDirectBackpressureFullOooWindow();
    TestDirectResumeStaleAndCloseCancellation();
    TestDirectSecondLegStrongLifetime();
    TestDirectFinCloseIsIdempotent();
    TestHalfCloseBothDirections();
    TestRstBeforeReadyCancelsFlow();
    TestConnectCloseChurn();
    TestQueuedBytesAccounting();
    TestRejectedExternalAcceptOwnsBridgeFd();
    xtcp::buf::ShutdownPools();

    if (failures != 0) {
        std::fprintf(stderr, "xtcp_runtime_bridge_test: %d failure(s)\n", failures);
        return 1;
    }
    std::puts("xtcp_runtime_bridge_test: passed");
    return 0;
}

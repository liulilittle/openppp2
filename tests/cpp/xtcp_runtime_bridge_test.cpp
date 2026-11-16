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
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <algorithm>
#include <stdexcept>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <memory>
#include <map>
#include <mutex>
#include <thread>
#include <string>
#include <cstdint>

#if !defined(_WIN32)
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sstream>
#include <csignal>
#include <cxxabi.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <sys/syscall.h>
#else
#include <tlhelp32.h>
#include <dbghelp.h>
#include <timeapi.h>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "winmm.lib")
#endif
#include <vector>

namespace ppp::coroutines { class YieldContext; }

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

bool SetTestEnvironment(const char* name, const char* value) noexcept {
#if defined(_WIN32)
    return _putenv_s(name, value != nullptr ? value : "") == 0;
#else
    return value != nullptr ? ::setenv(name, value, 1) == 0 : ::unsetenv(name) == 0;
#endif
}

using ppp::app::client::xtcp::XtcpDirectCompletion;
using ppp::app::client::xtcp::XtcpDirectReadReservation;
using ppp::app::client::xtcp::XtcpDirectResult;
using ppp::app::client::xtcp::XtcpFirstLegHooks;
using ppp::app::client::xtcp::XtcpRuntime;
using ppp::app::client::xtcp::XtcpSecondLegHooks;
// Pointer instantiation: identity checks only; production uses YieldContext::Anchor.
using PointerDirectReadWaiterState =
    ppp::app::protocol::BasicDirectReadWaiterState<ppp::coroutines::YieldContext*>;
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
    std::uint8_t wscale = 0xFF;  // RFC 7323 shift from a SYN option; 0xFF = absent
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
    view.wscale = 0xFF;
    for (std::size_t i = 20; i < tcp_header;) {
        const Byte kind = tcp[i];
        if (kind == 0) break;            // end of option list
        if (kind == 1) { ++i; continue; }  // NOP
        if (i + 1 >= tcp_header || tcp[i + 1] < 2 || i + tcp[i + 1] > tcp_header) break;
        if (kind == 3 && tcp[i + 1] == 3) view.wscale = tcp[i + 2];
        i += tcp[i + 1];
    }
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

std::shared_ptr<int> TrackRuntimeLifetime(const std::shared_ptr<std::atomic<bool>>& drained) {
    return std::shared_ptr<int>(new int(0), [drained](int* token) noexcept {
        delete token;
        drained->store(true, std::memory_order_release);
    });
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
#if defined(_WIN32)
    using WorkGuard = boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;
#else
    using WorkGuard = boost::asio::io_context::work;
#endif
    Bridge() {
        context_ = std::make_shared<boost::asio::io_context>();
#if defined(_WIN32)
        work_guard_ = std::make_unique<WorkGuard>(context_->get_executor());
#else
        work_guard_ = std::make_unique<WorkGuard>(*context_);
#endif
        io_thread_ = std::thread([this]() noexcept {
#if defined(_WIN32)
            context_->run();
#else
            io_tid_.store(static_cast<long>(::syscall(SYS_gettid)), std::memory_order_release);
            boost::system::error_code ec;
            context_->run(ec);
#endif
        });
    }

    ~Bridge() {
        if (runtime_) {
            runtime_->Stop();
            runtime_.reset();
            // Keep the owner context running until Stop's posted teardown and
            // cancellation handlers release Impl; stopping it first leaks a cycle.
            CHECK(WaitFor([this]() { return runtime_drained_->load(std::memory_order_acquire); }));
        }
        work_guard_.reset();
        context_->stop();
        if (io_thread_.joinable()) {
            io_thread_.join();
        }
        if (echo_thread_.joinable()) {
            echo_guard_.reset();
            echo_context_->stop();
            echo_thread_.join();
        }
        echo_.reset();
        echo_context_.reset();
    }

#if defined(_WIN32)
    HANDLE IoThreadHandle() { return static_cast<HANDLE>(io_thread_.native_handle()); }
#else
    long IoThreadId() const { return io_tid_.load(std::memory_order_acquire); }
#endif

    // separate_echo: run the echo server on its own io thread so the runtime
    // thread is not also charged for the peer's socket work (the throughput
    // benchmark's native reference gives its echo server a dedicated thread).
    bool StartRuntime(std::uint16_t echo_port, bool separate_echo = false) {
        if (separate_echo) {
            echo_context_ = std::make_shared<boost::asio::io_context>();
#if defined(_WIN32)
            echo_guard_ = std::make_unique<WorkGuard>(echo_context_->get_executor());
#else
            echo_guard_ = std::make_unique<WorkGuard>(*echo_context_);
#endif
            echo_thread_ = std::thread([context = echo_context_]() noexcept {
#if defined(_WIN32)
                context->run();
#else
                boost::system::error_code ec;
                context->run(ec);
#endif
            });
        }
        echo_ = std::make_shared<EchoServer>(separate_echo ? *echo_context_ : *context_, echo_port);
        echo_->Start();
        const auto listener_endpoint = echo_->Endpoint();
        runtime_drained_ = std::make_shared<std::atomic<bool>>(false);
        const auto lifetime = TrackRuntimeLifetime(runtime_drained_);
        runtime_ = std::make_shared<XtcpRuntime>(
            context_,
            [this, lifetime](std::shared_ptr<Byte>&& data, int length,
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
#if defined(_WIN32)
                // Windows runtime must use its loopback TCP bridge. Never treat
                // this int as a SOCKET or pass it to POSIX descriptor APIs.
                CHECK(fd < 0);
                if (fd >= 0) {
                    return false;
                }
#else
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
#endif
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

    bool TrySubmit(const std::vector<Byte>& packet) {
        return runtime_->SubmitIPv4Tcp(packet.data(), static_cast<int>(packet.size()));
    }

    void DrainOutput(std::deque<std::vector<Byte>>& packets) {
        std::lock_guard<std::mutex> lock(output_mutex_);
        packets.swap(output_);
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
    std::unique_ptr<WorkGuard> work_guard_;
    std::thread io_thread_;
#if !defined(_WIN32)
    std::atomic<long> io_tid_{0};
#endif
    std::shared_ptr<boost::asio::io_context> echo_context_;
    std::unique_ptr<WorkGuard> echo_guard_;
    std::thread echo_thread_;
    std::shared_ptr<XtcpRuntime> runtime_;
    std::shared_ptr<std::atomic<bool>> runtime_drained_;
    std::mutex output_mutex_;
    std::deque<std::vector<Byte>> output_;
    std::mutex flows_mutex_;
    std::vector<AcceptedFlow> accepted_;
    std::vector<std::uint16_t> cancelled_;
};

// Drives one full handshake and returns the established sequence numbers.
bool Handshake(Bridge& bridge, std::uint16_t client_port,
        std::uint32_t& client_next, std::uint32_t& server_next, std::uint16_t peer_mss = 0,
        const std::shared_ptr<XtcpSecondLegHooks>& direct = nullptr, bool window_scaling = false,
        std::uint8_t* runtime_wscale = nullptr) {
    const std::size_t accepted_before = bridge.AcceptedCount();
    const std::uint32_t client_isn = 1000 + client_port;
    auto syn = xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, client_port, kServicePort, client_isn, 0, kSyn);
    if (peer_mss != 0) {
        const std::size_t header_size = window_scaling ? 48 : 44;
        syn.resize(header_size, 0);
        syn[2] = 0;
        syn[3] = static_cast<Byte>(header_size);
        syn[32] = window_scaling ? 0x70 : 0x60;
        syn[40] = 2;
        syn[41] = 4;
        syn[42] = static_cast<Byte>(peer_mss >> 8);
        syn[43] = static_cast<Byte>(peer_mss);
        if (window_scaling) {
            syn[44] = 1;
            syn[45] = 3;
            syn[46] = 3;
            syn[47] = 8;
        }
        xtcp::harness::FillIp4Checksum(syn.data());
        xtcp::harness::FillTcp4Checksum(syn.data(), syn.data() + 20,
            static_cast<UInt32>(header_size - 20));
    }
    bridge.Submit(syn);
    if (!WaitFor([&]() { return bridge.AcceptedCount() > accepted_before; })) {
        return false;
    }
    if (direct) {
        bridge.ReadyLastFlowDirect(direct);
    }
    else {
        bridge.ReadyLastFlow();
    }
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
    if (runtime_wscale != nullptr) {
        // Scaling is in effect only when both SYNs carried the option.
        *runtime_wscale = window_scaling && peer_mss != 0 ? syn_ack.wscale : std::uint8_t(0xFF);
    }
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, client_port, kServicePort,
        client_isn + 1, server_isn + 1, kAck));
    client_next = client_isn + 1;
    server_next = server_isn + 1;
    return true;
}

// Rejected borrowed input is retried by the peer; it must never be partly
// delivered or retain ingress credits after a failed multi-chunk allocation.
void TestIngressPressure(const char* mode) {
    CHECK(SetTestEnvironment("OPENPPP2_XTCP_GRO_BYTES", "12288"));
    CHECK(SetTestEnvironment("OPENPPP2_XTCP_UNIX_BRIDGE", "1"));
    Bridge bridge;
    CHECK(bridge.StartRuntime(0));
    auto second = std::make_shared<DirectSecondLeg>();
    second->SetAccepting();
    std::uint32_t client_next = 0, server_next = 0;
    CHECK(Handshake(bridge, kClientPort, client_next, server_next, 0, second));
    const bool ordinary = std::strcmp(mode, "ordinary") == 0;
    const bool large = std::strcmp(mode, "large") == 0;
    const unsigned available = ordinary || large ? 0 : unsigned(mode[5] - '0');
    CHECK(available <= 2);
    const UInt32 request = ordinary ? 40 : 32752;
    std::vector<xtcp::buf::BufRef> held;
    for (;;) {
        auto ref = xtcp::buf::BufRef::Acquire(request);
        if (ref.IsEmpty()) break;
        held.push_back(std::move(ref));
    }
    CHECK(!held.empty());
    for (unsigned i = 0; i < available; ++i) held.pop_back();
    std::vector<Byte> payload(ordinary ? 1000 : large ? 8000 : 30000);
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = Byte(i % 251);
    const auto packet = xtcp::harness::BuildIp4Tcp(kClientIp, kServiceIp,
        kClientPort, kServicePort, client_next, server_next, kAck,
        payload.data(), UInt32(payload.size()));
    const auto before = bridge.Stats();
    for (unsigned i = 0; i < 256; ++i) CHECK(!bridge.TrySubmit(packet));
    const auto rejected = bridge.Stats();
    CHECK(rejected.ingress_dropped == before.ingress_dropped + 256);
    CHECK(rejected.ingress_submitted == before.ingress_submitted);
    CHECK(rejected.direct_upload_accepted_bytes == before.direct_upload_accepted_bytes);
    CHECK(second->Received().empty());
    // Earlier split chunks must have returned to the global tier-2 pool.
    std::vector<xtcp::buf::BufRef> recovered;
    if (!ordinary) {
        for (;;) {
            auto ref = xtcp::buf::BufRef::Acquire(32752);
            if (ref.IsEmpty()) break;
            recovered.push_back(std::move(ref));
        }
        CHECK(recovered.size() == available);
    }
    recovered.clear();
    std::mutex mutex;
    std::condition_variable cv;
    bool released = false, done = false;
    std::thread releaser([&] {
        held.clear();
        std::unique_lock<std::mutex> lock(mutex);
        released = true;
        cv.notify_all();
        cv.wait(lock, [&] { return done; });
    });
    {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [&] { return released; });
    }
    CHECK(bridge.TrySubmit(packet));
    CHECK(WaitFor([&] { return second->Received().size() == payload.size(); }, 1000));
    CHECK(second->Received() == payload);
    TcpView ack;
    CHECK(bridge.WaitOutput([&](const TcpView& view) {
        return view.ack == client_next + payload.size();
    }, ack, 1000));
    // A duplicate retransmission must be acknowledged without redelivery.
    CHECK(bridge.TrySubmit(packet));
    CHECK(bridge.WaitOutput([&](const TcpView& view) {
        return view.ack == client_next + payload.size();
    }, ack, 1000));
    CHECK(second->Received() == payload);
    { std::lock_guard<std::mutex> lock(mutex); done = true; }
    cv.notify_all();
    releaser.join();
    std::printf("pressure %s: rejected=256 delivered=%zu recovered_chunks=%zu\n",
        mode, second->Received().size(), recovered.size());
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
        PointerDirectReadWaiterState state;
        CHECK(state.Complete(a, XtcpDirectCompletion::Accepted) == nullptr);
        CHECK(state.Register(a, waiter) == PointerDirectReadWaiterState::Outcome::Accepted);
        CHECK(state.Consume(a) == PointerDirectReadWaiterState::Outcome::Accepted);
    }
    {
        PointerDirectReadWaiterState state;
        CHECK(state.Register(b, waiter) == PointerDirectReadWaiterState::Outcome::Pending);
        CHECK(state.Complete(a, XtcpDirectCompletion::Accepted) == nullptr);
        CHECK(state.Consume(b) == PointerDirectReadWaiterState::Outcome::Pending);
        CHECK(state.Complete(b, XtcpDirectCompletion::Accepted) == waiter);
        CHECK(state.Consume(b) == PointerDirectReadWaiterState::Outcome::Accepted);
    }
    {
        PointerDirectReadWaiterState state;
        CHECK(state.Complete(a, XtcpDirectCompletion::Terminal) == nullptr);
        CHECK(state.Complete(c, XtcpDirectCompletion::Accepted) == nullptr);
        CHECK(state.Register(b, waiter) == PointerDirectReadWaiterState::Outcome::Rejected);
        CHECK(state.Register(c, waiter) == PointerDirectReadWaiterState::Outcome::Accepted);
        CHECK(state.Consume(c) == PointerDirectReadWaiterState::Outcome::Accepted);
    }
    {
        PointerDirectReadWaiterState state;
        XtcpDirectReadReservation mismatch = b;
        mismatch.length += 1;
        CHECK(state.Register(b, waiter) == PointerDirectReadWaiterState::Outcome::Pending);
        CHECK(state.Complete(mismatch, XtcpDirectCompletion::Accepted) == nullptr);
        CHECK(state.Complete(b, XtcpDirectCompletion::Accepted) == waiter);
        CHECK(state.Complete(b, XtcpDirectCompletion::Accepted) == nullptr);
        CHECK(state.Consume(b) == PointerDirectReadWaiterState::Outcome::Accepted);
    }
    {
        PointerDirectReadWaiterState state;
        CHECK(state.Register(b, waiter) == PointerDirectReadWaiterState::Outcome::Pending);
        CHECK(state.Invalidate() == waiter);
        CHECK(state.Consume(b) == PointerDirectReadWaiterState::Outcome::Terminal);
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

    // 同一 flow 的第二个 second-leg reservation 占用唯一的 in-flight 槽位:
    // 只有第一个已被移交给 stack 后才会被接受。移交是否已发生取决于
    // worker/事件循环调度, 两种时序都合法, 因此记录实际路径并据此断言最终
    // 统计, 避免对异步调度顺序做硬性假设 (CI 在多核抢占下会翻车)。
    CHECK(hooks && hooks->OnSecondLegPayload(reservation_a, payload) ==
        XtcpDirectResult::Accepted);
    CHECK(reservation_a.token != 0);

    const XtcpDirectResult b_initial = hooks->OnSecondLegPayload(reservation_b, payload);
    CHECK(b_initial == XtcpDirectResult::Accepted ||
        b_initial == XtcpDirectResult::Backpressured);
    CHECK(reservation_b.token != 0);
    CHECK(reservation_b.token != reservation_a.token);
    const bool b_admitted_first_round = (b_initial == XtcpDirectResult::Accepted);

    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_isn + 1, syn_ack.seq + 1, kAck));
    CHECK(WaitFor([&]() {
        return second_leg->DownloadCompletionCount(
            reservation_a, XtcpDirectCompletion::Accepted) == 1;
    }));

    if (!b_admitted_first_round) {
        CHECK(hooks && hooks->OnSecondLegPayload(reservation_b, payload) ==
            XtcpDirectResult::Accepted);
    }
    bridge.Submit(xtcp::harness::BuildIp4Tcp(
        kClientIp, kServiceIp, kClientPort, kServicePort,
        client_isn + 1, syn_ack.seq + 1 + 8 * 1024, kAck));
    CHECK(WaitFor([&]() {
        return second_leg->DownloadCompletionCount(
            reservation_b, XtcpDirectCompletion::Accepted) == 1;
    }));

    const RuntimeXtcpStats stats = bridge.Stats();
    CHECK(stats.direct_download_queue_bytes == 0);
    CHECK(stats.direct_download_chunks == 2);
    CHECK(stats.direct_download_rejected == (b_admitted_first_round ? 0u : 1u));
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
#if !defined(_WIN32)
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
    const auto runtime_drained = std::make_shared<std::atomic<bool>>(false);
    auto lifetime = TrackRuntimeLifetime(runtime_drained);
    std::shared_ptr<XtcpRuntime> runtime = std::make_shared<XtcpRuntime>(
        context,
        [lifetime](std::shared_ptr<Byte>&&, int,
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
    lifetime.reset();

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
    runtime.reset();
    CHECK(WaitFor([&]() { return runtime_drained->load(std::memory_order_acquire); }));
    work_guard.reset();
    context->stop();
    if (io_thread.joinable()) {
        io_thread.join();
    }
    ::close(sentinel_source);
}
#endif

} // namespace

void TestGlobalUploadBudgetWakesOtherFlowAndSurvivesRestart() {
    struct RestoreEnvironment final {
        bool present = ::getenv("OPENPPP2_XTCP_GLOBAL_QUEUE_BYTES") != nullptr;
        std::string value = present ? ::getenv("OPENPPP2_XTCP_GLOBAL_QUEUE_BYTES") : "";
        ~RestoreEnvironment() {
            (void)SetTestEnvironment("OPENPPP2_XTCP_GLOBAL_QUEUE_BYTES",
                present ? value.c_str() : nullptr);
        }
    } restore;
    (void)SetTestEnvironment("OPENPPP2_XTCP_GLOBAL_QUEUE_BYTES", "32");
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


namespace {
// This measures the test harness + runtime + loopback echo, not PPP/Wintun.
// Application flight limit. XTCP_BENCH_WINDOW overrides it (bytes, 1360..1MiB)
// to separate latency-bound closed-loop effects from per-byte cost. XTCP_BENCH_CHUNK
// overrides the synthetic peer segment size (bytes, 1360..16KiB); the XTCP stack and
// external TCP bridge accept the resulting segments, but the report remains a fixed-
// cost comparison, not a GSO capability claim.
std::size_t BenchmarkWindow() {
    static const std::size_t window = []() {
        const char* env = std::getenv("XTCP_BENCH_WINDOW");
        const long long value = env != nullptr ? std::atoll(env) : 0;
        return value >= 1360 && value <= 1024 * 1024 ? static_cast<std::size_t>(value) : std::size_t(32768);
    }();
    return window;
}
std::size_t BenchmarkChunk() {
    static const std::size_t chunk = []() {
        const char* env = std::getenv("XTCP_BENCH_CHUNK");
        const long long value = env != nullptr ? std::atoll(env) : 0;
        return value >= 1360 && value <= 16 * 1024 ? static_cast<std::size_t>(value) : std::size_t(1360);
    }();
    return chunk;
}
constexpr std::uint16_t kBenchmarkMss = 1460;
// Data segments (XTCP) or write calls (native) issued by the harness. Snapshots
// at the measured window edges let runs with different XTCP_BENCH_CHUNK values
// separate per-segment fixed cost from per-byte cost.
std::uint64_t g_bench_segments = 0;
std::uint64_t g_bench_segments_start = 0;
std::uint64_t g_bench_segments_end = 0;

std::vector<Byte> BenchmarkPattern() {
    std::vector<Byte> data(1024 * 1024);
    std::uint32_t state = 0x12345678u;
    for (Byte& value : data) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        value = static_cast<Byte>(state);
    }
    return data;
}

bool CheckBenchmarkBytes(const std::vector<Byte>& pattern, std::uint64_t offset,
        const Byte* data, std::size_t length) {
    while (length != 0) {
        const std::size_t position = static_cast<std::size_t>(offset % pattern.size());
        const std::size_t count = std::min(length, pattern.size() - position);
        if (std::memcmp(pattern.data() + position, data, count) != 0) return false;
        data += count;
        offset += count;
        length -= count;
    }
    return true;
}

double ProcessCpuSeconds() {
#if !defined(_WIN32)
    timespec now{};
    if (::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &now) != 0) {
        throw std::runtime_error("clock_gettime failed");
    }
    return static_cast<double>(now.tv_sec) + static_cast<double>(now.tv_nsec) / 1e9;
#else
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) {
        throw std::runtime_error("GetProcessTimes failed");
    }
    ULARGE_INTEGER k{}, u{};
    k.LowPart = kernel.dwLowDateTime;
    k.HighPart = kernel.dwHighDateTime;
    u.LowPart = user.dwLowDateTime;
    u.HighPart = user.dwHighDateTime;
    return static_cast<double>(k.QuadPart + u.QuadPart) / 10000000.0;
#endif
}

// Benchmark knob: XTCP_BENCH_THREADS=1 prints per-thread CPU seconds spent
// inside the measured window (identifies the saturated thread).
std::vector<std::pair<unsigned long, double>> SnapshotThreadCpu() {
    std::vector<std::pair<unsigned long, double>> result;
#if !defined(_WIN32)
    const double ticks = static_cast<double>(::sysconf(_SC_CLK_TCK));
    DIR* dir = ::opendir("/proc/self/task");
    if (dir == nullptr) return result;
    while (const dirent* entry = ::readdir(dir)) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        std::ifstream stat(std::string("/proc/self/task/") + entry->d_name + "/stat");
        std::string line;
        if (!std::getline(stat, line)) continue;
        const std::size_t close = line.rfind(')');
        if (close == std::string::npos) continue;
        // Fields after "(comm)": state(3) ... utime(14) stime(15).
        std::istringstream fields(line.substr(close + 2));
        std::string field;
        unsigned long long utime = 0, stime = 0;
        for (int index = 3; fields >> field; ++index) {
            if (index == 14) utime = std::strtoull(field.c_str(), nullptr, 10);
            if (index == 15) {
                stime = std::strtoull(field.c_str(), nullptr, 10);
                break;
            }
        }
        result.emplace_back(std::strtoul(entry->d_name, nullptr, 10),
            static_cast<double>(utime + stime) / ticks);
    }
    ::closedir(dir);
    return result;
#else
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return result;
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL ok = Thread32First(snap, &entry); ok; ok = Thread32Next(snap, &entry)) {
        if (entry.th32OwnerProcessID != GetCurrentProcessId()) continue;
        const HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
        if (thread == nullptr) continue;
        FILETIME created{}, exited{}, kernel{}, user{};
        if (GetThreadTimes(thread, &created, &exited, &kernel, &user)) {
            ULARGE_INTEGER k{}, u{};
            k.LowPart = kernel.dwLowDateTime; k.HighPart = kernel.dwHighDateTime;
            u.LowPart = user.dwLowDateTime; u.HighPart = user.dwHighDateTime;
            result.emplace_back(entry.th32ThreadID, static_cast<double>(k.QuadPart + u.QuadPart) / 10000000.0);
        }
        CloseHandle(thread);
    }
    CloseHandle(snap);
    return result;
#endif
}

void BenchThreadsMark(bool begin) {
    static std::vector<std::pair<unsigned long, double>> start;
    const char* flag = std::getenv("XTCP_BENCH_THREADS");
    if (flag == nullptr || flag[0] != '1') return;
    if (begin) {
        start = SnapshotThreadCpu();
        return;
    }
    for (const auto& item : SnapshotThreadCpu()) {
        double before = 0;
        for (const auto& old : start) {
            if (old.first == item.first) before = old.second;
        }
        if (item.second - before > 0.01) {
            std::fprintf(stderr, "THREAD %lu cpu=%.3f\n", static_cast<unsigned long>(item.first), item.second - before);
        }
    }
}

#if defined(_WIN32)
// Benchmark knob: XTCP_BENCH_PROFILE=io|main samples one thread's call stack
// every ~1ms (SuspendThread + RtlVirtualUnwind, no allocation while the target
// is suspended) and prints self/inclusive hot functions after the run. Needs a
// build with PDBs to symbolize; timer resolution is raised to 1 ms while active.
std::size_t WalkSuspendedStack(CONTEXT* ctx, DWORD64* out, std::size_t max_frames) noexcept {
    std::size_t n = 0;
    __try {
        while (n < max_frames && ctx->Rip != 0) {
            out[n++] = ctx->Rip;
            DWORD64 image_base = 0;
            PRUNTIME_FUNCTION function = RtlLookupFunctionEntry(ctx->Rip, &image_base, nullptr);
            if (function == nullptr) {
                ctx->Rip = *reinterpret_cast<DWORD64*>(ctx->Rsp);
                ctx->Rsp += 8;
            }
            else {
                PVOID handler_data = nullptr;
                DWORD64 establisher = 0;
                RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, ctx->Rip, function, ctx,
                    &handler_data, &establisher, nullptr);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return n;
}

class StackSampler final {
public:
    static constexpr std::size_t kMaxSamples = 60000;
    static constexpr std::size_t kDepth = 48;

    void Start(HANDLE thread) {
        thread_ = thread;
        frames_.assign(kMaxSamples * kDepth, 0);
        depths_.assign(kMaxSamples, 0);
        timeBeginPeriod(1);
        worker_ = std::thread([this]() {
            while (!stop_.load(std::memory_order_relaxed) && count_ < kMaxSamples) {
                if (SuspendThread(thread_) != static_cast<DWORD>(-1)) {
                    CONTEXT ctx{};
                    ctx.ContextFlags = CONTEXT_FULL;
                    if (GetThreadContext(thread_, &ctx)) {
                        depths_[count_] = static_cast<std::uint8_t>(
                            WalkSuspendedStack(&ctx, &frames_[count_ * kDepth], kDepth));
                        ++count_;
                    }
                    ResumeThread(thread_);
                }
                Sleep(1);
            }
        });
    }

    void StopAndReport(const char* label) {
        stop_.store(true);
        if (worker_.joinable()) worker_.join();
        timeEndPeriod(1);
        const HANDLE process = GetCurrentProcess();
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
        SymInitialize(process, nullptr, TRUE);
        std::map<DWORD64, std::string> names;
        const auto name_of = [&](DWORD64 address) -> const std::string& {
            auto found = names.find(address);
            if (found != names.end()) return found->second;
            alignas(SYMBOL_INFO) char buffer[sizeof(SYMBOL_INFO) + 512] = {};
            auto* symbol = reinterpret_cast<SYMBOL_INFO*>(buffer);
            symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
            symbol->MaxNameLen = 511;
            DWORD64 displacement = 0;
            std::string name = SymFromAddr(process, address, &displacement, symbol)
                ? std::string(symbol->Name, symbol->NameLen) : std::string("?");
            if (name.size() > 150) name.resize(150);
            return names.emplace(address, std::move(name)).first->second;
        };
        std::map<std::string, std::size_t> self, inclusive;
        for (std::size_t i = 0; i < count_; ++i) {
            const DWORD64* frames = &frames_[i * kDepth];
            if (depths_[i] == 0) continue;
            ++self[name_of(frames[0])];
            std::vector<std::string> seen;
            for (std::size_t f = 0; f < depths_[i]; ++f) {
                const std::string& name = name_of(frames[f]);
                if (std::find(seen.begin(), seen.end(), name) == seen.end()) {
                    seen.push_back(name);
                    ++inclusive[name];
                }
            }
        }
        const auto print = [&](const char* title, const std::map<std::string, std::size_t>& table, std::size_t top) {
            std::vector<std::pair<std::size_t, std::string>> rows;
            for (const auto& item : table) rows.emplace_back(item.second, item.first);
            std::sort(rows.rbegin(), rows.rend());
            std::fprintf(stderr, "PROFILE %s %s (samples=%zu)\n", label, title, count_);
            for (std::size_t i = 0; i < rows.size() && i < top; ++i) {
                std::fprintf(stderr, "  %5.1f%%  %s\n", 100.0 * rows[i].first / (count_ ? count_ : 1), rows[i].second.c_str());
            }
        };
        print("self", self, 40);
        print("inclusive", inclusive, 60);
        SymCleanup(process);
    }

private:
    HANDLE thread_ = nullptr;
    std::thread worker_;
    std::atomic<bool> stop_{false};
    std::vector<DWORD64> frames_;
    std::vector<std::uint8_t> depths_;
    std::size_t count_ = 0;
};
#else
// Benchmark knob (Linux): XTCP_BENCH_PROFILE=io|main interrupts one thread
// every ~1ms with a real-time signal (tgkill) and records backtrace() into a
// preallocated buffer from the handler. Report symbolizes the test binary with
// addr2line (build with -g) and other modules via dladdr.
namespace linux_sampler {
constexpr std::size_t kMaxSamples = 60000;
constexpr int kDepth = 48;
void* g_frames[kMaxSamples][kDepth];
int g_depths[kMaxSamples];
std::atomic<std::size_t> g_count{0};

void OnSample(int, siginfo_t*, void*) {
    const std::size_t index = g_count.load(std::memory_order_relaxed);
    if (index >= kMaxSamples) return;
    g_depths[index] = ::backtrace(g_frames[index], kDepth);
    g_count.store(index + 1, std::memory_order_release);
}
} // namespace linux_sampler

class StackSampler final {
public:
    void Start(long tid) {
        void* warm[4];
        (void)::backtrace(warm, 4);  // load the unwinder outside the handler
        struct sigaction action{};
        action.sa_sigaction = &linux_sampler::OnSample;
        action.sa_flags = SA_SIGINFO | SA_RESTART;
        sigemptyset(&action.sa_mask);
        ::sigaction(SIGRTMIN + 3, &action, nullptr);
        worker_ = std::thread([this, tid]() {
            const pid_t pid = ::getpid();
            while (!stop_.load(std::memory_order_relaxed) &&
                linux_sampler::g_count.load(std::memory_order_relaxed) < linux_sampler::kMaxSamples) {
                ::syscall(SYS_tgkill, pid, tid, SIGRTMIN + 3);
                const timespec delay{0, 1000000};
                ::nanosleep(&delay, nullptr);
            }
        });
    }

    void StopAndReport(const char* label) {
        stop_.store(true);
        if (worker_.joinable()) worker_.join();
        const std::size_t count = linux_sampler::g_count.load(std::memory_order_acquire);
        // Resolve addresses: main-binary frames through addr2line, others by dladdr.
        std::map<void*, std::string> names;
        std::vector<std::pair<void*, unsigned long>> exe_frames;
        Dl_info self_info{};
        ::dladdr(reinterpret_cast<void*>(&linux_sampler::OnSample), &self_info);
        for (std::size_t i = 0; i < count; ++i) {
            for (int f = 0; f < linux_sampler::g_depths[i]; ++f) {
                void* address = linux_sampler::g_frames[i][f];
                if (names.count(address)) continue;
                Dl_info info{};
                if (::dladdr(address, &info) && info.dli_fbase == self_info.dli_fbase) {
                    // Return addresses point after the call; -1 lands inside it.
                    exe_frames.emplace_back(address, reinterpret_cast<unsigned long>(address) -
                        reinterpret_cast<unsigned long>(info.dli_fbase) - (f == 0 ? 0 : 1));
                    names[address] = "?";
                }
                else if (info.dli_sname != nullptr) {
                    int status = 0;
                    char* demangled = abi::__cxa_demangle(info.dli_sname, nullptr, nullptr, &status);
                    names[address] = demangled != nullptr ? demangled : info.dli_sname;
                    std::free(demangled);
                }
                else {
                    names[address] = info.dli_fname != nullptr ? info.dli_fname : "?";
                }
            }
        }
        if (!exe_frames.empty() && self_info.dli_fname != nullptr) {
            const std::string list = "/tmp/xtcp_prof_addrs.txt";
            {
                std::ofstream out(list);
                for (const auto& item : exe_frames) out << std::hex << "0x" << item.second << "\n";
            }
            const std::string command = std::string("addr2line -f -C -e /proc/") +
                std::to_string(::getpid()) + "/exe < " + list;
            if (FILE* pipe = ::popen(command.c_str(), "r")) {
                char line[4096];
                for (const auto& item : exe_frames) {
                    if (!std::fgets(line, sizeof(line), pipe)) break;
                    std::string name(line);
                    while (!name.empty() && (name.back() == '\n' || name.back() == '\r')) name.pop_back();
                    if (name.size() > 150) name.resize(150);
                    names[item.first] = name;
                    if (!std::fgets(line, sizeof(line), pipe)) break;  // file:line
                }
                ::pclose(pipe);
            }
        }
        std::map<std::string, std::size_t> self, inclusive;
        for (std::size_t i = 0; i < count; ++i) {
            // Skip the handler and the signal trampoline frames.
            const int first = linux_sampler::g_depths[i] > 2 ? 2 : 0;
            if (linux_sampler::g_depths[i] <= first) continue;
            ++self[names[linux_sampler::g_frames[i][first]]];
            std::vector<std::string> seen;
            for (int f = first; f < linux_sampler::g_depths[i]; ++f) {
                const std::string& name = names[linux_sampler::g_frames[i][f]];
                if (std::find(seen.begin(), seen.end(), name) == seen.end()) {
                    seen.push_back(name);
                    ++inclusive[name];
                }
            }
        }
        const auto print = [&](const char* title, const std::map<std::string, std::size_t>& table, std::size_t top) {
            std::vector<std::pair<std::size_t, std::string>> rows;
            for (const auto& item : table) rows.emplace_back(item.second, item.first);
            std::sort(rows.rbegin(), rows.rend());
            std::fprintf(stderr, "PROFILE %s %s (samples=%zu)\n", label, title, count);
            for (std::size_t i = 0; i < rows.size() && i < top; ++i) {
                std::fprintf(stderr, "  %5.1f%%  %s\n", 100.0 * rows[i].first / (count ? count : 1), rows[i].second.c_str());
            }
        };
        print("self", self, 40);
        print("inclusive", inclusive, 60);
    }

private:
    std::thread worker_;
    std::atomic<bool> stop_{false};
};
#endif

void PrintThroughput(const char* name, std::uint64_t bytes, double elapsed,
        double cpu, std::uint64_t dropped, std::uint64_t duplicates, std::uint16_t peer_mss = 0) {
    std::printf("{\"benchmark\":\"%s\",\"payload_bytes\":%llu,\"seconds\":%.6f,"
        "\"mbps\":%.3f,\"process_cpu_seconds\":%.6f,\"cpu_ns_per_byte\":%.3f,"
        "\"byte_exact\":true,\"ingress_dropped\":%llu,\"duplicate_packets\":%llu,"
        "\"connections\":1,\"warmup_seconds\":1,\"window_bytes\":%zu,\"chunk_bytes\":%zu,\"synthetic_peer_mss\":%u,"
        "\"segments\":%llu,\"cpu_ns_per_segment\":%.1f}\n",
        name, static_cast<unsigned long long>(bytes), elapsed,
        static_cast<double>(bytes) * 8.0 / elapsed / 1000000.0, cpu,
        cpu * 1000000000.0 / static_cast<double>(bytes),
        static_cast<unsigned long long>(dropped),
        static_cast<unsigned long long>(duplicates), BenchmarkWindow(), BenchmarkChunk(),
        static_cast<unsigned>(peer_mss),
        static_cast<unsigned long long>(g_bench_segments_end - g_bench_segments_start),
        g_bench_segments_end > g_bench_segments_start
            ? cpu * 1000000000.0 / static_cast<double>(g_bench_segments_end - g_bench_segments_start) : 0.0);
}

// Direct-bridge echo peer for the throughput benchmark: stands in for the
// production direct second leg (OPENPPP2_XTCP_MEMORY_BRIDGE=1), so no
// loopback TCP socket sits between XTCP and the peer. Uploaded bytes are
// queued and echoed back from a separate pump thread (the transmission
// thread in production) as <=16 KiB download reservations, one in flight.
class DirectEchoLeg final : public XtcpSecondLegHooks {
public:
    static constexpr std::size_t kChunk = 16 * 1024;

    void Bind(const AcceptedFlow& flow) {
        std::lock_guard<std::mutex> lock(sync_);
        hooks_ = flow.hooks;
        runtime_generation_ = flow.runtime_generation;
        flow_generation_ = flow.flow_generation;
    }

    void StartPump() {
        pump_ = std::thread([this]() { Pump(); });
    }

    void StopPump() {
        {
            std::lock_guard<std::mutex> lock(sync_);
            stop_ = true;
            pump_parked_ = false;
        }
        wake_.notify_all();
        if (pump_.joinable()) pump_.join();
    }

    ~DirectEchoLeg() override { StopPump(); }

    XtcpDirectResult SendToPeer(const std::uint8_t* data, std::uint32_t length,
        ppp::app::client::xtcp::XtcpUploadBudget::Reservation&& credit) noexcept override {
        if (data == nullptr || length == 0) {
            return XtcpDirectResult::Closed;
        }
        bool wake = false;
        try {
            std::lock_guard<std::mutex> lock(sync_);
            pending_.insert(pending_.end(), data, data + length);
            credits_.push_back(std::move(credit));
            credit_bytes_.push_back(length);
            // Only a parked pump needs a futex wake; a busy one re-checks.
            // With batching the wake waits for FlushPeerSend().
            if (!batching_) wake = std::exchange(pump_parked_, false);
        }
        catch (...) {
            return XtcpDirectResult::Backpressured;
        }
        uploaded_.fetch_add(length, std::memory_order_relaxed);
        if (wake) wake_.notify_one();
        return XtcpDirectResult::Accepted;
    }

    void OnDownloadComplete(const XtcpDirectReadReservation&,
        XtcpDirectCompletion completion) noexcept override {
        bool wake = false;
        {
            std::lock_guard<std::mutex> lock(sync_);
            in_flight_ = false;
            if (completion == XtcpDirectCompletion::Terminal) closed_ = true;
            wake = std::exchange(pump_parked_, false);
        }
        if (wake) wake_.notify_one();
    }

    void ClosePeerSend() noexcept override {}

    bool BatchesPeerSend() const noexcept override { return batching_; }

    void FlushPeerSend() noexcept override {
        bool wake = false;
        {
            std::lock_guard<std::mutex> lock(sync_);
            wake = std::exchange(pump_parked_, false);
        }
        if (wake) wake_.notify_one();
    }

    std::uint64_t EchoedBytes() const noexcept { return echoed_.load(std::memory_order_relaxed); }
    std::uint64_t UploadedBytes() const noexcept { return uploaded_.load(std::memory_order_relaxed); }

private:
    void Pump() {
        std::unique_lock<std::mutex> lock(sync_);
        for (;;) {
            while (!(stop_ || closed_ || (!in_flight_ && !pending_.empty()))) {
                pump_parked_ = true;
                wake_.wait(lock);
            }
            pump_parked_ = false;
            if (stop_ || closed_) return;
            const std::size_t count = std::min(pending_.size(), kChunk);
            const std::shared_ptr<std::uint8_t> payload(
                new std::uint8_t[count], std::default_delete<std::uint8_t[]>());
            std::copy(pending_.begin(), pending_.begin() + static_cast<std::ptrdiff_t>(count), payload.get());
            XtcpDirectReadReservation reservation;
            reservation.runtime_generation = runtime_generation_;
            reservation.flow_generation = flow_generation_;
            reservation.length = static_cast<std::uint32_t>(count);
            const std::shared_ptr<XtcpFirstLegHooks> hooks = hooks_.lock();
            in_flight_ = true;
            lock.unlock();
            const XtcpDirectResult result = hooks
                ? hooks->OnSecondLegPayload(reservation, payload) : XtcpDirectResult::Closed;
            lock.lock();
            if (result == XtcpDirectResult::Accepted) {
                pending_.erase(pending_.begin(), pending_.begin() + static_cast<std::ptrdiff_t>(count));
                echoed_.fetch_add(count, std::memory_order_relaxed);
                // Upload credit is held until the bytes leave this peer.
                std::size_t released = count;
                while (released != 0 && !credit_bytes_.empty()) {
                    if (credit_bytes_.front() <= released) {
                        released -= credit_bytes_.front();
                        credit_bytes_.pop_front();
                        credits_.pop_front();
                    }
                    else {
                        credit_bytes_.front() -= released;
                        released = 0;
                    }
                }
            }
            else if (result == XtcpDirectResult::Closed) {
                closed_ = true;
                return;
            }
            else {
                in_flight_ = false;
                wake_.wait_for(lock, std::chrono::microseconds(100));
            }
        }
    }

    std::mutex sync_;
    std::condition_variable wake_;
    std::thread pump_;
    std::weak_ptr<XtcpFirstLegHooks> hooks_;
    std::uint64_t runtime_generation_ = 0;
    std::uint64_t flow_generation_ = 0;
    std::deque<std::uint8_t> pending_;
    std::deque<ppp::app::client::xtcp::XtcpUploadBudget::Reservation> credits_;
    std::deque<std::size_t> credit_bytes_;
    bool in_flight_ = false;
    bool closed_ = false;
    bool stop_ = false;
    bool pump_parked_ = false;
    // XTCP_BENCH_DIRECT_BATCH=0 disables the FlushPeerSend batching opt-in.
    const bool batching_ = []() {
        const char* env = std::getenv("XTCP_BENCH_DIRECT_BATCH");
        return env == nullptr || env[0] != '0';
    }();
    std::atomic<std::uint64_t> echoed_{0};
    std::atomic<std::uint64_t> uploaded_{0};
};

bool BenchmarkDirectBridge() {
    const char* bench = std::getenv("XTCP_BENCH_DIRECT");
    const char* memory = std::getenv("OPENPPP2_XTCP_MEMORY_BRIDGE");
    return (bench != nullptr && bench[0] == '1') || (memory != nullptr && memory[0] == '1');
}

int RunXtcpThroughput(int seconds) {
    const auto pattern = BenchmarkPattern();
    Bridge bridge;
    if (!bridge.StartRuntime(0, true)) throw std::runtime_error("XTCP start failed");
    const bool direct = BenchmarkDirectBridge();
    const std::shared_ptr<DirectEchoLeg> echo_leg = direct ? std::make_shared<DirectEchoLeg>() : nullptr;
    std::uint32_t client_initial = 0, server_initial = 0;
    std::uint8_t runtime_wscale = 0xFF;
    // XTCP_BENCH_WSCALE=0 keeps the synthetic SYN without the window-scale option.
    const char* wscale_env = std::getenv("XTCP_BENCH_WSCALE");
    const bool window_scaling = wscale_env == nullptr || wscale_env[0] != '0';
    if (!Handshake(bridge, kClientPort, client_initial, server_initial, kBenchmarkMss, echo_leg,
            window_scaling, &runtime_wscale)) {
        throw std::runtime_error("XTCP handshake failed");
    }
    if (echo_leg) {
        echo_leg->Bind(bridge.LastAccepted());
        echo_leg->StartPump();
    }
    std::uint64_t sent = 0, received = 0, acknowledged = 0, duplicates = 0;
    StackSampler sampler;
    const char* profile_target = std::getenv("XTCP_BENCH_PROFILE");
#if !defined(_WIN32)
    const long main_tid = static_cast<long>(::syscall(SYS_gettid));
#else
    HANDLE main_thread = nullptr;
    if (profile_target != nullptr && std::strcmp(profile_target, "main") == 0) {
        DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &main_thread,
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, 0);
    }
#endif
    std::uint32_t receive_window = 65535;
    const auto warmup_start = std::chrono::steady_clock::now();
    const auto warmup_deadline = warmup_start + std::chrono::seconds(1);
    const auto send_deadline = warmup_deadline + std::chrono::seconds(seconds);
    const auto hard_deadline = send_deadline + std::chrono::seconds(10);
    std::chrono::steady_clock::time_point start{};
    double cpu_start = 0;
    std::uint64_t warmup_bytes = 0;
    bool measured = false;
    bool finished = false;
    std::chrono::steady_clock::time_point finish{};
    double cpu_end = 0;
    std::uint64_t finish_bytes = 0;
    while (std::chrono::steady_clock::now() < send_deadline || received < sent) {
        if (std::chrono::steady_clock::now() >= hard_deadline) {
            throw std::runtime_error("XTCP transfer/drain timeout");
        }
        if (!measured && std::chrono::steady_clock::now() >= warmup_deadline) {
            start = std::chrono::steady_clock::now();
            cpu_start = ProcessCpuSeconds();
            BenchThreadsMark(true);
            if (profile_target != nullptr) {
#if defined(_WIN32)
                sampler.Start(main_thread != nullptr ? main_thread : bridge.IoThreadHandle());
#else
                sampler.Start(std::strcmp(profile_target, "main") == 0 ? main_tid : bridge.IoThreadId());
#endif
            }
            warmup_bytes = received;
            g_bench_segments_start = g_bench_segments;
            measured = true;
        }
        if (measured && !finished && std::chrono::steady_clock::now() >= send_deadline) {
            finish = std::chrono::steady_clock::now();
            cpu_end = ProcessCpuSeconds();
            BenchThreadsMark(false);
            finish_bytes = received;
            g_bench_segments_end = g_bench_segments;
            finished = true;
        }
        bool progress = false;
        std::deque<std::vector<Byte>> packets;
        bridge.DrainOutput(packets);
        bool need_ack = false;
        for (const auto& packet : packets) {
            TcpView view;
            if (!ParseTcp(packet, view) || view.dport != kClientPort ||
                (view.flags & (kRst | kFin)) != 0) {
                throw std::runtime_error("unexpected XTCP output");
            }
            if ((view.flags & kAck) != 0) {
                const std::int32_t advance = static_cast<std::int32_t>(view.ack -
                    (client_initial + static_cast<std::uint32_t>(acknowledged)));
                if (advance >= 0) {
                    if (acknowledged + static_cast<std::uint32_t>(advance) > sent) {
                        throw std::runtime_error("XTCP ACK beyond sent bytes");
                    }
                    acknowledged += static_cast<std::uint32_t>(advance);
                    receive_window = runtime_wscale <= 14
                        ? static_cast<std::uint32_t>(view.window) << runtime_wscale
                        : static_cast<std::uint32_t>(view.window);
                }
            }
            if (!view.payload.empty()) {
                const std::uint32_t expected = server_initial + static_cast<std::uint32_t>(received);
                if (view.seq == expected) {
                    if (received + view.payload.size() > sent ||
                        !CheckBenchmarkBytes(pattern, received, view.payload.data(), view.payload.size())) {
                        throw std::runtime_error("XTCP echo byte mismatch");
                    }
                    received += view.payload.size();
                }
                else if (static_cast<std::int32_t>(view.seq - expected) < 0 &&
                    static_cast<std::int32_t>(view.seq - expected) +
                    static_cast<std::int32_t>(view.payload.size()) <= 0) {
                    ++duplicates;
                }
                else {
                    throw std::runtime_error("XTCP output sequence gap/overlap");
                }
                need_ack = true;
            }
            progress = true;
        }
        if (need_ack) {
            const auto ack = xtcp::harness::BuildIp4Tcp(kClientIp, kServiceIp,
                kClientPort, kServicePort, client_initial + static_cast<std::uint32_t>(sent),
                server_initial + static_cast<std::uint32_t>(received), kAck);
            if (!bridge.TrySubmit(ack)) throw std::runtime_error("XTCP ACK admission rejected");
        }
        while (std::chrono::steady_clock::now() < send_deadline &&
            sent - received < BenchmarkWindow() && sent < acknowledged + receive_window) {
            const std::size_t position = static_cast<std::size_t>(sent % pattern.size());
            const std::size_t count = std::min({BenchmarkChunk(),
                BenchmarkWindow() - static_cast<std::size_t>(sent - received),
                static_cast<std::size_t>(acknowledged + receive_window - sent),
                pattern.size() - position});
            const auto packet = xtcp::harness::BuildIp4Tcp(kClientIp, kServiceIp,
                kClientPort, kServicePort, client_initial + static_cast<std::uint32_t>(sent),
                server_initial + static_cast<std::uint32_t>(received), kAck,
                pattern.data() + position, static_cast<UInt32>(count));
            if (!bridge.TrySubmit(packet)) throw std::runtime_error("XTCP data admission rejected");
            sent += count;
            ++g_bench_segments;
            progress = true;
        }
        if (!progress) std::this_thread::yield();
    }
    if (!finished) {
        finish = std::chrono::steady_clock::now();
        cpu_end = ProcessCpuSeconds();
        finish_bytes = received;
        g_bench_segments_end = g_bench_segments;
    }
    if (profile_target != nullptr && measured) {
        sampler.StopAndReport(profile_target);
    }
#if defined(_WIN32)
    if (main_thread != nullptr) CloseHandle(main_thread);
#endif
    if (!measured || finish_bytes <= warmup_bytes) {
        throw std::runtime_error("no measured payload after warmup");
    }
    const double elapsed = std::chrono::duration<double>(finish - start).count();
    const double cpu = cpu_end - cpu_start;
    const auto stats = bridge.Stats();
    const bool counters_ok = echo_leg
        ? echo_leg->EchoedBytes() == received && echo_leg->UploadedBytes() == sent
        : bridge.echo_->EchoedBytes() == received && stats.connector_written_bytes == sent;
    if (echo_leg) echo_leg->StopPump();
    if (received == 0 || stats.ingress_dropped != 0 || !counters_ok) {
        throw std::runtime_error("XTCP transfer counters did not qualify");
    }
    PrintThroughput(echo_leg ? "xtcp_runtime_direct_bridge" : "xtcp_runtime_synthetic_loopback", finish_bytes - warmup_bytes, elapsed, cpu,
        stats.ingress_dropped, duplicates, kBenchmarkMss);
    return 0;
}

class NativeLoopback final {
public:
    NativeLoopback() : server_(std::make_shared<EchoServer>(context_, 0)),
        socket_(context_), guard_(context_.get_executor()) {
        server_->Start();
        socket_.connect(server_->Endpoint());
        socket_.non_blocking(true);
        thread_ = std::thread([this]() { context_.run(); });
    }
    ~NativeLoopback() {
        context_.stop();
        if (thread_.joinable()) thread_.join();
    }
    boost::asio::ip::tcp::socket& Socket() { return socket_; }
    std::uint64_t EchoedBytes() const { return server_->EchoedBytes(); }
private:
    boost::asio::io_context context_;
    std::shared_ptr<EchoServer> server_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> guard_;
    std::thread thread_;
};

int RunWinsockThroughput(int seconds) {
    const auto pattern = BenchmarkPattern();
    NativeLoopback native;
    std::vector<Byte> buffer(BenchmarkWindow());
    std::uint64_t sent = 0, received = 0;
    const auto warmup_start = std::chrono::steady_clock::now();
    const auto warmup_deadline = warmup_start + std::chrono::seconds(1);
    const auto send_deadline = warmup_deadline + std::chrono::seconds(seconds);
    const auto hard_deadline = send_deadline + std::chrono::seconds(10);
    std::chrono::steady_clock::time_point start{};
    double cpu_start = 0;
    std::uint64_t warmup_bytes = 0;
    bool measured = false;
    bool finished = false;
    std::chrono::steady_clock::time_point finish{};
    double cpu_end = 0;
    std::uint64_t finish_bytes = 0;
    while (std::chrono::steady_clock::now() < send_deadline || received < sent) {
        if (std::chrono::steady_clock::now() >= hard_deadline) {
            throw std::runtime_error("Winsock transfer/drain timeout");
        }
        if (!measured && std::chrono::steady_clock::now() >= warmup_deadline) {
            start = std::chrono::steady_clock::now();
            cpu_start = ProcessCpuSeconds();
            BenchThreadsMark(true);
            warmup_bytes = received;
            g_bench_segments_start = g_bench_segments;
            measured = true;
        }
        if (measured && !finished && std::chrono::steady_clock::now() >= send_deadline) {
            finish = std::chrono::steady_clock::now();
            cpu_end = ProcessCpuSeconds();
            BenchThreadsMark(false);
            finish_bytes = received;
            g_bench_segments_end = g_bench_segments;
            finished = true;
        }
        bool progress = false;
        boost::system::error_code ec;
        const auto read = native.Socket().read_some(boost::asio::buffer(buffer), ec);
        if (ec && ec != boost::asio::error::would_block && ec != boost::asio::error::try_again) {
            throw std::runtime_error("Winsock read failed");
        }
        if (!ec && read != 0) {
            if (received + read > sent || !CheckBenchmarkBytes(pattern, received, buffer.data(), read)) {
                throw std::runtime_error("Winsock echo byte mismatch");
            }
            received += read;
            progress = true;
        }
        while (std::chrono::steady_clock::now() < send_deadline && sent - received < BenchmarkWindow()) {
            const std::size_t position = static_cast<std::size_t>(sent % pattern.size());
            const std::size_t count = std::min({BenchmarkChunk(),
                BenchmarkWindow() - static_cast<std::size_t>(sent - received), pattern.size() - position});
            const auto written = native.Socket().write_some(boost::asio::buffer(pattern.data() + position, count), ec);
            if (ec == boost::asio::error::would_block || ec == boost::asio::error::try_again) break;
            if (ec || written == 0) throw std::runtime_error("Winsock write failed");
            sent += written;
            ++g_bench_segments;
            progress = true;
        }
        if (!progress) std::this_thread::yield();
    }
    if (!finished) {
        finish = std::chrono::steady_clock::now();
        cpu_end = ProcessCpuSeconds();
        finish_bytes = received;
        g_bench_segments_end = g_bench_segments;
    }
    if (!measured || finish_bytes <= warmup_bytes) {
        throw std::runtime_error("no measured payload after warmup");
    }
    const double elapsed = std::chrono::duration<double>(finish - start).count();
    const double cpu = cpu_end - cpu_start;
    if (received == 0 || native.EchoedBytes() != received) {
        throw std::runtime_error("Winsock transfer counters did not qualify");
    }
#if defined(_WIN32)
    PrintThroughput("winsock_tcp_loopback_reference", finish_bytes - warmup_bytes, elapsed, cpu, 0, 0);
#else
    PrintThroughput("kernel_tcp_loopback_reference", finish_bytes - warmup_bytes, elapsed, cpu, 0, 0);
#endif
    return 0;
}
} // namespace

int main(int argc, char** argv) {
    if (argc == 3 && std::strcmp(argv[1], "--pressure") == 0) {
        if (std::strcmp(argv[2], "ordinary") != 0 && std::strcmp(argv[2], "large") != 0 &&
            std::strcmp(argv[2], "split0") != 0 && std::strcmp(argv[2], "split1") != 0 &&
            std::strcmp(argv[2], "split2") != 0) return 2;
        xtcp::buf::InitPools();
        TestIngressPressure(argv[2]);
        xtcp::buf::ShutdownPools();
        return failures ? 1 : 0;
    }
#if defined(_WIN32)
    if (!SetTestEnvironment("OPENPPP2_XTCP_SHARDS", "1") ||
        // Functional cases pin kcc; the throughput benchmark uses the runtime
        // default (cubic on Windows) unless XTCP_BENCH_CC overrides it.
        !SetTestEnvironment("OPENPPP2_XTCP_CC",
            std::getenv("XTCP_BENCH_CC") != nullptr ? std::getenv("XTCP_BENCH_CC")
                : (argc == 1 ? "kcc" : nullptr)) ||
        !SetTestEnvironment("OPENPPP2_XTCP_PERF_JSON", nullptr)) {
        std::fprintf(stderr, "FAIL: could not configure Windows XTCP test environment\n");
        return 1;
    }
#else
    // Functional cases pin the AF_UNIX bridge. The throughput benchmark keeps
    // the production defaults (loopback TCP bridge, kcc) unless
    // XTCP_BENCH_UNIX_BRIDGE / XTCP_BENCH_CC override them.
    if (argc == 1) {
        (void)SetTestEnvironment("OPENPPP2_XTCP_UNIX_BRIDGE", "1");
    }
    else {
        (void)SetTestEnvironment("OPENPPP2_XTCP_SHARDS", "1");
        (void)SetTestEnvironment("OPENPPP2_XTCP_PERF_JSON", nullptr);
        (void)SetTestEnvironment("OPENPPP2_XTCP_UNIX_BRIDGE", std::getenv("XTCP_BENCH_UNIX_BRIDGE"));
        (void)SetTestEnvironment("OPENPPP2_XTCP_CC", std::getenv("XTCP_BENCH_CC"));
    }
#endif
#if defined(_WIN32)
    // Benchmark knob: XTCP_BENCH_TIMER1MS=1 raises the Windows timer
    // resolution to 1 ms (diagnoses timer-granularity bound paths).
    if (const char* t = std::getenv("XTCP_BENCH_TIMER1MS"); t != nullptr && t[0] == '1') {
        timeBeginPeriod(1);
    }
#endif
    if (argc != 1) {
        // "winsock" is kept as the reference-mode name; "native" is an alias
        // (on Linux it is the kernel TCP loopback).
        if (argc != 4 || std::strcmp(argv[1], "--throughput") != 0 ||
            (std::strcmp(argv[2], "xtcp") != 0 && std::strcmp(argv[2], "winsock") != 0 &&
             std::strcmp(argv[2], "native") != 0)) {
            std::fprintf(stderr, "Usage: xtcp_runtime_bridge_test --throughput xtcp|native seconds\n");
            return 2;
        }
        char* end = nullptr;
        const long seconds = std::strtol(argv[3], &end, 10);
        if (end == argv[3] || *end != '\0' || seconds < 1 || seconds > 15) return 2;
        try {
            const int result = std::strcmp(argv[2], "xtcp") == 0
                ? RunXtcpThroughput(static_cast<int>(seconds))
                : RunWinsockThroughput(static_cast<int>(seconds));
            return failures == 0 ? result : 1;
        }
        catch (const std::exception& ex) {
            std::fprintf(stderr, "THROUGHPUT FAILED: %s\n", ex.what());
            return 1;
        }
    }
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
#if !defined(_WIN32)
    TestRejectedExternalAcceptOwnsBridgeFd();
#endif
    xtcp::buf::ShutdownPools();

    if (failures != 0) {
        std::fprintf(stderr, "xtcp_runtime_bridge_test: %d failure(s)\n", failures);
        return 1;
    }
    std::puts("xtcp_runtime_bridge_test: passed");
    return 0;
}

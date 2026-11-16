#pragma once

#include <ppp/app/client/udp/UdpRelayHost.h>
#include <ppp/app/client/udp/UdpFlowPolicy.h>
#include <ppp/app/client/policy/PolicyCompiler.h>
#include <ppp/app/client/policy/PolicyEvaluator.h>
#include <ppp/coroutines/YieldContext.h>
#include <array>
#include <atomic>
#include <chrono>
#include <deque>

namespace ppp::app::client::udp {
    class DirectDatagramFlow final : public std::enable_shared_from_this<DirectDatagramFlow> {
    public:
        using Endpoint = boost::asio::ip::udp::endpoint;
        using Packet = std::shared_ptr<std::vector<Byte>>;
        using Reply = std::function<void(const Endpoint&, void*, int)>;
        using Resolve = std::function<bool(ppp::coroutines::YieldContext&, boost::asio::ip::address&)>;
        using TunnelSend = std::function<bool(const Endpoint&, const void*, int)>;
        DirectDatagramFlow(const std::shared_ptr<boost::asio::io_context>& context,
            std::shared_ptr<void> owner, const Endpoint& target, const Endpoint& logical,
            ClientUnderlyingSocketProtector protector,
            std::shared_ptr<ppp::p2p::IP2PDatagramTransport> provider,
            std::shared_ptr<const policy::PolicySnapshot> snapshot, int idle_seconds, Reply reply,
            Resolve resolve = {}, TunnelSend tunnel_send = {}, std::string domain = "", bool tunnel = false,
            std::function<void()> on_close = {}, int resolution_timeout = 0, std::function<void()> on_reject = {})
            : context_(context), strand_(context->get_executor()), socket_(*context), timer_(*context),
              owner_(std::move(owner)), target_(target), logical_(logical), protector_(std::move(protector)),
              provider_(std::move(provider)), snapshot_(std::move(snapshot)),
              idle_(std::chrono::seconds(std::max(1, idle_seconds))), reply_(std::move(reply)),
              resolve_(std::move(resolve)), tunnel_send_(std::move(tunnel_send)), domain_(std::move(domain)),
              on_close_(std::move(on_close)), resolution_timeout_(std::chrono::seconds(std::max(1, resolution_timeout))),
              on_reject_(std::move(on_reject)), tunnel_(tunnel) {}

        bool IsClosed() const noexcept { return closed_.load(); }
        void TunnelReply(const Endpoint& remote, const void* data, int size) noexcept {
            auto self = shared_from_this();
            if (closed_ || !data || size < 1 || size > 65507) return;
            // Tunnel replies use this flow's private relay identity. Copy before
            // dispatch because the carrier's receive buffer is borrowed.
            bool admitted = false;
            try {
                std::lock_guard<std::mutex> lock(admission_);
                if (!UdpFlowQueueLimit::Allows(reply_packets_, reply_bytes_, size)) return;
                auto packet = std::make_shared<std::vector<Byte>>(static_cast<const Byte*>(data), static_cast<const Byte*>(data) + size);
                ++reply_packets_; reply_bytes_ += size;
                admitted = true;
                boost::asio::post(strand_, [self, remote, packet]() {
                    {
                        std::lock_guard<std::mutex> lock(self->admission_);
                        --self->reply_packets_; self->reply_bytes_ -= packet->size();
                    }
                    if (!self->closed_ && remote == self->target_ && self->reply_) {
                        self->Refresh(); self->reply_(self->logical_, packet->data(), static_cast<int>(packet->size()));
                    }
                });
            } catch (...) {
                if (admitted) { std::lock_guard<std::mutex> lock(admission_); --reply_packets_; reply_bytes_ -= size; }
            }
        }
        bool Send(const void* data, int size) noexcept {
            if (!data || size < 1 || !logical_.address().is_v4() || !logical_.port()) return false;
            bool admitted = false;
            try {
                std::lock_guard<std::mutex> lock(admission_);
                if (closed_ || !UdpFlowQueueLimit::Allows(packets_, bytes_, size)) return false;
                auto packet = std::make_shared<std::vector<Byte>>(static_cast<const Byte*>(data), static_cast<const Byte*>(data) + size);
                ++packets_; bytes_ += size;
                admitted = true;
                auto self = shared_from_this();
                boost::asio::post(strand_, [self, packet]() {
                    if (self->closed_) { self->Complete(packet); return; }
                    self->queue_.push_back(packet);
                    if (!self->started_) self->Start();
                    else if (self->ready_ && !self->sending_) self->Drain();
                });
                return true;
            } catch (...) {
                if (admitted) { std::lock_guard<std::mutex> lock(admission_); --packets_; bytes_ -= size; }
                return false;
            }
        }
        void Close() noexcept {
            if (closed_.exchange(true)) return;
            auto self = shared_from_this();
            boost::asio::post(strand_, [self]() { self->Stop(); });
        }
    private:
        void Complete(const Packet& packet) noexcept {
            std::lock_guard<std::mutex> lock(admission_);
            --packets_; bytes_ -= packet->size();
        }
        void Stop() noexcept {
            try { timer_.cancel(); }
            catch (...) {}
            boost::system::error_code ec;
            if (!protecting_) { socket_.cancel(ec); socket_.close(ec); }
            if (provider_) provider_->Close();
            while (!queue_.empty()) { Complete(queue_.front()); queue_.pop_front(); }
            reply_ = {};
            if (on_close_) { auto callback = std::move(on_close_); callback(); }
            snapshot_.reset(); resolve_ = {}; tunnel_send_ = {}; on_reject_ = {}; owner_.reset();
        }
        void Refresh(bool resolving = false) {
            timer_.expires_after(resolving ? resolution_timeout_ : idle_);
            auto self = shared_from_this();
            timer_.async_wait(boost::asio::bind_executor(strand_, [self](const boost::system::error_code& ec) {
                if (!ec) self->Close();
            }));
        }
        void Start() {
            started_ = true; Refresh(static_cast<bool>(resolve_));
            auto self = shared_from_this();
            if (resolve_) {
                auto resolver = resolve_;
                const bool spawned = ppp::coroutines::YieldContext::Spawn(nullptr, *context_,
                    [self, resolver](ppp::coroutines::YieldContext& y) noexcept {
                        boost::asio::ip::address address;
                        const bool resolved = !self->closed_ && resolver(y, address);
                        boost::asio::post(self->strand_, [self, resolved, address]() {
                            if (self->closed_) return;
                            if (!resolved || !address.is_v4() || address.is_unspecified()) { self->Close(); return; }
                            self->target_.address(address);
                            const auto decision = policy::PolicyEvaluator::Evaluate(*self->snapshot_, self->domain_, address.to_string());
                            if (decision.action == policy::PolicyAction::Reject) {
                                if (self->on_reject_) self->on_reject_();
                                self->Close(); return;
                            }
                            self->tunnel_ = decision.action == policy::PolicyAction::Proxy;
                            self->StartSocket();
                        });
                    });
                if (!spawned) Close();
                return;
            }
            StartSocket();
        }
        void StartSocket() {
            auto self = shared_from_this();
            snapshot_.reset();
            resolve_ = {};
            Refresh();
            if (tunnel_) { ready_ = true; Drain(); return; }
            if (provider_) {
                auto weak = std::weak_ptr<DirectDatagramFlow>(self);
                ready_ = provider_->IsReady() && provider_->Start([weak](ppp::p2p::P2PDatagramReceiveStatus status,
                    const Endpoint& remote, const uint8_t* packet, int size) {
                    auto flow = weak.lock();
                    if (!flow || flow->closed_ || status != ppp::p2p::P2PDatagramReceiveStatus::Packet ||
                        remote != flow->target_ || !packet || size < 1 || size > 65507) return;
                    bool admitted = false;
                    try {
                        std::lock_guard<std::mutex> lock(flow->admission_);
                        if (!UdpFlowQueueLimit::Allows(flow->reply_packets_, flow->reply_bytes_, size)) return;
                        auto copy = std::make_shared<std::vector<Byte>>(packet, packet + size);
                        ++flow->reply_packets_; flow->reply_bytes_ += size; admitted = true;
                        boost::asio::post(flow->strand_, [flow, copy]() {
                            {
                                std::lock_guard<std::mutex> lock(flow->admission_);
                                --flow->reply_packets_; flow->reply_bytes_ -= copy->size();
                            }
                            if (!flow->closed_ && flow->reply_) {
                                flow->Refresh(); flow->reply_(flow->logical_, copy->data(), static_cast<int>(copy->size()));
                            }
                        });
                    } catch (...) {
                        if (admitted) {
                            std::lock_guard<std::mutex> lock(flow->admission_);
                            --flow->reply_packets_; flow->reply_bytes_ -= size;
                        }
                    }
                });
                if (!ready_) { Close(); return; }
                Drain(); return;
            }
            if (!protector_) { Close(); return; }
            boost::system::error_code ec;
            socket_.open(boost::asio::ip::udp::v4(), ec);
            if (ec) { Close(); return; }
            const auto handle = static_cast<ClientUnderlyingSocketHandle>(socket_.native_handle());
            // Android protection may suspend; readiness and all socket I/O are
            // published back on the strand only after protection succeeds.
            protecting_ = true;
            bool spawned = ppp::coroutines::YieldContext::Spawn(nullptr, *context_,
                [self, handle](ppp::coroutines::YieldContext& y) noexcept {
                    const bool protected_socket = !self->closed_ && self->protector_(handle, y);
                    boost::asio::post(self->strand_, [self, protected_socket]() {
                        self->protecting_ = false;
                        if (self->closed_) { self->Stop(); return; }
                        if (!protected_socket) { self->Close(); return; }
                        boost::system::error_code error;
                        self->socket_.connect(self->target_, error);
                        if (error) { self->Close(); return; }
                        self->ready_ = true; self->Receive(); self->Drain();
                    });
                });
            if (!spawned) { protecting_ = false; Close(); }
        }
        void Drain() {
            if (closed_ || sending_ || !ready_ || queue_.empty()) return;
            sending_ = true;
            auto packet = queue_.front(); queue_.pop_front();
            auto self = shared_from_this();
            if (provider_ || tunnel_) {
                const bool sent = tunnel_
                    ? tunnel_send_ && tunnel_send_(target_, packet->data(), static_cast<int>(packet->size()))
                    : provider_->SendTo(packet->data(), static_cast<int>(packet->size()), target_);
                Complete(packet); sending_ = false;
                if (!sent) { Close(); return; }
                Refresh();
                boost::asio::post(strand_, [self]() { self->Drain(); });
                return;
            }
            socket_.async_send(boost::asio::buffer(*packet), boost::asio::bind_executor(strand_,
                [self, packet](const boost::system::error_code& ec, std::size_t size) {
                    self->Complete(packet); self->sending_ = false;
                    if (self->closed_) return;
                    if (ec || size != packet->size()) { self->Close(); return; }
                    self->Refresh(); self->Drain();
                }));
        }
        void Receive() {
            if (closed_) return;
            auto self = shared_from_this();
            socket_.async_receive_from(boost::asio::buffer(receive_), remote_, boost::asio::bind_executor(strand_,
                [self](const boost::system::error_code& ec, std::size_t size) {
                    if (self->closed_) return;
                    if (ec && ec != boost::asio::error::message_size) { self->Close(); return; }
                    if (!ec && self->remote_ == self->target_ && size > 0 && self->reply_) {
                        self->Refresh(); self->reply_(self->logical_, self->receive_.data(), static_cast<int>(size));
                    }
                    self->Receive();
                }));
        }
        std::shared_ptr<boost::asio::io_context> context_;
        boost::asio::strand<boost::asio::io_context::executor_type> strand_;
        boost::asio::ip::udp::socket socket_;
        boost::asio::steady_timer timer_;
        std::shared_ptr<void> owner_;
        Endpoint target_, logical_, remote_;
        ClientUnderlyingSocketProtector protector_;
        std::shared_ptr<ppp::p2p::IP2PDatagramTransport> provider_;
        std::shared_ptr<const policy::PolicySnapshot> snapshot_;
        std::chrono::seconds idle_;
        Reply reply_;
        Resolve resolve_;
        TunnelSend tunnel_send_;
        std::string domain_;
        std::function<void()> on_close_;
        std::chrono::seconds resolution_timeout_;
        std::function<void()> on_reject_;
        std::array<Byte, 65536> receive_{};
        std::atomic<bool> closed_{false};
        std::atomic<bool> protecting_{false};
        std::mutex admission_;
        std::size_t packets_ = 0, bytes_ = 0;
        std::size_t reply_packets_ = 0, reply_bytes_ = 0;
        std::deque<Packet> queue_;
        bool started_ = false, ready_ = false, sending_ = false;
        bool tunnel_ = false;
    };
}

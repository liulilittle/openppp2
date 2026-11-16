#include <ppp/app/client/PolicyTunnelDnsStream.h>

#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/coroutines/YieldContext.h>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/bind_executor.hpp>
#include <chrono>

namespace ppp::app::client::dns {
namespace {
using Tcp = boost::asio::ip::tcp;
using Bridge = ppp::app::protocol::VirtualEthernetTcpipConnection;

struct StreamOperation final : std::enable_shared_from_this<StreamOperation> {
    std::shared_ptr<VEthernetExchanger> exchanger;
    std::shared_ptr<boost::asio::io_context> context;
    std::shared_ptr<boost::asio::strand<boost::asio::io_context::executor_type>> strand;
    std::shared_ptr<Tcp::acceptor> listener;
    std::shared_ptr<Tcp::socket> peer;
    std::shared_ptr<Bridge> bridge;
    std::shared_ptr<ppp::transmissions::ITransmission> pending_transmission;
    ppp::function<void()> pending_cancel;
#if defined(_IPHONE)
    std::uint64_t child_slot = 0;
#endif
    std::shared_ptr<boost::asio::steady_timer> timer;
    PolicyTunnelDnsStream::ActiveCheck active;
    PolicyTunnelDnsStream::Completion completion;
    std::atomic_bool completed{false};
    std::atomic_bool stopped{false};
    std::string upstream_host;
    std::uint16_t upstream_port = 0;
    Tcp::endpoint expected_peer;
    std::chrono::steady_clock::time_point deadline;

    bool IsActive() const noexcept {
        if (!active) return true;
        try { return active(); }
        catch (...) { return false; }
    }

    void RegisterCancellation(const ppp::function<void()>& cancel) noexcept {
        if (stopped.load(std::memory_order_acquire)) {
            try { if (cancel) cancel(); }
            catch (...) {}
            return;
        }
        try {
            pending_cancel = cancel;
        } catch (...) {
            try { if (cancel) cancel(); }
            catch (...) {}
            Finish(boost::asio::error::no_memory);
            Stop();
        }
    }

    void Monitor() noexcept {
        if (stopped.load(std::memory_order_acquire)) return;
        if (!IsActive()) {
            Finish(boost::asio::error::operation_aborted);
            Stop();
            return;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            Finish(boost::asio::error::timed_out);
            Stop();
            return;
        }
        try {
            auto self = shared_from_this();
            timer->expires_after(std::chrono::milliseconds(25));
            timer->async_wait(boost::asio::bind_executor(*strand,
                [self](boost::system::error_code error) noexcept {
                    if (!error) self->Monitor();
                }));
        } catch (...) {
            Finish(boost::asio::error::no_memory);
            Stop();
        }
    }

    void Finish(boost::system::error_code error) noexcept {
        if (completed.exchange(true)) return;
        auto callback = std::move(completion);
        if (error) Stop();
        if (callback) callback(error);
    }

    void Stop() noexcept {
        if (stopped.exchange(true)) return;
        boost::system::error_code ignored;
        if (listener) listener->close(ignored);
        if (peer) peer->close(ignored);
        if (timer) {
            try { timer->cancel(); }
            catch (...) {}
        }
        auto cancel = std::move(pending_cancel);
        try { if (cancel) cancel(); }
        catch (...) {}
        if (pending_transmission) pending_transmission->Dispose();
        if (bridge) bridge->Dispose();
#if defined(_IPHONE)
        if (child_slot) {
            exchanger->ReleaseIosChildTransmissionSlot(child_slot);
            child_slot = 0;
        }
#endif
    }

    void BeginBridge() noexcept {
        if (stopped.load()) return;
        auto self = shared_from_this();
        const bool spawned = ppp::coroutines::YieldContext::Spawn(nullptr, *context, strand.get(),
            [self](ppp::coroutines::YieldContext& y) noexcept {
#if defined(_IPHONE)
                auto transmission = self->exchanger->ConnectTransmission(self->context, self->strand, y, &self->child_slot,
                    self->active, [self](const ppp::function<void()>& cancel) { self->RegisterCancellation(cancel); });
#else
                auto transmission = self->exchanger->ConnectTransmission(self->context, self->strand, y, NULLPTR,
                    self->active, [self](const ppp::function<void()>& cancel) { self->RegisterCancellation(cancel); });
#endif
                self->RegisterCancellation({});
                if (!transmission || self->stopped.load() || !self->IsActive()) {
                    if (transmission) transmission->Dispose();
#if defined(_IPHONE)
                    if (self->child_slot) {
                        self->exchanger->ReleaseIosChildTransmissionSlot(self->child_slot);
                        self->child_slot = 0;
                    }
#endif
                    self->Finish(boost::asio::error::connection_aborted);
                    return;
                }
                self->pending_transmission = transmission;
                self->bridge = make_shared_object<Bridge>(self->exchanger->GetConfiguration(),
                    self->context, self->strand, self->exchanger->GetId(), self->peer);
                if (!self->bridge || !self->bridge->Connect(y, transmission,
                        ppp::string(self->upstream_host.data(), self->upstream_host.size()), self->upstream_port) || self->stopped.load()) {
                    transmission->Dispose();
                    self->Finish(boost::asio::error::connection_aborted);
                    return;
                }
                self->Finish({});
                if (!self->IsActive() || self->stopped.load(std::memory_order_acquire)) {
                    self->Stop();
                    return;
                }
                self->bridge->Run(y);
                self->Stop();
            });
        if (!spawned) Finish(boost::asio::error::no_memory);
    }
};
} // namespace

void PolicyTunnelDnsStream::Connect(const std::shared_ptr<VEthernetExchanger>& exchanger,
    Tcp::socket& socket, const Tcp::endpoint& upstream, const ActiveCheck& active,
    const Completion& completion) noexcept {
    Connect(exchanger, socket, upstream.address().to_string(), upstream.port(), active, completion);
}

void PolicyTunnelDnsStream::Connect(const std::shared_ptr<VEthernetExchanger>& exchanger,
    Tcp::socket& socket, const std::string& host, std::uint16_t port, const ActiveCheck& active,
    const Completion& completion) noexcept {
    if (!completion) return;
    auto context = exchanger ? exchanger->GetContext() : nullptr;
    if (!context || host.empty() || host.size() > 255 || port == 0) {
        completion(boost::asio::error::invalid_argument);
        return;
    }
    try {
        if (active && !active()) {
            completion(boost::asio::error::operation_aborted);
            return;
        }
    } catch (...) {
        completion(boost::asio::error::operation_aborted);
        return;
    }
    std::shared_ptr<StreamOperation> operation;
    try {
        operation = std::make_shared<StreamOperation>();
        operation->completion = completion;
        operation->active = active;
        operation->exchanger = exchanger;
        operation->context = context;
        operation->strand = std::make_shared<boost::asio::strand<boost::asio::io_context::executor_type>>(
            context->get_executor());
        operation->upstream_host = host;
        operation->upstream_port = port;
        operation->listener = std::make_shared<Tcp::acceptor>(*context);
        operation->peer = std::make_shared<Tcp::socket>(*context);
        operation->timer = std::make_shared<boost::asio::steady_timer>(*context);
        boost::system::error_code error;
        operation->listener->open(Tcp::v4(), error);
        if (!error) operation->listener->bind(Tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0), error);
        if (!error) operation->listener->listen(1, error);
        auto local = error ? Tcp::endpoint() : operation->listener->local_endpoint(error);
        if (error) { operation->Finish(error); return; }

        // DNS retains its original TLS stream; only its socket's byte transport changes.
        socket.close(error);
        socket.open(Tcp::v4(), error);
        if (!error) socket.bind(Tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0), error);
        if (!error) operation->expected_peer = socket.local_endpoint(error);
        if (error) { operation->Finish(error); return; }
        operation->deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        operation->Monitor();
        if (operation->stopped.load(std::memory_order_acquire)) return;
        socket.async_connect(local, boost::asio::bind_executor(*operation->strand,
            [operation](boost::system::error_code error) noexcept {
            if (error || operation->stopped.load()) {
                operation->Finish(error ? error : boost::asio::error::operation_aborted);
                return;
            }
            operation->listener->async_accept(*operation->peer,
                boost::asio::bind_executor(*operation->strand,
                [operation](boost::system::error_code error) noexcept {
                    if (error || operation->stopped.load()) {
                        operation->Finish(error ? error : boost::asio::error::operation_aborted);
                        return;
                    }
                    auto remote = operation->peer->remote_endpoint(error);
                    if (error || remote != operation->expected_peer) {
                        operation->Finish(boost::asio::error::access_denied);
                        return;
                    }
                    operation->listener->close(error);
                    operation->BeginBridge();
                }));
        }));
    } catch (...) {
        if (operation) {
            const bool has_completion = static_cast<bool>(operation->completion);
            if (has_completion) operation->Finish(boost::asio::error::no_memory);
            operation->Stop();
            if (!has_completion && !operation->completed.load()) completion(boost::asio::error::no_memory);
        } else completion(boost::asio::error::no_memory);
    }
}
} // namespace ppp::app::client::dns

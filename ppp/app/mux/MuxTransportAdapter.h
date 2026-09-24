#pragma once

#include <ppp/app/mux/IMuxTransport.h>

namespace ppp::app::mux {

template <typename TConnection>
class MuxTransportAdapter final : public IMuxTransport {
public:
    MuxTransportAdapter(std::shared_ptr<TConnection> connection,
                        ppp::function<void()> owner_dispose) noexcept
        : connection_(std::move(connection)), owner_dispose_(std::move(owner_dispose)) {}

    bool IsLinked() noexcept override {
        return !disposed_.load(std::memory_order_acquire) && connection_ && connection_->IsLinked();
    }

    ContextPtr GetContext() noexcept override {
        return connection_ ? connection_->GetContext() : nullptr;
    }

    StrandPtr GetStrand() noexcept override {
        return connection_ ? connection_->GetStrand() : nullptr;
    }

    ITransmissionPtr GetTransmission() noexcept override {
        return connection_ ? connection_->GetTransmission() : nullptr;
    }

    Int128 GetId() noexcept override {
        return connection_ ? connection_->GetId() : Int128{};
    }

    void Update() noexcept override {
        if (IsLinked()) {
            connection_->Update();
        }
    }

    void Dispose() noexcept override {
        if (disposed_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        if (connection_) {
            connection_->Dispose();
        }
        if (owner_dispose_) {
            owner_dispose_();
        }
    }

private:
    std::shared_ptr<TConnection> connection_;
    ppp::function<void()> owner_dispose_;
    std::atomic_bool disposed_{false};
};

template <typename TConnection>
IMuxTransportPtr MakeMuxTransport(
    const std::shared_ptr<TConnection>& connection,
    ppp::function<void()> owner_dispose = {}) noexcept {
    if (!connection) {
        return nullptr;
    }
    return ppp::make_shared_object<MuxTransportAdapter<TConnection>>(
        connection, std::move(owner_dispose));
}

} // namespace ppp::app::mux

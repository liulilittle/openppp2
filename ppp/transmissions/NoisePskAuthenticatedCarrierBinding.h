#pragma once

#include <ppp/cryptography/noise/NoisePsk.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>

namespace ppp::transmissions {

/** Owns Noise exporter state for one authenticated carrier and owner executor. */
class NoisePskAuthenticatedCarrierBinding final {
public:
    using ContextPtr = std::shared_ptr<boost::asio::io_context>;
    using Strand = boost::asio::strand<boost::asio::io_context::executor_type>;
    using StrandPtr = std::shared_ptr<Strand>;

    NoisePskAuthenticatedCarrierBinding(
        const ContextPtr& context,
        const StrandPtr& strand,
        ppp::cryptography::noise::NoisePskHandshakeResult&& result) noexcept;
    ~NoisePskAuthenticatedCarrierBinding() noexcept;

    NoisePskAuthenticatedCarrierBinding(
        const NoisePskAuthenticatedCarrierBinding&) = delete;
    NoisePskAuthenticatedCarrierBinding& operator=(
        const NoisePskAuthenticatedCarrierBinding&) = delete;

    bool IsValid() const noexcept;
    bool IsAvailable(
        const ContextPtr& context,
        const StrandPtr& strand) const noexcept;
    bool Export(
        const ContextPtr& context,
        const StrandPtr& strand,
        const char* label,
        const std::uint8_t* exporter_context,
        std::size_t context_length,
        std::uint8_t* output,
        std::size_t output_length) noexcept;
    void Invalidate() noexcept;

private:
    bool IsOwnerExecutor(
        const ContextPtr& context,
        const StrandPtr& strand) const noexcept;

    ContextPtr context_;
    StrandPtr strand_;
    mutable std::mutex mutex_;
    ppp::cryptography::noise::NoisePskHandshakeResult result_;
    std::atomic_bool valid_{false};
};

}

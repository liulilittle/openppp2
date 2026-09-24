#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include <ppp/app/runtime/XtcpUploadBudget.h>

namespace ppp::app::runtime { class XtcpDirectQueueTelemetry; }

namespace ppp::app::client::xtcp {

enum class XtcpDirectResult : std::uint8_t {
    Accepted,
    Backpressured,
    Closed,
};

struct XtcpDirectReadReservation final {
    std::uint64_t runtime_generation = 0;
    std::uint64_t flow_generation = 0;
    std::uint64_t token = 0;
    std::uint32_t length = 0;

    bool IsValid() const noexcept {
        return runtime_generation != 0 && flow_generation != 0 && token != 0 && length != 0;
    }

    bool IsSame(const XtcpDirectReadReservation& other) const noexcept {
        return runtime_generation == other.runtime_generation &&
            flow_generation == other.flow_generation && token == other.token &&
            length == other.length;
    }
};

enum class XtcpDirectCompletion : std::uint8_t {
    Accepted,
    Terminal,
};

enum class XtcpDirectCloseReason : std::uint8_t {
    PeerEof,
    Terminal,
};

class XtcpSecondLegHooks {
public:
    virtual ~XtcpSecondLegHooks() noexcept = default;
    // Bytes are borrowed for this call. On acceptance the implementation
    // copies only after local admission, and retains the reservation through
    // its asynchronous write. On rejection it must not consume any bytes.
    virtual XtcpDirectResult SendToPeer(const std::uint8_t* data, std::uint32_t length,
        XtcpUploadBudget::Reservation&& credit) noexcept = 0;
    virtual void OnDownloadComplete(
        const XtcpDirectReadReservation& reservation,
        XtcpDirectCompletion completion) noexcept {
        (void)reservation;
        (void)completion;
    }
    virtual void SetDirectQueueTelemetry(
        const std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry>& telemetry) noexcept {
        (void)telemetry;
    }
    virtual void ClosePeerSend() noexcept = 0;
};

class XtcpFirstLegHooks {
public:
    virtual ~XtcpFirstLegHooks() noexcept = default;

    virtual void OnFirstLegReady(
        std::uint64_t runtime_generation,
        std::uint64_t flow_generation) noexcept = 0;
    virtual void OnFirstLegDirectReady(
        std::uint64_t runtime_generation,
        std::uint64_t flow_generation,
        const std::shared_ptr<XtcpSecondLegHooks>& second_leg) noexcept {
        (void)second_leg;
        OnFirstLegReady(runtime_generation, flow_generation);
    }
    virtual XtcpDirectResult OnSecondLegPayload(
        XtcpDirectReadReservation& reservation,
        const std::shared_ptr<std::uint8_t>& payload) noexcept {
        (void)reservation;
        (void)payload;
        return XtcpDirectResult::Closed;
    }
    virtual void OnSecondLegWritable(
        std::uint64_t runtime_generation,
        std::uint64_t flow_generation) noexcept {
        (void)runtime_generation;
        (void)flow_generation;
    }
    virtual void OnSecondLegClosed(
        std::uint64_t runtime_generation,
        std::uint64_t flow_generation) noexcept {
        OnFirstLegClosed(runtime_generation, flow_generation);
    }
    virtual void OnDirectBridgeFallback(
        std::uint64_t runtime_generation,
        std::uint64_t flow_generation) noexcept {
        (void)runtime_generation;
        (void)flow_generation;
    }
    virtual void OnFirstLegClosed(
        std::uint64_t runtime_generation,
        std::uint64_t flow_generation) noexcept = 0;
};

} // namespace ppp::app::client::xtcp

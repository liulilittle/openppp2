#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include <ppp/app/client/xtcp/XtcpUploadBudget.h>

namespace ppp::app::runtime { class XtcpDirectQueueTelemetry; }

namespace ppp::app::client::xtcp {

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
    // Optional upload batching. When BatchesPeerSend() is true the runtime may
    // deliver several SendToPeer() calls from one ingress batch back-to-back
    // and then call FlushPeerSend() once, so the implementation can defer
    // waking its writer thread until the flush (one cross-thread wake per
    // batch instead of per segment). Accepted bytes must still be delivered.
    virtual bool BatchesPeerSend() const noexcept { return false; }
    virtual void FlushPeerSend() noexcept {}
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

#pragma once

#include <cstddef>
#include <cstdint>

namespace ppp {
namespace app {
namespace mux {

/** Decision for whether a flow-v2 receive context may be retained. */
enum class FlowContextAdmission : std::uint8_t {
    AllowExisting = 0,
    AllowCreate = 1,
    RejectUnknown = 2,
    RejectCap = 3,
    RejectZero = 4,
};

/**
 * Admits a flow-v2 receive context only for known sockets (or already-tracked
 * flows) and within a hard context-count cap. Prevents attacker-chosen fake
 * connection_ids from retaining unbounded state.
 */
inline FlowContextAdmission AdmitFlowContext(
    std::uint32_t connection_id,
    bool already_tracked,
    bool socket_exists,
    std::size_t current_contexts,
    std::size_t context_cap) noexcept {
    if (connection_id == 0) {
        return FlowContextAdmission::RejectZero;
    }
    if (already_tracked) {
        return FlowContextAdmission::AllowExisting;
    }
    if (!socket_exists) {
        return FlowContextAdmission::RejectUnknown;
    }
    if (context_cap > 0 && current_contexts >= context_cap) {
        return FlowContextAdmission::RejectCap;
    }
    return FlowContextAdmission::AllowCreate;
}

} // namespace mux
} // namespace app
} // namespace ppp

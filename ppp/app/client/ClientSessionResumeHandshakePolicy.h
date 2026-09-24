#pragma once

namespace ppp {
    namespace app {
        namespace client {

            enum class ClientSessionResumePreamble {
                Legacy,
                FreshProbe,
                ResumeRequest,
            };

            inline ClientSessionResumePreamble SelectClientSessionResumePreamble(
                bool enabled, bool is_vnet, bool has_authenticated_exporter,
                bool recovery_armed, bool has_retained_root) noexcept {
                if (!enabled || !is_vnet || !has_authenticated_exporter) {
                    return ClientSessionResumePreamble::Legacy;
                }
                if (recovery_armed && has_retained_root) {
                    return ClientSessionResumePreamble::ResumeRequest;
                }
                return ClientSessionResumePreamble::FreshProbe;
            }

        }
    }
}

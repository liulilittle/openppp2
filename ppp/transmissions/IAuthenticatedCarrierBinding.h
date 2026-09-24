/**
 * @file IAuthenticatedCarrierBinding.h
 * @brief Declares the authenticated carrier key-export contract.
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace ppp {
    namespace transmissions {

        /**
         * @brief Exposes authenticated, carrier-bound key material to protocol consumers.
         *
         * Availability is only a policy hint. ExportAuthenticatedSessionKey() is the
         * authoritative operation and must fail closed when provider lifecycle or
         * owner-context requirements are not satisfied.
         */
        class IAuthenticatedCarrierBinding {
        public:
            virtual ~IAuthenticatedCarrierBinding() noexcept = default;

        public:
            /** @brief Reports whether authenticated carrier export may be available. */
            virtual bool HasAuthenticatedSessionExporter() const noexcept = 0;
            /** @brief Exports label- and context-bound key material for this carrier. */
            virtual bool ExportAuthenticatedSessionKey(
                const char* label,
                const std::uint8_t* context,
                std::size_t context_length,
                std::uint8_t* output,
                std::size_t output_length) noexcept = 0;
        };

    }
}

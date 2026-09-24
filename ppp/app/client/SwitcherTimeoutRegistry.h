#pragma once

#include <memory>
#include <ppp/collections/Dictionary.h>
#include <ppp/ethernet/VEthernet.h>

namespace ppp { namespace threading { class Timer; } }

namespace ppp {
    namespace app {
        namespace client {

            class SwitcherTimeoutRegistry {
            public:
                void Bind(ppp::ethernet::VEthernet::SynchronizedObject* sync) noexcept;

                using RegistrationHandle = void*;

                bool Emplace(RegistrationHandle handle,
                    const std::shared_ptr<ppp::function<void(ppp::threading::Timer*)>>& handler) noexcept;

                bool Delete(RegistrationHandle handle) noexcept;
                void ReleaseAll() noexcept;

            private:
                ppp::ethernet::VEthernet::SynchronizedObject* sync_ = nullptr;
                bool released_ = false;
                ppp::unordered_map<RegistrationHandle,
                    std::shared_ptr<ppp::function<void(ppp::threading::Timer*)>>> timeouts_;
            };
        }
    }
}

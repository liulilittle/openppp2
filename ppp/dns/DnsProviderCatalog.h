#pragma once

#include <ppp/dns/DnsResolver.h>

namespace ppp {
    namespace dns {

        class DnsProviderCatalog final {
        public:
            static bool HasProvider(const ppp::string& name) noexcept;
            // Policy resolvers only use a provider's DoH/DoT endpoints.
            static bool HasEncryptedEndpoint(const ppp::string& name) noexcept;
            static const ppp::vector<ServerEntry>* GetProvider(const ppp::string& name) noexcept;
        };

    }
}

#pragma once

#include <ppp/stdafx.h>

#include <string>

namespace ppp
{
    namespace win32
    {
        namespace network
        {
            class Fw
            {
            public:
                // Durable ownership identity for a modern (INetFwPolicy2)
                // application rule.  A snapshot with existed=true is never
                // removed by RestoreApplicationOwned.
                struct ApplicationOwnership final
                {
                    std::string name;
                    std::string executable_path;
                    bool existed = false;
                    bool added = false;
                };

                typedef enum
                {
                    NetFirewallType_DomainNetwork,
                    NetFirewallType_PrivateNetwork,
                    NetFirewallType_PublicNetwork,
                } NetFirewallType;

            public:
                static bool NetFirewallAddApplication(const char* name, const char* executablePath, NetFirewallType netFwType) noexcept;
                static bool NetFirewallAddApplication(const char* name, const char* executablePath) noexcept;
                static bool NetFirewallAddAllApplication(const char* name, const char* executablePath) noexcept;

                // Captures whether an exact name/path rule already exists.
                // Failure is reported as false so callers never assume
                // ownership without a durable pre-change observation.
                static bool CaptureApplicationOwnership(const char* name,
                                                         const char* executablePath,
                                                         ApplicationOwnership* ownership) noexcept;
                // Captures ownership before adding.  The output is valid for
                // restoration only when this call returns true.
                static bool AddApplicationOwned(const char* name,
                                                const char* executablePath,
                                                ApplicationOwnership* ownership) noexcept;
                // Removes only a rule proven to have been added by this
                // snapshot and unchanged since then.  Existing, changed, or
                // ambiguous rules are preserved and return false.
                static bool RestoreApplicationOwned(const ApplicationOwnership& ownership) noexcept;
                // Stable, versioned representation used by the network
                // recovery journal.  The fields are hex encoded so rule
                // names and paths cannot alter the journal delimiters.
                static std::string SerializeApplicationOwnership(
                    const ApplicationOwnership& ownership);
                static bool DeserializeApplicationOwnership(
                    const std::string& value,
                    ApplicationOwnership* ownership) noexcept;
                static std::string ApplicationOwnershipTarget(
                    const ApplicationOwnership& ownership);
            };
        }
    }
}

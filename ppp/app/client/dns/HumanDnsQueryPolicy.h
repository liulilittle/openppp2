#pragma once

namespace ppp::app::client::dns {

    enum class HumanDnsStartupMode {
        RealAnswers,
        FakeIp,
    };

    struct HumanDnsStartupPolicyInput final {
        bool fake_ip_enabled = false;
        bool has_domain_rules = false;
    };

    enum class HumanDnsQueryMode {
        Continue,
        ResolveReal,
        AttemptFake,
        Reject,
    };

    struct HumanDnsQueryPolicyInput final {
        bool fake_ip_enabled = false;
        bool strict_human_match = false;
        bool is_a_query = false;
        bool hostname_fake_eligible = false;
        bool tcp_domain_sniff_enabled = false;
    };

    enum class HumanDnsFakeAttemptResult {
        RespondFake,
        Reject,
    };

    class HumanDnsQueryPolicy final {
    public:
        static constexpr HumanDnsStartupMode DecideStartup(
            const HumanDnsStartupPolicyInput& input) noexcept {
            return input.fake_ip_enabled
                ? HumanDnsStartupMode::FakeIp
                : HumanDnsStartupMode::RealAnswers;
        }

        static constexpr HumanDnsQueryMode DecideQuery(
            const HumanDnsQueryPolicyInput& input) noexcept {
            if (!input.strict_human_match || !input.is_a_query) {
                return HumanDnsQueryMode::Continue;
            }
            if (!input.fake_ip_enabled) {
                return HumanDnsQueryMode::ResolveReal;
            }
            if (!input.hostname_fake_eligible) {
                return HumanDnsQueryMode::Reject;
            }
            return HumanDnsQueryMode::AttemptFake;
        }

        static constexpr HumanDnsFakeAttemptResult DecideFakeAttempt(
            bool allocation_succeeded,
            bool response_built) noexcept {
            return allocation_succeeded && response_built
                ? HumanDnsFakeAttemptResult::RespondFake
                : HumanDnsFakeAttemptResult::Reject;
        }
    };

} // namespace ppp::app::client::dns

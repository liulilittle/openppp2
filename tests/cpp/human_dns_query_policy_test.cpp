#define BOOST_TEST_MODULE human_dns_query_policy_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/dns/HumanDnsQueryPolicy.h>

namespace dns = ppp::app::client::dns;

namespace {

int StartupModeValue(dns::HumanDnsStartupMode mode) {
    return static_cast<int>(mode);
}

int QueryModeValue(dns::HumanDnsQueryMode mode) {
    return static_cast<int>(mode);
}

int FakeResultValue(dns::HumanDnsFakeAttemptResult result) {
    return static_cast<int>(result);
}

} // namespace

BOOST_AUTO_TEST_CASE(startup_matrix_allows_domain_rules_with_or_without_fake_ip) {
    dns::HumanDnsStartupPolicyInput input;
    input.fake_ip_enabled = false;
    input.has_domain_rules = false;
    BOOST_TEST(StartupModeValue(dns::HumanDnsQueryPolicy::DecideStartup(input)) ==
        StartupModeValue(dns::HumanDnsStartupMode::RealAnswers));

    input.has_domain_rules = true;
    BOOST_TEST(StartupModeValue(dns::HumanDnsQueryPolicy::DecideStartup(input)) ==
        StartupModeValue(dns::HumanDnsStartupMode::RealAnswers));

    input.fake_ip_enabled = true;
    input.has_domain_rules = false;
    BOOST_TEST(StartupModeValue(dns::HumanDnsQueryPolicy::DecideStartup(input)) ==
        StartupModeValue(dns::HumanDnsStartupMode::FakeIp));

    input.has_domain_rules = true;
    BOOST_TEST(StartupModeValue(dns::HumanDnsQueryPolicy::DecideStartup(input)) ==
        StartupModeValue(dns::HumanDnsStartupMode::FakeIp));
}

BOOST_AUTO_TEST_CASE(fake_disabled_strict_a_uses_real_provider_without_fake_attempt) {
    dns::HumanDnsQueryPolicyInput input;
    input.fake_ip_enabled = false;
    input.strict_human_match = true;
    input.is_a_query = true;
    input.hostname_fake_eligible = true;

    BOOST_TEST(QueryModeValue(dns::HumanDnsQueryPolicy::DecideQuery(input)) ==
        QueryModeValue(dns::HumanDnsQueryMode::ResolveReal));

    input.hostname_fake_eligible = false;
    BOOST_TEST(QueryModeValue(dns::HumanDnsQueryPolicy::DecideQuery(input)) ==
        QueryModeValue(dns::HumanDnsQueryMode::ResolveReal));
}

BOOST_AUTO_TEST_CASE(fake_enabled_strict_ineligible_hostname_fails_closed) {
    dns::HumanDnsQueryPolicyInput input;
    input.fake_ip_enabled = true;
    input.strict_human_match = true;
    input.is_a_query = true;
    input.hostname_fake_eligible = false;

    BOOST_TEST(QueryModeValue(dns::HumanDnsQueryPolicy::DecideQuery(input)) ==
        QueryModeValue(dns::HumanDnsQueryMode::Reject));
}

BOOST_AUTO_TEST_CASE(fake_enabled_strict_allocation_or_build_failure_fails_closed) {
    BOOST_TEST(FakeResultValue(dns::HumanDnsQueryPolicy::DecideFakeAttempt(false, false)) ==
        FakeResultValue(dns::HumanDnsFakeAttemptResult::Reject));
    BOOST_TEST(FakeResultValue(dns::HumanDnsQueryPolicy::DecideFakeAttempt(true, false)) ==
        FakeResultValue(dns::HumanDnsFakeAttemptResult::Reject));
    BOOST_TEST(FakeResultValue(dns::HumanDnsQueryPolicy::DecideFakeAttempt(true, true)) ==
        FakeResultValue(dns::HumanDnsFakeAttemptResult::RespondFake));
}

BOOST_AUTO_TEST_CASE(tcp_sniff_switch_does_not_change_dns_real_answer_policy) {
    dns::HumanDnsQueryPolicyInput input;
    input.fake_ip_enabled = false;
    input.strict_human_match = true;
    input.is_a_query = true;
    input.hostname_fake_eligible = true;
    input.tcp_domain_sniff_enabled = false;
    const dns::HumanDnsQueryMode sniff_off = dns::HumanDnsQueryPolicy::DecideQuery(input);

    input.tcp_domain_sniff_enabled = true;
    const dns::HumanDnsQueryMode sniff_on = dns::HumanDnsQueryPolicy::DecideQuery(input);

    BOOST_TEST(QueryModeValue(sniff_off) == QueryModeValue(dns::HumanDnsQueryMode::ResolveReal));
    BOOST_TEST(QueryModeValue(sniff_on) == QueryModeValue(sniff_off));
}

BOOST_AUTO_TEST_CASE(non_a_or_non_strict_queries_continue_existing_policy) {
    dns::HumanDnsQueryPolicyInput input;
    input.fake_ip_enabled = true;
    input.strict_human_match = true;
    input.is_a_query = false;
    BOOST_TEST(QueryModeValue(dns::HumanDnsQueryPolicy::DecideQuery(input)) ==
        QueryModeValue(dns::HumanDnsQueryMode::Continue));

    input.strict_human_match = false;
    input.is_a_query = true;
    BOOST_TEST(QueryModeValue(dns::HumanDnsQueryPolicy::DecideQuery(input)) ==
        QueryModeValue(dns::HumanDnsQueryMode::Continue));
}

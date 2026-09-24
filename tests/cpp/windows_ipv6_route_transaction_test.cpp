#define BOOST_TEST_MODULE windows_ipv6_route_transaction_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/ipv6/IPv6RouteTransaction.h>

#include <algorithm>
#include <deque>
#include <string>
#include <vector>

namespace transaction = ppp::ipv6::route_transaction;
using ppp::ipv6::client_policy::OwnershipMutation;

namespace {
    transaction::RouteIdentity Route(transaction::RouteKind kind, std::uint8_t marker) {
        transaction::RouteIdentity route;
        route.Kind = kind;
        route.Destination[0] = marker;
        route.PrefixLength = kind == transaction::RouteKind::EgressPin ? 128 : 1;
        route.InterfaceLuid = marker;
        route.InterfaceIndex = marker;
        route.Metric = 7;
        route.Protocol = 3;
        route.Origin = 1;
        route.Immortal = true;
        return route;
    }

    const char* Name(transaction::RouteKind kind) {
        switch (kind) {
        case transaction::RouteKind::EgressPin: return "pin";
        case transaction::RouteKind::LowerHalf: return "lower";
        case transaction::RouteKind::UpperHalf: return "upper";
        }
        return "unknown";
    }

    class FakeMutator final : public transaction::IRouteMutator {
    public:
        std::deque<OwnershipMutation> Creates;
        std::deque<bool> Deletes;
        std::vector<std::string> Events;

        OwnershipMutation Create(const transaction::RouteIdentity& route) noexcept override {
            Events.emplace_back(std::string("create:") + Name(route.Kind) + ":" + std::to_string(route.Destination[0]));
            if (Creates.empty()) {
                return OwnershipMutation::Changed;
            }
            const auto result = Creates.front();
            Creates.pop_front();
            return result;
        }

        bool Delete(const transaction::RouteIdentity& route) noexcept override {
            Events.emplace_back(std::string("delete:") + Name(route.Kind) + ":" + std::to_string(route.Destination[0]));
            if (Deletes.empty()) {
                return true;
            }
            const bool result = Deletes.front();
            Deletes.pop_front();
            return result;
        }
    };
}

BOOST_AUTO_TEST_CASE(exact_route_equivalence_rejects_every_stable_mismatch) {
    const auto expected = Route(transaction::RouteKind::EgressPin, 1);
    BOOST_TEST(transaction::IsExactRouteMatch(expected, expected));

    auto mismatch = expected;
    mismatch.NextHopScopeId = 9;
    BOOST_TEST(!transaction::IsExactRouteMatch(mismatch, expected));
    mismatch = expected;
    mismatch.InterfaceLuid++;
    BOOST_TEST(!transaction::IsExactRouteMatch(mismatch, expected));
    mismatch = expected;
    mismatch.Metric++;
    BOOST_TEST(!transaction::IsExactRouteMatch(mismatch, expected));
    mismatch = expected;
    mismatch.Publish = true;
    BOOST_TEST(!transaction::IsExactRouteMatch(mismatch, expected));
}

BOOST_AUTO_TEST_CASE(pin_precedes_split_pair_and_unchanged_is_not_owned) {
    FakeMutator fake;
    fake.Creates = { OwnershipMutation::Unchanged, OwnershipMutation::Changed, OwnershipMutation::Unchanged };
    transaction::IPv6RouteTransaction state(fake);

    BOOST_TEST(state.StagePin(Route(transaction::RouteKind::EgressPin, 9)));
    BOOST_TEST(state.EnsureSinkMode(Route(transaction::RouteKind::LowerHalf, 1), Route(transaction::RouteKind::UpperHalf, 2)));
    BOOST_TEST(state.CommitStagedPin());
    BOOST_TEST(state.Stop());

    BOOST_REQUIRE(fake.Events.size() >= 4u);
    BOOST_TEST(fake.Events[0] == "create:pin:9");
    BOOST_TEST(fake.Events[1] == "create:lower:1");
    BOOST_TEST(fake.Events[2] == "create:upper:2");
    BOOST_TEST(fake.Events[3] == "delete:lower:1");
    const bool unchanged_pin_was_not_deleted =
        fake.Events.end() == std::find(fake.Events.begin(), fake.Events.end(), "delete:pin:9");
    BOOST_TEST(unchanged_pin_was_not_deleted);
}

BOOST_AUTO_TEST_CASE(second_pair_failure_rolls_back_only_changed_first_route) {
    FakeMutator changed;
    changed.Creates = { OwnershipMutation::Changed, OwnershipMutation::Failed };
    transaction::IPv6RouteTransaction first(changed);
    BOOST_TEST(!first.EnsureSinkMode(Route(transaction::RouteKind::LowerHalf, 1), Route(transaction::RouteKind::UpperHalf, 2)));
    BOOST_REQUIRE_EQUAL(changed.Events.size(), 3u);
    BOOST_TEST(changed.Events[2] == "delete:lower:1");

    FakeMutator unchanged;
    unchanged.Creates = { OwnershipMutation::Unchanged, OwnershipMutation::Failed };
    transaction::IPv6RouteTransaction second(unchanged);
    BOOST_TEST(!second.EnsureSinkMode(Route(transaction::RouteKind::LowerHalf, 1), Route(transaction::RouteKind::UpperHalf, 2)));
    BOOST_REQUIRE_EQUAL(unchanged.Events.size(), 2u);
}

BOOST_AUTO_TEST_CASE(failed_delete_is_retained_and_retried) {
    FakeMutator fake;
    fake.Deletes = { false, true };
    transaction::IPv6RouteTransaction state(fake);
    BOOST_TEST(state.StagePin(Route(transaction::RouteKind::EgressPin, 1)));
    BOOST_TEST(!state.RollbackStagedPin());
    BOOST_TEST(state.HasStagedPin());
    BOOST_TEST(state.RollbackStagedPin());
    BOOST_TEST(!state.HasStagedPin());
}

BOOST_AUTO_TEST_CASE(reconnect_stage_commit_and_rollback_preserve_committed_pin) {
    FakeMutator fake;
    transaction::IPv6RouteTransaction state(fake);
    BOOST_TEST(state.StagePin(Route(transaction::RouteKind::EgressPin, 1)));
    BOOST_TEST(state.CommitStagedPin());
    BOOST_TEST(state.StagePin(Route(transaction::RouteKind::EgressPin, 2)));
    BOOST_TEST(state.RollbackStagedPin());
    BOOST_TEST(state.StagePin(Route(transaction::RouteKind::EgressPin, 3)));
    BOOST_TEST(state.CommitStagedPin());

    const auto old_delete = std::find(fake.Events.begin(), fake.Events.end(), "delete:pin:1");
    const auto staged_delete = std::find(fake.Events.begin(), fake.Events.end(), "delete:pin:2");
    const auto third_create = std::find(fake.Events.begin(), fake.Events.end(), "create:pin:3");
    BOOST_TEST(static_cast<bool>(old_delete != fake.Events.end()));
    BOOST_TEST(static_cast<bool>(staged_delete != fake.Events.end()));
    BOOST_TEST(static_cast<bool>(third_create < old_delete));
}

BOOST_AUTO_TEST_CASE(sink_to_managed_switch_builds_target_before_retiring_old_pair) {
    FakeMutator fake;
    transaction::IPv6RouteTransaction state(fake);
    BOOST_TEST(state.EnsureSinkMode(Route(transaction::RouteKind::LowerHalf, 1), Route(transaction::RouteKind::UpperHalf, 2)));
    BOOST_TEST(state.ActivateManagedMode(Route(transaction::RouteKind::LowerHalf, 3), Route(transaction::RouteKind::UpperHalf, 4)));
    const bool managed = state.Mode() == transaction::PairMode::Managed;
    BOOST_TEST(managed);

    const auto create_upper = std::find(fake.Events.begin(), fake.Events.end(), "create:upper:4");
    const auto delete_old_upper = std::find(fake.Events.begin(), fake.Events.end(), "delete:upper:2");
    BOOST_TEST(static_cast<bool>(create_upper != fake.Events.end()));
    BOOST_TEST(static_cast<bool>(delete_old_upper != fake.Events.end()));
    BOOST_TEST(static_cast<bool>(create_upper < delete_old_upper));
}

BOOST_AUTO_TEST_CASE(stop_removes_takeover_before_any_pin) {
    FakeMutator fake;
    transaction::IPv6RouteTransaction state(fake);
    BOOST_TEST(state.StagePin(Route(transaction::RouteKind::EgressPin, 9)));
    BOOST_TEST(state.CommitStagedPin());
    BOOST_TEST(state.EnsureSinkMode(Route(transaction::RouteKind::LowerHalf, 1), Route(transaction::RouteKind::UpperHalf, 2)));
    fake.Events.clear();
    BOOST_TEST(state.Stop());

    BOOST_REQUIRE_EQUAL(fake.Events.size(), 3u);
    BOOST_TEST(fake.Events[0] == "delete:upper:2");
    BOOST_TEST(fake.Events[1] == "delete:lower:1");
    BOOST_TEST(fake.Events[2] == "delete:pin:9");
}

#include <ppp/app/protocol/MappingPortConnectReentrancy.h>

#include <atomic>
#include <cassert>
#include <memory>
#include <unordered_map>

using ppp::app::protocol::MappingPortConnectReentrancy;

namespace {

class Owner final {
public:
    void Dispose() noexcept {
        bool expected = false;
        if (disposed_.compare_exchange_strong(expected, true)) {
            dispose_count_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    bool IsDisposed() const noexcept {
        return disposed_.load(std::memory_order_acquire);
    }

    int DisposeCount() const noexcept {
        return dispose_count_.load(std::memory_order_relaxed);
    }

private:
    std::atomic_bool disposed_{false};
    std::atomic_int dispose_count_{0};
};

using OwnerMap = std::unordered_map<int, std::shared_ptr<Owner>>;

bool PublishOwner(OwnerMap& owners, int id, const std::shared_ptr<Owner>& owner) {
    return owners.emplace(id, owner).second;
}

void CleanupOwner(OwnerMap& owners, int id, const std::shared_ptr<Owner>& owner) noexcept {
    owner->Dispose();
    MappingPortConnectReentrancy::EraseIfOwner(owners, id, owner.get());
}

void TestSynchronousFinalizeDuringStart() {
    OwnerMap owners;
    auto owner = std::make_shared<Owner>();

    const bool started = MappingPortConnectReentrancy::PublishThenStart(
        [&]() { return PublishOwner(owners, 7, owner); },
        [&]() noexcept {
            CleanupOwner(owners, 7, owner);
            return false;
        },
        [&]() noexcept { return MappingPortConnectReentrancy::IsOwner(owners, 7, owner.get()); },
        [&]() noexcept { CleanupOwner(owners, 7, owner); });

    assert(!started);
    assert(owners.empty());
    assert(owner->IsDisposed());
    assert(owner->DisposeCount() == 1);
}

void TestStartReturningFalseCleansPublishedOwner() {
    OwnerMap owners;
    auto owner = std::make_shared<Owner>();

    const bool started = MappingPortConnectReentrancy::PublishThenStart(
        [&]() { return PublishOwner(owners, 9, owner); },
        []() noexcept { return false; },
        [&]() noexcept { return MappingPortConnectReentrancy::IsOwner(owners, 9, owner.get()); },
        [&]() noexcept { CleanupOwner(owners, 9, owner); });

    assert(!started);
    assert(owners.empty());
    assert(owner->IsDisposed());
    assert(owner->DisposeCount() == 1);
}

void TestConflictDoesNotStartOrDispose() {
    OwnerMap owners;
    auto existing = std::make_shared<Owner>();
    auto conflict = std::make_shared<Owner>();
    owners.emplace(11, existing);
    bool start_called = false;

    const bool started = MappingPortConnectReentrancy::PublishThenStart(
        [&]() { return PublishOwner(owners, 11, conflict); },
        [&]() noexcept { start_called = true; return true; },
        [&]() noexcept { return MappingPortConnectReentrancy::IsOwner(owners, 11, conflict.get()); },
        [&]() noexcept { CleanupOwner(owners, 11, conflict); });

    assert(!started);
    assert(!start_called);
    assert(owners.size() == 1);
    assert(owners.at(11) == existing);
    assert(conflict->DisposeCount() == 0);
}

void TestLateEraseCannotRemoveReplacement() {
    OwnerMap owners;
    auto old_owner = std::make_shared<Owner>();
    auto replacement = std::make_shared<Owner>();
    owners.emplace(13, replacement);

    assert(!MappingPortConnectReentrancy::EraseIfOwner(owners, 13, old_owner.get()));
    assert(owners.size() == 1);
    assert(owners.at(13) == replacement);
    assert(MappingPortConnectReentrancy::EraseIfOwner(owners, 13, replacement.get()));
    assert(owners.empty());
}

}  // namespace

int main() {
    TestSynchronousFinalizeDuringStart();
    TestStartReturningFalseCleansPublishedOwner();
    TestConflictDoesNotStartOrDispose();
    TestLateEraseCannotRemoveReplacement();
    return 0;
}

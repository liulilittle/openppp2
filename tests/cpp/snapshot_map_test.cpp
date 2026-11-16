#include <ppp/collections/SnapshotMap.h>

#include <atomic>
#include <iostream>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

using Table = std::unordered_map<int, std::string>;

void MutationsPublishSnapshots() {
    ppp::collections::SnapshotMap<Table> map;
    Require(map.Snapshot()->empty(), "initial snapshot is not empty");

    auto empty = map.Snapshot();
    Require(map.emplace(1, "one").second, "emplace failed");
    Require(!map.emplace(1, "uno").second, "duplicate emplace succeeded");
    Require(empty->empty(), "earlier snapshot changed after a write");
    Require(map.Snapshot()->at(1) == "one", "emplace not published");

    map.assign(1, "uno");
    Require(map.Snapshot()->at(1) == "uno", "assign not published");

    map.emplace(2, "two");
    map.emplace(3, "three");
    for (auto tail = map.begin(); tail != map.end();) {
        tail = tail->first == 2 ? map.erase(tail) : std::next(tail);
    }
    Require(map.Snapshot()->count(2) == 0 && map.Snapshot()->size() == 2, "iterator erase not published");

    Require(map.erase(3) == 1 && map.erase(3) == 0, "key erase result is wrong");
    Require(map.Snapshot()->size() == 1, "key erase not published");

    Table taken = map.take();
    Require(taken.size() == 1 && map.empty() && map.Snapshot()->empty(), "take did not empty the table");

    map.emplace(4, "four");
    map.clear();
    Require(map.Snapshot()->empty(), "clear not published");
}

struct ToOrderedKeys final {
    std::map<std::string, int> operator()(const Table& table) const {
        std::map<std::string, int> result;
        for (const auto& kv : table) {
            result.emplace(kv.second, kv.first);
        }
        return result;
    }
};

void ProjectionBuildsReKeyedSnapshot() {
    ppp::collections::SnapshotMap<Table, std::map<std::string, int>, ToOrderedKeys> map;
    map.emplace(7, "seven");
    Require(map.Snapshot()->at("seven") == 7, "projected snapshot missing key");
    map.erase(7);
    Require(map.Snapshot()->empty(), "projected snapshot not updated");
}

void ReadersNeverSeeTornState() {
    // Writers keep every value equal to its key; lock-free readers must only ever
    // observe complete snapshots that satisfy the invariant.
    ppp::collections::SnapshotMap<std::unordered_map<int, int>> map;
    std::mutex owner_lock;
    std::atomic<bool> stop{false};
    std::atomic<int> violations{0};

    std::vector<std::thread> readers;
    for (int r = 0; r < 4; r++) {
        readers.emplace_back([&]() {
            while (!stop.load(std::memory_order_relaxed)) {
                auto snapshot = map.Snapshot();
                for (const auto& kv : *snapshot) {
                    if (kv.first != kv.second) {
                        violations++;
                    }
                }
            }
        });
    }

    for (int i = 0; i < 2000; i++) {
        std::lock_guard<std::mutex> scope(owner_lock);
        map.emplace(i % 64, i % 64);
        if (i % 3 == 0) {
            map.erase((i * 7) % 64);
        }
    }

    stop = true;
    for (auto& reader : readers) {
        reader.join();
    }

    Require(violations == 0, "reader observed an inconsistent snapshot");
}

} // namespace

int main() {
    try {
        MutationsPublishSnapshots();
        ProjectionBuildsReKeyedSnapshot();
        ReadersNeverSeeTornState();
    }
    catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "PASS: snapshot_map_test" << std::endl;
    return 0;
}

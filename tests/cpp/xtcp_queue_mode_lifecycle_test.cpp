// Lifecycle tests for the opt-in XTCP queue mode (OPENPPP2_XTCP_AFFINITY=queues):
// per-shard io_context + one pinned worker per shard.

#include <ppp/app/client/xtcp/XtcpRuntime.h>

#include <xtcp/buf/bufref.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <sched.h>

namespace {
int failures = 0;

#define CHECK(condition)                                                          \
    do {                                                                          \
        if (!(condition)) {                                                       \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            ++failures;                                                           \
        }                                                                         \
    } while (0)

using Runtime = ppp::app::client::xtcp::XtcpRuntime;

class ScopedEnv final {
public:
    ScopedEnv(const char* name, const char* value) : name_(name) {
        if (const char* old = std::getenv(name)) { had_ = true; old_ = old; }
        if (value) setenv(name, value, 1); else unsetenv(name);
    }
    ~ScopedEnv() { if (had_) setenv(name_, old_.c_str(), 1); else unsetenv(name_); }
private:
    const char* name_;
    bool had_ = false;
    std::string old_;
};

std::vector<unsigned> AllowedCpus() {
    std::vector<unsigned> cpus;
    cpu_set_t set; CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof(set), &set) == 0)
        for (unsigned i = 0; i < CPU_SETSIZE; ++i) if (CPU_ISSET(i, &set)) cpus.push_back(i);
    return cpus;
}

std::string CpuList(std::size_t n) {
    const auto cpus = AllowedCpus();
    std::string text;
    for (std::size_t i = 0; i < n && i < cpus.size(); ++i) {
        if (!text.empty()) text += ',';
        text += std::to_string(cpus[i]);
    }
    return text;
}

std::shared_ptr<Runtime> MakeRuntime(const std::shared_ptr<boost::asio::io_context>& context) {
    return std::make_shared<Runtime>(context,
        [](std::shared_ptr<Byte>&&, int, std::optional<ppp::tap::TxGsoMetadata>) noexcept { return true; },
        Runtime::ListenerEndpointHandler{}, Runtime::ExternalAcceptHandler{},
        Runtime::ExternalCancelHandler{});
}

// Bounded wait: Stop() finalizes asynchronously on the shard workers.
bool StartWithin(Runtime& runtime, std::chrono::milliseconds limit) {
    const auto deadline = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < deadline) {
        if (runtime.Start()) return true;
        std::this_thread::yield();
    }
    return false;
}

// Runs fn on a helper thread and fails (instead of hanging) past the limit.
template<class Fn>
bool CompletesWithin(Fn&& fn, std::chrono::seconds limit) {
    std::packaged_task<void()> task(std::forward<Fn>(fn));
    auto done = task.get_future();
    std::thread worker(std::move(task));
    const bool ok = done.wait_for(limit) == std::future_status::ready;
    if (ok) worker.join(); else worker.detach();
    return ok;
}

void QueueModeStartStop(std::size_t shards) {
    if (AllowedCpus().size() < shards) {
        std::printf("skip QueueModeStartStop(%zu): not enough CPUs\n", shards);
        return;
    }
    const std::string count = std::to_string(shards);
    const std::string cpus = CpuList(shards);
    ScopedEnv e1("OPENPPP2_XTCP_SHARDS", count.c_str());
    ScopedEnv e2("OPENPPP2_XTCP_AFFINITY", "queues");
    ScopedEnv e3("OPENPPP2_XTCP_IO_CPUS", cpus.c_str());
    ScopedEnv e4("OPENPPP2_XTCP_AFFINITY_STRICT", "1");
    auto context = std::make_shared<boost::asio::io_context>();
    auto runtime = MakeRuntime(context);
    CHECK(runtime->Start());
    const auto snapshot = runtime->SnapshotStats();
    CHECK(snapshot.queue_mode_active);
    CHECK(snapshot.affinity_mode == "queues");
    CHECK(snapshot.affinity_pinned_workers == shards);
    std::set<std::uint64_t> tids;
    for (std::size_t i = 0; i < shards; ++i) {
        tids.insert(snapshot.workers[i].tid);
        CHECK(snapshot.workers[i].effective_cpus.size() == 1);
        CHECK(snapshot.workers[i].effective_cpus.size() == 1 &&
              snapshot.workers[i].effective_cpus[0] == AllowedCpus()[i]);
    }
    CHECK(tids.size() == shards && tids.count(0) == 0);
    runtime->MarkReady();
    runtime->Stop();
    CHECK(!runtime->IsRunning());
    // Destruction stops and joins every per-shard worker.
    CHECK(CompletesWithin([&runtime]() { runtime.reset(); }, std::chrono::seconds(10)));
}

void PartialStartupUnwind() {
    if (AllowedCpus().size() < 4) return;
    const std::string cpus = CpuList(4);
    ScopedEnv e1("OPENPPP2_XTCP_SHARDS", "4");
    ScopedEnv e2("OPENPPP2_XTCP_AFFINITY", "queues");
    ScopedEnv e3("OPENPPP2_XTCP_IO_CPUS", cpus.c_str());
    ScopedEnv e4("OPENPPP2_XTCP_AFFINITY_STRICT", "1");
    auto context = std::make_shared<boost::asio::io_context>();
    auto runtime = MakeRuntime(context);
    Runtime::FailWorkerStartForTesting(2);
    CHECK(!runtime->Start());          // shards 0 and 1 started, 2 failed
    CHECK(!runtime->IsRunning());
    CHECK(StartWithin(*runtime, std::chrono::milliseconds(2000))); // clean retry
    CHECK(runtime->SnapshotStats().queue_mode_active);
    runtime->Stop();
    CHECK(CompletesWithin([&runtime]() { runtime.reset(); }, std::chrono::seconds(10)));
}

void RestartStaleCallbacks() {
    if (AllowedCpus().size() < 2) return;
    const std::string cpus = CpuList(2);
    ScopedEnv e1("OPENPPP2_XTCP_SHARDS", "2");
    ScopedEnv e2("OPENPPP2_XTCP_AFFINITY", "queues");
    ScopedEnv e3("OPENPPP2_XTCP_IO_CPUS", cpus.c_str());
    ScopedEnv e4("OPENPPP2_XTCP_AFFINITY_STRICT", "0");
    auto context = std::make_shared<boost::asio::io_context>();
    auto runtime = MakeRuntime(context);
    for (int round = 0; round < 5; ++round) {
        CHECK(StartWithin(*runtime, std::chrono::milliseconds(2000)));
        // Restart replaces every per-shard io_context; handlers queued on the
        // previous executors are destroyed with them and never run here.
        CHECK(runtime->SnapshotStats().queue_mode_active);
        CHECK(runtime->Generation() != 0);
        runtime->MarkReady();
        runtime->Stop();
    }
    CHECK(CompletesWithin([&runtime]() { runtime.reset(); }, std::chrono::seconds(10)));
}

// The last runtime reference is dropped on a shard worker: the destructor
// must not join its own thread (it detaches it) and must not deadlock.
void StopFromOwnWorker() {
    if (AllowedCpus().size() < 2) return;
    const std::string cpus = CpuList(2);
    ScopedEnv e1("OPENPPP2_XTCP_SHARDS", "2");
    ScopedEnv e2("OPENPPP2_XTCP_AFFINITY", "queues");
    ScopedEnv e3("OPENPPP2_XTCP_IO_CPUS", cpus.c_str());
    ScopedEnv e4("OPENPPP2_XTCP_AFFINITY_STRICT", "0");
    auto context = std::make_shared<boost::asio::io_context>();
    auto runtime = MakeRuntime(context);
    CHECK(runtime->Start());
    ppp::tap::TapLaneBinding binding;
    CHECK(!runtime->GetLaneBinding(2, binding));
    CHECK(!runtime->GetLaneBinding(-1, binding));
    CHECK(runtime->GetLaneBinding(1, binding) && binding.context);
    std::shared_ptr<boost::asio::io_context> worker = std::move(binding.context);
    auto done = std::make_shared<std::promise<void>>();
    auto finished = done->get_future();
    auto holder = std::make_shared<std::shared_ptr<Runtime>>(std::move(runtime));
    boost::asio::post(*worker, [holder, done]() {
        (*holder)->Stop();
        ppp::tap::TapLaneBinding after;
        if ((*holder)->GetLaneBinding(1, after)) ++failures; // bindings cleared on Stop
        holder->reset();
        done->set_value();
    });
    holder.reset();
    CHECK(finished.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    worker.reset();
}

void SsmtQueueModeRejected() {
    ScopedEnv e1("OPENPPP2_XTCP_SHARDS", "2");
    ScopedEnv e2("OPENPPP2_XTCP_AFFINITY", "queues");
    const std::string cpus = CpuList(2);
    ScopedEnv e3("OPENPPP2_XTCP_IO_CPUS", cpus.c_str());
    ScopedEnv e4("OPENPPP2_XTCP_AFFINITY_STRICT", "0");
    if (AllowedCpus().size() < 2) return;
    auto context = std::make_shared<boost::asio::io_context>();
    auto runtime = MakeRuntime(context);
    runtime->SetSsmtActive(true);
    CHECK(!runtime->Start());
    CHECK(runtime->SnapshotStats().affinity_reason == "queues-rejected-ssmt");
    runtime->SetSsmtActive(false);
    CHECK(runtime->Start());
    runtime->Stop();
    CHECK(CompletesWithin([&runtime]() { runtime.reset(); }, std::chrono::seconds(10)));
}

void Shards1QueueModeUnsupported() {
    ScopedEnv e1("OPENPPP2_XTCP_SHARDS", "1");
    ScopedEnv e2("OPENPPP2_XTCP_AFFINITY", "queues");
    ScopedEnv e3("OPENPPP2_XTCP_IO_CPUS", "0");
    ScopedEnv e4("OPENPPP2_XTCP_AFFINITY_STRICT", "1");
    auto context = std::make_shared<boost::asio::io_context>();
    auto runtime = MakeRuntime(context);
    CHECK(runtime->Start()); // single shard keeps the external context
    const auto snapshot = runtime->SnapshotStats();
    CHECK(!snapshot.queue_mode_active);
    CHECK(snapshot.affinity_mode == "queues");
    CHECK(snapshot.affinity_reason == "queues-unsupported-single-shard");
    CHECK(snapshot.affinity_pinned_workers == 0);
    runtime->Stop();
    context->run_for(std::chrono::milliseconds(50));
}
} // namespace

int main() {
    xtcp::buf::InitPools();
    QueueModeStartStop(2);
    QueueModeStartStop(4);
    PartialStartupUnwind();
    RestartStaleCallbacks();
    StopFromOwnWorker();
    SsmtQueueModeRejected();
    Shards1QueueModeUnsupported();
    xtcp::buf::ShutdownPools();
    if (failures != 0) {
        std::fprintf(stderr, "xtcp_queue_mode_lifecycle_test: %d failure(s)\n", failures);
        return 1;
    }
    std::puts("xtcp_queue_mode_lifecycle_test: passed");
    return 0;
}

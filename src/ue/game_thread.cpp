#include "ue/game_thread.h"

#include "core/log.h"
#include "core/memory.h"
#include "core/modules.h"
#include "core/strings.h"

#include <MinHook.h>

#include <chrono>
#include <thread>

namespace fmcp::ue {

namespace {

bool g_mhInitialized = false;

uint64_t NowUs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

}

namespace {
GameThread* g_gameThread = nullptr;
}

GameThread& GameThread::Get() {
    if (!g_gameThread) {
        g_gameThread = new GameThread();
    }
    return *g_gameThread;
}

GameThread::~GameThread() {
    RemoveHook();
}

bool GameThread::Install(uintptr_t processEvent, int timeoutMs, int maxQueued, int jobsPerPump,
                         int pumpBudgetUs, std::string* error) {
    if (!processEvent) {
        if (error) *error = "process_event address is not resolved";
        return false;
    }
    if (!modules::IsExecutableAddress(processEvent, 1)) {
        if (error) *error = "process_event address is not executable";
        return false;
    }

    SetDirectTarget(processEvent);
    Configure(timeoutMs, maxQueued, jobsPerPump, pumpBudgetUs);

    if (hooked_.load()) {
        if (target_ == processEvent) {
            return true;
        }
        if (!RemoveHook()) {
            if (error) *error = "previous hook is still busy; cannot switch process_event target";
            return false;
        }
    }

    if (!hooked_.load() && target_ == processEvent && original_) {
        const MH_STATUS status = MH_EnableHook(reinterpret_cast<LPVOID>(processEvent));
        if (status == MH_OK) {
            hooked_ = true;
            return true;
        }
    }

    if (!g_mhInitialized) {
        const MH_STATUS status = MH_Initialize();
        if (status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED) {
            if (error) *error = str::Format("MH_Initialize failed: %d", static_cast<int>(status));
            return false;
        }
        g_mhInitialized = true;
    }

    FMCP_LOGI("Installing ProcessEvent hook at %s", mem::FormatAddress(processEvent).c_str());
    void* trampoline = nullptr;
    MH_STATUS status = MH_CreateHook(reinterpret_cast<LPVOID>(processEvent),
                                     reinterpret_cast<LPVOID>(&GameThread::HookThunk), &trampoline);
    if (status == MH_ERROR_ALREADY_CREATED) {
        MH_RemoveHook(reinterpret_cast<LPVOID>(processEvent));
        status = MH_CreateHook(reinterpret_cast<LPVOID>(processEvent),
                               reinterpret_cast<LPVOID>(&GameThread::HookThunk), &trampoline);
    }
    if (status != MH_OK) {
        if (error) *error = str::Format("MH_CreateHook failed: %d", static_cast<int>(status));
        return false;
    }

    status = MH_EnableHook(reinterpret_cast<LPVOID>(processEvent));
    if (status != MH_OK) {
        MH_RemoveHook(reinterpret_cast<LPVOID>(processEvent));
        if (error) *error = str::Format("MH_EnableHook failed: %d", static_cast<int>(status));
        return false;
    }

    {
        std::lock_guard lock(mutex_);
        target_ = processEvent;
        original_ = trampoline;
        stopping_ = false;
    }

    hooked_ = true;
    FMCP_LOGI("ProcessEvent hook installed at %s", mem::FormatAddress(processEvent).c_str());
    return true;
}

bool GameThread::RemoveHook() {
    uintptr_t target = 0;
    bool wasHooked = false;
    {
        std::lock_guard lock(mutex_);
        wasHooked = hooked_.load();
        target = target_;
        stopping_ = true;
    }

    if (wasHooked) {
        const MH_STATUS status = MH_DisableHook(reinterpret_cast<LPVOID>(target));
        if (status != MH_OK && status != MH_ERROR_NOT_CREATED) {
            FMCP_LOGW("MH_DisableHook failed: %d", static_cast<int>(status));
        }
    }

    {
        std::lock_guard lock(mutex_);
        for (auto& job : queue_) {
            job->cancelled = true;
            job->done = true;
        }
        queue_.clear();
        pending_ = 0;
        cv_.notify_all();
    }

    const bool idle = WaitIdle(2000);

    {
        std::lock_guard lock(mutex_);
        hooked_ = false;
        stopping_ = false;
    }

    if (!idle) {
        FMCP_LOGW("ProcessEvent hook disabled, but game-thread calls are still active");
    }
    return idle;
}

void GameThread::Shutdown() {
    const bool idle = RemoveHook();
    if (g_mhInitialized && idle) {
        MH_Uninitialize();
        g_mhInitialized = false;
    } else if (g_mhInitialized) {
        FMCP_LOGW("Skipping MH_Uninitialize while game-thread calls are active");
    }
}

bool GameThread::Hooked() const {
    return hooked_.load();
}

uintptr_t GameThread::Target() const {
    std::lock_guard lock(mutex_);
    return target_;
}

uintptr_t GameThread::DirectTarget() const {
    std::lock_guard lock(mutex_);
    return target_;
}

size_t GameThread::Pending() const {
    return pending_.load();
}

uint64_t GameThread::ExecutedJobs() const {
    return executed_.load();
}

int GameThread::TimeoutMs() const {
    std::lock_guard lock(mutex_);
    return timeoutMs_;
}

void GameThread::SetDirectTarget(uintptr_t target) {
    std::lock_guard lock(mutex_);
    target_ = target;
}

void GameThread::Configure(int timeoutMs, int maxQueued, int jobsPerPump, int pumpBudgetUs) {
    std::lock_guard lock(mutex_);
    timeoutMs_ = timeoutMs > 0 ? timeoutMs : 5000;
    maxQueued_ = maxQueued > 0 ? maxQueued : 1;
    jobsPerPump_ = jobsPerPump > 0 ? jobsPerPump : 8;
    pumpBudgetUs_ = pumpBudgetUs > 0 ? pumpBudgetUs : 1500;
}

GameThreadStatus GameThread::Run(const std::function<void()>& job, std::string* error) {
    if (!job) {
        if (error) *error = "empty job";
        return GameThreadStatus::Cancelled;
    }

    if (pumpThreadId_.load(std::memory_order_acquire) == static_cast<uint32_t>(GetCurrentThreadId())) {
        try {
            job();
        } catch (const std::exception& e) {
            if (error) *error = e.what();
            return GameThreadStatus::Cancelled;
        }
        return GameThreadStatus::Ok;
    }

    if (!hooked_.load()) {
        return GameThreadStatus::NotInstalled;
    }

    auto entry = std::make_shared<Job>();
    entry->fn = job;

    int timeout = 5000;
    {
        std::lock_guard lock(mutex_);
        timeout = timeoutMs_;
        if (queue_.size() >= static_cast<size_t>(maxQueued_)) {
            if (error) *error = "game-thread queue is full";
            return GameThreadStatus::QueueFull;
        }
        queue_.push_back(entry);
        pending_.fetch_add(1, std::memory_order_release);
    }

    std::unique_lock lock(mutex_);
    const bool completed = cv_.wait_for(lock, std::chrono::milliseconds(timeout),
                                        [&] { return entry->done; });
    if (entry->cancelled) {
        if (error) *error = "game-thread job was cancelled";
        return GameThreadStatus::Cancelled;
    }
    if (!completed) {
        if (error) *error = "game-thread job timed out; it may still execute";
        return GameThreadStatus::Timeout;
    }
    return GameThreadStatus::Ok;
}

uint64_t GameThread::InvokeProcessEvent(uintptr_t object, uintptr_t function, void* params) {
    using PeFn = uint64_t (*)(uintptr_t, uintptr_t, void*);

    void* fn = nullptr;
    {
        std::lock_guard lock(mutex_);
        fn = original_ ? original_ : reinterpret_cast<void*>(target_);
    }

    if (!fn) {
        return 0;
    }
    return reinterpret_cast<PeFn>(fn)(object, function, params);
}

bool GameThread::WaitIdle(int timeoutMs) {
    const uint64_t deadline = NowUs() + static_cast<uint64_t>(timeoutMs) * 1000;
    while ((pending_.load() != 0 || activeCalls_.load() != 0) && NowUs() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return pending_.load() == 0 && activeCalls_.load() == 0;
}

uint64_t GameThread::HookThunk(uintptr_t object, uintptr_t function, void* params) {
    auto& self = Get();
    const uint32_t depth = self.activeCalls_.fetch_add(1, std::memory_order_acq_rel) + 1;

    using PeFn = uint64_t (*)(uintptr_t, uintptr_t, void*);
    void* original = nullptr;
    {
        std::lock_guard lock(self.mutex_);
        original = self.original_;
    }
    const uint64_t result = original
        ? reinterpret_cast<PeFn>(original)(object, function, params)
        : 0;

    if (depth == 1 && self.pumpThreadId_.load(std::memory_order_acquire) == 0 &&
        self.pending_.load(std::memory_order_acquire) != 0) {
        self.Pump();
    }
    self.activeCalls_.fetch_sub(1, std::memory_order_acq_rel);
    return result;
}

void GameThread::Pump() {
    const uint32_t currentThread = static_cast<uint32_t>(GetCurrentThreadId());
    uint32_t expected = 0;
    if (!pumpThreadId_.compare_exchange_strong(expected, currentThread,
                                               std::memory_order_acq_rel,
                                               std::memory_order_acquire)) {
        return;
    }

    struct PumpGuard {
        std::atomic<uint32_t>& id;
        ~PumpGuard() { id.store(0, std::memory_order_release); }
    } pumpGuard{pumpThreadId_};

    int jobs = 0;
    int budget = 0;
    {
        std::lock_guard lock(mutex_);
        jobs = jobsPerPump_;
        budget = pumpBudgetUs_;
    }

    const uint64_t start = NowUs();

    while (jobs-- > 0) {
        std::shared_ptr<Job> job;
        {
            std::lock_guard lock(mutex_);
            if (queue_.empty()) {
                break;
            }
            job = queue_.front();
            queue_.pop_front();
            pending_.fetch_sub(1, std::memory_order_acq_rel);
        }

        if (job && !job->cancelled) {
            try {
                job->fn();
                executed_.fetch_add(1, std::memory_order_relaxed);
            } catch (const std::exception& e) {
                FMCP_LOGE("Game-thread job threw: %s", e.what());
            } catch (...) {
                FMCP_LOGE("Game-thread job threw an unknown exception");
            }
        }

        {
            std::lock_guard lock(mutex_);
            job->done = true;
        }
        cv_.notify_all();

        if (budget > 0 && NowUs() - start >= static_cast<uint64_t>(budget)) {
            break;
        }
    }

}

}

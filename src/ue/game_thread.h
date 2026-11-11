#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace fmcp::ue {

enum class GameThreadStatus {
    Ok,
    Timeout,
    NotInstalled,
    QueueFull,
    Cancelled
};

class GameThread {
public:
    static GameThread& Get();

    bool Install(uintptr_t processEvent, int timeoutMs, int maxQueued, int jobsPerPump,
                 int pumpBudgetUs, std::string* error);
    bool RemoveHook();
    void Shutdown();

    [[nodiscard]] bool Hooked() const;
    [[nodiscard]] uintptr_t Target() const;
    [[nodiscard]] uintptr_t DirectTarget() const;
    [[nodiscard]] size_t Pending() const;
    [[nodiscard]] uint64_t ExecutedJobs() const;
    [[nodiscard]] int TimeoutMs() const;

    void SetDirectTarget(uintptr_t target);
    void Configure(int timeoutMs, int maxQueued, int jobsPerPump, int pumpBudgetUs);

    GameThreadStatus Run(const std::function<void()>& job, std::string* error = nullptr);
    uint64_t InvokeProcessEvent(uintptr_t object, uintptr_t function, void* params);
    bool WaitIdle(int timeoutMs);

private:
    GameThread() = default;
    ~GameThread();

    struct Job {
        std::function<void()> fn;
        bool done = false;
        bool cancelled = false;
    };

    static uint64_t HookThunk(uintptr_t object, uintptr_t function, void* params);
    void Pump();

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::shared_ptr<Job>> queue_;
    std::atomic<uint32_t> pending_{0};
    std::atomic<bool> hooked_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<uint64_t> executed_{0};
    std::atomic<uint32_t> activeCalls_{0};
    std::atomic<uint32_t> pumpThreadId_{0};
    uintptr_t target_ = 0;
    void* original_ = nullptr;
    int timeoutMs_ = 5000;
    int maxQueued_ = 32;
    int jobsPerPump_ = 8;
    int pumpBudgetUs_ = 1500;
};

}

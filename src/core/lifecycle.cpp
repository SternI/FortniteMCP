#include "core/lifecycle.h"

#include <atomic>

namespace fmcp::lifecycle {

namespace {

std::atomic<bool> g_pending{false};
std::atomic<bool> g_unload{true};
std::atomic<bool> g_restore{false};

}

void RequestShutdown(bool unloadSelf, bool restorePatches) {
    g_unload = unloadSelf;
    g_restore = restorePatches;
    g_pending = true;
}

bool Pending() {
    return g_pending.load(std::memory_order_acquire);
}

bool Consume(bool& unloadSelf, bool& restorePatches) {
    if (!g_pending.exchange(false, std::memory_order_acq_rel)) {
        return false;
    }
    unloadSelf = g_unload.load(std::memory_order_relaxed);
    restorePatches = g_restore.load(std::memory_order_relaxed);
    return true;
}

}

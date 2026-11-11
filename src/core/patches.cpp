#include "core/patches.h"

#include "core/log.h"
#include "core/memory.h"

#include <mutex>

namespace fmcp::patches {

namespace {

std::mutex g_mutex;
bool g_enabled = true;
int g_maxPatches = 128;
uint32_t g_nextId = 1;
std::vector<Patch> g_patches;

}

void Initialize(bool enabled, int maxPatches) {
    std::lock_guard lock(g_mutex);
    g_enabled = enabled;
    g_maxPatches = maxPatches < 1 ? 1 : maxPatches;
    g_patches.clear();
}

bool Enabled() {
    std::lock_guard lock(g_mutex);
    return g_enabled;
}

std::optional<uint32_t> Record(uintptr_t address, size_t size, std::string note) {
    if (!g_enabled || size == 0 || size > 0x10000) {
        return std::nullopt;
    }

    Patch patch;
    patch.original.resize(size);
    if (!mem::Read(address, patch.original.data(), size)) {
        return std::nullopt;
    }

    std::lock_guard lock(g_mutex);
    if (static_cast<int>(g_patches.size()) >= g_maxPatches) {
        g_patches.erase(g_patches.begin());
    }

    patch.id = g_nextId++;
    patch.address = address;
    patch.note = std::move(note);
    patch.timestamp = GetTickCount64();
    g_patches.push_back(std::move(patch));
    return g_patches.back().id;
}

std::vector<Patch> List() {
    std::lock_guard lock(g_mutex);
    return g_patches;
}

bool Undo(uint32_t id) {
    Patch patch;
    {
        std::lock_guard lock(g_mutex);
        auto it = std::find_if(g_patches.begin(), g_patches.end(),
                               [id](const Patch& p) { return p.id == id; });
        if (it == g_patches.end()) {
            return false;
        }
        patch = *it;
        g_patches.erase(it);
    }

    if (!mem::Write(patch.address, patch.original.data(), patch.original.size(), true)) {
        FMCP_LOGW("Failed to restore patch %u at %s", id, mem::FormatAddress(patch.address).c_str());
        return false;
    }
    return true;
}

size_t UndoAll() {
    std::vector<Patch> patches;
    {
        std::lock_guard lock(g_mutex);
        patches = g_patches;
        g_patches.clear();
    }

    size_t restored = 0;
    for (auto it = patches.rbegin(); it != patches.rend(); ++it) {
        if (mem::Write(it->address, it->original.data(), it->original.size(), true)) {
            ++restored;
        }
    }
    return restored;
}

size_t Count() {
    std::lock_guard lock(g_mutex);
    return g_patches.size();
}

void Clear() {
    std::lock_guard lock(g_mutex);
    g_patches.clear();
}

}

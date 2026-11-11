#include "core/allocator.h"

#include "core/log.h"
#include "core/memory.h"

#include <windows.h>

namespace fmcp {

namespace {

uintptr_t FindNearbyFree(size_t size, uintptr_t nearAddress) {
    const uintptr_t granularity = 0x10000;
    const uintptr_t start = nearAddress & ~(granularity - 1);
    const uintptr_t minAddress = 0x10000;
    const uintptr_t maxAddress = 0x00007FFFFFFEFFFFull;
    const uintptr_t range = 0x40000000ull;

    for (uintptr_t delta = granularity; delta < range; delta += granularity) {
        for (int direction = 0; direction < 2; ++direction) {
            const uintptr_t candidate = direction == 0 ? start - delta : start + delta;
            if (candidate < minAddress || candidate > maxAddress || candidate + size > maxAddress) {
                continue;
            }
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(candidate), &mbi, sizeof(mbi)) == 0) {
                continue;
            }
            if (mbi.State != MEM_FREE) {
                continue;
            }
            void* memory = VirtualAlloc(reinterpret_cast<LPVOID>(candidate), size,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (memory) {
                return reinterpret_cast<uintptr_t>(memory);
            }
        }
    }
    return 0;
}

}

namespace {
Allocator* g_allocator = nullptr;
}

Allocator& Allocator::Get() {
    if (!g_allocator) {
        g_allocator = new Allocator();
    }
    return *g_allocator;
}

uintptr_t Allocator::Allocate(size_t size, unsigned long protection, uintptr_t nearAddress,
                              const std::string& label, std::string* error) {
    if (size == 0 || size > 256ull * 1024 * 1024) {
        if (error) *error = "invalid allocation size";
        return 0;
    }

    uintptr_t address = 0;
    if (nearAddress) {
        address = FindNearbyFree(size, nearAddress);
    }
    if (!address) {
        void* memory = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!memory) {
            if (error) *error = "VirtualAlloc failed";
            return 0;
        }
        address = reinterpret_cast<uintptr_t>(memory);
    }

    DWORD old = 0;
    if (protection != PAGE_READWRITE &&
        !VirtualProtect(reinterpret_cast<LPVOID>(address), size, protection, &old)) {
        VirtualFree(reinterpret_cast<LPVOID>(address), 0, MEM_RELEASE);
        if (error) *error = "VirtualProtect failed";
        return 0;
    }

    AllocationInfo info;
    info.address = address;
    info.size = size;
    info.protection = protection;
    info.timestamp = GetTickCount64();
    info.label = label;

    {
        std::lock_guard lock(mutex_);
        allocations_[address] = info;
    }

    FMCP_LOGD("Allocated %zu bytes at %s (%s)", size, mem::FormatAddress(address).c_str(), label.c_str());
    return address;
}

bool Allocator::Free(uintptr_t address, bool allowUntracked, std::string* error) {
    {
        std::lock_guard lock(mutex_);
        auto it = allocations_.find(address);
        if (it != allocations_.end()) {
            const void* memory = reinterpret_cast<const void*>(address);
            if (!VirtualFree(const_cast<LPVOID>(memory), 0, MEM_RELEASE)) {
                if (error) *error = "VirtualFree failed for tracked allocation";
                return false;
            }
            allocations_.erase(it);
            return true;
        }
    }

    if (!allowUntracked) {
        if (error) *error = "address is not a tracked MCP allocation";
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0 ||
        mbi.BaseAddress != reinterpret_cast<LPVOID>(address) || mbi.Type != MEM_PRIVATE ||
        mbi.State != MEM_COMMIT) {
        if (error) *error = "refusing to free an address that is not a private allocation base";
        return false;
    }

    if (!VirtualFree(reinterpret_cast<LPVOID>(address), 0, MEM_RELEASE)) {
        if (error) *error = "VirtualFree failed";
        return false;
    }
    return true;
}

std::vector<AllocationInfo> Allocator::List() {
    std::lock_guard lock(mutex_);
    std::vector<AllocationInfo> out;
    out.reserve(allocations_.size());
    for (const auto& [_, info] : allocations_) {
        out.push_back(info);
    }
    return out;
}

size_t Allocator::Count() {
    std::lock_guard lock(mutex_);
    return allocations_.size();
}

void Allocator::FreeAll() {
    std::vector<AllocationInfo> items;
    {
        std::lock_guard lock(mutex_);
        for (const auto& [_, info] : allocations_) {
            items.push_back(info);
        }
        allocations_.clear();
    }
    for (const auto& info : items) {
        VirtualFree(reinterpret_cast<LPVOID>(info.address), 0, MEM_RELEASE);
    }
}

}

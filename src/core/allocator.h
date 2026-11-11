#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace fmcp {

struct AllocationInfo {
    uintptr_t address = 0;
    size_t size = 0;
    unsigned long protection = 0;
    uint64_t timestamp = 0;
    std::string label;
};

class Allocator {
public:
    static Allocator& Get();

    uintptr_t Allocate(size_t size, unsigned long protection, uintptr_t nearAddress,
                       const std::string& label, std::string* error);
    bool Free(uintptr_t address, bool allowUntracked, std::string* error);
    std::vector<AllocationInfo> List();
    size_t Count();
    void FreeAll();

private:
    std::mutex mutex_;
    std::unordered_map<uintptr_t, AllocationInfo> allocations_;
};

}

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace fmcp::modules {

struct SectionInfo {
    std::string name;
    uintptr_t address = 0;
    size_t size = 0;
    uint32_t characteristics = 0;
    bool executable = false;
    bool writable = false;
    bool readable = false;
};

struct ModuleInfo {
    std::string name;
    std::string path;
    uintptr_t base = 0;
    size_t size = 0;
    std::vector<SectionInfo> sections;

    [[nodiscard]] bool Contains(uintptr_t address, size_t length = 1) const {
        return address >= base && length <= size && address - base <= size - length;
    }
};

bool Refresh();
const ModuleInfo* Main();
std::vector<ModuleInfo> All();
std::optional<ModuleInfo> Find(std::string_view name);
const ModuleInfo* FindByAddress(uintptr_t address);
bool IsExecutableAddress(uintptr_t address, size_t size = 1);
bool IsReadOnlyAddress(uintptr_t address, size_t size = 1);
std::optional<uintptr_t> Resolve(std::string_view expression, std::string* error = nullptr);
std::string NameFromAddress(uintptr_t address);

}

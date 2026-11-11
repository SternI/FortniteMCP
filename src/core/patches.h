#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace fmcp::patches {

struct Patch {
    uint32_t id = 0;
    uintptr_t address = 0;
    std::vector<uint8_t> original;
    std::string note;
    uint64_t timestamp = 0;
};

void Initialize(bool enabled, int maxPatches);
bool Enabled();
std::optional<uint32_t> Record(uintptr_t address, size_t size, std::string note = {});
std::vector<Patch> List();
bool Undo(uint32_t id);
size_t UndoAll();
size_t Count();
void Clear();

}

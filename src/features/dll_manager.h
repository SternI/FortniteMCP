#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace fmcp::dll {

struct LoadedDll {
    uintptr_t base = 0;
    std::string path;
    uint64_t timestamp = 0;
    std::string label;
};

bool Load(const std::string& path, const std::string& label, LoadedDll& out, std::string* error);
bool Unload(const std::string& identifier, std::string* error);
std::vector<LoadedDll> List();
void Shutdown();

}

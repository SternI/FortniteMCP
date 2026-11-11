#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace fmcp::scan {

struct PatternByte {
    uint8_t value = 0;
    uint8_t mask = 0;
};

struct Request {
    uintptr_t start = 0;
    uintptr_t end = 0;
    std::vector<PatternByte> pattern;
    size_t alignment = 1;
    size_t maxResults = 64;
    uint64_t maxBytes = 512ull * 1024 * 1024;
    bool executableOnly = false;
    bool writableOnly = false;
};

struct Result {
    std::vector<uintptr_t> matches;
    uint64_t bytesScanned = 0;
    bool truncated = false;
    bool limitHit = false;
    std::string error;
};

std::optional<std::vector<PatternByte>> ParsePattern(std::string_view text, std::string* error = nullptr);
Result Search(const Request& request);

}

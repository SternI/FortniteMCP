#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace fmcp::b64 {

std::string Encode(const void* data, size_t size);
std::optional<std::vector<uint8_t>> Decode(std::string_view text);

}

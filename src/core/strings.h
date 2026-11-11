#pragma once

#include <cstdarg>
#include <cstdint>
#include <windows.h>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace fmcp::str {

std::string Format(const char* fmt, ...);
std::string VFormat(const char* fmt, va_list args);
std::string ToLower(std::string_view value);
bool IEquals(std::string_view a, std::string_view b);
bool IContains(std::string_view haystack, std::string_view needle);
std::string Trim(std::string_view value);
std::vector<std::string> Split(std::string_view value, char delim);
std::string ReplaceAll(std::string value, std::string_view from, std::string_view to);
bool StartsWith(std::string_view value, std::string_view prefix);
bool EndsWith(std::string_view value, std::string_view suffix);
std::string Hex(const void* data, size_t size, bool uppercase = false);
std::optional<std::vector<uint8_t>> Unhex(std::string_view text);
std::optional<uint64_t> ParseUint(std::string_view text, uint64_t max = UINT64_MAX);
std::string Narrow(const std::wstring& wide);
std::wstring Widen(const std::string& text);
std::string Sanitize(std::string_view value, size_t maxLength = 256);
std::string Basename(std::string_view path);

}

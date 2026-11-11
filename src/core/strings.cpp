#include "core/strings.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace fmcp::str {

std::string VFormat(const char* fmt, va_list args) {
    va_list copy;
    va_copy(copy, args);
    int needed = std::vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);

    if (needed <= 0) {
        return {};
    }

    std::string out(static_cast<size_t>(needed), '\0');
    std::vsnprintf(out.data(), out.size() + 1, fmt, args);
    return out;
}

std::string Format(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    std::string out = VFormat(fmt, args);
    va_end(args);
    return out;
}

std::string ToLower(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (char c : value) {
        out.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c));
    }
    return out;
}

bool IEquals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        char ca = a[i] >= 'A' && a[i] <= 'Z' ? static_cast<char>(a[i] + 32) : a[i];
        char cb = b[i] >= 'A' && b[i] <= 'Z' ? static_cast<char>(b[i] + 32) : b[i];
        if (ca != cb) {
            return false;
        }
    }
    return true;
}

bool IContains(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) {
        return true;
    }
    if (needle.size() > haystack.size()) {
        return false;
    }
    const std::string h = ToLower(haystack);
    const std::string n = ToLower(needle);
    return h.find(n) != std::string::npos;
}

std::string Trim(std::string_view value) {
    size_t start = 0;
    while (start < value.size() && static_cast<unsigned char>(value[start]) <= ' ') {
        ++start;
    }
    size_t end = value.size();
    while (end > start && static_cast<unsigned char>(value[end - 1]) <= ' ') {
        --end;
    }
    return std::string(value.substr(start, end - start));
}

std::vector<std::string> Split(std::string_view value, char delim) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= value.size()) {
        size_t end = value.find(delim, start);
        if (end == std::string_view::npos) {
            end = value.size();
        }
        std::string part = Trim(value.substr(start, end - start));
        if (!part.empty()) {
            out.push_back(std::move(part));
        }
        if (end == value.size()) {
            break;
        }
        start = end + 1;
    }
    return out;
}

std::string ReplaceAll(std::string value, std::string_view from, std::string_view to) {
    if (from.empty()) {
        return value;
    }
    size_t pos = 0;
    while ((pos = value.find(from, pos)) != std::string::npos) {
        value.replace(pos, from.size(), to);
        pos += to.size();
    }
    return value;
}

bool StartsWith(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

bool EndsWith(std::string_view value, std::string_view suffix) {
    return value.size() >= suffix.size() && value.substr(value.size() - suffix.size()) == suffix;
}

std::string Hex(const void* data, size_t size, bool uppercase) {
    static constexpr char kLower[] = "0123456789abcdef";
    static constexpr char kUpper[] = "0123456789ABCDEF";
    const char* digits = uppercase ? kUpper : kLower;

    const auto* bytes = static_cast<const uint8_t*>(data);
    std::string out;
    out.resize(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 0x0F];
    }
    return out;
}

std::optional<std::vector<uint8_t>> Unhex(std::string_view text) {
    std::vector<uint8_t> out;
    out.reserve(text.size() / 2);

    std::string trimmed = Trim(text);
    if (trimmed.size() >= 2 && trimmed[0] == '0' && (trimmed[1] == 'x' || trimmed[1] == 'X')) {
        trimmed.erase(0, 2);
    }

    int high = -1;
    for (char c : trimmed) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == '-' ||
            c == ':' || c == '_') {
            continue;
        }
        int value;
        if (c >= '0' && c <= '9') value = c - '0';
        else if (c >= 'a' && c <= 'f') value = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') value = c - 'A' + 10;
        else return std::nullopt;

        if (high < 0) {
            high = value;
        } else {
            out.push_back(static_cast<uint8_t>((high << 4) | value));
            high = -1;
        }
    }

    if (high >= 0) {
        return std::nullopt;
    }

    return out;
}

std::optional<uint64_t> ParseUint(std::string_view text, uint64_t max) {
    const std::string trimmed = Trim(text);
    if (trimmed.empty()) {
        return std::nullopt;
    }

    size_t pos = 0;
    int base = 10;
    if (trimmed.size() > 2 && trimmed[0] == '0' && (trimmed[1] == 'x' || trimmed[1] == 'X')) {
        base = 16;
        pos = 2;
    }

    uint64_t value = 0;
    bool any = false;
    for (; pos < trimmed.size(); ++pos) {
        const char c = trimmed[pos];
        if (c == '\'' || c == '_') {
            continue;
        }
        int digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (base == 16 && c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return std::nullopt;

        if (value > (max - static_cast<uint64_t>(digit)) / static_cast<uint64_t>(base)) {
            return std::nullopt;
        }
        value = value * static_cast<uint64_t>(base) + static_cast<uint64_t>(digit);
        any = true;
    }

    return any ? std::optional<uint64_t>(value) : std::nullopt;
}

std::string Narrow(const std::wstring& wide) {
    if (wide.empty()) {
        return {};
    }
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                                   nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }
    std::string out(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                        out.data(), size, nullptr, nullptr);
    return out;
}

std::wstring Widen(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                   nullptr, 0);
    if (size <= 0) {
        size = MultiByteToWideChar(CP_ACP, 0, text.data(), static_cast<int>(text.size()),
                                   nullptr, 0);
        if (size <= 0) {
            return {};
        }
        std::wstring out(static_cast<size_t>(size), L'\0');
        MultiByteToWideChar(CP_ACP, 0, text.data(), static_cast<int>(text.size()),
                            out.data(), size);
        return out;
    }
    std::wstring out(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size);
    return out;
}

std::string Sanitize(std::string_view value, size_t maxLength) {
    std::string out;
    out.reserve(std::min(value.size(), maxLength));
    for (char c : value) {
        if (out.size() >= maxLength) {
            break;
        }
        unsigned char uc = static_cast<unsigned char>(c);
        out.push_back(uc >= 32 && uc <= 126 ? c : '_');
    }
    return out;
}

std::string Basename(std::string_view path) {
    size_t pos = path.find_last_of("\\/");
    return pos == std::string_view::npos ? std::string(path) : std::string(path.substr(pos + 1));
}

}

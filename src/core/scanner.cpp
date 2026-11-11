#include "core/scanner.h"

#include "core/memory.h"
#include "core/strings.h"

#include <algorithm>
#include <cstring>
#include <windows.h>

namespace fmcp::scan {

namespace {

int HexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool IsWritableProtection(DWORD protection) {
    switch (protection & 0xFF) {
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

bool IsExecutableProtection(DWORD protection) {
    switch (protection & 0xFF) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

bool ReadableProtection(DWORD protection) {
    if (protection & (PAGE_GUARD | PAGE_NOACCESS)) {
        return false;
    }
    switch (protection & 0xFF) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

}

std::optional<std::vector<PatternByte>> ParsePattern(std::string_view text, std::string* error) {
    std::vector<PatternByte> pattern;

    std::string compact;
    compact.reserve(text.size());
    for (char c : text) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            continue;
        }
        if (c == '\\') {
            if (error) *error = "escaped patterns are not supported";
            return std::nullopt;
        }
        compact.push_back(c);
    }

    if (compact.empty()) {
        if (error) *error = "empty pattern";
        return std::nullopt;
    }

    if (compact.find('?') == std::string::npos && compact.size() <= 2) {
        compact.insert(0, 2 - compact.size(), '0');
    }

    if ((compact.size() % 2) != 0) {
        if (error) *error = "pattern must contain an even number of nibbles";
        return std::nullopt;
    }

    pattern.reserve(compact.size() / 2);
    for (size_t i = 0; i < compact.size(); i += 2) {
        const char high = compact[i];
        const char low = compact[i + 1];

        PatternByte byte{};
        if (high == '?') {
            byte.mask &= 0x0F;
        } else {
            const int value = HexValue(high);
            if (value < 0) {
                if (error) *error = str::Format("invalid hex character '%c'", high);
                return std::nullopt;
            }
            byte.value |= static_cast<uint8_t>(value << 4);
            byte.mask |= 0xF0;
        }

        if (low == '?') {
            byte.mask &= 0xF0;
        } else {
            const int value = HexValue(low);
            if (value < 0) {
                if (error) *error = str::Format("invalid hex character '%c'", low);
                return std::nullopt;
            }
            byte.value |= static_cast<uint8_t>(value);
            byte.mask |= 0x0F;
        }

        pattern.push_back(byte);
    }

    return pattern;
}

Result Search(const Request& request) {
    Result result;

    if (request.pattern.empty()) {
        result.error = "empty pattern";
        return result;
    }
    if (!mem::IsCanonical(request.start) || !mem::IsCanonical(request.end - 1) ||
        request.end <= request.start) {
        result.error = "invalid scan range";
        return result;
    }

    const size_t patternSize = request.pattern.size();
    size_t anchor = patternSize;
    uint8_t anchorMask = 0;
    for (size_t i = 0; i < patternSize; ++i) {
        if (request.pattern[i].mask == 0xFF) {
            anchor = i;
            anchorMask = 0xFF;
            break;
        }
        if (anchor == patternSize && request.pattern[i].mask != 0) {
            anchor = i;
            anchorMask = request.pattern[i].mask;
        }
    }
    if (anchor == patternSize) {
        result.error = "pattern has no fixed bytes";
        return result;
    }

    constexpr size_t kChunk = 1024 * 1024;
    uintptr_t cursor = request.start;
    const uintptr_t end = request.end;

    while (cursor < end) {
        if (result.bytesScanned >= request.maxBytes) {
            result.limitHit = true;
            result.truncated = true;
            break;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) == 0) {
            break;
        }

        const uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const uintptr_t regionEnd = regionBase + mbi.RegionSize;
        if (regionEnd <= cursor) {
            cursor += 0x1000;
            continue;
        }

        const bool usable = mbi.State == MEM_COMMIT && ReadableProtection(mbi.Protect) &&
                            (!request.executableOnly || IsExecutableProtection(mbi.Protect)) &&
                            (!request.writableOnly || IsWritableProtection(mbi.Protect));
        if (!usable) {
            cursor = std::min(regionEnd, end);
            continue;
        }

        const uintptr_t scanEnd = std::min(regionEnd, end);
        while (cursor < scanEnd) {
            const size_t regionRemaining = static_cast<size_t>(scanEnd - cursor);
            const size_t readSize = std::min(kChunk + patternSize - 1, regionRemaining);
            if (readSize < patternSize) {
                cursor = scanEnd;
                break;
            }

            std::vector<uint8_t> buffer(readSize);
            if (!mem::Read(cursor, buffer.data(), readSize)) {
                cursor += std::min<size_t>(readSize, 0x1000);
                continue;
            }

            if (readSize < patternSize) {
                cursor += readSize;
                break;
            }

            const size_t maxStart = readSize - patternSize;
            const size_t startCount = maxStart + 1;
            size_t pos = 0;

            while (pos < startCount) {
                const uint8_t* base = buffer.data() + pos;
                const size_t candidates = startCount - pos;
                size_t hit = std::string::npos;

                if (anchorMask == 0xFF) {
                    const void* found = memchr(base + anchor, request.pattern[anchor].value,
                                               candidates);
                    if (!found) {
                        break;
                    }
                    hit = static_cast<size_t>(static_cast<const uint8_t*>(found) - base);
                } else {
                    for (size_t i = anchor; i < anchor + candidates; ++i) {
                        if ((base[i] & anchorMask) == request.pattern[anchor].value) {
                            hit = i;
                            break;
                        }
                    }
                    if (hit == std::string::npos) {
                        break;
                    }
                }

                if (hit < anchor) {
                    pos += 1;
                    continue;
                }

                const size_t startIndex = hit - anchor;
                if (startIndex >= candidates) {
                    break;
                }

                bool match = true;
                for (size_t i = 0; i < patternSize; ++i) {
                    if ((base[startIndex + i] & request.pattern[i].mask) !=
                        (request.pattern[i].value & request.pattern[i].mask)) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    const uintptr_t address = cursor + pos + startIndex;
                    if (request.alignment <= 1 || (address % request.alignment) == 0) {
                        if (result.matches.size() >= request.maxResults) {
                            result.truncated = true;
                            result.limitHit = true;
                            return result;
                        }
                        result.matches.push_back(address);
                    }
                }

                pos += startIndex + 1;
            }

            result.bytesScanned += readSize;
            cursor += readSize - (patternSize - 1);
        }
    }

    return result;
}

}

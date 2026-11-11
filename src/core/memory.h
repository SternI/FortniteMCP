#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <type_traits>
#include <windows.h>

namespace fmcp::mem {

bool IsCanonical(uintptr_t address);
bool IsReadable(uintptr_t address, size_t size);
bool IsWritable(uintptr_t address, size_t size);
bool IsExecutable(uintptr_t address, size_t size = 1);
bool Protect(uintptr_t address, size_t size, DWORD protection, DWORD* oldProtection = nullptr);
bool Read(uintptr_t address, void* buffer, size_t size);
bool Write(uintptr_t address, const void* buffer, size_t size, bool force = false);

template <typename T>
bool Read(uintptr_t address, T& out) {
    static_assert(std::is_trivially_copyable_v<T>);
    return Read(address, &out, sizeof(T));
}

template <typename T>
T ReadOr(uintptr_t address, T fallback = T{}) {
    T value{};
    if (!Read(address, value)) {
        return fallback;
    }
    return value;
}

template <typename T>
bool Write(uintptr_t address, const T& value, bool force = false) {
    static_assert(std::is_trivially_copyable_v<T>);
    return Write(address, &value, sizeof(T), force);
}

std::optional<std::string> ReadCString(uintptr_t address, size_t maxLength = 512);
std::optional<std::wstring> ReadWString(uintptr_t address, size_t maxChars = 512);
std::string ProtectionName(DWORD protection);
std::string FormatAddress(uintptr_t address);
bool AlignRange(uintptr_t& address, size_t& size);

}

#include "core/memory.h"

#include "core/strings.h"

#include <windows.h>

namespace fmcp::mem {

namespace {

bool CopyFrom(void* dst, uintptr_t src, size_t size) {
    __try {
        memcpy(dst, reinterpret_cast<const void*>(src), size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool CopyTo(uintptr_t dst, const void* src, size_t size) {
    __try {
        memcpy(reinterpret_cast<void*>(dst), src, size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
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

bool WritableProtection(DWORD protection) {
    if (protection & (PAGE_GUARD | PAGE_NOACCESS)) {
        return false;
    }
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

bool ExecutableProtection(DWORD protection) {
    if (protection & (PAGE_GUARD | PAGE_NOACCESS)) {
        return false;
    }
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

template <typename Predicate>
bool CheckRange(uintptr_t address, size_t size, Predicate predicate) {
    if (size == 0) {
        return true;
    }
    if (!IsCanonical(address) || size > (UINTPTR_MAX - address)) {
        return false;
    }

    const uintptr_t end = address + size;
    uintptr_t cursor = address;

    while (cursor < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) == 0) {
            return false;
        }
        if (mbi.State != MEM_COMMIT || !predicate(mbi.Protect)) {
            return false;
        }

        const uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (regionEnd <= cursor) {
            return false;
        }
        cursor = regionEnd;
    }

    return true;
}

}

bool IsCanonical(uintptr_t address) {
    return address >= 0x10000ull && address <= 0x00007FFFFFFEFFFFull;
}

bool IsReadable(uintptr_t address, size_t size) {
    return CheckRange(address, size, ReadableProtection);
}

bool IsWritable(uintptr_t address, size_t size) {
    return CheckRange(address, size, WritableProtection);
}

bool IsExecutable(uintptr_t address, size_t size) {
    return CheckRange(address, size, ExecutableProtection);
}

bool Protect(uintptr_t address, size_t size, DWORD protection, DWORD* oldProtection) {
    DWORD old = 0;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(address), size, protection, &old)) {
        return false;
    }
    if (oldProtection) {
        *oldProtection = old;
    }
    return true;
}

bool Read(uintptr_t address, void* buffer, size_t size) {
    if (!buffer || size == 0) {
        return size == 0;
    }
    if (!IsReadable(address, size)) {
        return false;
    }
    return CopyFrom(buffer, address, size);
}

bool Write(uintptr_t address, const void* buffer, size_t size, bool force) {
    if (!buffer || size == 0) {
        return size == 0;
    }
    if (!IsCanonical(address) || size > (UINTPTR_MAX - address)) {
        return false;
    }

    if (!IsWritable(address, size)) {
        if (!force) {
            return false;
        }

        DWORD old = 0;
        const DWORD target = IsExecutable(address, size) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
        if (!VirtualProtect(reinterpret_cast<LPVOID>(address), size, target, &old)) {
            return false;
        }

        const bool ok = CopyTo(address, buffer, size);
        DWORD ignored = 0;
        VirtualProtect(reinterpret_cast<LPVOID>(address), size, old, &ignored);
        if (ok) {
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), size);
        }
        return ok;
    }

    return CopyTo(address, buffer, size);
}

std::optional<std::string> ReadCString(uintptr_t address, size_t maxLength) {
    if (!IsCanonical(address) || maxLength == 0) {
        return std::nullopt;
    }

    std::string out;
    out.reserve(std::min<size_t>(maxLength, 64));

    for (size_t i = 0; i < maxLength; ++i) {
        char c = 0;
        if (!Read(address + i, c)) {
            return out.empty() ? std::nullopt : std::optional<std::string>(std::move(out));
        }
        if (c == '\0') {
            return out;
        }
        out.push_back(c);
    }

    return out;
}

std::optional<std::wstring> ReadWString(uintptr_t address, size_t maxChars) {
    if (!IsCanonical(address) || maxChars == 0) {
        return std::nullopt;
    }

    std::wstring out;
    out.reserve(std::min<size_t>(maxChars, 64));

    for (size_t i = 0; i < maxChars; ++i) {
        wchar_t c = 0;
        if (!Read(address + i * sizeof(wchar_t), c)) {
            return out.empty() ? std::nullopt : std::optional<std::wstring>(std::move(out));
        }
        if (c == L'\0') {
            return out;
        }
        out.push_back(c);
    }

    return out;
}

std::string ProtectionName(DWORD protection) {
    if (protection & PAGE_GUARD) return "guard";
    if (protection & PAGE_NOACCESS) return "noaccess";

    switch (protection & 0xFF) {
    case PAGE_READONLY: return "r";
    case PAGE_READWRITE: return "rw";
    case PAGE_WRITECOPY: return "rwc";
    case PAGE_EXECUTE: return "x";
    case PAGE_EXECUTE_READ: return "rx";
    case PAGE_EXECUTE_READWRITE: return "rwx";
    case PAGE_EXECUTE_WRITECOPY: return "rwxc";
    default: return "?";
    }
}

std::string FormatAddress(uintptr_t address) {
    return str::Format("0x%llX", static_cast<unsigned long long>(address));
}

bool AlignRange(uintptr_t& address, size_t& size) {
    if (size == 0) {
        return true;
    }
    const uintptr_t page = 0x1000;
    const uintptr_t end = address + size;
    const uintptr_t alignedStart = address & ~(page - 1);
    const uintptr_t alignedEnd = (end + page - 1) & ~(page - 1);
    if (alignedEnd < alignedStart) {
        return false;
    }
    address = alignedStart;
    size = static_cast<size_t>(alignedEnd - alignedStart);
    return true;
}

}

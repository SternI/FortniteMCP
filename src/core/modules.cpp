#include "core/modules.h"

#include "core/memory.h"
#include "core/strings.h"

#include <TlHelp32.h>
#include <windows.h>

namespace fmcp::modules {

namespace {

std::vector<ModuleInfo> g_modules;
ModuleInfo g_main;
bool g_ready = false;

std::string ReadSectionName(const IMAGE_SECTION_HEADER& header) {
    char name[9]{};
    memcpy(name, header.Name, 8);
    return name;
}

ModuleInfo BuildModule(const MODULEENTRY32W& entry) {
    ModuleInfo info;
    info.name = str::Narrow(entry.szModule);
    info.path = str::Narrow(entry.szExePath);
    info.base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
    info.size = entry.modBaseSize;

    if (!info.base || !info.size) {
        return info;
    }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(info.base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return info;
    }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(info.base + static_cast<uintptr_t>(dos->e_lfanew));
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return info;
    }

    auto* sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto& header = sections[i];
        SectionInfo section;
        section.name = ReadSectionName(header);
        section.address = info.base + header.VirtualAddress;
        section.size = header.Misc.VirtualSize ? header.Misc.VirtualSize : header.SizeOfRawData;
        section.characteristics = header.Characteristics;
        section.executable = (header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        section.writable = (header.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        section.readable = (header.Characteristics & IMAGE_SCN_MEM_READ) != 0;
        info.sections.push_back(std::move(section));
    }

    return info;
}

bool NameMatches(std::string_view moduleName, std::string_view query) {
    if (str::IEquals(moduleName, query)) {
        return true;
    }

    std::string_view nameNoExt = moduleName;
    if (str::EndsWith(str::ToLower(moduleName), ".dll")) {
        nameNoExt = moduleName.substr(0, moduleName.size() - 4);
    }
    std::string_view queryNoExt = query;
    if (str::EndsWith(str::ToLower(query), ".dll")) {
        queryNoExt = query.substr(0, query.size() - 4);
    }
    return str::IEquals(nameNoExt, queryNoExt);
}

}

bool Refresh() {
    std::vector<ModuleInfo> modules;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                               GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Module32FirstW(snapshot, &entry)) {
        do {
            ModuleInfo info = BuildModule(entry);
            if (!info.base) {
                continue;
            }
            if (info.base == reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr))) {
                g_main = info;
            }
            modules.push_back(std::move(info));
        } while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    if (modules.empty()) {
        return false;
    }

    if (!g_main.base) {
        for (auto& module : modules) {
            if (module.base == reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr))) {
                g_main = module;
                break;
            }
        }
    }

    g_modules = std::move(modules);
    g_ready = true;
    return true;
}

const ModuleInfo* Main() {
    if (!g_ready) {
        Refresh();
    }
    return g_main.base ? &g_main : nullptr;
}

std::vector<ModuleInfo> All() {
    if (!g_ready) {
        Refresh();
    }
    return g_modules;
}

std::optional<ModuleInfo> Find(std::string_view name) {
    if (name == "main" || name == "base" || name == "exe") {
        if (const auto* main = Main()) {
            return *main;
        }
        return std::nullopt;
    }

    if (!g_ready) {
        Refresh();
    }
    for (const auto& module : g_modules) {
        if (NameMatches(module.name, name)) {
            return module;
        }
    }
    return std::nullopt;
}

const ModuleInfo* FindByAddress(uintptr_t address) {
    if (!g_ready) {
        Refresh();
    }
    for (const auto& module : g_modules) {
        if (module.Contains(address)) {
            return &module;
        }
    }
    return nullptr;
}

bool IsExecutableAddress(uintptr_t address, size_t size) {
    if (const auto* module = FindByAddress(address)) {
        for (const auto& section : module->sections) {
            if (!section.executable) {
                continue;
            }
            if (address >= section.address && size <= section.size &&
                address - section.address <= section.size - size) {
                return true;
            }
        }
    }
    return mem::IsExecutable(address, size);
}

bool IsReadOnlyAddress(uintptr_t address, size_t size) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0) {
        return false;
    }
    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
        return false;
    }
    if (reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize < address + size) {
        return false;
    }
    const DWORD protect = mbi.Protect & 0xFF;
    return protect == PAGE_READONLY || protect == PAGE_EXECUTE_READ;
}

std::optional<uintptr_t> Resolve(std::string_view expression, std::string* error) {
    std::string trimmed = str::Trim(expression);
    if (trimmed.empty()) {
        if (error) *error = "empty address";
        return std::nullopt;
    }

    if (auto direct = str::ParseUint(trimmed)) {
        return static_cast<uintptr_t>(*direct);
    }

    const size_t plus = trimmed.find_last_of('+');
    if (plus == std::string::npos) {
        if (error) *error = "address must be a number, module+offset, or base+offset";
        return std::nullopt;
    }

    std::string moduleName = str::Trim(trimmed.substr(0, plus));
    std::string offsetText = str::Trim(trimmed.substr(plus + 1));
    auto offset = str::ParseUint(offsetText);
    if (!offset) {
        if (error) *error = "invalid module offset";
        return std::nullopt;
    }

    auto module = Find(moduleName);
    if (!module) {
        if (error) *error = "module not found: " + moduleName;
        return std::nullopt;
    }

    return module->base + static_cast<uintptr_t>(*offset);
}

std::string NameFromAddress(uintptr_t address) {
    if (const auto* module = FindByAddress(address)) {
        return str::Format("%s+0x%llX", module->name.c_str(),
                           static_cast<unsigned long long>(address - module->base));
    }
    return mem::FormatAddress(address);
}

}

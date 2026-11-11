#include "features/dll_manager.h"

#include "core/config.h"
#include "core/log.h"
#include "core/memory.h"
#include "core/strings.h"

#include <windows.h>

#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

namespace fmcp::dll {

namespace {

std::mutex g_mutex;
std::unordered_map<uintptr_t, LoadedDll> g_loaded;

bool IsProtectedModule(HMODULE module) {
    const HMODULE self = GetModuleHandleW(L"FortniteMCP.dll");
    if (module == self) {
        return true;
    }
    if (module == GetModuleHandleW(nullptr)) {
        return true;
    }

    wchar_t path[MAX_PATH]{};
    if (GetModuleFileNameW(module, path, static_cast<DWORD>(std::size(path))) == 0) {
        return true;
    }

    const std::string lowered = str::ToLower(str::Narrow(path));
    for (const char* protectedName : {"\\windows\\system32\\ntdll.dll", "\\windows\\system32\\kernel32.dll",
                                      "\\windows\\system32\\kernelbase.dll", "\\windows\\system32\\user32.dll",
                                      "\\windows\\system32\\ws2_32.dll", "\\windows\\system32\\bcrypt.dll"}) {
        if (lowered.find(protectedName) != std::string::npos) {
            return true;
        }
    }
    return false;
}

}

bool Load(const std::string& path, const std::string& label, LoadedDll& out, std::string* error) {
    if (path.empty()) {
        if (error) *error = "path is empty";
        return false;
    }

    fs::path filePath = fs::path(path);
    if (filePath.is_relative()) {
        filePath = fs::path(Config::Get().directory) / filePath;
    }

    std::error_code ec;
    if (!fs::exists(filePath, ec) || !fs::is_regular_file(filePath, ec)) {
        if (error) *error = "DLL not found: " + filePath.string();
        return false;
    }

    const std::wstring wide = filePath.wstring();
    HMODULE module = LoadLibraryExW(wide.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!module) {
        if (error) *error = str::Format("LoadLibraryEx failed (error %lu)", GetLastError());
        return false;
    }

    LoadedDll info;
    info.base = reinterpret_cast<uintptr_t>(module);
    info.path = filePath.string();
    info.timestamp = GetTickCount64();
    info.label = label;

    {
        std::lock_guard lock(g_mutex);
        g_loaded[info.base] = info;
    }

    out = info;
    FMCP_LOGI("Loaded DLL %s at %s", info.path.c_str(), mem::FormatAddress(info.base).c_str());
    return true;
}

bool Unload(const std::string& identifier, std::string* error) {
    if (identifier.empty()) {
        if (error) *error = "identifier is empty";
        return false;
    }

    HMODULE module = nullptr;
    uintptr_t base = 0;
    if (auto address = str::ParseUint(identifier)) {
        base = static_cast<uintptr_t>(*address);
        module = reinterpret_cast<HMODULE>(base);
    }

    {
        std::lock_guard lock(g_mutex);
        for (const auto& [loadedBase, info] : g_loaded) {
            if (module && loadedBase == base) {
                base = loadedBase;
                module = reinterpret_cast<HMODULE>(loadedBase);
                break;
            }
            if (!module) {
                const std::string fileName = str::Basename(info.path);
                if (str::IEquals(fileName, identifier) || str::IEquals(info.path, identifier) ||
                    str::IEquals(str::Basename(identifier), fileName)) {
                    base = loadedBase;
                    module = reinterpret_cast<HMODULE>(loadedBase);
                    break;
                }
            }
        }

        if (!module || g_loaded.find(base) == g_loaded.end()) {
            if (error) *error = "DLL was not loaded through this MCP session";
            return false;
        }
    }

    if (IsProtectedModule(module)) {
        if (error) *error = "refusing to unload a protected module";
        return false;
    }

    const std::string path = g_loaded[base].path;
    if (!FreeLibrary(module)) {
        if (error) *error = str::Format("FreeLibrary failed (error %lu)", GetLastError());
        return false;
    }

    {
        std::lock_guard lock(g_mutex);
        g_loaded.erase(base);
    }
    FMCP_LOGI("Unloaded DLL %s", path.c_str());
    return true;
}

std::vector<LoadedDll> List() {
    std::lock_guard lock(g_mutex);
    std::vector<LoadedDll> out;
    out.reserve(g_loaded.size());
    for (const auto& [_, info] : g_loaded) {
        out.push_back(info);
    }
    return out;
}

void Shutdown() {
    std::lock_guard lock(g_mutex);
    g_loaded.clear();
}

}

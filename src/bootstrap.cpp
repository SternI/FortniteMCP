#include "bootstrap.h"

#include "core/allocator.h"
#include "core/config.h"
#include "core/lifecycle.h"
#include "core/log.h"
#include "core/memory.h"
#include "core/modules.h"
#include "core/patches.h"
#include "core/strings.h"
#include "features/dll_manager.h"
#include "mcp/http_server.h"
#include "mcp/json_rpc.h"
#include "mcp/tools.h"
#include "ue/context.h"

#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <winnt.h>

namespace fs = std::filesystem;

namespace fmcp {

namespace {

extern "C" NTSYSAPI BOOLEAN NTAPI RtlAddFunctionTable(PRUNTIME_FUNCTION FunctionTable,
                                                      DWORD EntryCount, DWORD64 BaseAddress);
extern "C" NTSYSAPI PRUNTIME_FUNCTION NTAPI RtlLookupFunctionEntry(
    DWORD64 ControlPc, PDWORD64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable);

HMODULE g_module = nullptr;
HANDLE g_stopEvent = nullptr;
std::atomic<bool> g_stopSignaled{false};
std::atomic<bool> g_unloadSelf{true};
std::atomic<bool> g_restorePatches{false};
std::atomic<uint64_t> g_startTick{0};

std::string DefaultLogPath() {
    wchar_t* local = nullptr;
    size_t length = 0;
    std::string base;

    if (_wdupenv_s(&local, &length, L"LOCALAPPDATA") == 0 && local) {
        base = str::Narrow(local);
    }
    free(local);

    if (base.empty()) {
        base = "C:\\FortniteMCP";
    }
    return base + "\\FortniteMCP\\FortniteMCP.log";
}

void WriteClientConfig(const Config& config, uint16_t port) {
    nlohmann::json root;
    nlohmann::json server = {{"url", str::Format("http://127.0.0.1:%u/mcp", port)}};
    if (!config.server.token.empty()) {
        server["headers"] = {{"Authorization", "Bearer " + config.server.token}};
    }
    root["mcpServers"]["fortnite"] = std::move(server);

    const std::string path = config.directory + "\\mcp-client.json";
    std::ofstream out(path, std::ios::trunc);
    if (out) {
        out << root.dump(2) << "\n";
        FMCP_LOGI("Wrote MCP client config to %s", path.c_str());
    }
}

}

void RequestStop(bool unloadSelf, bool restorePatches) {
    g_unloadSelf = unloadSelf;
    g_restorePatches = restorePatches;
    g_stopSignaled = true;
    if (g_stopEvent) {
        SetEvent(g_stopEvent);
    }
}

uint64_t UptimeMs() {
    const uint64_t start = g_startTick.load();
    return start ? GetTickCount64() - start : 0;
}

bool IsManuallyMapped() {
    if (!g_module) {
        return false;
    }
    HMODULE module = nullptr;
    return !GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(g_module), &module);
}

void RegisterExceptionTable(HMODULE module);

void EnsureExceptionTable(HMODULE module) {
    if (!module) {
        return;
    }

    DWORD64 imageBase = 0;
    PRUNTIME_FUNCTION existing = RtlLookupFunctionEntry(
        reinterpret_cast<DWORD64>(&EnsureExceptionTable), &imageBase, nullptr);
    if (existing && imageBase == reinterpret_cast<DWORD64>(module)) {
        FMCP_LOGI("Exception table already registered (entry=%p base=0x%llX)", existing,
                  static_cast<unsigned long long>(imageBase));
        return;
    }

    RegisterExceptionTable(module);

    imageBase = 0;
    PRUNTIME_FUNCTION check = RtlLookupFunctionEntry(
        reinterpret_cast<DWORD64>(&EnsureExceptionTable), &imageBase, nullptr);
    FMCP_LOGI("Exception lookup after registration: entry=%p base=0x%llX", check,
              static_cast<unsigned long long>(imageBase));
}


void RegisterExceptionTable(HMODULE module) {
    if (!module) {
        return;
    }

    auto* base = reinterpret_cast<uint8_t*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        FMCP_LOGW("Exception table: invalid DOS header");
        return;
    }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        FMCP_LOGW("Exception table: invalid NT header");
        return;
    }

    auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (std::strncmp(reinterpret_cast<const char*>(section->Name), ".pdata", 6) != 0) {
            continue;
        }
        auto* table = reinterpret_cast<RUNTIME_FUNCTION*>(base + section->VirtualAddress);
        const DWORD count = section->Misc.VirtualSize / sizeof(RUNTIME_FUNCTION);
        const BOOLEAN ok =
            RtlAddFunctionTable(table, count, reinterpret_cast<DWORD64>(base));
        FMCP_LOGI("Exception table: %lu entries at %p (%s)", count, table,
                  ok ? "registered" : "failed");
        return;
    }

    FMCP_LOGW("Exception table: .pdata not found; exceptions may not unwind");
}

void BootstrapMain(HMODULE module) {
    g_module = module;
    g_startTick = GetTickCount64();
    log::Init("", log::Level::Info, 4 * 1024 * 1024, false);

    Sleep(100);

    Config& config = Config::Get();
    config.Load();

    const log::Level level = log::ParseLevel(config.log.level);
    log::Init(config.log_path, level, config.log.max_file_bytes, config.log.debug_output);

    FMCP_LOGI("FortniteMCP %s starting (pid %lu)", FMCP_VERSION, GetCurrentProcessId());
    const bool manualMap = IsManuallyMapped();
    FMCP_LOGI("Load mode: %s", manualMap ? "manual map (self-unload unavailable)" : "loader");
    if (manualMap) {
        EnsureExceptionTable(module);
    }
    FMCP_LOGI("Config: %s", config.path.c_str());
    FMCP_LOGI("Config directory: %s", config.directory.c_str());
    if (!config.server.token.empty()) {
        FMCP_LOGI("Token file: %s", config.server.token_file.c_str());
    }

    modules::Refresh();
    patches::Initialize(config.safety.undo_patches, config.safety.max_patches);

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_stopSignaled) {
        SetEvent(g_stopEvent);
    }

    McpServer mcp;
    ue::UeContext::Get().Resolve(true);

    HttpServer http;
    http.SetAfterResponse([] {
        bool unloadSelf = false;
        bool restorePatches = false;
        if (!lifecycle::Consume(unloadSelf, restorePatches)) {
            return false;
        }
        RequestStop(unloadSelf, restorePatches);
        return true;
    });

    std::string serverError;
    const bool started = http.Start(config.server.host, config.server.port,
                                    [&mcp](const HttpRequest& request) { return mcp.HandleHttp(request); },
                                    config.server.max_body_bytes, config.server.max_connections,
                                    config.server.idle_timeout_ms, &serverError);
    if (!started) {
        FMCP_LOGE("HTTP server failed to start: %s", serverError.c_str());
        ue::UeContext::Get().Shutdown();
        if (g_stopEvent) {
            CloseHandle(g_stopEvent);
            g_stopEvent = nullptr;
        }
        log::Shutdown();
        return;
    }

    const uint16_t port = http.Port();
    FMCP_LOGI("MCP endpoint: http://%s:%u/mcp", config.server.host.c_str(), port);
    WriteClientConfig(config, port);

    if (!g_stopEvent) {
        return;
    }

    WaitForSingleObject(g_stopEvent, INFINITE);

    FMCP_LOGI("Shutdown requested");
    if (http.Running()) {
        http.Stop();
    }

    if (g_restorePatches) {
        const size_t restored = patches::UndoAll();
        FMCP_LOGI("Restored %zu patches", restored);
    }

    ue::UeContext::Get().Shutdown();
    const bool gameThreadIdle = ue::GameThread::Get().WaitIdle(5000);
    if (!gameThreadIdle) {
        FMCP_LOGE("Game-thread calls are still active; refusing to unload FortniteMCP");
    }
    Allocator::Get().FreeAll();
    dll::Shutdown();

    if (g_stopEvent) {
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
    }

    const bool unload = g_unloadSelf.load() && gameThreadIdle && !manualMap;
    if (g_unloadSelf.load() && manualMap) {
        FMCP_LOGW("Skipping FreeLibrary for a manually mapped DLL; unload it with the injector "
                  "or terminate the process");
    }
    FMCP_LOGI("Cleanup complete (unload_self=%s)", unload ? "true" : "false");
    log::Shutdown();

    if (unload && g_module) {
        FreeLibraryAndExitThread(g_module, 0);
    }
}

}

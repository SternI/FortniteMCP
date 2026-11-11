#include "mcp/tools.h"

#include "bootstrap.h"
#include "core/allocator.h"
#include "core/base64.h"
#include "core/config.h"
#include "core/lifecycle.h"
#include "core/log.h"
#include "core/memory.h"
#include "core/modules.h"
#include "core/patches.h"
#include "core/process.h"
#include "core/scanner.h"
#include "core/strings.h"
#include "features/dll_manager.h"
#include "ue/context.h"

#include <algorithm>

namespace fmcp {

namespace {

nlohmann::json VersionInfo() {
    return {{"name", "FortniteMCP"}, {"version", FMCP_VERSION}, {"abi", 1}};
}

void RegisterStatus(ToolRegistry& registry) {
    registry.Add({"status",
                  "High-level server, process, config, safety, DLL, and UE status.",
                  nlohmann::json::parse(R"({"type":"object","properties":{},"additionalProperties":false})"),
                  [](const nlohmann::json&) -> nlohmann::json {
        const Config& config = Config::Get();
        modules::Refresh();

        nlohmann::json safety = {{"max_transfer_bytes", config.safety.max_transfer_bytes},
                                 {"max_read_bytes", config.safety.max_read_bytes},
                                 {"max_scan_results", config.safety.max_scan_results},
                                 {"max_scan_bytes", config.safety.max_scan_bytes},
                                 {"max_patches", config.safety.max_patches},
                                 {"undo_patches", config.safety.undo_patches},
                                 {"allow_raw_calls", config.safety.allow_raw_calls},
                                 {"allow_any_free", config.safety.allow_any_free},
                                 {"allow_self_unload", config.safety.allow_self_unload},
                                 {"require_confirm", config.safety.require_confirm}};

        nlohmann::json dlls = nlohmann::json::array();
        for (const auto& dll : dll::List()) {
            dlls.push_back({{"base", mem::FormatAddress(dll.base)},
                            {"path", dll.path},
                            {"label", dll.label},
                            {"timestamp", dll.timestamp}});
        }

        nlohmann::json result = {
            {"server", {{"version", FMCP_VERSION},
                        {"uptime_ms", UptimeMs()},
                        {"endpoint", str::Format("http://%s:%u/mcp", config.server.host.c_str(), config.server.port)},
                        {"auth_required", !config.server.token.empty()},
                        {"token_file", config.server.token_file}}},
            {"process", {{"pid", GetCurrentProcessId()},
                         {"config_path", config.path},
                         {"log_path", config.log_path},
                         {"module_count", modules::All().size()},
                         {"main_module", modules::Main() ? modules::Main()->name : std::string{}},
                         {"main_base", modules::Main() ? mem::FormatAddress(modules::Main()->base) : std::string{}}}},
            {"safety", std::move(safety)},
            {"game_thread", {{"enabled", config.game_thread.enabled},
                             {"direct_fallback", config.game_thread.direct_fallback},
                             {"hooked", ue::UeContext::Get().GameThreadHooked()},
                             {"pending_jobs", ue::GameThread::Get().Pending()}}},
            {"allocations", Allocator::Get().Count()},
            {"patches", patches::Count()},
            {"loaded_dlls", std::move(dlls)},
            {"ue", ue::UeContext::Get().Status()}};
        return result;
    }});
}

void RegisterLog(ToolRegistry& registry) {
    registry.Add({"get_log",
                  "Read the tail of the FortniteMCP log.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{"lines":{"type":"integer","default":200,"minimum":1,"maximum":2000}},
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        const size_t lines = std::clamp<size_t>(args.value("lines", 200), 1, 2000);
        return nlohmann::json{{"path", log::Path()}, {"text", log::Tail(lines)}};
    }});
}

void RegisterSelfTest(ToolRegistry& registry) {
    registry.Add({"self_test",
                  "Run safety checks for memory access, scanning, base64, allocation, "
                  "the x64 call thunk, and the game-thread queue.",
                  nlohmann::json::parse(R"({"type":"object","properties":{},"additionalProperties":false})"),
                  [](const nlohmann::json&) -> nlohmann::json {
        nlohmann::json tests = nlohmann::json::array();
        bool allOk = true;

        auto add = [&](const std::string& name, bool ok, const std::string& detail) {
            tests.push_back({{"name", name}, {"ok", ok}, {"detail", detail}});
            if (!ok) allOk = false;
        };

        {
            uint64_t value = 0x1122334455667788ull;
            uint64_t readBack = 0;
            const bool ok = mem::Read(reinterpret_cast<uintptr_t>(&value), readBack) &&
                            readBack == value;
            add("memory_read", ok, ok ? "read scalar" : "failed to read a local scalar");
        }

        {
            const bool invalid1 = !mem::IsReadable(0x10, 8);
            const bool invalid2 = !mem::IsReadable(0xFFFFFFFFFFFFFFFFull, 8);
            add("memory_validation", invalid1 && invalid2, "invalid addresses rejected");
        }

        {
            auto pattern = scan::ParsePattern("4D 5A");
            bool ok = false;
            std::string detail = "no main module";
            if (pattern && modules::Main()) {
                scan::Request request;
                request.start = modules::Main()->base;
                request.end = modules::Main()->base + std::min<size_t>(modules::Main()->size, 0x1000);
                request.pattern = *pattern;
                request.maxResults = 1;
                auto result = scan::Search(request);
                ok = !result.matches.empty();
                detail = ok ? "MZ header found" : "MZ header not found";
            }
            add("scanner", ok, detail);
        }

        {
            std::string detail = "allocation failed";
            bool ok = false;
            const uintptr_t memory = Allocator::Get().Allocate(2 * 1024 * 1024, PAGE_READWRITE, 0,
                                                                "scanner_boundary", nullptr);
            if (memory) {
                const uint8_t marker[8] = {0x4D, 0x5A, 0xC3, 0x99, 0x01, 0x02, 0x03, 0x04};
                const uintptr_t target = memory + 1024 * 1024 - 3;
                auto pattern = scan::ParsePattern("4D 5A C3 99 01 02 03 04");
                scan::Request request;
                request.start = memory;
                request.end = memory + 2 * 1024 * 1024;
                request.pattern = pattern ? *pattern : std::vector<scan::PatternByte>{};
                request.maxResults = 4;
                request.maxBytes = 4 * 1024 * 1024;
                if (pattern && mem::Write(target, static_cast<const void*>(marker), sizeof(marker))) {
                    const auto result = scan::Search(request);
                    ok = result.matches.size() == 1 && result.matches[0] == target;
                    detail = ok ? "chunk-boundary match found"
                                : str::Format("boundary mismatch (%zu matches)", result.matches.size());
                } else {
                    detail = "write or pattern failed";
                }
                std::string freeError;
                Allocator::Get().Free(memory, false, &freeError);
            }
            add("scanner_boundary", ok, detail);
        }

        {
            const std::string text = "FortniteMCP self test";
            const std::string encoded = b64::Encode(text.data(), text.size());
            auto decoded = b64::Decode(encoded);
            const bool ok = decoded && std::string(decoded->begin(), decoded->end()) == text;
            add("base64", ok, ok ? "roundtrip ok" : "roundtrip failed");
        }

        {
            std::string error;
            const uintptr_t memory = Allocator::Get().Allocate(64, PAGE_READWRITE, 0, "self_test", &error);
            bool ok = false;
            if (memory) {
                const uint64_t value = 0xA1B2C3D4E5F60718ull;
                ok = mem::Write(memory, value) && mem::ReadOr<uint64_t>(memory, 0) == value &&
                     Allocator::Get().Free(memory, false, &error);
            }
            add("allocator", ok, ok ? "allocate/write/read/free ok" : error);
        }

        {
            std::string error;
            const bool ok = SelfTestCallingConvention(&error);
            add("call_thunk", ok, ok ? "Win64 argument passing ok" : error);
        }

        {
            auto& ctx = ue::UeContext::Get();
            bool ok = true;
            std::string detail = "game-thread hook is not installed (skipped)";
            if (ctx.GameThreadHooked()) {
                std::string error;
                ok = ctx.RunOnGameThread([] {}, false, &error, nullptr);
                detail = ok ? "game-thread job executed" : error;
            }
            add("game_thread", ok, detail);
        }

        auto& ctx = ue::UeContext::Get();
        const auto& report = ctx.Report();
        add("ue_resolution", report.resolved,
            report.resolved ? "UE resolver ran" : "UE resolver has not run");

        return nlohmann::json{{"ok", allOk}, {"tests", std::move(tests)}, {"ue", {
            {"static_find_object", report.static_find_object},
            {"process_event", report.process_event},
            {"names", report.names},
            {"properties", report.properties},
            {"game_thread", report.game_thread}}}};
    }});
}

void RegisterDllTools(ToolRegistry& registry) {
    registry.Add({"load_dll",
                  "Load a DLL from disk into the current game process. Only absolute paths or paths "
                  "relative to the FortniteMCP config directory are accepted.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "path":{"type":"string"},
                      "label":{"type":"string"}
                    },
                    "required":["path"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        std::string error;
        dll::LoadedDll loaded;
        if (!dll::Load(args["path"].get<std::string>(), args.value("label", "load_dll"), loaded, &error)) {
            throw ToolError(error);
        }
        return nlohmann::json{{"loaded", true},
                              {"base", mem::FormatAddress(loaded.base)},
                              {"path", loaded.path},
                              {"label", loaded.label}};
    }});

    registry.Add({"unload_dll",
                  "Unload a DLL previously loaded through load_dll. Requires confirm=true.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "module":{"type":"string"},
                      "confirm":{"type":"boolean","default":false}
                    },
                    "required":["module"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        RequireConfirmation(args);
        std::string error;
        if (!dll::Unload(args["module"].get<std::string>(), &error)) {
            throw ToolError(error);
        }
        return nlohmann::json{{"unloaded", args["module"]}};
    }});

    registry.Add({"dll_list",
                  "List DLLs loaded by this MCP session.",
                  nlohmann::json::parse(R"({"type":"object","properties":{},"additionalProperties":false})"),
                  [](const nlohmann::json&) -> nlohmann::json {
        nlohmann::json items = nlohmann::json::array();
        for (const auto& dll : dll::List()) {
            items.push_back({{"base", mem::FormatAddress(dll.base)},
                             {"path", dll.path},
                             {"label", dll.label},
                             {"timestamp", dll.timestamp}});
        }
        return nlohmann::json{{"dlls", std::move(items)}};
    }});
}

void RegisterShutdown(ToolRegistry& registry) {
    registry.Add({"shutdown",
                  "Stop the MCP server and optionally unload FortniteMCP from the game. "
                  "Requires confirm=true. The HTTP response is sent before shutdown begins. "
                  "unload_self=false leaves the DLL loaded but stops all MCP services. "
                  "For a manually mapped DLL, unload_self is ignored; eject with the injector.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "confirm":{"type":"boolean","default":false},
                      "unload_self":{"type":"boolean","default":true},
                      "restore_patches":{"type":"boolean","default":false}
                    },
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        RequireConfirmation(args);
        bool unloadSelf = args.value("unload_self", true);
        const bool restorePatches = args.value("restore_patches", false);
        const bool manualMap = IsManuallyMapped();

        if (manualMap) {
            unloadSelf = false;
        }
        if (unloadSelf && !Config::Get().safety.allow_self_unload) {
            throw ToolError("self unload is disabled in config (safety.allow_self_unload)");
        }

        if (lifecycle::Pending()) {
            throw ToolError("shutdown is already pending");
        }

        lifecycle::RequestShutdown(unloadSelf, restorePatches);
        return nlohmann::json{{"shutdown", "scheduled"},
                              {"unload_self", unloadSelf},
                              {"manual_map", manualMap},
                              {"restore_patches", restorePatches},
                              {"note", manualMap
                                  ? "server will stop; a manually mapped DLL must be ejected by the injector"
                                  : "the server will stop after this response is sent"}};
    }});
}

}

void RegisterSystemTools(ToolRegistry& registry) {
    RegisterStatus(registry);
    RegisterLog(registry);
    RegisterSelfTest(registry);
    RegisterDllTools(registry);
    RegisterShutdown(registry);
}

}

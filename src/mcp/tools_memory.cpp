#include "mcp/tools.h"

#include "core/allocator.h"
#include "core/base64.h"
#include "core/config.h"
#include "core/log.h"
#include "core/memory.h"
#include "core/modules.h"
#include "core/patches.h"
#include "core/scanner.h"
#include "core/strings.h"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace fmcp {

namespace {

nlohmann::json DecodeTyped(const uint8_t* data, size_t size, const std::string& type) {
    using nlohmann::json;
    const auto check = [&](size_t bytes) { return data && size >= bytes; };

    if (type == "u8") return check(1) ? json(*reinterpret_cast<const uint8_t*>(data)) : json("out of range");
    if (type == "i8") return check(1) ? json(*reinterpret_cast<const int8_t*>(data)) : json("out of range");
    if (type == "u16") { uint16_t v{}; if (!check(2)) return "out of range"; memcpy(&v, data, 2); return json(v); }
    if (type == "i16") { int16_t v{}; if (!check(2)) return "out of range"; memcpy(&v, data, 2); return json(v); }
    if (type == "u32") { uint32_t v{}; if (!check(4)) return "out of range"; memcpy(&v, data, 4); return json(v); }
    if (type == "i32") { int32_t v{}; if (!check(4)) return "out of range"; memcpy(&v, data, 4); return json(v); }
    if (type == "u64") { uint64_t v{}; if (!check(8)) return "out of range"; memcpy(&v, data, 8); return json(v); }
    if (type == "i64") { int64_t v{}; if (!check(8)) return "out of range"; memcpy(&v, data, 8); return json(v); }
    if (type == "f32") {
        float v = NAN;
        if (!check(4)) return "out of range";
        memcpy(&v, data, 4);
        if (!std::isfinite(v)) return json("non-finite");
        return json(v);
    }
    if (type == "f64") {
        double v = NAN;
        if (!check(8)) return "out of range";
        memcpy(&v, data, 8);
        if (!std::isfinite(v)) return json("non-finite");
        return json(v);
    }
    if (type == "bool") return check(1) ? json(*data != 0) : json("out of range");
    if (type == "ptr") {
        uintptr_t pointer = 0;
        if (!check(sizeof(pointer))) return "out of range";
        memcpy(&pointer, data, sizeof(pointer));
        return json{{"address", mem::FormatAddress(pointer)},
                    {"location", modules::NameFromAddress(pointer)}};
    }
    if (type == "cstr") {
        std::string text;
        for (size_t i = 0; i < size; ++i) {
            if (data[i] == 0) break;
            text.push_back(static_cast<char>(data[i]));
        }
        return json(text);
    }
    if (type == "wstr") {
        std::wstring text;
        for (size_t i = 0; i + 1 < size; i += 2) {
            wchar_t c = 0;
            memcpy(&c, data + i, 2);
            if (!c) break;
            text.push_back(c);
        }
        return json(str::Narrow(text));
    }
    if (type == "guid") {
        if (!check(16)) return "out of range";
        const uint32_t* dwords = reinterpret_cast<const uint32_t*>(data);
        return json{{"a", dwords[0]}, {"b", dwords[1]}, {"c", dwords[2]}, {"d", dwords[3]}};
    }
    if (type == "vec2f" || type == "vec3f" || type == "vec4f") {
        const size_t count = type == "vec2f" ? 2 : (type == "vec3f" ? 3 : 4);
        if (!check(count * 4)) return "out of range";
        json array = json::array();
        for (size_t i = 0; i < count; ++i) {
            float v = 0;
            memcpy(&v, data + i * 4, 4);
            array.push_back(v);
        }
        return array;
    }
    if (type == "vec2d" || type == "vec3d" || type == "vec4d") {
        const size_t count = type == "vec2d" ? 2 : (type == "vec3d" ? 3 : 4);
        if (!check(count * 8)) return "out of range";
        json array = json::array();
        for (size_t i = 0; i < count; ++i) {
            double v = 0;
            memcpy(&v, data + i * 8, 8);
            array.push_back(v);
        }
        return array;
    }

    return "unknown type";
}

DWORD ProtectionFromName(const std::string& name, bool* valid) {
    *valid = true;
    const std::string lower = str::ToLower(name);
    if (lower == "rw" || lower == "readwrite") return PAGE_READWRITE;
    if (lower == "r" || lower == "read" || lower == "readonly") return PAGE_READONLY;
    if (lower == "rx" || lower == "execute_read") return PAGE_EXECUTE_READ;
    if (lower == "rwx" || lower == "execute_readwrite") return PAGE_EXECUTE_READWRITE;
    if (lower == "x" || lower == "execute") return PAGE_EXECUTE;
    *valid = false;
    return PAGE_READWRITE;
}

void RegisterRead(ToolRegistry& registry) {
    registry.Add({"memory_read",
                  "Read process memory. Supports hex/base64 output and optional typed decoding. "
                  "Addresses accept 0x..., decimal, or module+offset.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "address":{"type":["string","integer"],"description":"Target address or module+offset"},
                      "size":{"type":"integer","minimum":1},
                      "format":{"type":"string","enum":["auto","hex","base64"],"default":"auto"},
                      "include_hex":{"type":"boolean","default":true},
                      "decode":{"type":"array","items":{"type":"object","properties":{
                        "type":{"type":"string","description":"u8,i8,u16,i16,u32,i32,u64,i64,f32,f64,bool,ptr,cstr,wstr,guid,vec2f,vec3f,vec4f,vec2d,vec3d,vec4d"},
                        "offset":{"type":"integer","minimum":0,"default":0}},
                        "required":["type"]}}
                    },
                    "required":["address","size"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        std::string error;
        const uintptr_t address = AddressFromObject(args, "address", &error);
        if (!address) throw ToolError(error);

        const uint64_t sizeValue = args["size"].get<uint64_t>();
        const auto& safety = Config::Get().safety;
        if (sizeValue == 0 || sizeValue > safety.max_read_bytes) {
            throw ToolError(str::Format("size must be 1..%zu", safety.max_read_bytes));
        }
        const size_t size = static_cast<size_t>(sizeValue);
        if (!mem::IsReadable(address, size)) {
            throw ToolError("memory range is not readable");
        }

        std::vector<uint8_t> data(size);
        if (!mem::Read(address, data.data(), size)) {
            throw ToolError("read failed");
        }

        std::string format = args.value("format", "auto");
        const bool includeHex = args.value("include_hex", true);
        if (!includeHex) {
            format = "base64";
        } else if (format == "auto") {
            format = size <= 65536 ? "hex" : "base64";
        }

        nlohmann::json result;
        result["address"] = mem::FormatAddress(address);
        result["location"] = modules::NameFromAddress(address);
        result["size"] = size;
        result["format"] = format;

        if (format == "base64") {
            result["data_base64"] = b64::Encode(data.data(), data.size());
        } else {
            if (data.size() > 262144) {
                throw ToolError("hex output is limited to 256 KiB; use format=base64 or read a smaller range");
            }
            result["hex"] = str::Hex(data.data(), data.size());
        }

        if (args.contains("decode") && args["decode"].is_array()) {
            nlohmann::json values = nlohmann::json::array();
            for (const auto& field : args["decode"]) {
                if (!field.is_object() || !field.contains("type")) continue;
                const int64_t offset = field.value("offset", 0);
                const std::string type = field["type"].get<std::string>();
                nlohmann::json entry = {{"type", type}, {"offset", offset}};
                if (offset < 0 || static_cast<uint64_t>(offset) > size) {
                    entry["error"] = "offset out of range";
                } else {
                    entry["value"] = DecodeTyped(data.data() + offset, size - static_cast<size_t>(offset), type);
                }
                values.push_back(std::move(entry));
            }
            result["values"] = std::move(values);
        }

        return result;
    }});

    registry.Add({"memory_read_safe",
                  "Non-throwing memory read. Returns ok=false with an error instead of raising a "
                  "tool error; used by diagnostics that probe unknown addresses.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "address":{"type":["string","integer"]},
                      "size":{"type":"integer","minimum":1,"maximum":65536}
                    },
                    "required":["address","size"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        nlohmann::json result{{"ok", false}};
        std::string error;
        const uintptr_t address = AddressFromObject(args, "address", &error);
        if (!address) {
            result["error"] = error;
            return result;
        }

        const uint64_t sizeValue = args["size"].get<uint64_t>();
        if (sizeValue == 0 || sizeValue > 65536) {
            result["error"] = "size must be 1..65536";
            return result;
        }
        const size_t size = static_cast<size_t>(sizeValue);

        result["address"] = mem::FormatAddress(address);
        result["size"] = size;
        if (!mem::IsReadable(address, size)) {
            result["error"] = "memory range is not readable";
            return result;
        }

        std::vector<uint8_t> data(size);
        if (!mem::Read(address, data.data(), size)) {
            result["error"] = "read failed";
            return result;
        }

        result["ok"] = true;
        result["hex"] = str::Hex(data.data(), data.size());
        return result;
    }});
}

void RegisterWrite(ToolRegistry& registry) {
    registry.Add({"memory_write",
                  "Write process memory. Set force=true to change non-writable pages (code patches). "
                  "The original bytes are recorded for patch_undo when safety.undo_patches is enabled.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "address":{"type":["string","integer"]},
                      "bytes_hex":{"type":"string"},
                      "data_base64":{"type":"string"},
                      "bytes":{"type":["string","array"]},
                      "force":{"type":"boolean","default":false},
                      "label":{"type":"string"}
                    },
                    "required":["address"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        std::string error;
        const uintptr_t address = AddressFromObject(args, "address", &error);
        if (!address) throw ToolError(error);

        auto data = DataFromJson(args);
        if (data.empty()) throw ToolError("no bytes provided");
        if (data.size() > Config::Get().safety.max_transfer_bytes) {
            throw ToolError("write exceeds max_transfer_bytes");
        }

        const bool force = args.value("force", false);
        if (!mem::IsWritable(address, data.size()) && !force) {
            throw ToolError("memory is not writable; pass force=true to patch it");
        }
        if (!mem::IsCanonical(address) || data.size() > UINTPTR_MAX - address) {
            throw ToolError("invalid write range");
        }

        std::optional<uint32_t> patchId;
        if (Config::Get().safety.undo_patches) {
            patchId = patches::Record(address, data.size(), args.value("label", "memory_write"));
        }

        if (!mem::Write(address, data.data(), data.size(), force)) {
            throw ToolError("write failed");
        }

        nlohmann::json result = {{"address", mem::FormatAddress(address)},
                                 {"location", modules::NameFromAddress(address)},
                                 {"written", data.size()},
                                 {"forced", force}};
        if (patchId) result["patch_id"] = *patchId;

        std::vector<uint8_t> verify(std::min<size_t>(data.size(), 256));
        if (mem::Read(address, verify.data(), verify.size())) {
            result["readback_hex"] = str::Hex(verify.data(), verify.size());
        }

        return result;
    }});
}

void RegisterScan(ToolRegistry& registry) {
    registry.Add({"memory_scan",
                  "Scan a module or address range for an IDA-style byte pattern (e.g. \"48 8B ?? 4C\"). "
                  "Useful for locating signatures and offsets.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "pattern":{"type":"string"},
                      "module":{"type":"string","default":"main"},
                      "start":{"type":["string","integer"]},
                      "end":{"type":["string","integer"]},
                      "max_results":{"type":"integer","default":64,"minimum":1},
                      "alignment":{"type":"integer","default":1,"minimum":1},
                      "executable_only":{"type":"boolean","default":false},
                      "writable_only":{"type":"boolean","default":false},
                      "max_bytes":{"type":"integer"}
                    },
                    "required":["pattern"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        const auto& safety = Config::Get().safety;
        std::string error;
        auto pattern = scan::ParsePattern(args["pattern"].get<std::string>(), &error);
        if (!pattern) throw ToolError("invalid pattern: " + error);

        uintptr_t start = 0;
        uintptr_t end = 0;
        if (args.contains("start") || args.contains("end")) {
            if (!args.contains("start") || !args.contains("end")) {
                throw ToolError("start and end must be provided together");
            }
            start = AddressFromJson(args["start"], &error);
            end = AddressFromJson(args["end"], &error);
        } else {
            std::string moduleName = args.value("module", "main");
            auto module = modules::Find(moduleName);
            if (!module) throw ToolError("module not found: " + moduleName);
            start = module->base;
            end = module->base + module->size;
        }

        if (!start || end <= start) throw ToolError("invalid scan range");

        size_t maxResults = static_cast<size_t>(args.value("max_results", 64));
        maxResults = std::clamp<size_t>(maxResults, 1, std::min<size_t>(safety.max_scan_results, 4096));
        size_t alignment = static_cast<size_t>(args.value("alignment", 1));
        alignment = std::clamp<size_t>(alignment, 1, 0x10000);

        uint64_t maxBytes = safety.max_scan_bytes;
        if (args.contains("max_bytes")) {
            maxBytes = std::min<uint64_t>(args["max_bytes"].get<uint64_t>(), safety.max_scan_bytes);
        }

        scan::Request request;
        request.start = start;
        request.end = end;
        request.pattern = std::move(*pattern);
        request.maxResults = maxResults;
        request.alignment = alignment;
        request.maxBytes = maxBytes;
        request.executableOnly = args.value("executable_only", false);
        request.writableOnly = args.value("writable_only", false);

        const scan::Result result = scan::Search(request);
        if (!result.error.empty()) throw ToolError(result.error);

        nlohmann::json matches = nlohmann::json::array();
        for (uintptr_t match : result.matches) {
            matches.push_back({{"address", mem::FormatAddress(match)},
                               {"location", modules::NameFromAddress(match)}});
        }

        return nlohmann::json{{"pattern", args["pattern"]},
                              {"range", {{"start", mem::FormatAddress(start)},
                                         {"end", mem::FormatAddress(end)}}},
                              {"matches", std::move(matches)},
                              {"matches_count", result.matches.size()},
                              {"bytes_scanned", result.bytesScanned},
                              {"truncated", result.truncated},
                              {"limit_hit", result.limitHit}};
    }});
}

void RegisterAlloc(ToolRegistry& registry) {
    registry.Add({"memory_alloc",
                  "Allocate memory inside the game process. Tracked allocations can be freed with memory_free.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "size":{"type":"integer","minimum":1},
                      "protection":{"type":"string","enum":["rw","r","rx","rwx","x"],"default":"rw"},
                      "near":{"type":["string","integer"],"description":"Preferred address / module+offset"},
                      "label":{"type":"string"}
                    },
                    "required":["size"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        const uint64_t sizeValue = args["size"].get<uint64_t>();
        if (sizeValue == 0 || sizeValue > 256ull * 1024 * 1024) throw ToolError("invalid size");

        bool protectionValid = false;
        const DWORD protection = ProtectionFromName(args.value("protection", "rw"), &protectionValid);
        if (!protectionValid) throw ToolError("invalid protection");

        const bool executable = (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        if (executable && !Config::Get().safety.allow_exec_alloc) {
            throw ToolError("executable allocations are disabled in config");
        }

        uintptr_t nearAddress = 0;
        if (args.contains("near")) {
            nearAddress = AddressFromJson(args["near"]);
            if (!nearAddress) throw ToolError("invalid near address");
        }

        std::string error;
        const uintptr_t address = Allocator::Get().Allocate(
            static_cast<size_t>(sizeValue), protection, nearAddress,
            args.value("label", "memory_alloc"), &error);
        if (!address) throw ToolError(error);

        return nlohmann::json{{"address", mem::FormatAddress(address)},
                              {"size", sizeValue},
                              {"protection", mem::ProtectionName(protection)},
                              {"location", modules::NameFromAddress(address)}};
    }});

    registry.Add({"memory_free",
                  "Free memory allocated through memory_alloc. "
                  "Untracked frees require force_untracked=true, confirm=true, and safety.allow_any_free.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "address":{"type":["string","integer"]},
                      "force_untracked":{"type":"boolean","default":false},
                      "confirm":{"type":"boolean","default":false}
                    },
                    "required":["address"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        std::string error;
        const uintptr_t address = AddressFromObject(args, "address", &error);
        if (!address) throw ToolError(error);

        const bool force = args.value("force_untracked", false);
        if (force) {
            if (!Config::Get().safety.allow_any_free) {
                throw ToolError("untracked frees are disabled in config");
            }
            RequireConfirmation(args);
        }

        if (!Allocator::Get().Free(address, force, &error)) {
            throw ToolError(error);
        }
        return nlohmann::json{{"freed", mem::FormatAddress(address)}};
    }});

    registry.Add({"memory_allocations",
                  "List memory allocations tracked by this MCP session.",
                  nlohmann::json::parse(R"({"type":"object","properties":{},"additionalProperties":false})"),
                  [](const nlohmann::json&) -> nlohmann::json {
        nlohmann::json items = nlohmann::json::array();
        for (const auto& info : Allocator::Get().List()) {
            items.push_back({{"address", mem::FormatAddress(info.address)},
                             {"size", info.size},
                             {"protection", mem::ProtectionName(info.protection)},
                             {"timestamp", info.timestamp},
                             {"label", info.label}});
        }
        const size_t count = items.size();
        return nlohmann::json{{"allocations", std::move(items)}, {"count", count}};
    }});
}

void RegisterPointerChain(ToolRegistry& registry) {
    registry.Add({"memory_pointer_chain",
                  "Resolve a pointer chain: base + offset, dereference, repeat. "
                  "Each step may be a number offset or {offset, deref}.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "base":{"type":["string","integer"]},
                      "steps":{"type":"array","items":{"type":["integer","object"]},"minItems":1,"maxItems":64},
                      "final_type":{"type":"string","description":"Optional typed read at final address"}
                    },
                    "required":["base","steps"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        std::string error;
        uintptr_t address = AddressFromObject(args, "base", &error);
        if (!address) throw ToolError(error);
        if (!args["steps"].is_array() || args["steps"].empty()) throw ToolError("steps required");

        nlohmann::json trace = nlohmann::json::array();
        int index = 0;
        for (const auto& step : args["steps"]) {
            int64_t offset = 0;
            bool deref = true;
            if (step.is_number_integer()) {
                offset = step.get<int64_t>();
            } else if (step.is_object()) {
                if (!step.contains("offset") || !step["offset"].is_number_integer()) {
                    throw ToolError("step " + std::to_string(index) + " needs an integer offset");
                }
                offset = step["offset"].get<int64_t>();
                deref = step.value("deref", true);
            } else {
                throw ToolError("invalid step " + std::to_string(index));
            }

            address = static_cast<uintptr_t>(static_cast<int64_t>(address) + offset);
            nlohmann::json entry = {{"step", index},
                                    {"offset", offset},
                                    {"address", mem::FormatAddress(address)},
                                    {"location", modules::NameFromAddress(address)},
                                    {"deref", deref}};

            if (deref) {
                if (!mem::IsReadable(address, sizeof(uintptr_t))) {
                    entry["error"] = "unreadable";
                    trace.push_back(std::move(entry));
                    throw ToolError("chain dereference failed at step " + std::to_string(index));
                }
                const uintptr_t value = mem::ReadOr<uintptr_t>(address, 0);
                entry["value"] = mem::FormatAddress(value);
                entry["value_location"] = modules::NameFromAddress(value);
                address = value;
            }

            trace.push_back(std::move(entry));
            ++index;
        }

        nlohmann::json result = {{"final_address", mem::FormatAddress(address)},
                                 {"trace", std::move(trace)}};

        if (args.contains("final_type")) {
            const std::string type = args["final_type"].get<std::string>();
            uint8_t buffer[16]{};
            const size_t readSize = type == "u8" || type == "i8" || type == "bool" ? 1
                                  : type == "u16" || type == "i16" ? 2
                                  : type == "u32" || type == "i32" || type == "f32" ? 4
                                  : type == "guid" ? 16 : 8;
            if (mem::Read(address, buffer, readSize)) {
                result["value"] = DecodeTyped(buffer, readSize, type);
            } else {
                result["value_error"] = "unreadable";
            }
        }

        return result;
    }});
}

void RegisterPatches(ToolRegistry& registry) {
    registry.Add({"patch_list",
                  "List memory patches recorded for undo.",
                  nlohmann::json::parse(R"({"type":"object","properties":{},"additionalProperties":false})"),
                  [](const nlohmann::json&) -> nlohmann::json {
        nlohmann::json items = nlohmann::json::array();
        for (const auto& patch : patches::List()) {
            items.push_back({{"id", patch.id},
                             {"address", mem::FormatAddress(patch.address)},
                             {"location", modules::NameFromAddress(patch.address)},
                             {"size", patch.original.size()},
                             {"original_hex", str::Hex(patch.original.data(), std::min<size_t>(patch.original.size(), 256))},
                             {"truncated", patch.original.size() > 256},
                             {"note", patch.note},
                             {"timestamp", patch.timestamp}});
        }
        const size_t count = items.size();
        return nlohmann::json{{"patches", std::move(items)}, {"count", count}};
    }});

    registry.Add({"patch_undo",
                  "Restore original bytes for a recorded patch, or all patches.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "id":{"type":"integer"},
                      "all":{"type":"boolean","default":false}
                    },
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        if (args.value("all", false)) {
            const size_t restored = patches::UndoAll();
            return nlohmann::json{{"restored", restored}};
        }
        if (!args.contains("id") || !args["id"].is_number_integer()) {
            throw ToolError("provide id or all=true");
        }
        const uint32_t id = args["id"].get<uint32_t>();
        if (!patches::Undo(id)) throw ToolError("patch not found or restore failed");
        return nlohmann::json{{"restored", 1}, {"id", id}};
    }});
}

void RegisterModules(ToolRegistry& registry) {
    registry.Add({"memory_modules",
                  "List loaded modules in the game process.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "filter":{"type":"string"},
                      "limit":{"type":"integer","default":512}
                    },
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        modules::Refresh();
        const std::string filter = args.value("filter", "");
        const size_t limit = std::clamp<size_t>(args.value("limit", 512), 1, 1024);

        nlohmann::json items = nlohmann::json::array();
        for (const auto& module : modules::All()) {
            if (!filter.empty() && !str::IContains(module.name, filter) &&
                !str::IContains(module.path, filter)) {
                continue;
            }
            items.push_back({{"name", module.name},
                             {"base", mem::FormatAddress(module.base)},
                             {"size", module.size},
                             {"path", module.path}});
            if (items.size() >= limit) break;
        }
        const size_t count = items.size();
        return nlohmann::json{{"modules", std::move(items)},
                              {"count", count},
                              {"main", modules::Main() ? modules::Main()->name : std::string{}}};
    }});

    registry.Add({"memory_module_info",
                  "Return sections and metadata for a loaded module.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{"name":{"type":"string","default":"main"}},
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        modules::Refresh();
        const std::string name = args.value("name", "main");
        auto module = modules::Find(name);
        if (!module) throw ToolError("module not found: " + name);

        nlohmann::json sections = nlohmann::json::array();
        for (const auto& section : module->sections) {
            sections.push_back({{"name", section.name},
                                {"address", mem::FormatAddress(section.address)},
                                {"size", section.size},
                                {"characteristics", section.characteristics},
                                {"readable", section.readable},
                                {"writable", section.writable},
                                {"executable", section.executable}});
        }

        return nlohmann::json{{"name", module->name},
                              {"path", module->path},
                              {"base", mem::FormatAddress(module->base)},
                              {"size", module->size},
                              {"end", mem::FormatAddress(module->base + module->size)},
                              {"sections", std::move(sections)}};
    }});
}

}

void RegisterMemoryTools(ToolRegistry& registry) {
    RegisterRead(registry);
    RegisterWrite(registry);
    RegisterScan(registry);
    RegisterAlloc(registry);
    RegisterPointerChain(registry);
    RegisterPatches(registry);
    RegisterModules(registry);
}

}

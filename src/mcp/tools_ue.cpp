#include "mcp/tools.h"

#include "core/base64.h"
#include "core/config.h"
#include "core/log.h"
#include "core/memory.h"
#include "core/modules.h"
#include "core/process.h"
#include "core/strings.h"
#include "ue/context.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cwchar>
#include <malloc.h>
#include <cstring>
#include <memory>
#include <thread>

namespace fmcp {

namespace {

constexpr uint64_t CPF_OutParm = 0x0000000000000100ull;
constexpr uint64_t CPF_ReturnParm = 0x0000000000000400ull;
constexpr uint32_t RF_ClassDefaultObject = 0x00000010;

nlohmann::json ObjectOrNull(uintptr_t object) {
    if (!object) return nullptr;
    return ObjectSummary(object);
}

uintptr_t ResolveObjectValue(const nlohmann::json& value, std::string* error) {
    auto& ctx = ue::UeContext::Get();

    if (value.is_object()) {
        if (value.contains("path")) {
            const uintptr_t object = ctx.FindObjectPath(value["path"].get<std::string>());
            if (!object) {
                if (error) *error = "object path not found";
                return 0;
            }
            return object;
        }
        return AddressFromJson(value, error);
    }

    if (value.is_string()) {
        const std::string text = value.get<std::string>();
        std::string addressError;
        const auto address = modules::Resolve(text, &addressError);
        if (address && *address && ctx.IsValidObject(*address)) {
            return *address;
        }

        const uintptr_t object = ctx.FindObjectPath(text);
        if (object) {
            return object;
        }

        if (error) {
            *error = "object not found: " + text;
            if (!ctx.StaticFindObjectAddress()) {
                *error += " (static_find_object is not configured)";
            }
        }
        return 0;
    }

    if (value.is_number()) {
        return AddressFromJson(value, error);
    }

    if (error) *error = "object reference expected";
    return 0;
}

uintptr_t ResolveObjectArg(const nlohmann::json& args, const char* key, std::string* error) {
    if (!args.is_object() || !args.contains(key)) {
        if (error) *error = std::string("missing '") + key + "'";
        return 0;
    }
    const uintptr_t object = ResolveObjectValue(args[key], error);
    if (object && !ue::UeContext::Get().IsValidObject(object)) {
        if (error) *error = std::string("'") + key + "' is not a valid UObject";
        return 0;
    }
    return object;
}

uintptr_t ResolveClassValue(const nlohmann::json& value, std::string* error) {
    const uintptr_t object = ResolveObjectValue(value, error);
    if (!object) {
        return 0;
    }
    auto& ctx = ue::UeContext::Get();
    if (!ctx.IsValidObject(object)) {
        if (error) *error = "class object is invalid";
        return 0;
    }
    if (!ctx.IsClassObject(object)) {
        if (error) *error = "address/path is not a UClass";
        return 0;
    }
    return object;
}

uintptr_t ResolveFunctionValue(const nlohmann::json& args, uintptr_t object, std::string* error) {
    auto& ctx = ue::UeContext::Get();
    nlohmann::json value;
    if (args.contains("function")) {
        value = args["function"];
    } else if (args.contains("function_name")) {
        value = args["function_name"];
    } else {
        if (error) *error = "missing 'function'";
        return 0;
    }

    uintptr_t function = 0;
    if (value.is_number()) {
        function = AddressFromJson(value, error);
    } else if (value.is_object()) {
        function = ResolveObjectValue(value, error);
    } else if (value.is_string()) {
        const std::string text = value.get<std::string>();
        std::string addressError;
        const auto address = modules::Resolve(text, &addressError);
        if (address && *address) {
            function = *address;
        }
        if (!function) {
            function = ctx.FindObjectPath(text);
        }
        if (!function && object) {
            function = ctx.FindFunction(object, text, true);
        }
        if (!function && text.find('.') != std::string::npos) {
            const size_t dot = text.rfind('.');
            const std::string classPath = text.substr(0, dot);
            const std::string functionName = text.substr(dot + 1);
            const uintptr_t classObject = ctx.FindObjectPath(classPath);
            if (classObject) {
                function = ctx.FindFunction(classObject, functionName, true);
            }
        }
    }

    if (!function) {
        if (error && error->empty()) *error = "function not found";
        return 0;
    }

    ue::FunctionInfo info;
    const bool decoded = ctx.DecodeFunction(function, info);
    const bool allowUnknown = args.value("allow_unknown_function", false);
    if (!decoded && !allowUnknown) {
        if (error) {
            *error = "target does not look like a UFunction; pass allow_unknown_function=true to force";
        }
        return 0;
    }

    if (!ctx.IsValidObject(function)) {
        if (error) *error = "function object is invalid";
        return 0;
    }

    const uintptr_t outer = ctx.OuterOf(function);
    if (!args.value("allow_mismatch", false) && object && outer && ctx.IsClassObject(outer) &&
        !ctx.IsA(object, outer)) {
        if (error) {
            *error = "function does not belong to the object's class; pass allow_mismatch=true to force";
        }
        return 0;
    }

    return function;
}

nlohmann::json PropertyJson(const ue::PropertyInfo& property) {
    return {{"name", property.name},
            {"type", property.type},
            {"address", mem::FormatAddress(property.address)},
            {"offset", property.offset},
            {"size", property.size},
            {"array_dim", property.array_dim},
            {"flags", property.flags},
            {"flags_hex", str::Format("0x%llX", static_cast<unsigned long long>(property.flags))},
            {"is_out", (property.flags & CPF_OutParm) != 0},
            {"is_return", (property.flags & CPF_ReturnParm) != 0},
            {"payload", property.payload ? mem::FormatAddress(property.payload) : "0x0"},
            {"payload_name", property.payload_name}};
}

nlohmann::json FunctionJson(const ue::FunctionInfo& function) {
    return {{"address", mem::FormatAddress(function.address)},
            {"name", function.name},
            {"path", function.path},
            {"class", function.class_name},
            {"flags", function.flags},
            {"flags_hex", str::Format("0x%X", function.flags)}};
}

struct AlignedBuffer {
    uint8_t* data = nullptr;
    size_t size = 0;

    explicit AlignedBuffer(size_t bytes) {
        size = bytes ? bytes : 16;
        data = static_cast<uint8_t*>(_aligned_malloc(size, 16));
        if (data) {
            memset(data, 0, size);
        }
    }

    ~AlignedBuffer() {
        if (data) _aligned_free(data);
    }

    AlignedBuffer(const AlignedBuffer&) = delete;
    AlignedBuffer& operator=(const AlignedBuffer&) = delete;
};

struct PeState {
    std::shared_ptr<AlignedBuffer> parms;
    uint8_t* externalParms = nullptr;
    std::atomic<bool> valid{true};
    uint64_t engineReturn = 0;

    [[nodiscard]] uint8_t* Params() const {
        return externalParms ? externalParms : (parms ? parms->data : nullptr);
    }
};

bool InvokeProcessEvent(ue::UeContext& ctx, uintptr_t object, uintptr_t function,
                        const std::shared_ptr<PeState>& state, bool allowDirect,
                        bool requireConnection, std::string* error, bool* direct) {
    if (direct) *direct = false;
    if (!ctx.ProcessEventAddress()) {
        if (error) *error = "process_event address is not configured";
        return false;
    }

    const bool ran = ctx.RunOnGameThread(
        [&ctx, object, function, state, requireConnection] {
            if (!ctx.IsValidObject(object) || !ctx.IsValidObject(function)) {
                state->valid = false;
                return;
            }
            if (requireConnection) {
                const uintptr_t world = ctx.GWorld();
                const uintptr_t driver =
                    world ? mem::ReadOr<uintptr_t>(world + 0x48, 0) : 0;
                const uintptr_t connection =
                    driver ? mem::ReadOr<uintptr_t>(driver + 0x118, 0) : 0;
                const std::string className = ctx.ClassName(object);
                const bool isPlayerController =
                    className.find("PlayerController") != std::string::npos;
                const uintptr_t player =
                    isPlayerController ? mem::ReadOr<uintptr_t>(object + 0x310, 0) : 1;
                if (!connection || !player) {
                    state->valid = false;
                    return;
                }
            }
            state->engineReturn = ctx.ProcessEventNow(object, function, state->Params());
        },
        allowDirect, error, direct);

    if (!ran) {
        return false;
    }
    if (!state->valid) {
        if (error) *error = "object/connection became invalid before the game-thread call";
        return false;
    }
    return true;
}

nlohmann::json DecodeOutputs(ue::UeContext& ctx, uintptr_t function, uintptr_t parms,
                             bool decodeAll) {
    nlohmann::json outputs = nlohmann::json::array();
    const auto properties = ctx.ListProperties(function, false, nullptr);
    int count = 0;
    for (const auto& property : properties) {
        if (!decodeAll && (property.flags & (CPF_OutParm | CPF_ReturnParm)) == 0 &&
            property.name != "ReturnValue") {
            continue;
        }
        if (++count > 256) break;

        nlohmann::json entry = PropertyJson(property);
        std::string valueError;
        nlohmann::json value;
        if (ctx.ReadParamValue(parms, property, value, &valueError)) {
            entry["value"] = std::move(value);
        } else {
            entry["error"] = valueError;
        }
        outputs.push_back(std::move(entry));
    }
    return outputs;
}

void RegisterFindObject(ToolRegistry& registry) {
    registry.Add({"find_object",
                  "Find a UObject by full path or short name using the engine's StaticFindObject. "
                  "Example paths: Engine.Actor, /Script/Engine.Actor, /Game/Map.Map:PersistentLevel.Foo.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "path":{"type":"string"},
                      "class":{"type":["string","integer"]},
                      "outer":{"type":["string","integer"]},
                      "exact_class":{"type":"boolean","default":false}
                    },
                    "required":["path"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        if (!ctx.StaticFindObjectAddress()) {
            throw ToolError("static_find_object is not configured; use ue_configure or use objects_of_class");
        }

        uintptr_t classObject = 0;
        if (args.contains("class")) {
            std::string classError;
            classObject = ResolveClassValue(args["class"], &classError);
            if (!classObject) throw ToolError(classError);
        }

        uintptr_t outer = 0;
        if (args.contains("outer")) {
            std::string error;
            outer = ResolveObjectValue(args["outer"], &error);
            if (!outer) throw ToolError(error);
        }

        std::vector<std::string> tried;
        const uintptr_t object = ctx.FindObjectPath(args["path"].get<std::string>(), classObject, outer, &tried);
        if (!object) {
            nlohmann::json result = {{"found", false}, {"tried", tried}};
            if (!ctx.StaticFindObjectAddress()) {
                result["hint"] = "static_find_object is not configured";
            }
            return result;
        }

        nlohmann::json result = ObjectSummary(object);
        result["found"] = true;
        result["tried"] = tried;
        result["is_class"] = ctx.IsClassObject(object);
        return result;
    }});
}

void RegisterObjectsOfClass(ToolRegistry& registry) {
    registry.Add({"objects_of_class",
                  "List live objects of a UClass (uses native GetObjectsOfClass when configured, "
                  "otherwise the configured object array).",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "class":{"type":["string","integer"]},
                      "include_derived":{"type":"boolean","default":true},
                      "include_cdo":{"type":"boolean","default":false},
                      "exclude_flags":{"type":"integer"},
                      "offset":{"type":"integer","default":0,"minimum":0},
                      "limit":{"type":"integer","default":100,"minimum":1},
                      "include_names":{"type":"boolean","default":true},
                      "safe":{"type":"boolean","default":false,"description":"return an error object instead of throwing"}
                    },
                    "required":["class"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        const bool safeMode = args.value("safe", false);
        auto fail = [safeMode](std::string message) -> nlohmann::json {
            if (safeMode) {
                return nlohmann::json{{"objects", nlohmann::json::array()},
                                      {"error", std::move(message)}};
            }
            throw ToolError(message);
        };
        std::string error;
        const uintptr_t classObject = ResolveClassValue(args["class"], &error);
        if (!classObject) return fail(error);

        const int64_t offset = args.value("offset", 0);
        const int64_t limit = std::clamp<int64_t>(args.value("limit", 100), 1, 5000);
        if (offset < 0) return fail("offset must be >= 0");
        const uint32_t excludeFlags = args.contains("exclude_flags")
            ? args["exclude_flags"].get<uint32_t>()
            : (args.value("include_cdo", false) ? 0u : RF_ClassDefaultObject);

        auto query = ctx.ObjectsOfClass(classObject, args.value("include_derived", true),
                                        excludeFlags, static_cast<size_t>(offset + limit), &error);

        const bool includeNames = args.value("include_names", true);
        nlohmann::json objects = nlohmann::json::array();
        for (size_t i = static_cast<size_t>(offset);
             i < query.objects.size() && objects.size() < static_cast<size_t>(limit); ++i) {
            const uintptr_t object = query.objects[i];
            if (!object) continue;
            if (includeNames) {
                objects.push_back(ObjectSummary(object));
            } else {
                objects.push_back({{"address", mem::FormatAddress(object)}});
            }
        }

        nlohmann::json result = {{"class", ObjectSummary(classObject)},
                                 {"total", query.total},
                                 {"offset", offset},
                                 {"returned", objects.size()},
                                 {"truncated", query.truncated || query.total > static_cast<size_t>(offset) + objects.size()},
                                 {"objects", std::move(objects)}};
        if (!error.empty()) result["error"] = error;
        return result;
    }});
}

void RegisterObjectInfo(ToolRegistry& registry) {
    registry.Add({"object_info",
                  "Describe a UObject: address, class, outer, name, path, flags, indices.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{"object":{"type":["string","integer"]}},
                    "required":["object"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        std::string error;
        const uintptr_t object = ResolveObjectArg(args, "object", &error);
        if (!object) throw ToolError(error);

        nlohmann::json result = ObjectSummary(object);
        const ue::ObjectInfo info = ctx.DescribeObject(object);
        result["name_index"] = info.name_index;
        result["name_raw"] = mem::FormatAddress(static_cast<uintptr_t>(info.name_raw));
        result["internal_index"] = info.internal_index;
        result["is_class"] = ctx.IsClassObject(object);
        result["class_path"] = ctx.ObjectPath(info.class_address);
        return result;
    }});
}

void RegisterProperties(ToolRegistry& registry) {
    registry.Add({"list_properties",
                  "List reflected properties of an object or UClass, including offsets and types.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "object":{"type":["string","integer"]},
                      "include_inherited":{"type":"boolean","default":true},
                      "include_values":{"type":"boolean","default":false},
                      "filter":{"type":"string"},
                      "limit":{"type":"integer","default":256,"minimum":1}
                    },
                    "required":["object"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        std::string error;
        const uintptr_t target = ResolveObjectArg(args, "object", &error);
        if (!target) throw ToolError(error);

        auto properties = ctx.ListProperties(target, args.value("include_inherited", true), &error);
        if (properties.empty() && !error.empty()) throw ToolError(error);

        const std::string filter = args.value("filter", "");
        const size_t limit = std::clamp<size_t>(args.value("limit", 256), 1, 2000);
        const bool includeValues = args.value("include_values", false);

        nlohmann::json items = nlohmann::json::array();
        for (const auto& property : properties) {
            if (!filter.empty() && !str::IContains(property.name, filter)) continue;
            nlohmann::json entry = PropertyJson(property);
            if (includeValues) {
                std::string valueError;
                nlohmann::json value;
                if (ctx.ReadPropertyValue(target, property, value, &valueError)) {
                    entry["value"] = std::move(value);
                } else {
                    entry["error"] = valueError;
                }
            }
            items.push_back(std::move(entry));
            if (items.size() >= limit) break;
        }

        return nlohmann::json{{"object", ObjectSummary(target)},
                              {"properties", std::move(items)},
                              {"count", items.size()},
                              {"total", properties.size()}};
    }});

    registry.Add({"get_property",
                  "Read one reflected property by name.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "object":{"type":["string","integer"]},
                      "property":{"type":"string"},
                      "include_inherited":{"type":"boolean","default":true}
                    },
                    "required":["object","property"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        std::string error;
        const uintptr_t target = ResolveObjectArg(args, "object", &error);
        if (!target) throw ToolError(error);

        ue::PropertyInfo property;
        if (!ctx.FindProperty(target, args["property"].get<std::string>(),
                              args.value("include_inherited", true), property)) {
            throw ToolError("property not found: " + args["property"].get<std::string>());
        }

        nlohmann::json value;
        if (!ctx.ReadPropertyValue(target, property, value, &error)) {
            throw ToolError(error);
        }

        return nlohmann::json{{"object", ObjectSummary(target)},
                              {"property", PropertyJson(property)},
                              {"value", std::move(value)}};
    }});

    registry.Add({"set_property",
                  "Write one reflected property by name. Supports numeric, bool, object pointers, "
                  "FName {index,number}, common structs, and raw_hex for other POD data.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "object":{"type":["string","integer"]},
                      "property":{"type":"string"},
                      "value":{},
                      "include_inherited":{"type":"boolean","default":true}
                    },
                    "required":["object","property","value"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        std::string error;
        const uintptr_t target = ResolveObjectArg(args, "object", &error);
        if (!target) throw ToolError(error);

        ue::PropertyInfo property;
        if (!ctx.FindProperty(target, args["property"].get<std::string>(),
                              args.value("include_inherited", true), property)) {
            throw ToolError("property not found: " + args["property"].get<std::string>());
        }

        nlohmann::json before;
        std::string beforeError;
        ctx.ReadPropertyValue(target, property, before, &beforeError);

        if (!ctx.WritePropertyValue(target, property, args["value"], &error)) {
            throw ToolError(error);
        }

        nlohmann::json after;
        std::string afterError;
        ctx.ReadPropertyValue(target, property, after, &afterError);

        nlohmann::json result = {{"object", ObjectSummary(target)},
                                 {"property", PropertyJson(property)},
                                 {"new_value", after}};
        if (!beforeError.empty()) result["old_value_error"] = beforeError;
        else result["old_value"] = std::move(before);
        if (!afterError.empty()) result["new_value_error"] = afterError;
        return result;
    }});
}

void RegisterFunctions(ToolRegistry& registry) {
    registry.Add({"list_functions",
                  "List UFunctions declared on an object's class or a UClass.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "object":{"type":["string","integer"]},
                      "include_inherited":{"type":"boolean","default":true},
                      "filter":{"type":"string"},
                      "limit":{"type":"integer","default":512,"minimum":1}
                    },
                    "required":["object"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        std::string error;
        const uintptr_t target = ResolveObjectArg(args, "object", &error);
        if (!target) throw ToolError(error);

        auto functions = ctx.ListFunctions(target, args.value("include_inherited", true), &error);
        if (functions.empty() && !error.empty()) throw ToolError(error);

        const std::string filter = args.value("filter", "");
        const size_t limit = std::clamp<size_t>(args.value("limit", 512), 1, 4000);

        nlohmann::json items = nlohmann::json::array();
        for (const auto& function : functions) {
            if (!filter.empty() && !str::IContains(function.name, filter) &&
                !str::IContains(function.path, filter)) {
                continue;
            }
            items.push_back(FunctionJson(function));
            if (items.size() >= limit) break;
        }

        return nlohmann::json{{"object", ObjectSummary(target)},
                              {"functions", std::move(items)},
                              {"count", items.size()},
                              {"total", functions.size()}};
    }});
}

void RegisterProcessEvent(ToolRegistry& registry) {
    registry.Add({"process_event",
                  "Call a UFunction through ProcessEvent with a raw parameter buffer. "
                  "Pass parms_address + parms_size to use an SDK-built buffer directly, or parms_hex "
                  "for inline bytes. Explicit parms_size avoids all FProperty inference. "
                  "Set decode_outputs=false for a pure pointer-only call. "
                  "Runs on the game thread when the ProcessEvent hook is installed.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "object":{"type":["string","integer"]},
                      "function":{"type":["string","integer"]},
                      "parms_hex":{"type":"string"},
                      "parms_base64":{"type":"string"},
                      "parms_address":{"type":["string","integer"],"description":"Existing writable parameter buffer; requires parms_size"},
                      "parms_size":{"type":"integer","minimum":0},
                      "allow_unknown_function":{"type":"boolean","default":false},
                      "allow_mismatch":{"type":"boolean","default":false},
                      "allow_direct":{"type":"boolean","default":false},
                      "decode_outputs":{"type":"boolean","default":true},
                      "decode_all":{"type":"boolean","default":false},
                      "safe":{"type":"boolean","default":false,"description":"return ok=false instead of throwing on invalid objects/params"},
                      "require_connection":{"type":"boolean","default":false,"description":"refuse the call if the net driver/connection or PlayerController player is gone"}
                    },
                    "required":["object","function"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        const bool safeMode = args.value("safe", false);
        auto fail = [safeMode](std::string message) -> nlohmann::json {
            if (safeMode) {
                return nlohmann::json{{"ok", false}, {"error", std::move(message)}};
            }
            throw ToolError(message);
        };
        std::string error;
        const uintptr_t object = ResolveObjectArg(args, "object", &error);
        if (!object) return fail(error);
        const uintptr_t function = ResolveFunctionValue(args, object, &error);
        if (!function) return fail(error);

        const bool hasExternalParms = args.contains("parms_address");
        uintptr_t externalParms = 0;
        if (hasExternalParms) {
            externalParms = AddressFromJson(args["parms_address"], &error);
            if (!externalParms) return fail("invalid parms_address");
            if (args.contains("parms_hex") || args.contains("parms_base64")) {
                return fail("use either parms_address or inline parms bytes, not both");
            }
            if (!args.contains("parms_size")) {
                return fail("parms_address requires an explicit parms_size");
            }
        }

        std::vector<uint8_t> seed;
        if (args.contains("parms_hex")) {
            auto decoded = str::Unhex(args["parms_hex"].get<std::string>());
            if (!decoded) return fail("invalid parms_hex");
            seed = std::move(*decoded);
        } else if (args.contains("parms_base64")) {
            auto decoded = b64::Decode(args["parms_base64"].get<std::string>());
            if (!decoded) return fail("invalid parms_base64");
            seed = std::move(*decoded);
        }

        int32_t parmsSize = 0;
        if (args.contains("parms_size")) {
            parmsSize = args["parms_size"].get<int32_t>();
            if (parmsSize < 0 || parmsSize > 1024 * 1024) return fail("invalid parms_size");
        } else {
            std::string sizeError;
            parmsSize = ctx.FunctionParmsSize(function, &sizeError);
            if (parmsSize == 0 && !ctx.PropertiesReady()) {
                return fail("cannot infer parameter size without reflection; pass parms_size "
                            "(0 for a no-argument function)");
            }
        }
        if (parmsSize < 0 || parmsSize > 1024 * 1024) return fail("invalid parms_size");
        if (seed.size() > static_cast<size_t>(parmsSize)) {
            return fail("provided parameters exceed parms_size");
        }

        auto state = std::make_shared<PeState>();
        if (hasExternalParms) {
            if (parmsSize <= 0) {
                return fail("parms_address requires parms_size > 0");
            }
            if (!mem::IsReadable(externalParms, static_cast<size_t>(parmsSize)) ||
                !mem::IsWritable(externalParms, static_cast<size_t>(parmsSize))) {
                return fail("parms_address must point to a readable/writable parameter buffer");
            }
            state->externalParms = reinterpret_cast<uint8_t*>(externalParms);
        } else {
            state->parms = std::make_shared<AlignedBuffer>(static_cast<size_t>(parmsSize) + 64);
            if (!seed.empty()) {
                std::copy(seed.begin(), seed.end(), state->parms->data);
            }
        }

        bool direct = false;
        const bool allowDirect = args.value("allow_direct", false) ||
                                 Config::Get().game_thread.direct_fallback;
        if (!InvokeProcessEvent(ctx, object, function, state, allowDirect,
                                args.value("require_connection", false), &error, &direct)) {
            return fail(error);
        }

        ue::FunctionInfo functionInfo;
        ctx.DecodeFunction(function, functionInfo);

        nlohmann::json result = {{"ok", true},
                                 {"object", ObjectSummary(object)},
                                 {"function", FunctionJson(functionInfo)},
                                 {"parms_size", parmsSize},
                                 {"parms_hex", str::Hex(state->Params(),
                                                        std::min<size_t>(static_cast<size_t>(parmsSize), 65536))},
                                 {"parms_address", hasExternalParms ? mem::FormatAddress(externalParms) : std::string{}},
                                 {"process_event_return", state->engineReturn},
                                 {"process_event_return_hex", str::Format("0x%llX",
                                     static_cast<unsigned long long>(state->engineReturn))},
                                 {"game_thread", direct ? "direct" : "hooked"}};

        if (args.value("decode_outputs", true) && ctx.PropertiesReady()) {
            result["outputs"] = DecodeOutputs(ctx, function, reinterpret_cast<uintptr_t>(state->Params()),
                                              args.value("decode_all", false));
        }
        if (direct) {
            result["warning"] = "called directly on the MCP thread; the game-thread hook is not active";
        }
        if (!functionInfo.address) {
            result["metadata_warning"] = "function metadata could not be decoded";
        }
        return result;
    }});

    registry.Add({"call_ufunction",
                  "Call a UFunction with JSON arguments marshaled through reflection. "
                  "Provide args as {\"PropertyName\": value}. Runs on the game thread.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "object":{"type":["string","integer"]},
                      "function":{"type":["string","integer"]},
                      "args":{"type":"object"},
                      "allow_direct":{"type":"boolean","default":false},
                      "allow_mismatch":{"type":"boolean","default":false}
                    },
                    "required":["object","function"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        if (!ctx.PropertiesReady()) {
            throw ToolError("reflection layout is not ready; configure layout offsets or use process_event");
        }

        std::string error;
        const uintptr_t object = ResolveObjectArg(args, "object", &error);
        if (!object) throw ToolError(error);

        nlohmann::json functionArgs = args.contains("args") && args["args"].is_object()
                                          ? args["args"]
                                          : nlohmann::json::object();
        nlohmann::json functionLookup = args;
        functionLookup["allow_mismatch"] = args.value("allow_mismatch", false);
        const uintptr_t function = ResolveFunctionValue(functionLookup, object, &error);
        if (!function) throw ToolError(error);

        const auto properties = ctx.ListProperties(function, false, &error);
        if (properties.empty() && !error.empty()) throw ToolError(error);

        const int32_t parmsSize = ctx.FunctionParmsSize(function, &error);
        if (parmsSize < 0) {
            throw ToolError("unable to determine the function parameter buffer size");
        }

        auto parms = std::make_shared<AlignedBuffer>(static_cast<size_t>(parmsSize) + 64);
        std::vector<std::wstring> strings;
        std::vector<std::vector<wchar_t>> buffers;
        strings.reserve(64);

        for (const auto& property : properties) {
            if (property.type.find("StrProperty") != std::string::npos &&
                !functionArgs.contains(property.name)) {
                std::string stringError;
                ctx.WriteParamValue(reinterpret_cast<uintptr_t>(parms->data), property,
                                    nlohmann::json(""), strings, buffers, &stringError);
            }
        }

        for (auto it = functionArgs.begin(); it != functionArgs.end(); ++it) {
            const std::string& name = it.key();
            auto found = std::find_if(properties.begin(), properties.end(),
                                      [&](const ue::PropertyInfo& property) {
                                          return str::IEquals(property.name, name);
                                      });
            if (found == properties.end()) {
                throw ToolError("unknown parameter: " + name);
            }
            std::string writeError;
            if (!ctx.WriteParamValue(reinterpret_cast<uintptr_t>(parms->data), *found, it.value(),
                                     strings, buffers, &writeError)) {
                throw ToolError(name + ": " + writeError);
            }
        }

        if (!ctx.IsValidObject(function) || !ctx.IsValidObject(object)) {
            throw ToolError("object/function became invalid");
        }

        auto state = std::make_shared<PeState>();
        state->parms = parms;

        bool direct = false;
        const bool allowDirect = args.value("allow_direct", false) ||
                                 Config::Get().game_thread.direct_fallback;
        if (!InvokeProcessEvent(ctx, object, function, state, allowDirect, false, &error, &direct)) {
            throw ToolError(error);
        }

        ue::FunctionInfo functionInfo;
        ctx.DecodeFunction(function, functionInfo);

        nlohmann::json outputs = nlohmann::json::object();
        nlohmann::json outputList = nlohmann::json::array();
        for (const auto& property : properties) {
            if ((property.flags & (CPF_OutParm | CPF_ReturnParm)) == 0 &&
                property.name != "ReturnValue") {
                continue;
            }
            nlohmann::json value;
            std::string readError;
            if (ctx.ReadParamValue(reinterpret_cast<uintptr_t>(parms->data), property, value,
                                   &readError)) {
                outputs[property.name] = value;
                outputList.push_back({{"name", property.name}, {"type", property.type}, {"value", value}});
            } else {
                outputs[property.name] = {{"error", readError}};
            }
        }

        nlohmann::json result = {{"ok", true},
                                 {"object", ObjectSummary(object)},
                                 {"function", FunctionJson(functionInfo)},
                                 {"parms_size", parmsSize},
                                 {"parms_hex", str::Hex(parms->data, static_cast<size_t>(parmsSize))},
                                 {"outputs", std::move(outputs)},
                                 {"output_list", std::move(outputList)},
                                 {"process_event_return", state->engineReturn},
                                 {"process_event_return_hex", str::Format("0x%llX",
                                     static_cast<unsigned long long>(state->engineReturn))},
                                 {"game_thread", direct ? "direct" : "hooked"}};
        if (direct) {
            result["warning"] = "called directly on the MCP thread; the game-thread hook is not active";
        }
        return result;
    }});
}

void RegisterCallAddress(ToolRegistry& registry) {
    registry.Add({"call_address",
                  "Call an arbitrary x64 function pointer with typed arguments. "
                  "Supports up to 4 integer + 4 float register args and additional stack args. "
                  "Returns RAX and XMM0. This can crash the game.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "address":{"type":["string","integer"]},
                      "args":{"type":"array","maxItems":16,"items":{
                        "oneOf":[
                          {"type":["string","integer","number","boolean"]},
                          {"type":"object","properties":{
                            "type":{"type":"string","enum":["int","uint","ptr","bool","float","double"]},
                            "value":{}},
                            "required":["type","value"],"additionalProperties":false}
                        ]}},
                      "return_type":{"type":"string","enum":["void","u8","i8","u16","i16","u32","i32","u64","i64","ptr","bool","float","double"],"default":"u64"},
                      "allow_direct":{"type":"boolean","default":false}
                    },
                    "required":["address"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        if (!Config::Get().safety.allow_raw_calls) {
            throw ToolError("raw calls are disabled in config");
        }

        std::string error;
        const uintptr_t address = AddressFromObject(args, "address", &error);
        if (!address) throw ToolError(error);
        if (!modules::IsExecutableAddress(address, 1)) {
            throw ToolError("target is not executable");
        }

        CallPlan plan;
        if (args.contains("args")) {
            if (!args["args"].is_array()) throw ToolError("args must be an array");
            for (const auto& item : args["args"]) {
                std::string type = "int";
                nlohmann::json value = item;
                if (item.is_object()) {
                    if (!item.contains("value")) throw ToolError("argument object requires a value");
                    type = item.value("type", std::string("int"));
                    value = item["value"];
                }

                if (type == "ptr") {
                    uintptr_t pointer = AddressFromJson(value, &error);
                    if (!pointer) throw ToolError("invalid pointer argument: " + error);
                    if (!plan.AddPointer(pointer)) throw ToolError(plan.Error());
                } else if (type == "float") {
                    if (!value.is_number()) throw ToolError("float argument must be numeric");
                    if (!plan.AddFloat(value.get<float>())) throw ToolError(plan.Error());
                } else if (type == "double") {
                    if (!value.is_number()) throw ToolError("double argument must be numeric");
                    if (!plan.AddDouble(value.get<double>())) throw ToolError(plan.Error());
                } else if (type == "bool") {
                    const bool boolean = value.is_boolean() ? value.get<bool>()
                                                           : (value.is_number() && value.get<int64_t>() != 0);
                    if (!plan.AddInt(boolean ? 1 : 0)) throw ToolError(plan.Error());
                } else if (type == "int" || type == "uint") {
                    uint64_t raw = 0;
                    if (value.is_number_unsigned()) {
                        raw = value.get<uint64_t>();
                    } else if (value.is_number_integer()) {
                        raw = static_cast<uint64_t>(value.get<int64_t>());
                    } else if (value.is_string()) {
                        const std::string text = str::Trim(value.get<std::string>());
                        if (!text.empty() && text[0] == '-') {
                            try {
                                raw = static_cast<uint64_t>(std::stoll(text, nullptr, 0));
                            } catch (...) {
                                throw ToolError("invalid integer argument");
                            }
                        } else {
                            auto parsed = str::ParseUint(text);
                            if (!parsed) throw ToolError("invalid integer argument");
                            raw = *parsed;
                        }
                    } else {
                        throw ToolError("integer argument expected");
                    }
                    if (!plan.AddInt(raw)) throw ToolError(plan.Error());
                } else {
                    throw ToolError("unknown argument type: " + type);
                }
            }
        }

        const bool allowDirect = args.value("allow_direct", false) ||
                                 Config::Get().game_thread.direct_fallback;

        struct RawState {
            CallResult result;
            bool invoked = false;
        };
        auto state = std::make_shared<RawState>();

        const bool ran = ctx.RunOnGameThread(
            [address, plan, state] {
                state->result = plan.Invoke(address);
                state->invoked = true;
            },
            allowDirect, &error, nullptr);

        if (!ran) throw ToolError(error);
        if (!state->invoked) throw ToolError("call did not execute");

        const std::string returnType = args.value("return_type", "u64");
        const uint64_t rax = state->result.rax;
        const uint64_t xmm = state->result.xmm0;

        nlohmann::json result = {{"ok", true},
                                 {"address", mem::FormatAddress(address)},
                                 {"location", modules::NameFromAddress(address)},
                                 {"arg_count", plan.ArgumentCount()},
                                 {"rax", str::Format("0x%llX", static_cast<unsigned long long>(rax))},
                                 {"xmm0", str::Format("0x%llX", static_cast<unsigned long long>(xmm))},
                                 {"return_type", returnType},
                                 {"warning", "raw function call; verify the target signature and calling convention"}};

        if (returnType == "ptr") {
            result["value"] = {{"address", mem::FormatAddress(rax)},
                               {"location", modules::NameFromAddress(rax)}};
        } else if (returnType == "void") {
            // no value
        } else if (returnType == "float") {
            uint32_t bits = static_cast<uint32_t>(xmm);
            float value = 0;
            memcpy(&value, &bits, sizeof(value));
            if (std::isfinite(value)) result["value"] = value;
            else result["value"] = "non-finite";
        } else if (returnType == "double") {
            double value = 0;
            memcpy(&value, &xmm, sizeof(value));
            if (std::isfinite(value)) result["value"] = value;
            else result["value"] = "non-finite";
        } else if (returnType == "bool") {
            result["value"] = rax != 0;
        } else {
            auto signedValue = [&](int bits) -> int64_t {
                switch (bits) {
                case 8: return static_cast<int8_t>(rax);
                case 16: return static_cast<int16_t>(rax);
                case 32: return static_cast<int32_t>(rax);
                default: return static_cast<int64_t>(rax);
                }
            };
            auto unsignedValue = [&](int bits) -> uint64_t {
                switch (bits) {
                case 8: return static_cast<uint8_t>(rax);
                case 16: return static_cast<uint16_t>(rax);
                case 32: return static_cast<uint32_t>(rax);
                default: return rax;
                }
            };
            if (returnType == "u8") result["value"] = unsignedValue(8);
            else if (returnType == "i8") result["value"] = signedValue(8);
            else if (returnType == "u16") result["value"] = unsignedValue(16);
            else if (returnType == "i16") result["value"] = signedValue(16);
            else if (returnType == "u32") result["value"] = unsignedValue(32);
            else if (returnType == "i32") result["value"] = signedValue(32);
            else if (returnType == "u64") result["value"] = unsignedValue(64);
            else if (returnType == "i64") result["value"] = signedValue(64);
            else result["value"] = str::Format("0x%llX", static_cast<unsigned long long>(rax));
        }

        return result;
    }});
}

void RegisterGlobals(ToolRegistry& registry) {
    registry.Add({"get_globals",
                  "Read configured UE globals (GWorld/GEngine and extra globals).",
                  nlohmann::json::parse(R"({"type":"object","properties":{},"additionalProperties":false})"),
                  [](const nlohmann::json&) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        const Config& config = Config::Get();

        auto describe = [&](const std::string& name, const GlobalSpec& spec, uintptr_t slot,
                            uintptr_t value) {
            nlohmann::json entry = {{"name", name},
                                    {"slot", mem::FormatAddress(slot)},
                                    {"value", mem::FormatAddress(value)},
                                    {"resolve", spec.resolve},
                                    {"offset", spec.offset},
                                    {"decode", spec.decode},
                                    {"from", spec.from},
                                    {"chain", spec.chain}};
            if (value && ctx.IsValidObject(value)) {
                entry["object"] = ObjectSummary(value);
            } else if (value && mem::IsCanonical(value)) {
                entry["location"] = modules::NameFromAddress(value);
            }
            return entry;
        };

        nlohmann::json result = nlohmann::json::array();

        std::string worldError;
        const uintptr_t world = ctx.GWorld(&worldError);
        nlohmann::json worldEntry = describe("gworld", config.ue.gworld, ctx.GWorldSlot(), world);
        if (worldError.empty() == false) {
            if (!world) worldEntry["error"] = worldError;
            else worldEntry["note"] = worldError;
        }
        result.push_back(std::move(worldEntry));

        std::string engineError;
        const uintptr_t engine = ctx.GEngine(&engineError);
        nlohmann::json engineEntry = describe("gengine", config.ue.gengine, ctx.GEngineSlot(), engine);
        if (!engineError.empty()) {
            if (!engine) engineEntry["error"] = engineError;
            else engineEntry["note"] = engineError;
        }
        result.push_back(std::move(engineEntry));

        for (const auto& [name, spec] : config.ue.extra_globals) {
            std::string globalError;
            const uintptr_t value = ctx.ReadNamedGlobal(name, &globalError).value_or(0);
            nlohmann::json entry = describe(name, spec, 0, value);
            if (!value && !globalError.empty()) entry["error"] = globalError;
            result.push_back(std::move(entry));
        }

        return nlohmann::json{{"globals", std::move(result)},
                              {"module", {{"base", mem::FormatAddress(ctx.ModuleBase())},
                                          {"size", ctx.ModuleSize()}}},
                              {"names_table", mem::FormatAddress(ctx.NamesTable())},
                              {"objects_table", mem::FormatAddress(ctx.ObjectsTable())}};
    }});
}

void RegisterResolveFName(ToolRegistry& registry) {
    registry.Add({"resolve_fname",
                  "Resolve a raw FName through the engine's FNameToString. Fault-safe: an invalid ID "
                  "returns faulted=true instead of crashing. Pass index+number, or address of a raw "
                  "FName in memory.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "index":{"type":"integer","minimum":0,"description":"raw FName index"},
                      "number":{"type":"integer","minimum":0,"default":0},
                      "address":{"type":"string","description":"address of a raw FName in memory; alternative to index"}
                    },
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        if (!ctx.NamesReady()) {
            throw ToolError("name backend is not resolved; configure ue.names.style and offsets");
        }

        uint32_t index = 0;
        uint32_t number = 0;
        std::string source = "index";

        if (args.contains("address")) {
            std::string error;
            const uintptr_t address = AddressFromObject(args, "address", &error);
            if (!address) throw ToolError(error);

            const int fnameSize = std::max(ctx.CurrentLayout().fname_size, 4);
            if (!mem::IsReadable(address, static_cast<size_t>(fnameSize))) {
                throw ToolError("FName address is not readable");
            }
            index = mem::ReadOr<uint32_t>(address, 0);
            number = fnameSize >= 8 ? mem::ReadOr<uint32_t>(address + 4, 0) : 0;
            source = "address";
        } else {
            if (!args.contains("index")) {
                throw ToolError("provide 'index' or 'address'");
            }
            const uint64_t raw = args["index"].get<uint64_t>();
            if (raw > 0xFFFFFFFFull) throw ToolError("index exceeds 32 bits");
            index = static_cast<uint32_t>(raw);
            const uint64_t count = args.value("number", 0ull);
            if (count > 0xFFFFFFFFull) throw ToolError("number exceeds 32 bits");
            number = static_cast<uint32_t>(count);
        }

        const auto lookup = ctx.LookupFName(index, number);
        return nlohmann::json{{"source", source},
                              {"index", index},
                              {"number", number},
                              {"backend", lookup.backend},
                              {"faulted", lookup.faulted},
                              {"name", lookup.name}};
    }});
}

void RegisterFindPointerField(ToolRegistry& registry) {
    registry.Add({"find_pointer_field",
                  "Scan an object's memory for pointer fields that reference a valid UObject with a "
                  "given class or name. Useful for rediscovering member offsets after a game update.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "owner":{"type":"string","description":"address of the object to scan"},
                      "class":{"type":"string","description":"target UObject class name"},
                      "name":{"type":"string","description":"target UObject name"},
                      "max_offset":{"type":"integer","default":8192},
                      "alignment":{"type":"integer","default":8}
                    },
                    "required":["owner"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();

        std::string error;
        const uintptr_t owner = AddressFromObject(args, "owner", &error);
        if (!owner) throw ToolError(error);

        const std::string className = args.value("class", std::string{});
        const std::string objectName = args.value("name", std::string{});
        if (className.empty() && objectName.empty()) {
            throw ToolError("provide 'class' or 'name'");
        }

        const uint64_t requestedMax = args.value("max_offset", 8192ull);
        const size_t maxOffset = static_cast<size_t>(std::clamp<uint64_t>(requestedMax, 8, 0x100000));
        const int alignment = std::clamp(args.value("alignment", 8), 1, 64);

        if (!mem::IsReadable(owner, maxOffset)) {
            throw ToolError("owner range is not readable");
        }

        std::vector<uint8_t> data(maxOffset);
        if (!mem::Read(owner, data.data(), data.size())) {
            throw ToolError("owner read failed");
        }

        nlohmann::json matches = nlohmann::json::array();
        for (size_t offset = 0; offset + sizeof(uintptr_t) <= maxOffset;
             offset += static_cast<size_t>(alignment)) {
            uintptr_t candidate = 0;
            std::memcpy(&candidate, data.data() + offset, sizeof(candidate));
            if (!candidate || !ctx.IsValidObject(candidate)) {
                continue;
            }

            const std::string candidateClass = ctx.ClassName(candidate);
            const std::string candidateName = ctx.ObjectName(candidate);
            const bool match = (!className.empty() && str::IEquals(candidateClass, className)) ||
                               (!objectName.empty() && str::IEquals(candidateName, objectName));
            if (!match) {
                continue;
            }

            matches.push_back({{"offset", offset},
                               {"offset_hex", str::Format("0x%zX", offset)},
                               {"value", mem::FormatAddress(candidate)},
                               {"class", candidateClass},
                               {"name", candidateName},
                               {"path", ctx.ObjectPath(candidate)}});
            if (matches.size() >= 32) {
                break;
            }
        }

        return nlohmann::json{{"owner", mem::FormatAddress(owner)},
                              {"scanned", maxOffset},
                              {"matches_count", matches.size()},
                              {"matches", std::move(matches)}};
    }});
}

void RegisterNetStats(ToolRegistry& registry) {
    registry.Add({"net_stats",
                  "Sample the local UNetConnection and return ping, packet loss, packets/s and "
                  "download/upload KB/s. Pure memory reads; stalled=true when no packets or bytes "
                  "arrive during the window.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "window_ms":{"type":"integer","minimum":100,"maximum":5000,"default":1000},
                      "connection":{"type":"string","description":"optional UNetConnection address"}
                    },
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        const int windowMs = std::clamp(args.value("window_ms", 1000), 100, 5000);

        uintptr_t connection = 0;
        if (args.contains("connection")) {
            std::string addressError;
            connection = AddressFromObject(args, "connection", &addressError);
            if (!connection) {
                return nlohmann::json{{"connected", false}, {"error", addressError}};
            }
        }

        std::string worldError;
        const uintptr_t world = ctx.GWorld(&worldError);
        uintptr_t netDriver = 0;
        if (!connection) {
            if (!world) {
                return nlohmann::json{{"connected", false}, {"error", worldError}};
            }
            netDriver = mem::ReadOr<uintptr_t>(world + 0x48, 0);
            if (netDriver) {
                connection = mem::ReadOr<uintptr_t>(netDriver + 0x118, 0);
            }
            if (!connection && netDriver) {
                const uintptr_t data = mem::ReadOr<uintptr_t>(netDriver + 0x120, 0);
                const int32_t count = mem::ReadOr<int32_t>(netDriver + 0x128, 0);
                if (data && count > 0) {
                    connection = mem::ReadOr<uintptr_t>(data, 0);
                }
            }
        }

        if (!connection) {
            return nlohmann::json{{"connected", false},
                                  {"error", "no net driver/server connection (not in a networked match)"},
                                  {"world", mem::FormatAddress(world)},
                                  {"net_driver", mem::FormatAddress(netDriver)}};
        }
        if (!ctx.IsValidObject(connection)) {
            return nlohmann::json{{"connected", false},
                                  {"error", "connection object is not valid"},
                                  {"connection", mem::FormatAddress(connection)}};
        }

        struct NetSample {
            uint32_t inPackets = 0;
            uint32_t outPackets = 0;
            uint32_t inBytes = 0;
            uint32_t outBytes = 0;
            float latency = 0.0f;
        };

        auto sample = [](uintptr_t conn) {
            NetSample s;
            s.inPackets = mem::ReadOr<uint32_t>(conn + 0x4FC, 0);
            s.outPackets = mem::ReadOr<uint32_t>(conn + 0x500, 0);
            s.inBytes = mem::ReadOr<uint32_t>(conn + 0x4E4, 0);
            s.outBytes = mem::ReadOr<uint32_t>(conn + 0x4E8, 0);
            s.latency = mem::ReadOr<float>(conn + 0x49C, 0.0f);
            return s;
        };

        const NetSample first = sample(connection);
        std::this_thread::sleep_for(std::chrono::milliseconds(windowMs));
        const NetSample second = sample(connection);

        const double seconds = static_cast<double>(windowMs) / 1000.0;
        auto delta = [](uint32_t a, uint32_t b) { return static_cast<uint32_t>(b - a); };
        auto perSec = [seconds](uint32_t value) { return static_cast<double>(value) / seconds; };
        auto round2 = [](double value) { return std::round(value * 100.0) / 100.0; };

        const uint32_t dInPackets = delta(first.inPackets, second.inPackets);
        const uint32_t dOutPackets = delta(first.outPackets, second.outPackets);
        const uint32_t dInBytes = delta(first.inBytes, second.inBytes);
        const uint32_t dOutBytes = delta(first.outBytes, second.outBytes);

        return nlohmann::json{
            {"connected", true},
            {"world", mem::FormatAddress(world)},
            {"net_driver", mem::FormatAddress(netDriver)},
            {"connection", mem::FormatAddress(connection)},
            {"connection_name", ctx.ObjectName(connection)},
            {"window_ms", windowMs},
            {"ping_ms", round2(static_cast<double>(first.latency) * 1000.0)},
            {"packet_loss_pct", nullptr},
            {"loss_available", false},
            {"packets_per_sec", round2(perSec(dInPackets) + perSec(dOutPackets))},
            {"download_kb_s", round2(perSec(dInBytes) / 1024.0)},
            {"upload_kb_s", round2(perSec(dOutBytes) / 1024.0)},
            {"stalled", dInPackets == 0 && dInBytes == 0},
            {"in", {{"packets_per_sec", round2(perSec(dInPackets))},
                    {"kb_s", round2(perSec(dInBytes) / 1024.0)},
                    {"total_packets", second.inPackets},
                    {"total_bytes", second.inBytes}}},
            {"out", {{"packets_per_sec", round2(perSec(dOutPackets))},
                     {"kb_s", round2(perSec(dOutBytes) / 1024.0)},
                     {"total_packets", second.outPackets},
                     {"total_bytes", second.outBytes}}},
            {"raw", {{"latency_s", first.latency},
                     {"in_packets", second.inPackets},
                     {"out_packets", second.outPackets},
                     {"in_bytes", second.inBytes},
                     {"out_bytes", second.outBytes}}}};
    }});
}

void RegisterUeStatus(ToolRegistry& registry) {
    registry.Add({"ue_status",
                  "Return UE resolution state: function addresses, names/objects tables, layout, "
                  "hook state, globals, warnings.",
                  nlohmann::json::parse(R"({"type":"object","properties":{},"additionalProperties":false})"),
                  [](const nlohmann::json&) -> nlohmann::json {
        return ue::UeContext::Get().Status();
    }});
}

void RegisterUeConfigure(ToolRegistry& registry) {
    registry.Add({"ue_configure",
                  "Update UE settings at runtime and re-resolve. Accepts the same 'ue', 'game_thread', "
                  "and 'safety' objects as config.json. Use save=true to persist. "
                  "Changing process_event can install a hook; verify the address/signature first.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "ue":{"type":"object"},
                      "game_thread":{"type":"object"},
                      "safety":{"type":"object"},
                      "save":{"type":"boolean","default":false}
                    },
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        if (!args.contains("ue") && !args.contains("game_thread") && !args.contains("safety")) {
            throw ToolError("provide ue, game_thread, or safety updates");
        }

        Config& config = Config::Get();
        config.ApplyRuntimeJson(args);

        auto& ctx = ue::UeContext::Get();
        ctx.Invalidate();
        ctx.Resolve(true);

        bool saved = false;
        if (args.value("save", false)) {
            saved = config.Save();
        }

        return nlohmann::json{{"saved", saved}, {"status", ctx.Status()}};
    }});
}

uintptr_t FindLocalPlayerController(ue::UeContext& ctx, std::string* error) {
    static const char* kClasses[] = {
        "/Script/FortniteGame.FortPlayerControllerAthena",
        "/Script/FortniteGame.FortPlayerControllerZone",
        "/Script/FortniteGame.FortPlayerController",
    };
    for (const char* path : kClasses) {
        const uintptr_t classObject = ctx.FindObjectPath(path);
        if (!classObject) continue;
        std::string queryError;
        auto query = ctx.ObjectsOfClass(classObject, true, RF_ClassDefaultObject, 128, &queryError);
        uintptr_t fallback = 0;
        for (uintptr_t candidate : query.objects) {
            if (!candidate || !ctx.IsValidObject(candidate)) continue;
            if (!fallback) fallback = candidate;
            if (mem::ReadOr<uintptr_t>(candidate + 0x310, 0)) return candidate;
        }
        if (fallback) return fallback;
    }
    if (error) *error = "local player controller not found";
    return 0;
}

bool NetConnectionActive(ue::UeContext& ctx) {
    const uintptr_t world = ctx.GWorld();
    if (!world) return false;
    const uintptr_t driver = mem::ReadOr<uintptr_t>(world + 0x48, 0);
    return driver && mem::ReadOr<uintptr_t>(driver + 0x118, 0);
}

uint64_t ElapsedMs(std::chrono::steady_clock::time_point start) {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count());
}

void RegisterMatchmaking(ToolRegistry& registry) {
    registry.Add({"matchmaking_play_button",
                  "Find and click the frontend Play/matchmaking button widget by invoking "
                  "UCommonButtonBase::HandleButtonClicked (the same handler a UI click triggers). "
                  "Use dry_run to list candidates without clicking.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "filter":{"type":"string","default":"play"},
                      "dry_run":{"type":"boolean","default":false},
                      "index":{"type":"integer","default":0,"minimum":0},
                      "wait_ms":{"type":"integer","default":0,"minimum":0,"maximum":120000},
                      "skip_if_connected":{"type":"boolean","default":true}
                    },
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        auto fail = [](std::string message) -> nlohmann::json {
            return nlohmann::json{{"ok", false}, {"error", std::move(message)}};
        };
        const std::string filter = str::ToLower(args.value("filter", "play"));
        if (args.value("skip_if_connected", true) && NetConnectionActive(ctx)) {
            return nlohmann::json{{"ok", true}, {"already_connected", true}};
        }

        std::vector<std::pair<uintptr_t, std::string>> candidates;
        auto collect = [&](const char* classPath) {
            const uintptr_t classObject = ctx.FindObjectPath(classPath);
            if (!classObject) return;
            std::string queryError;
            auto query = ctx.ObjectsOfClass(classObject, true, RF_ClassDefaultObject, 1024, &queryError);
            for (uintptr_t object : query.objects) {
                if (!object || !ctx.IsValidObject(object)) continue;
                std::string path = ctx.ObjectPath(object);
                const std::string lower = str::ToLower(path);
                if (lower.find(filter) == std::string::npos) continue;
                if (lower.find("restart") != std::string::npos) continue;
                candidates.emplace_back(object, std::move(path));
            }
        };
        collect("/Script/FortniteGame.AthenaMatchmakingPlayButtonBase");
        if (candidates.empty()) collect("/Script/CommonUI.CommonButtonBase");
        if (candidates.empty()) collect("/Script/CommonUILegacy.CommonButtonLegacy");

        if (candidates.empty()) return fail("no play button widget found (is the game in the frontend?)");
        // Prefer live widget instances over class templates, then matchmaking-specific widgets.
        auto rank = [](const std::string& path) {
            const std::string lower = str::ToLower(path);
            int score = 0;
            if (lower.find("/engine/transient") != std::string::npos) score += 2;
            if (lower.find("rootlayout") != std::string::npos) score += 2;
            if (lower.find("matchmaking") != std::string::npos) score += 1;
            if (lower.find("mmplayorcancel") != std::string::npos) score += 1;
            return score;
        };
        std::stable_sort(candidates.begin(), candidates.end(),
                         [&](const auto& a, const auto& b) {
                             return rank(a.second) > rank(b.second);
                         });

        nlohmann::json listed = nlohmann::json::array();
        for (const auto& [object, path] : candidates) {
            listed.push_back({{"address", mem::FormatAddress(object)}, {"path", path}});
        }
        if (args.value("dry_run", false)) {
            return nlohmann::json{{"ok", true}, {"dry_run", true}, {"candidates", listed}};
        }

        const int index = std::clamp(args.value("index", 0), 0,
                                     static_cast<int>(candidates.size()) - 1);
        const uintptr_t button = candidates[static_cast<size_t>(index)].first;
        const std::string buttonPath = candidates[static_cast<size_t>(index)].second;

        const uintptr_t function =
            ctx.FindObjectPath("/Script/CommonUI.CommonButtonBase.HandleButtonClicked");
        if (!function) return fail("HandleButtonClicked not found");
        if (!ctx.GameThreadHooked() && !Config::Get().game_thread.direct_fallback) {
            return fail("game-thread hook is not installed; enable ue.process_event.hook first");
        }

        auto state = std::make_shared<PeState>();
        state->parms = std::make_shared<AlignedBuffer>(8);
        if (!state->parms->data) return fail("parameter allocation failed");

        std::string error;
        bool direct = false;
        if (!InvokeProcessEvent(ctx, button, function, state,
                                Config::Get().game_thread.direct_fallback, false, &error, &direct)) {
            return fail(error);
        }

        const auto start = std::chrono::steady_clock::now();
        const int waitMs = std::clamp(args.value("wait_ms", 0), 0, 120000);
        bool connected = NetConnectionActive(ctx);
        while (waitMs > 0 && !connected && ElapsedMs(start) < static_cast<uint64_t>(waitMs)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            connected = NetConnectionActive(ctx);
        }

        return nlohmann::json{{"ok", true},
                              {"button", {{"address", mem::FormatAddress(button)}, {"path", buttonPath}}},
                              {"candidates", listed},
                              {"game_thread", direct ? "direct" : "hooked"},
                              {"connected", connected},
                              {"waited_ms", ElapsedMs(start)}};
    }});

    registry.Add({"matchmaking_start",
                  "Start Fortnite matchmaking from the frontend by island link code, or through the party "
                  "leader ready-up path. Optionally waits until the client is connected to a server.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "link_code":{"type":"string","description":"Island/playlist link code, e.g. 2744-5526-2967 or 2744-5526-2967?v=561"},
                      "version":{"type":"integer","default":0},
                      "private":{"type":"boolean","default":true},
                      "method":{"type":"string","enum":["link","party_ready"],"default":"link"},
                      "wait_ms":{"type":"integer","default":0,"minimum":0,"maximum":120000}
                    },
                    "required":["link_code"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        auto fail = [](std::string message) -> nlohmann::json {
            return nlohmann::json{{"ok", false}, {"error", std::move(message)}};
        };
        if (!ctx.ProcessEventAddress()) return fail("process_event is not configured");
        if (!ctx.GameThreadHooked() && !Config::Get().game_thread.direct_fallback) {
            return fail("game-thread hook is not installed; enable ue.process_event.hook first");
        }

        std::string error;
        const uintptr_t pc = FindLocalPlayerController(ctx, &error);
        if (!pc) return fail(error);

        const std::string method = args.value("method", "link");
        if (method != "link" && method != "party_ready") return fail("method must be link or party_ready");

        std::string link = args.value("link_code", "");
        if (link.empty()) return fail("link_code is required");
        int32_t version = args.value("version", 0);
        const size_t versionPos = link.find("?v=");
        if (versionPos != std::string::npos) {
            try {
                version = std::stoi(link.substr(versionPos + 3));
            } catch (...) {
            }
            link = link.substr(0, versionPos);
        }
        const bool isPrivate = args.value("private", true);

        std::string functionError;
        const uintptr_t function = method == "party_ready"
            ? ctx.FindObjectPath("/Script/FortniteGame.FortPlayerControllerAthena.PartyLeaderReadyUpOrStartMatchmaking")
            : ctx.FindObjectPath("/Script/FortniteGame.FortPlayerControllerAthena.StartMatchmakingByLinkCode");
        if (!function) return fail("matchmaking function not found on FortPlayerControllerAthena");

        auto state = std::make_shared<PeState>();
        state->parms = std::make_shared<AlignedBuffer>(0x20 + 64);
        if (!state->parms->data) return fail("parameter allocation failed");

        const std::wstring wide(link.begin(), link.end());
        // The matchmaking flow may keep the FString contents, so this buffer is intentionally not freed.
        wchar_t* text = new wchar_t[wide.size() + 1];
        std::wmemcpy(text, wide.c_str(), wide.size() + 1);

        uint8_t* p = state->parms->data;
        *reinterpret_cast<void**>(p) = text;
        *reinterpret_cast<int32_t*>(p + 0x8) = static_cast<int32_t>(wide.size());
        *reinterpret_cast<int32_t*>(p + 0xC) = static_cast<int32_t>(wide.size() + 1);
        *reinterpret_cast<int32_t*>(p + 0x10) = version;
        if (method == "party_ready") {
            *reinterpret_cast<uint8_t*>(p + 0x18) = 0;
            *reinterpret_cast<uint8_t*>(p + 0x19) = isPrivate ? 1 : 0;
        } else {
            *reinterpret_cast<uint8_t*>(p + 0x18) = isPrivate ? 1 : 0;
        }

        bool direct = false;
        if (!InvokeProcessEvent(ctx, pc, function, state,
                                Config::Get().game_thread.direct_fallback, false, &error, &direct)) {
            return fail(error);
        }

        const auto start = std::chrono::steady_clock::now();
        const int waitMs = std::clamp(args.value("wait_ms", 0), 0, 120000);
        bool connected = NetConnectionActive(ctx);
        while (waitMs > 0 && !connected && ElapsedMs(start) < static_cast<uint64_t>(waitMs)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            connected = NetConnectionActive(ctx);
        }

        return nlohmann::json{{"ok", true},
                              {"pc", ObjectSummary(pc)},
                              {"function", ObjectSummary(function)},
                              {"method", method},
                              {"link", {{"mnemonic", link}, {"version", version}, {"private", isPrivate}}},
                              {"engine_return", state->engineReturn},
                              {"game_thread", direct ? "direct" : "hooked"},
                              {"connected", connected},
                              {"waited_ms", ElapsedMs(start)}};
    }});

    registry.Add({"matchmaking_cancel",
                  "Cancel an in-progress Fortnite matchmaking search.",
                  nlohmann::json::parse(R"({
                    "type":"object","properties":{},"additionalProperties":false
                  })"),
                  [](const nlohmann::json&) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        auto fail = [](std::string message) -> nlohmann::json {
            return nlohmann::json{{"ok", false}, {"error", std::move(message)}};
        };
        if (!ctx.ProcessEventAddress()) return fail("process_event is not configured");
        if (!ctx.GameThreadHooked() && !Config::Get().game_thread.direct_fallback) {
            return fail("game-thread hook is not installed; enable ue.process_event.hook first");
        }
        std::string error;
        const uintptr_t pc = FindLocalPlayerController(ctx, &error);
        if (!pc) return fail(error);
        const uintptr_t function =
            ctx.FindObjectPath("/Script/FortniteGame.FortPlayerControllerAthena.CancelMatchmaking");
        if (!function) return fail("CancelMatchmaking not found");

        auto state = std::make_shared<PeState>();
        state->parms = std::make_shared<AlignedBuffer>(8);
        if (!state->parms->data) return fail("parameter allocation failed");
        state->parms->data[0] = 0; // EMatchmakingCancelReasonV2::Explicit

        bool direct = false;
        if (!InvokeProcessEvent(ctx, pc, function, state,
                                Config::Get().game_thread.direct_fallback, false, &error, &direct)) {
            return fail(error);
        }
        return nlohmann::json{{"ok", true},
                              {"pc", ObjectSummary(pc)},
                              {"function", ObjectSummary(function)},
                              {"reason", "Explicit"},
                              {"game_thread", direct ? "direct" : "hooked"}};
    }});

    registry.Add({"matchmaking_status",
                  "Report matchmaking/frontend state: network connection, world, local player controller, "
                  "and the FortMatchmakingContext flow flag when available.",
                  nlohmann::json::parse(R"({
                    "type":"object","properties":{},"additionalProperties":false
                  })"),
                  [](const nlohmann::json&) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        const uintptr_t world = ctx.GWorld();
        nlohmann::json result = {{"ok", true}, {"connected", NetConnectionActive(ctx)}};
        if (world) result["world"] = ObjectSummary(world);

        std::string error;
        const uintptr_t pc = FindLocalPlayerController(ctx, &error);
        if (pc) {
            result["pc"] = ObjectSummary(pc);
            result["pc_has_player"] = mem::ReadOr<uintptr_t>(pc + 0x310, 0) != 0;
        } else {
            result["pc_error"] = error;
        }

        const uintptr_t contextClass = ctx.FindObjectPath("/Script/FortniteGame.FortMatchmakingContext");
        if (contextClass) {
            std::string queryError;
            auto query = ctx.ObjectsOfClass(contextClass, true, RF_ClassDefaultObject, 8, &queryError);
            if (!query.objects.empty() && ctx.IsValidObject(query.objects.front())) {
                const uintptr_t context = query.objects.front();
                result["matchmaking_context"] = ObjectSummary(context);
                result["in_matchmaking_flow"] =
                    mem::ReadOr<uint8_t>(context + 0x1A4, 0) != 0;
            }
        }
        return result;
    }});

    registry.Add({"matchmaking_wait",
                  "Wait until the client is connected to a match server (or time out). Useful after "
                  "matchmaking_start or after a disconnect when auto-requeueing.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "timeout_ms":{"type":"integer","default":60000,"minimum":0,"maximum":180000},
                      "interval_ms":{"type":"integer","default":250,"minimum":50,"maximum":5000}
                    },
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        auto& ctx = ue::UeContext::Get();
        const int timeoutMs = std::clamp(args.value("timeout_ms", 60000), 0, 180000);
        const int intervalMs = std::clamp(args.value("interval_ms", 250), 50, 5000);
        const auto start = std::chrono::steady_clock::now();
        bool connected = NetConnectionActive(ctx);
        while (!connected && ElapsedMs(start) < static_cast<uint64_t>(timeoutMs)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
            connected = NetConnectionActive(ctx);
        }
        return nlohmann::json{{"ok", true},
                              {"connected", connected},
                              {"timed_out", !connected},
                              {"waited_ms", ElapsedMs(start)}};
    }});
}

}

void RegisterUeTools(ToolRegistry& registry) {
    RegisterFindObject(registry);
    RegisterObjectsOfClass(registry);
    RegisterObjectInfo(registry);
    RegisterProperties(registry);
    RegisterFunctions(registry);
    RegisterProcessEvent(registry);
    RegisterCallAddress(registry);
    RegisterGlobals(registry);
    RegisterResolveFName(registry);
    RegisterFindPointerField(registry);
    RegisterNetStats(registry);
    RegisterMatchmaking(registry);
    RegisterUeStatus(registry);
    RegisterUeConfigure(registry);
}

}

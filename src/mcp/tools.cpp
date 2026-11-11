#include "mcp/tools.h"

#include "core/base64.h"
#include "core/config.h"
#include "core/log.h"
#include "core/memory.h"
#include "core/modules.h"
#include "core/strings.h"
#include "ue/context.h"

#include <algorithm>
#include <chrono>

namespace fmcp {

void RegisterMemoryTools(ToolRegistry& registry);
void RegisterSystemTools(ToolRegistry& registry);
void RegisterUeTools(ToolRegistry& registry);
void RegisterInputTools(ToolRegistry& registry);

void ToolRegistry::Add(Tool tool) {
    if (tool.name.empty() || !tool.handler) {
        return;
    }
    for (const auto& existing : tools_) {
        if (existing.name == tool.name) {
            return;
        }
    }
    tools_.push_back(std::move(tool));
}

const Tool* ToolRegistry::Find(const std::string& name) const {
    for (const auto& tool : tools_) {
        if (tool.name == name) {
            return &tool;
        }
    }
    return nullptr;
}

nlohmann::json ToolRegistry::List() const {
    nlohmann::json tools = nlohmann::json::array();
    for (const auto& tool : tools_) {
        tools.push_back({{"name", tool.name}, {"description", tool.description},
                         {"inputSchema", tool.schema}});
    }
    return tools;
}

nlohmann::json ToolRegistry::Call(const std::string& name, const nlohmann::json& arguments) {
    const Tool* tool = Find(name);
    if (!tool) {
        throw ToolError("unknown tool: " + name);
    }
    if (!arguments.is_object() && !arguments.is_null()) {
        throw ToolError("tool arguments must be an object");
    }

    const nlohmann::json args = arguments.is_null() ? nlohmann::json::object() : arguments;
    const uint64_t start = GetTickCount64();

    try {
        nlohmann::json result = tool->handler(args);
        if (result.is_null()) {
            result = nlohmann::json::object();
        }
        FMCP_LOGD("tool %s ok (%llu ms)", name.c_str(),
                  static_cast<unsigned long long>(GetTickCount64() - start));
        return {{"content", nlohmann::json::array({{{"type", "text"}, {"text", JsonDump(result)}}})},
                {"isError", false}};
    } catch (const ToolError& e) {
        FMCP_LOGW("tool %s failed: %s", name.c_str(), e.what());
        return {{"content", nlohmann::json::array({{{"type", "text"}, {"text", e.what()}}})},
                {"isError", true}};
    } catch (const std::exception& e) {
        FMCP_LOGE("tool %s exception: %s", name.c_str(), e.what());
        return {{"content", nlohmann::json::array({{{"type", "text"}, {"text", e.what()}}})},
                {"isError", true}};
    } catch (...) {
        FMCP_LOGE("tool %s exception: unknown", name.c_str());
        return {{"content", nlohmann::json::array({{{"type", "text"}, {"text", "unknown exception"}}})},
                {"isError", true}};
    }
}

void RegisterAllTools(ToolRegistry& registry) {
    RegisterSystemTools(registry);
    RegisterMemoryTools(registry);
    RegisterUeTools(registry);
    RegisterInputTools(registry);
}

uintptr_t AddressFromJson(const nlohmann::json& value, std::string* error) {
    if (value.is_number_unsigned()) {
        return static_cast<uintptr_t>(value.get<uint64_t>());
    }
    if (value.is_number_integer()) {
        const int64_t signedValue = value.get<int64_t>();
        if (signedValue < 0) {
            if (error) *error = "negative address";
            return 0;
        }
        return static_cast<uintptr_t>(signedValue);
    }
    if (value.is_string()) {
        std::string resolveError;
        auto address = modules::Resolve(value.get<std::string>(), &resolveError);
        if (!address) {
            if (error) *error = resolveError;
            return 0;
        }
        return *address;
    }
    if (value.is_object() && value.contains("address")) {
        return AddressFromJson(value["address"], error);
    }
    if (error) *error = "address expected";
    return 0;
}

uintptr_t AddressFromObject(const nlohmann::json& args, const char* key, std::string* error) {
    if (!args.is_object() || !args.contains(key)) {
        if (error) *error = std::string("missing '") + key + "'";
        return 0;
    }
    return AddressFromJson(args[key], error);
}

std::string JsonDump(const nlohmann::json& value) {
    const std::string compact = value.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    if (compact.size() <= 16384) {
        return value.dump(2, ' ', false, nlohmann::json::error_handler_t::replace);
    }
    return compact;
}

void RequireConfirmation(const nlohmann::json& args) {
    if (!Config::Get().safety.require_confirm) {
        return;
    }
    if (!args.is_object() || !args.contains("confirm") || !args["confirm"].is_boolean() ||
        !args["confirm"].get<bool>()) {
        throw ToolError("confirmation required: pass \"confirm\": true");
    }
}

std::vector<uint8_t> DataFromJson(const nlohmann::json& args) {
    if (args.contains("bytes_hex")) {
        auto data = str::Unhex(args["bytes_hex"].get<std::string>());
        if (!data) throw ToolError("invalid bytes_hex");
        return *data;
    }
    if (args.contains("data_base64")) {
        auto data = b64::Decode(args["data_base64"].get<std::string>());
        if (!data) throw ToolError("invalid data_base64");
        return *data;
    }
    if (args.contains("bytes")) {
        if (args["bytes"].is_array()) {
            std::vector<uint8_t> data;
            data.reserve(args["bytes"].size());
            for (const auto& item : args["bytes"]) {
                if (!item.is_number_unsigned() || item.get<uint32_t>() > 0xFF) {
                    throw ToolError("bytes array must contain 0..255");
                }
                data.push_back(static_cast<uint8_t>(item.get<uint32_t>()));
            }
            return data;
        }
        if (args["bytes"].is_string()) {
            auto data = str::Unhex(args["bytes"].get<std::string>());
            if (!data) throw ToolError("invalid bytes");
            return *data;
        }
    }
    throw ToolError("provide bytes_hex, data_base64, or bytes");
}

nlohmann::json ObjectSummary(uintptr_t object) {
    auto& ctx = ue::UeContext::Get();
    nlohmann::json result;
    result["address"] = mem::FormatAddress(object);
    if (!ctx.IsValidObject(object)) {
        result["valid"] = false;
        return result;
    }
    const ue::ObjectInfo info = ctx.DescribeObject(object);
    result["valid"] = true;
    result["name"] = info.name;
    result["class"] = info.class_name;
    result["class_address"] = mem::FormatAddress(info.class_address);
    result["outer"] = mem::FormatAddress(info.outer);
    result["path"] = info.path;
    result["flags"] = info.flags;
    return result;
}

}

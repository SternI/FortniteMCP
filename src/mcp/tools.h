#pragma once

#include <cstdint>
#include <functional>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <vector>

namespace fmcp {

class ToolError : public std::runtime_error {
public:
    explicit ToolError(const std::string& message) : std::runtime_error(message) {}
};

struct Tool {
    std::string name;
    std::string description;
    nlohmann::json schema;
    std::function<nlohmann::json(const nlohmann::json&)> handler;
};

class ToolRegistry {
public:
    void Add(Tool tool);
    [[nodiscard]] const Tool* Find(const std::string& name) const;
    [[nodiscard]] nlohmann::json List() const;
    [[nodiscard]] nlohmann::json Call(const std::string& name, const nlohmann::json& arguments);

private:
    std::vector<Tool> tools_;
};

void RegisterAllTools(ToolRegistry& registry);

uintptr_t AddressFromJson(const nlohmann::json& value, std::string* error = nullptr);
uintptr_t AddressFromObject(const nlohmann::json& args, const char* key, std::string* error = nullptr);
std::string JsonDump(const nlohmann::json& value);
void RequireConfirmation(const nlohmann::json& args);
std::vector<uint8_t> DataFromJson(const nlohmann::json& args);
nlohmann::json ObjectSummary(uintptr_t object);

}

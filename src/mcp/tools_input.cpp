#include "mcp/tools.h"

#include "core/strings.h"
#include "ue/input.h"

#include <algorithm>

namespace fmcp {

namespace {

nlohmann::json WindowJson(const input::WindowInfo& window) {
    return {{"handle", str::Format("0x%llX", static_cast<unsigned long long>(window.handle))},
            {"pid", window.pid},
            {"title", window.title},
            {"class", window.className},
            {"left", window.left},
            {"top", window.top},
            {"right", window.right},
            {"bottom", window.bottom},
            {"visible", window.visible},
            {"minimized", window.minimized},
            {"foreground", window.foreground}};
}

void RegisterWindow(ToolRegistry& registry) {
    registry.Add({"input_window",
                  "Describe the game window and whether it is foreground.",
                  nlohmann::json::parse(R"({"type":"object","properties":{},"additionalProperties":false})"),
                  [](const nlohmann::json&) -> nlohmann::json {
        std::string error;
        const auto window = input::GameWindow(&error);
        if (!window) throw ToolError(error);
        return nlohmann::json{{"window", WindowJson(*window)}};
    }});
}

void RegisterKey(ToolRegistry& registry) {
    registry.Add({"input_key",
                  "Send keyboard input to the game window. Keys: letters, digits, F1-F24, space, enter, "
                  "escape, tab, shift, ctrl, alt, arrows, etc. Use vk:N for raw virtual-key codes. "
                  "By default the game window must be foreground; key events are sent to whatever window "
                  "is foreground, so allow_background only uses window messages (best-effort).",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "keys":{"oneOf":[{"type":"string"},{"type":"array","items":{"type":"string"}}]},
                      "action":{"type":"string","enum":["press","down","up"],"default":"press"},
                      "hold_ms":{"type":"integer","minimum":1,"maximum":10000,"default":40},
                      "allow_background":{"type":"boolean","default":false}
                    },
                    "required":["keys"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        std::vector<std::string> keys;
        if (args["keys"].is_string()) {
            keys.push_back(args["keys"].get<std::string>());
        } else if (args["keys"].is_array()) {
            for (const auto& key : args["keys"]) {
                if (!key.is_string()) throw ToolError("keys must be strings");
                keys.push_back(key.get<std::string>());
            }
        }
        if (keys.empty()) throw ToolError("no keys provided");
        if (keys.size() > 32) throw ToolError("too many keys");

        const std::string action = args.value("action", "press");
        const int holdMs = std::clamp(args.value("hold_ms", 40), 1, 10000);
        const bool allowBackground = args.value("allow_background", false);

        nlohmann::json sent = nlohmann::json::array();
        for (const auto& key : keys) {
            std::string error;
            if (!input::SendKey(key, action, holdMs, allowBackground, &error)) {
                throw ToolError(key + ": " + error);
            }
            sent.push_back(key);
        }

        std::string error;
        const auto window = input::GameWindow(&error);
        nlohmann::json result = {{"sent", std::move(sent)},
                                 {"action", action},
                                 {"hold_ms", holdMs},
                                 {"background", allowBackground}};
        if (window) result["window"] = WindowJson(*window);
        return result;
    }});

    registry.Add({"input_text",
                  "Send unicode text to the focused game window. Useful for chat or debug fields. "
                  "The game window must be foreground.",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "text":{"type":"string","maxLength":1024},
                      "allow_background":{"type":"boolean","default":false}
                    },
                    "required":["text"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        const std::string text = args["text"].get<std::string>();
        if (text.size() > 1024) throw ToolError("text is too long");
        std::string error;
        if (!input::SendText(text, args.value("allow_background", false), &error)) {
            throw ToolError(error);
        }
        return nlohmann::json{{"sent", true}, {"length", text.size()}};
    }});
}

void RegisterMouse(ToolRegistry& registry) {
    registry.Add({"input_mouse",
                  "Send mouse input to the game window. move_relative is recommended for camera rotation. "
                  "move_absolute uses normalized absolute screen coordinates (raw-input games may ignore it).",
                  nlohmann::json::parse(R"({
                    "type":"object",
                    "properties":{
                      "action":{"type":"string","enum":["move_relative","move_absolute","click","down","up","wheel"]},
                      "dx":{"type":"integer","default":0},
                      "dy":{"type":"integer","default":0},
                      "x":{"type":"integer"},
                      "y":{"type":"integer"},
                      "button":{"type":"string","enum":["left","right","middle","x1","x2"],"default":"left"},
                      "delta":{"type":"integer","default":120},
                      "allow_background":{"type":"boolean","default":false}
                    },
                    "required":["action"],
                    "additionalProperties":false
                  })"),
                  [](const nlohmann::json& args) -> nlohmann::json {
        const std::string action = args["action"].get<std::string>();
        const bool allowBackground = args.value("allow_background", false);
        std::string error;

        bool ok = false;
        if (action == "move_relative") {
            const int dx = std::clamp(args.value("dx", 0), -100000, 100000);
            const int dy = std::clamp(args.value("dy", 0), -100000, 100000);
            ok = input::MouseMoveRelative(dx, dy, allowBackground, &error);
        } else if (action == "move_absolute") {
            if (!args.contains("x") || !args.contains("y")) {
                throw ToolError("x and y are required for move_absolute");
            }
            const int x = args["x"].get<int>();
            const int y = args["y"].get<int>();
            ok = input::MouseMoveAbsolute(x, y, allowBackground, &error);
        } else if (action == "click" || action == "down" || action == "up") {
            ok = input::MouseButton(args.value("button", "left"), action, allowBackground, &error);
        } else if (action == "wheel") {
            const int delta = std::clamp(args.value("delta", 120), -1200, 1200);
            ok = input::MouseWheel(delta, allowBackground, &error);
        } else {
            throw ToolError("unknown mouse action");
        }

        if (!ok) throw ToolError(error);

        std::string windowError;
        const auto window = input::GameWindow(&windowError);
        nlohmann::json result = {{"action", action}, {"sent", true}};
        if (window) result["window"] = WindowJson(*window);
        return result;
    }});
}

}

void RegisterInputTools(ToolRegistry& registry) {
    RegisterWindow(registry);
    RegisterKey(registry);
    RegisterMouse(registry);
}

}

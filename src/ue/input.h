#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace fmcp::input {

struct WindowInfo {
    uintptr_t handle = 0;
    uint32_t pid = 0;
    std::string title;
    std::string className;
    long left = 0;
    long top = 0;
    long right = 0;
    long bottom = 0;
    bool visible = false;
    bool minimized = false;
    bool foreground = false;
};

std::optional<WindowInfo> GameWindow(std::string* error = nullptr);
bool RefreshGameWindow();
bool ForceForeground(std::string* error = nullptr);
bool IsForeground();

bool SendKey(const std::string& key, const std::string& action, int holdMs,
             bool allowBackground, std::string* error);
bool SendText(const std::string& text, bool allowBackground, std::string* error);
bool MouseMoveRelative(int dx, int dy, bool allowBackground, std::string* error);
bool MouseMoveAbsolute(int x, int y, bool allowBackground, std::string* error);
bool MouseButton(const std::string& button, const std::string& action, bool allowBackground,
                 std::string* error);
bool MouseWheel(int delta, bool allowBackground, std::string* error);

}

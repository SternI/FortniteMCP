#include "ue/input.h"

#include "core/log.h"
#include "core/strings.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <thread>
#include <vector>

namespace fmcp::input {

namespace {

uintptr_t g_window = 0;
std::string g_title;
std::string g_class;
DWORD g_pid = 0;

struct WindowSearch {
    DWORD pid = 0;
    HWND best = nullptr;
    long bestArea = 0;
    std::string bestTitle;
    std::string bestClass;
    RECT bestRect{};
};

BOOL CALLBACK EnumWindowsProc(HWND window, LPARAM param) {
    auto* search = reinterpret_cast<WindowSearch*>(param);
    DWORD pid = 0;
    GetWindowThreadProcessId(window, &pid);
    if (pid != search->pid) {
        return TRUE;
    }
    if (!IsWindowVisible(window)) {
        return TRUE;
    }

    wchar_t title[512]{};
    GetWindowTextW(window, title, static_cast<int>(std::size(title)));
    wchar_t className[256]{};
    GetClassNameW(window, className, static_cast<int>(std::size(className)));

    RECT rect{};
    GetClientRect(window, &rect);
    const long area = (rect.right - rect.left) * (rect.bottom - rect.top);
    if (area < 64 * 48) {
        return TRUE;
    }

    const std::string titleText = str::Narrow(title);
    const std::string classText = str::Narrow(className);
    long score = area;
    if (str::IContains(classText, "UnrealWindow")) {
        score += 100000000;
    }
    if (str::IContains(titleText, "Fortnite")) {
        score += 50000000;
    }

    if (score > search->bestArea) {
        search->bestArea = score;
        search->best = window;
        search->bestTitle = titleText;
        search->bestClass = classText;
        search->bestRect = rect;
    }
    return TRUE;
}

bool EnsureForeground(bool allowBackground, std::string* error) {
    if (allowBackground) {
        return true;
    }
    if (IsForeground()) {
        return true;
    }
    if (ForceForeground(error) && IsForeground()) {
        return true;
    }
    if (error) {
        if (error->empty()) {
            *error = "game window is not foreground; focus it or pass allow_background=true";
        }
    }
    return false;
}

uint32_t VirtualKeyFromText(const std::string& text) {
    if (text.empty()) return 0;

    if (text.size() == 1) {
        const unsigned char c = static_cast<unsigned char>(text[0]);
        if (c >= 'a' && c <= 'z') return static_cast<uint32_t>(std::toupper(c));
        if (c >= 'A' && c <= 'Z') return c;
        if (c >= '0' && c <= '9') return c;
    }

    const std::string key = str::ToLower(text);
    if (key.size() == 1) {
        return static_cast<uint32_t>(std::toupper(static_cast<unsigned char>(key[0])));
    }

    static const struct {
        const char* name;
        uint32_t vk;
    } keys[] = {
        {"backspace", VK_BACK}, {"tab", VK_TAB}, {"enter", VK_RETURN}, {"return", VK_RETURN},
        {"shift", VK_SHIFT}, {"lshift", VK_LSHIFT}, {"rshift", VK_RSHIFT},
        {"ctrl", VK_CONTROL}, {"control", VK_CONTROL}, {"lctrl", VK_LCONTROL}, {"rctrl", VK_RCONTROL},
        {"alt", VK_MENU}, {"lalt", VK_LMENU}, {"ralt", VK_RMENU}, {"win", VK_LWIN},
        {"escape", VK_ESCAPE}, {"esc", VK_ESCAPE}, {"space", VK_SPACE},
        {"capslock", VK_CAPITAL}, {"numlock", VK_NUMLOCK}, {"scrolllock", VK_SCROLL},
        {"pause", VK_PAUSE}, {"printscreen", VK_SNAPSHOT},
        {"up", VK_UP}, {"down", VK_DOWN}, {"left", VK_LEFT}, {"right", VK_RIGHT},
        {"home", VK_HOME}, {"end", VK_END}, {"pageup", VK_PRIOR}, {"pagedown", VK_NEXT},
        {"insert", VK_INSERT}, {"delete", VK_DELETE}, {"del", VK_DELETE},
        {"multiply", VK_MULTIPLY}, {"add", VK_ADD}, {"subtract", VK_SUBTRACT},
        {"divide", VK_DIVIDE}, {"decimal", VK_DECIMAL},
    };

    for (const auto& entry : keys) {
        if (key == entry.name) {
            return entry.vk;
        }
    }

    if (key.size() >= 2 && key[0] == 'f') {
        const auto number = str::ParseUint(key.substr(1));
        if (number && *number >= 1 && *number <= 24) {
            return VK_F1 + static_cast<uint32_t>(*number - 1);
        }
    }

    if (str::StartsWith(key, "vk:")) {
        const auto number = str::ParseUint(key.substr(3));
        if (number && *number <= 0xFF) {
            return static_cast<uint32_t>(*number);
        }
    }

    return 0;
}

bool IsExtendedKey(uint32_t vk, uint16_t scanCode) {
    switch (vk) {
    case VK_INSERT: case VK_DELETE: case VK_HOME: case VK_END:
    case VK_PRIOR: case VK_NEXT: case VK_LEFT: case VK_RIGHT:
    case VK_UP: case VK_DOWN: case VK_DIVIDE: case VK_RCONTROL:
    case VK_RMENU: case VK_LWIN: case VK_RWIN: case VK_APPS:
    case VK_SNAPSHOT:
        return true;
    default:
        return scanCode == 0;
    }
}

bool SendKeyInput(uint32_t vk, bool down, bool unicode, wchar_t character, bool useScanCode) {
    INPUT input{};
    input.type = INPUT_KEYBOARD;

    if (unicode) {
        input.ki.wScan = character;
        input.ki.dwFlags = KEYEVENTF_UNICODE | (down ? 0 : KEYEVENTF_KEYUP);
    } else {
        const uint16_t scan = static_cast<uint16_t>(MapVirtualKeyW(vk, MAPVK_VK_TO_VSC));
        if (useScanCode && scan != 0) {
            input.ki.wScan = scan;
            input.ki.dwFlags = KEYEVENTF_SCANCODE | (down ? 0 : KEYEVENTF_KEYUP);
            if (IsExtendedKey(vk, scan)) {
                input.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
            }
        } else {
            input.ki.wVk = static_cast<WORD>(vk);
            input.ki.dwFlags = down ? 0 : KEYEVENTF_KEYUP;
        }
    }

    return SendInput(1, &input, sizeof(input)) == 1;
}

bool PostKeyMessage(uint32_t vk, bool down) {
    if (!g_window) {
        return false;
    }
    const uint16_t scan = static_cast<uint16_t>(MapVirtualKeyW(vk, MAPVK_VK_TO_VSC));
    const bool extended = IsExtendedKey(vk, scan);
    UINT message = down ? WM_KEYDOWN : WM_KEYUP;
    LPARAM lParam = 1 | (static_cast<LPARAM>(scan) << 16);
    if (extended) lParam |= (1ll << 24);
    if (!down) {
        lParam |= (1ll << 30) | (1ll << 31);
    }
    return PostMessageW(reinterpret_cast<HWND>(g_window), message, vk, lParam) != 0;
}

int ButtonFlag(const std::string& button, bool down) {
    const std::string lower = str::ToLower(button);
    if (lower == "left") return down ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
    if (lower == "right") return down ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
    if (lower == "middle") return down ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;
    if (lower == "x1") return down ? MOUSEEVENTF_XDOWN : MOUSEEVENTF_XUP;
    if (lower == "x2") return down ? MOUSEEVENTF_XDOWN : MOUSEEVENTF_XUP;
    return 0;
}

uint32_t ButtonData(const std::string& button) {
    const std::string lower = str::ToLower(button);
    if (lower == "x1") return XBUTTON1;
    if (lower == "x2") return XBUTTON2;
    return 0;
}

bool SendMouse(const INPUT& base, DWORD flags, LONG dx, LONG dy, DWORD mouseData) {
    INPUT input = base;
    input.type = INPUT_MOUSE;
    input.mi.dx = dx;
    input.mi.dy = dy;
    input.mi.mouseData = mouseData;
    input.mi.dwFlags = flags;
    return SendInput(1, &input, sizeof(input)) == 1;
}

}

bool RefreshGameWindow() {
    WindowSearch search;
    search.pid = GetCurrentProcessId();
    EnumWindows(&EnumWindowsProc, reinterpret_cast<LPARAM>(&search));
    if (!search.best) {
        return false;
    }

    g_window = reinterpret_cast<uintptr_t>(search.best);
    g_title = std::move(search.bestTitle);
    g_class = std::move(search.bestClass);
    g_pid = search.pid;
    return true;
}

std::optional<WindowInfo> GameWindow(std::string* error) {
    if (!g_window && !RefreshGameWindow()) {
        if (error) *error = "game window was not found";
        return std::nullopt;
    }

    RECT rect{};
    GetClientRect(reinterpret_cast<HWND>(g_window), &rect);
    POINT topLeft{rect.left, rect.top};
    ClientToScreen(reinterpret_cast<HWND>(g_window), &topLeft);
    POINT bottomRight{rect.right, rect.bottom};
    ClientToScreen(reinterpret_cast<HWND>(g_window), &bottomRight);

    WindowInfo info;
    info.handle = g_window;
    info.pid = g_pid;
    info.title = g_title;
    info.className = g_class;
    info.left = topLeft.x;
    info.top = topLeft.y;
    info.right = bottomRight.x;
    info.bottom = bottomRight.y;
    info.visible = IsWindowVisible(reinterpret_cast<HWND>(g_window)) != FALSE;
    info.minimized = IsIconic(reinterpret_cast<HWND>(g_window)) != FALSE;
    info.foreground = IsForeground();
    return info;
}

bool IsForeground() {
    if (!g_window) {
        return false;
    }
    HWND foreground = GetForegroundWindow();
    if (!foreground) {
        return false;
    }
    if (reinterpret_cast<uintptr_t>(foreground) == g_window) {
        return true;
    }
    return GetAncestor(foreground, GA_ROOT) == reinterpret_cast<HWND>(g_window);
}

bool ForceForeground(std::string* error) {
    if (g_window && !IsWindow(reinterpret_cast<HWND>(g_window))) {
        g_window = 0;
    }
    if (!g_window) {
        if (error) *error = "game window was not found";
        return false;
    }

    HWND game = reinterpret_cast<HWND>(g_window);
    if (IsIconic(game)) {
        ShowWindow(game, SW_RESTORE);
    }

    if (IsForeground()) {
        return true;
    }

    const HWND foreground = GetForegroundWindow();
    const DWORD foregroundThread = foreground ? GetWindowThreadProcessId(foreground, nullptr) : 0;
    const DWORD gameThread = GetWindowThreadProcessId(game, nullptr);
    const DWORD currentThread = GetCurrentThreadId();

    bool attachedForeground = false;
    bool attachedGame = false;
    if (foregroundThread && foregroundThread != currentThread) {
        attachedForeground = AttachThreadInput(currentThread, foregroundThread, TRUE) != FALSE;
    }
    if (gameThread && gameThread != currentThread) {
        attachedGame = AttachThreadInput(currentThread, gameThread, TRUE) != FALSE;
    }

    BringWindowToTop(game);
    SetForegroundWindow(game);
    SetActiveWindow(game);
    SetFocus(game);

    if (attachedGame) AttachThreadInput(currentThread, gameThread, FALSE);
    if (attachedForeground) AttachThreadInput(currentThread, foregroundThread, FALSE);

    for (int i = 0; i < 20; ++i) {
        if (IsForeground()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }

    if (error) *error = "failed to bring the game window to the foreground";
    return false;
}

bool EnsureMouseFocus(bool allowBackground, std::string* error) {
    if (allowBackground && !IsForeground()) {
        if (error) *error = "mouse input requires the game window to be foreground";
        return false;
    }
    return EnsureForeground(false, error);
}

bool SendKey(const std::string& key, const std::string& action, int holdMs,
             bool allowBackground, std::string* error) {
    if (g_window && !IsWindow(reinterpret_cast<HWND>(g_window))) {
        g_window = 0;
    }
    if (!g_window && !RefreshGameWindow()) {
        if (error) *error = "game window was not found";
        return false;
    }

    uint32_t vk = 0;
    if (auto number = str::ParseUint(key)) {
        if (*number <= 0xFF) vk = static_cast<uint32_t>(*number);
    }
    if (!vk) {
        vk = VirtualKeyFromText(key);
    }
    if (!vk) {
        if (error) *error = "unknown key name: " + key;
        return false;
    }

    const std::string actionLower = str::ToLower(action);
    const bool background = allowBackground && !IsForeground();
    if (!EnsureForeground(allowBackground, error)) {
        return false;
    }

    auto sendDown = [&]() -> bool {
        return background ? PostKeyMessage(vk, true) : SendKeyInput(vk, true, false, 0, true);
    };
    auto sendUp = [&]() -> bool {
        return background ? PostKeyMessage(vk, false) : SendKeyInput(vk, false, false, 0, true);
    };

    if (actionLower == "down") {
        if (!sendDown()) {
            if (error) *error = "failed to send key down";
            return false;
        }
        return true;
    }

    if (actionLower == "up") {
        if (!sendUp()) {
            if (error) *error = "failed to send key up";
            return false;
        }
        return true;
    }

    if (actionLower != "press") {
        if (error) *error = "action must be press, down, or up";
        return false;
    }

    if (!sendDown()) {
        if (error) *error = "failed to send key down";
        return false;
    }

    const int delay = std::clamp(holdMs, 1, 10000);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    if (!sendUp()) {
        if (error) *error = "failed to send key up (key may remain held)";
        return false;
    }
    return true;
}

bool SendText(const std::string& text, bool allowBackground, std::string* error) {
    if (!EnsureForeground(allowBackground, error)) {
        return false;
    }
    if (allowBackground && !IsForeground()) {
        if (error) *error = "input_text requires the game window to be foreground";
        return false;
    }

    for (wchar_t c : str::Widen(text)) {
        if (c == L'\n') {
            if (!SendKeyInput(VK_RETURN, true, false, 0, true) ||
                !SendKeyInput(VK_RETURN, false, false, 0, true)) {
                if (error) *error = "failed to send enter";
                return false;
            }
            continue;
        }
        if (!SendKeyInput(0, true, true, c, false) || !SendKeyInput(0, false, true, c, false)) {
            if (error) *error = "failed to send unicode character";
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return true;
}

bool MouseMoveRelative(int dx, int dy, bool allowBackground, std::string* error) {
    if (!EnsureMouseFocus(allowBackground, error)) {
        return false;
    }
    if (!SendMouse(INPUT{}, MOUSEEVENTF_MOVE, dx, dy, 0)) {
        if (error) *error = "SendInput mouse move failed";
        return false;
    }
    return true;
}

bool MouseMoveAbsolute(int x, int y, bool allowBackground, std::string* error) {
    if (!EnsureMouseFocus(allowBackground, error)) {
        return false;
    }

    const int left = GetSystemMetrics(SM_XVIRTUALSCREEN);
    const int top = GetSystemMetrics(SM_YVIRTUALSCREEN);
    const int width = std::max(GetSystemMetrics(SM_CXVIRTUALSCREEN), 1);
    const int height = std::max(GetSystemMetrics(SM_CYVIRTUALSCREEN), 1);

    const LONG nx = static_cast<LONG>((static_cast<int64_t>(x - left) * 65535) / std::max(width - 1, 1));
    const LONG ny = static_cast<LONG>((static_cast<int64_t>(y - top) * 65535) / std::max(height - 1, 1));

    SetCursorPos(x, y);
    if (!SendMouse(INPUT{}, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                   nx, ny, 0)) {
        if (error) *error = "SendInput absolute mouse move failed";
        return false;
    }
    return true;
}

bool MouseButton(const std::string& button, const std::string& action, bool allowBackground,
                 std::string* error) {
    if (!EnsureMouseFocus(allowBackground, error)) {
        return false;
    }

    const std::string actionLower = str::ToLower(action);
    const int downFlag = ButtonFlag(button, true);
    const int upFlag = ButtonFlag(button, false);
    if (!downFlag || !upFlag) {
        if (error) *error = "button must be left, right, middle, x1, or x2";
        return false;
    }

    const uint32_t data = ButtonData(button);
    auto send = [&](bool down) {
        const DWORD flags = static_cast<DWORD>(down ? downFlag : upFlag);
        return SendMouse(INPUT{}, flags, 0, 0, data);
    };

    if (actionLower == "down") {
        if (!send(true)) {
            if (error) *error = "SendInput mouse down failed";
            return false;
        }
        return true;
    }
    if (actionLower == "up") {
        if (!send(false)) {
            if (error) *error = "SendInput mouse up failed";
            return false;
        }
        return true;
    }
    if (actionLower != "click") {
        if (error) *error = "action must be click, down, or up";
        return false;
    }

    if (!send(true)) {
        if (error) *error = "SendInput mouse down failed";
        return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    if (!send(false)) {
        if (error) *error = "SendInput mouse up failed";
        return false;
    }
    return true;
}

bool MouseWheel(int delta, bool allowBackground, std::string* error) {
    if (!EnsureMouseFocus(allowBackground, error)) {
        return false;
    }
    if (!SendMouse(INPUT{}, MOUSEEVENTF_WHEEL, 0, 0, static_cast<DWORD>(delta))) {
        if (error) *error = "SendInput wheel failed";
        return false;
    }
    return true;
}

}

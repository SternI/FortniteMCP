#include "core/log.h"

#include "core/strings.h"

#include <cstdarg>
#include <cstdio>
#include <deque>
#include <share.h>
#include <mutex>
#include <windows.h>

namespace fmcp::log {

namespace {

std::mutex g_mutex;
Level g_level = Level::Info;
FILE* g_file = nullptr;
std::string g_path;
std::string g_openPath;
size_t g_maxFileBytes = 4 * 1024 * 1024;
bool g_debugOutput = false;
std::deque<std::string> g_ring;
constexpr size_t kRingMax = 2000;

std::string Timestamp() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    return str::Format("%04u-%02u-%02u %02u:%02u:%02u.%03u", st.wYear, st.wMonth, st.wDay,
                       st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

void RotateIfNeeded(size_t incoming) {
    if (!g_file || g_maxFileBytes == 0) {
        return;
    }

    long size = ftell(g_file);
    if (size < 0 || static_cast<size_t>(size) + incoming <= g_maxFileBytes) {
        return;
    }

    fclose(g_file);
    g_file = nullptr;

    const std::string oldPath = g_openPath + ".1";
    DeleteFileA(oldPath.c_str());
    MoveFileA(g_openPath.c_str(), oldPath.c_str());

    g_file = _fsopen(g_openPath.c_str(), "ab", _SH_DENYNO);
}

void OpenFile() {
    if (g_openPath.empty()) {
        return;
    }
    if (g_file) {
        fclose(g_file);
        g_file = nullptr;
    }
    g_file = _fsopen(g_openPath.c_str(), "ab", _SH_DENYNO);
}

}

Level ParseLevel(const std::string& name) {
    const std::string lower = str::ToLower(name);
    if (lower == "trace") return Level::Trace;
    if (lower == "debug") return Level::Debug;
    if (lower == "info") return Level::Info;
    if (lower == "warn" || lower == "warning") return Level::Warn;
    if (lower == "error") return Level::Error;
    if (lower == "off" || lower == "none") return Level::Off;
    return Level::Info;
}

const char* LevelName(Level level) {
    switch (level) {
    case Level::Trace: return "TRACE";
    case Level::Debug: return "DEBUG";
    case Level::Info: return "INFO";
    case Level::Warn: return "WARN";
    case Level::Error: return "ERROR";
    default: return "OFF";
    }
}

void Init(const std::string& path, Level level, size_t maxFileBytes, bool debugOutput) {
    std::lock_guard lock(g_mutex);
    g_level = level;
    g_maxFileBytes = maxFileBytes;
    g_debugOutput = debugOutput;
    g_path = path;

    if (path != g_openPath) {
        if (g_file) {
            fclose(g_file);
            g_file = nullptr;
        }
        g_openPath = path;
        OpenFile();
    }
}

void Shutdown() {
    std::lock_guard lock(g_mutex);
    if (g_file) {
        fflush(g_file);
        fclose(g_file);
        g_file = nullptr;
    }
}

void SetLevel(Level level) {
    std::lock_guard lock(g_mutex);
    g_level = level;
}

bool Enabled(Level level) {
    std::lock_guard lock(g_mutex);
    return g_level != Level::Off && level >= g_level;
}

void Write(Level level, const char* fmt, ...) {
    std::lock_guard lock(g_mutex);
    if (g_level == Level::Off || level < g_level) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    std::string message = str::VFormat(fmt, args);
    va_end(args);

    if (message.size() > 8192) {
        message.resize(8192);
        message += "...";
    }

    const std::string line = Timestamp() + " [" + LevelName(level) + "] " + message;

    g_ring.push_back(line);
    if (g_ring.size() > kRingMax) {
        g_ring.pop_front();
    }

    if (g_file) {
        RotateIfNeeded(line.size() + 2);
        if (g_file) {
            fwrite(line.data(), 1, line.size(), g_file);
            fputc('\n', g_file);
            fflush(g_file);
        }
    }

    if (g_debugOutput) {
        OutputDebugStringA((line + "\n").c_str());
    }
}

std::string Tail(size_t maxLines) {
    std::lock_guard lock(g_mutex);
    if (g_ring.empty() || maxLines == 0) {
        return {};
    }
    if (maxLines > g_ring.size()) {
        maxLines = g_ring.size();
    }

    std::string out;
    size_t start = g_ring.size() - maxLines;
    for (size_t i = start; i < g_ring.size(); ++i) {
        out += g_ring[i];
        out.push_back('\n');
    }
    return out;
}

const std::string& Path() {
    return g_path;
}

}

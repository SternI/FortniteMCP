#pragma once

#include <cstddef>
#include <string>

namespace fmcp::log {

enum class Level {
    Trace = 0,
    Debug,
    Info,
    Warn,
    Error,
    Off
};

Level ParseLevel(const std::string& name);
const char* LevelName(Level level);

void Init(const std::string& path, Level level, size_t maxFileBytes, bool debugOutput);
void Shutdown();
void SetLevel(Level level);
bool Enabled(Level level);
void Write(Level level, const char* fmt, ...);
std::string Tail(size_t maxLines = 200);
const std::string& Path();

}

#define FMCP_LOGT(...) ::fmcp::log::Write(::fmcp::log::Level::Trace, __VA_ARGS__)
#define FMCP_LOGD(...) ::fmcp::log::Write(::fmcp::log::Level::Debug, __VA_ARGS__)
#define FMCP_LOGI(...) ::fmcp::log::Write(::fmcp::log::Level::Info, __VA_ARGS__)
#define FMCP_LOGW(...) ::fmcp::log::Write(::fmcp::log::Level::Warn, __VA_ARGS__)
#define FMCP_LOGE(...) ::fmcp::log::Write(::fmcp::log::Level::Error, __VA_ARGS__)

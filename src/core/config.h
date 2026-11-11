#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <nlohmann/json.hpp>
#include <ue/layout.h>

namespace fmcp {

struct ServerConfig {
    std::string host = "127.0.0.1";
    uint16_t port = 26064;
    std::string auth_token = "auto";
    std::string token;
    std::string token_file;
    size_t max_body_bytes = 4ull * 1024 * 1024;
    int max_connections = 32;
    int idle_timeout_ms = 30000;
};

struct LogConfig {
    std::string level = "info";
    size_t max_file_bytes = 4ull * 1024 * 1024;
    bool debug_output = false;
};

struct SafetyConfig {
    size_t max_transfer_bytes = 16ull * 1024 * 1024;
    size_t max_read_bytes = 4ull * 1024 * 1024;
    size_t max_scan_results = 128;
    uint64_t max_scan_bytes = 512ull * 1024 * 1024;
    int max_patches = 128;
    bool undo_patches = true;
    bool allow_raw_calls = true;
    bool allow_any_free = false;
    bool allow_self_unload = true;
    bool allow_exec_alloc = true;
    bool require_confirm = true;
};

struct GameThreadConfig {
    bool enabled = true;
    int timeout_ms = 5000;
    int max_queued = 32;
    int jobs_per_pump = 8;
    int pump_budget_us = 1500;
    bool direct_fallback = false;
};

struct FunctionSpec {
    std::string resolve = "off";
    uint64_t offset = 0;
    std::string signature;
    int vtable_index = -1;
    std::string name_arg = "wchar_ptr";
    bool hook = true;
};

struct NamesSpec {
    std::string style = "off";
    std::string resolve = "offset";
    uint64_t offset = 0;
    std::string signature;
    int fname_size = 8;
    int block_table_offset = 0x10;
    int block_bits = 16;
    int stride = 2;
    std::string codec = "plain";
    std::string abi = "fstring_ref";
    int max_chars = 2048;
    bool game_thread = false;
    bool validate = false;
    uint64_t pool_offset = 0;
    std::string decrypt = "none";
    uint64_t decrypt_key = 0;
};

struct ObjectsSpec {
    std::string style = "off";
    std::string resolve = "offset";
    uint64_t offset = 0;
    std::string signature;
    uint64_t objects_offset = 0x10;
    int item_size = 24;
    int chunk_bits = 16;
    int item_object_offset = 0;
    int max_objects = 2000000;
    int empty_chunk_stop = 4;
};

struct GlobalSpec {
    std::string resolve = "off";
    uint64_t offset = 0;
    std::string signature;
    std::string decode;
    std::string from;
    std::vector<uint64_t> chain;
};

struct UeConfig {
    std::string profile = "ue5";
    bool auto_tune = true;
    FunctionSpec static_find_object;
    FunctionSpec get_objects_of_class;
    FunctionSpec process_event;
    NamesSpec names;
    ObjectsSpec objects;
    GlobalSpec gworld;
    GlobalSpec gengine;
    std::map<std::string, GlobalSpec> extra_globals;
    ue::Layout layout;
};

struct Config {
    ServerConfig server;
    LogConfig log;
    SafetyConfig safety;
    GameThreadConfig game_thread;
    UeConfig ue;

    std::string directory;
    std::string path;
    std::string log_path;
    bool loaded = false;

    static Config& Get();

    bool Load();
    bool Save();
    void ApplyRuntimeJson(const nlohmann::json& root);
    void ResetDefaults();

private:
    void ApplyJson(const std::string& text);
    std::string Serialize() const;
};

}

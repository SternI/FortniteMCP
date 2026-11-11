#include "core/config.h"

#include "core/log.h"
#include "core/strings.h"

#include <bcrypt.h>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace fmcp {

namespace {

std::string DefaultDirectory() {
    wchar_t* local = nullptr;
    size_t len = 0;
    std::string out;

    if (_wdupenv_s(&local, &len, L"LOCALAPPDATA") == 0 && local) {
        out = str::Narrow(local);
    }
    free(local);

    if (out.empty()) {
        out = "C:\\FortniteMCP";
    }

    return out + "\\FortniteMCP";
}

std::string RandomHex(size_t bytes) {
    std::string data(bytes, '\0');

    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(data.data()), static_cast<ULONG>(bytes),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        uint64_t seed = GetTickCount64() ^ (uintptr_t)&bytes;
        for (size_t i = 0; i < bytes; ++i) {
            seed = seed * 6364136223846793005ull + 1442695040888963407ull;
            data[i] = static_cast<char>((seed >> 33) & 0xFF);
        }
    }

    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes * 2);
    for (unsigned char c : data) {
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0xF]);
    }
    return out;
}

bool IsLoopbackHost(const std::string& host) {
    return host == "127.0.0.1" || host == "localhost" || host == "::1";
}

int IntOr(const json& j, const char* key, int fallback) {
    if (!j.is_object() || !j.contains(key) || !j[key].is_number_integer()) {
        return fallback;
    }
    return j[key].get<int>();
}

uint64_t UIntOr(const json& j, const char* key, uint64_t fallback) {
    if (!j.is_object() || !j.contains(key)) {
        return fallback;
    }
    if (j[key].is_number_unsigned()) {
        return j[key].get<uint64_t>();
    }
    if (j[key].is_number_integer()) {
        const int64_t value = j[key].get<int64_t>();
        return value >= 0 ? static_cast<uint64_t>(value) : fallback;
    }
    if (j[key].is_string()) {
        return str::ParseUint(j[key].get<std::string>()).value_or(fallback);
    }
    return fallback;
}

bool BoolOr(const json& j, const char* key, bool fallback) {
    if (!j.is_object() || !j.contains(key) || !j[key].is_boolean()) {
        return fallback;
    }
    return j[key].get<bool>();
}

std::string StringOr(const json& j, const char* key, const std::string& fallback) {
    if (!j.is_object() || !j.contains(key) || !j[key].is_string()) {
        return fallback;
    }
    return j[key].get<std::string>();
}

uint64_t ParseOffsetValue(const json& j) {
    if (j.is_number_unsigned()) {
        return j.get<uint64_t>();
    }
    if (j.is_number_integer()) {
        return static_cast<uint64_t>(j.get<int64_t>());
    }
    if (j.is_string()) {
        auto value = str::ParseUint(j.get<std::string>());
        return value.value_or(0);
    }
    return 0;
}

FunctionSpec ReadFunction(const json& j, const FunctionSpec& def) {
    FunctionSpec out = def;
    if (!j.is_object()) {
        return out;
    }
    out.resolve = StringOr(j, "resolve", out.resolve);
    out.offset = UIntOr(j, "offset", out.offset);
    out.signature = StringOr(j, "signature", out.signature);
    out.vtable_index = IntOr(j, "vtable_index", out.vtable_index);
    out.name_arg = StringOr(j, "name_arg", out.name_arg);
    out.hook = BoolOr(j, "hook", out.hook);
    return out;
}

GlobalSpec ReadGlobal(const json& j, const GlobalSpec& def) {
    GlobalSpec out = def;
    if (!j.is_object()) {
        return out;
    }
    out.resolve = StringOr(j, "resolve", out.resolve);
    out.offset = UIntOr(j, "offset", out.offset);
    out.signature = StringOr(j, "signature", out.signature);
    out.decode = StringOr(j, "decode", out.decode);
    out.from = StringOr(j, "from", out.from);
    if (j.contains("chain") && j["chain"].is_array()) {
        out.chain.clear();
        for (const auto& item : j["chain"]) {
            if (item.is_number_unsigned()) {
                out.chain.push_back(item.get<uint64_t>());
            } else if (item.is_number_integer()) {
                const int64_t value = item.get<int64_t>();
                if (value >= 0) out.chain.push_back(static_cast<uint64_t>(value));
            } else if (item.is_string()) {
                if (auto value = str::ParseUint(item.get<std::string>())) {
                    out.chain.push_back(*value);
                }
            }
        }
    }
    return out;
}

void ApplyLayoutJson(ue::Layout& l, const json& j) {
    if (!j.is_object()) {
        return;
    }

#define FMCP_LAYOUT_INT(field, key) \
    if (j.contains(key) && j[key].is_number_integer()) l.field = j[key].get<int>()

    FMCP_LAYOUT_INT(object_vtable, "object_vtable");
    FMCP_LAYOUT_INT(object_flags, "object_flags");
    FMCP_LAYOUT_INT(object_internal_index, "object_internal_index");
    FMCP_LAYOUT_INT(object_class, "object_class");
    FMCP_LAYOUT_INT(object_name, "object_name");
    FMCP_LAYOUT_INT(object_outer, "object_outer");
    FMCP_LAYOUT_INT(fname_size, "fname_size");
    FMCP_LAYOUT_INT(ufield_next, "ufield_next");
    FMCP_LAYOUT_INT(ustruct_super, "ustruct_super");
    FMCP_LAYOUT_INT(ustruct_children, "ustruct_children");
    FMCP_LAYOUT_INT(ustruct_child_properties, "ustruct_child_properties");
    FMCP_LAYOUT_INT(ustruct_properties_size, "ustruct_properties_size");
    FMCP_LAYOUT_INT(ustruct_min_alignment, "ustruct_min_alignment");
    FMCP_LAYOUT_INT(uclass_class_cast_flags, "uclass_class_cast_flags");
    FMCP_LAYOUT_INT(uclass_class_default_object, "uclass_class_default_object");
    FMCP_LAYOUT_INT(ffield_class, "ffield_class");
    FMCP_LAYOUT_INT(ffield_owner, "ffield_owner");
    FMCP_LAYOUT_INT(ffield_next, "ffield_next");
    FMCP_LAYOUT_INT(ffield_name, "ffield_name");
    FMCP_LAYOUT_INT(ffieldclass_name, "ffieldclass_name");
    FMCP_LAYOUT_INT(fproperty_array_dim, "fproperty_array_dim");
    FMCP_LAYOUT_INT(fproperty_element_size, "fproperty_element_size");
    FMCP_LAYOUT_INT(fproperty_flags, "fproperty_flags");
    FMCP_LAYOUT_INT(fproperty_offset, "fproperty_offset");
    FMCP_LAYOUT_INT(ufunction_flags, "ufunction_flags");
    FMCP_LAYOUT_INT(ufunction_parms_size, "ufunction_parms_size");
    FMCP_LAYOUT_INT(ufunction_return_offset, "ufunction_return_offset");
    FMCP_LAYOUT_INT(ufunction_func, "ufunction_func");
    FMCP_LAYOUT_INT(bool_field_size, "bool_field_size");
    FMCP_LAYOUT_INT(bool_byte_offset, "bool_byte_offset");
    FMCP_LAYOUT_INT(bool_byte_mask, "bool_byte_mask");
    FMCP_LAYOUT_INT(bool_field_mask, "bool_field_mask");
    FMCP_LAYOUT_INT(property_payload, "property_payload");

#undef FMCP_LAYOUT_INT

    if (j.contains("fortnite_property_decoders") && j["fortnite_property_decoders"].is_boolean()) {
        l.fortnite_property_decoders = j["fortnite_property_decoders"].get<bool>();
    }
    if (j.contains("large_world_coords") && j["large_world_coords"].is_boolean()) {
        l.large_world_coords = j["large_world_coords"].get<bool>();
    }
    if (j.contains("children_is_array") && j["children_is_array"].is_boolean()) {
        l.children_is_array = j["children_is_array"].get<bool>();
    }
    if (j.contains("child_properties_is_array") && j["child_properties_is_array"].is_boolean()) {
        l.child_properties_is_array = j["child_properties_is_array"].get<bool>();
    }
}

json FunctionToJson(const FunctionSpec& f) {
    return json{{"resolve", f.resolve}, {"offset", f.offset}, {"signature", f.signature},
                {"vtable_index", f.vtable_index}, {"name_arg", f.name_arg}, {"hook", f.hook}};
}

json GlobalToJson(const GlobalSpec& g) {
    return json{{"resolve", g.resolve}, {"offset", g.offset}, {"signature", g.signature},
                {"decode", g.decode}, {"from", g.from}, {"chain", g.chain}};
}

json LayoutToJson(const ue::Layout& l) {
    return json{
        {"object_vtable", l.object_vtable}, {"object_flags", l.object_flags},
        {"object_internal_index", l.object_internal_index}, {"object_class", l.object_class},
        {"object_name", l.object_name}, {"object_outer", l.object_outer}, {"fname_size", l.fname_size},
        {"ufield_next", l.ufield_next}, {"ustruct_super", l.ustruct_super},
        {"ustruct_children", l.ustruct_children}, {"ustruct_child_properties", l.ustruct_child_properties},
        {"ustruct_properties_size", l.ustruct_properties_size}, {"ustruct_min_alignment", l.ustruct_min_alignment},
        {"uclass_class_cast_flags", l.uclass_class_cast_flags},
        {"uclass_class_default_object", l.uclass_class_default_object},
        {"ffield_class", l.ffield_class}, {"ffield_owner", l.ffield_owner}, {"ffield_next", l.ffield_next},
        {"ffield_name", l.ffield_name}, {"ffieldclass_name", l.ffieldclass_name},
        {"fproperty_array_dim", l.fproperty_array_dim}, {"fproperty_element_size", l.fproperty_element_size},
        {"fproperty_flags", l.fproperty_flags}, {"fproperty_offset", l.fproperty_offset},
        {"ufunction_flags", l.ufunction_flags}, {"ufunction_parms_size", l.ufunction_parms_size},
        {"ufunction_return_offset", l.ufunction_return_offset}, {"ufunction_func", l.ufunction_func},
        {"bool_field_size", l.bool_field_size}, {"bool_byte_offset", l.bool_byte_offset},
        {"bool_byte_mask", l.bool_byte_mask}, {"bool_field_mask", l.bool_field_mask},
        {"property_payload", l.property_payload},
        {"fortnite_property_decoders", l.fortnite_property_decoders},
        {"large_world_coords", l.large_world_coords},
        {"children_is_array", l.children_is_array},
        {"child_properties_is_array", l.child_properties_is_array}};
}

}

namespace {
Config* g_config = nullptr;
}

Config& Config::Get() {
    if (!g_config) {
        g_config = new Config();
    }
    return *g_config;
}

void Config::ResetDefaults() {
    server = ServerConfig{};
    log = LogConfig{};
    safety = SafetyConfig{};
    game_thread = GameThreadConfig{};
    ue = UeConfig{};
    ue.layout = ue::LayoutForProfile(ue.profile);
}

bool Config::Load() {
    ResetDefaults();

    wchar_t* env = nullptr;
    size_t envLen = 0;
    if (_wdupenv_s(&env, &envLen, L"FORTNITEMCP_CONFIG") == 0 && env && *env) {
        path = str::Narrow(env);
    }
    free(env);

    if (path.empty()) {
        directory = DefaultDirectory();
        path = directory + "\\config.json";
    } else {
        directory = fs::path(path).parent_path().string();
    }

    std::error_code ec;
    fs::create_directories(directory, ec);
    log_path = directory + "\\FortniteMCP.log";

    if (!fs::exists(path, ec)) {
        ResetDefaults();
        loaded = true;
        Save();
        log::Write(log::Level::Info, "Created default config at %s", path.c_str());
    }

    std::ifstream file(path);
    if (!file) {
        log::Write(log::Level::Error, "Cannot open config: %s", path.c_str());
        loaded = false;
        return false;
    }

    std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    ApplyJson(text);
    loaded = true;

    server.token_file = directory + "\\token.txt";
    server.token = server.auth_token;
    if (server.auth_token == "auto") {
        std::ifstream tokenFile(server.token_file);
        std::string token;
        if (tokenFile && std::getline(tokenFile, token)) {
            server.token = str::Trim(token);
        }
        if (server.token.empty() || server.token == "auto") {
            server.token = RandomHex(24);
            std::ofstream out(server.token_file, std::ios::trunc);
            if (out) {
                out << server.token;
            }
        }
    }

    if (!IsLoopbackHost(server.host) && server.token.empty()) {
        log::Write(log::Level::Warn, "Binding a non-loopback host without a token is unsafe; forcing 127.0.0.1");
        server.host = "127.0.0.1";
    }

    if (server.max_body_bytes < 1024) server.max_body_bytes = 1024;
    if (server.max_connections < 1 || server.max_connections > 256) server.max_connections = 32;
    if (game_thread.timeout_ms < 100) game_thread.timeout_ms = 100;
    if (game_thread.max_queued < 1) game_thread.max_queued = 1;

    return true;
}

void Config::ApplyJson(const std::string& text) {
    json j;
    try {
        j = json::parse(text, nullptr, true, true);
    } catch (const std::exception& e) {
        log::Write(log::Level::Error, "Config parse failed: %s", e.what());
        return;
    }

    if (j.contains("server") && j["server"].is_object()) {
        const auto& s = j["server"];
        server.host = StringOr(s, "host", server.host);
        const int port = IntOr(s, "port", server.port);
        if (port < 0 || port > 65535) {
            log::Write(log::Level::Warn, "Invalid server.port %d; using 26064", port);
        } else {
            server.port = static_cast<uint16_t>(port);
        }
        server.auth_token = StringOr(s, "auth_token", server.auth_token);
        server.max_body_bytes = static_cast<size_t>(UIntOr(s, "max_body_bytes", server.max_body_bytes));
        server.max_connections = IntOr(s, "max_connections", server.max_connections);
        server.idle_timeout_ms = IntOr(s, "idle_timeout_ms", server.idle_timeout_ms);
    }

    if (j.contains("log") && j["log"].is_object()) {
        log.level = StringOr(j["log"], "level", log.level);
        log.max_file_bytes = static_cast<size_t>(UIntOr(j["log"], "max_file_bytes", log.max_file_bytes));
        log.debug_output = BoolOr(j["log"], "debug_output", log.debug_output);
    }

    if (j.contains("safety") && j["safety"].is_object()) {
        const auto& s = j["safety"];
        safety.max_transfer_bytes = static_cast<size_t>(UIntOr(s, "max_transfer_bytes", safety.max_transfer_bytes));
        safety.max_read_bytes = static_cast<size_t>(UIntOr(s, "max_read_bytes", safety.max_read_bytes));
        safety.max_scan_results = static_cast<size_t>(UIntOr(s, "max_scan_results", safety.max_scan_results));
        safety.max_scan_bytes = UIntOr(s, "max_scan_bytes", safety.max_scan_bytes);
        safety.max_patches = IntOr(s, "max_patches", safety.max_patches);
        safety.undo_patches = BoolOr(s, "undo_patches", safety.undo_patches);
        safety.allow_raw_calls = BoolOr(s, "allow_raw_calls", safety.allow_raw_calls);
        safety.allow_any_free = BoolOr(s, "allow_any_free", safety.allow_any_free);
        safety.allow_self_unload = BoolOr(s, "allow_self_unload", safety.allow_self_unload);
        safety.allow_exec_alloc = BoolOr(s, "allow_exec_alloc", safety.allow_exec_alloc);
        safety.require_confirm = BoolOr(s, "require_confirm", safety.require_confirm);
    }

    if (j.contains("game_thread") && j["game_thread"].is_object()) {
        const auto& g = j["game_thread"];
        game_thread.enabled = BoolOr(g, "enabled", game_thread.enabled);
        game_thread.timeout_ms = IntOr(g, "timeout_ms", game_thread.timeout_ms);
        game_thread.max_queued = IntOr(g, "max_queued", game_thread.max_queued);
        game_thread.jobs_per_pump = IntOr(g, "jobs_per_pump", game_thread.jobs_per_pump);
        game_thread.pump_budget_us = IntOr(g, "pump_budget_us", game_thread.pump_budget_us);
        game_thread.direct_fallback = BoolOr(g, "direct_fallback", game_thread.direct_fallback);
    }

    if (j.contains("ue") && j["ue"].is_object()) {
        const auto& u = j["ue"];
        ue.profile = StringOr(u, "profile", ue.profile);
        ue.auto_tune = BoolOr(u, "auto_tune", ue.auto_tune);
        ue.layout = ue::LayoutForProfile(ue.profile);

        if (u.contains("static_find_object")) ue.static_find_object = ReadFunction(u["static_find_object"], ue.static_find_object);
        if (u.contains("get_objects_of_class")) ue.get_objects_of_class = ReadFunction(u["get_objects_of_class"], ue.get_objects_of_class);
        if (u.contains("process_event")) ue.process_event = ReadFunction(u["process_event"], ue.process_event);

        if (u.contains("names") && u["names"].is_object()) {
            const auto& n = u["names"];
            ue.names.style = StringOr(n, "style", ue.names.style);
            ue.names.resolve = StringOr(n, "resolve", ue.names.resolve);
            ue.names.offset = UIntOr(n, "offset", ue.names.offset);
            ue.names.signature = StringOr(n, "signature", ue.names.signature);
            ue.names.fname_size = IntOr(n, "fname_size", ue.names.fname_size);
            ue.names.block_table_offset = IntOr(n, "block_table_offset", ue.names.block_table_offset);
            ue.names.block_bits = IntOr(n, "block_bits", ue.names.block_bits);
            ue.names.stride = IntOr(n, "stride", ue.names.stride);
            ue.names.codec = StringOr(n, "codec", ue.names.codec);
            ue.names.abi = StringOr(n, "abi", ue.names.abi);
            ue.names.max_chars = IntOr(n, "max_chars", ue.names.max_chars);
            ue.names.game_thread = BoolOr(n, "game_thread", ue.names.game_thread);
            ue.names.validate = BoolOr(n, "validate", ue.names.validate);
            ue.names.pool_offset = UIntOr(n, "pool_offset", ue.names.pool_offset);
            ue.names.decrypt = StringOr(n, "decrypt", ue.names.decrypt);
            ue.names.decrypt_key = UIntOr(n, "decrypt_key", ue.names.decrypt_key);
        }

        if (u.contains("objects") && u["objects"].is_object()) {
            const auto& o = u["objects"];
            ue.objects.style = StringOr(o, "style", ue.objects.style);
            ue.objects.resolve = StringOr(o, "resolve", ue.objects.resolve);
            ue.objects.offset = UIntOr(o, "offset", ue.objects.offset);
            ue.objects.signature = StringOr(o, "signature", ue.objects.signature);
            ue.objects.objects_offset = UIntOr(o, "objects_offset", ue.objects.objects_offset);
            ue.objects.item_size = IntOr(o, "item_size", ue.objects.item_size);
            ue.objects.chunk_bits = IntOr(o, "chunk_bits", ue.objects.chunk_bits);
            ue.objects.item_object_offset = IntOr(o, "item_object_offset", ue.objects.item_object_offset);
            ue.objects.max_objects = IntOr(o, "max_objects", ue.objects.max_objects);
            ue.objects.empty_chunk_stop = IntOr(o, "empty_chunk_stop", ue.objects.empty_chunk_stop);
        }

        if (u.contains("gworld")) ue.gworld = ReadGlobal(u["gworld"], ue.gworld);
        if (u.contains("gengine")) ue.gengine = ReadGlobal(u["gengine"], ue.gengine);

        if (u.contains("extra_globals") && u["extra_globals"].is_object()) {
            for (auto it = u["extra_globals"].begin(); it != u["extra_globals"].end(); ++it) {
                ue.extra_globals[it.key()] = ReadGlobal(it.value(), GlobalSpec{});
            }
        }

        if (u.contains("layout")) {
            ApplyLayoutJson(ue.layout, u["layout"]);
        }

        if (ue.names.fname_size != 4 && ue.names.fname_size != 8) {
            ue.names.fname_size = ue.layout.fname_size;
        }
        ue.layout.fname_size = ue.names.fname_size;
    }

    if (ue.layout.fname_size != 4 && ue.layout.fname_size != 8) {
        ue.layout.fname_size = 8;
    }
}

std::string Config::Serialize() const {
    json j;
    j["server"] = {{"host", server.host},
                   {"port", server.port},
                   {"auth_token", server.auth_token == "auto" ? "auto" : server.auth_token},
                   {"max_body_bytes", server.max_body_bytes},
                   {"max_connections", server.max_connections},
                   {"idle_timeout_ms", server.idle_timeout_ms}};
    j["log"] = {{"level", log.level}, {"max_file_bytes", log.max_file_bytes}, {"debug_output", log.debug_output}};
    j["safety"] = {{"max_transfer_bytes", safety.max_transfer_bytes},
                   {"max_read_bytes", safety.max_read_bytes},
                   {"max_scan_results", safety.max_scan_results},
                   {"max_scan_bytes", safety.max_scan_bytes},
                   {"max_patches", safety.max_patches},
                   {"undo_patches", safety.undo_patches},
                   {"allow_raw_calls", safety.allow_raw_calls},
                   {"allow_any_free", safety.allow_any_free},
                   {"allow_self_unload", safety.allow_self_unload},
                   {"allow_exec_alloc", safety.allow_exec_alloc},
                   {"require_confirm", safety.require_confirm}};
    j["game_thread"] = {{"enabled", game_thread.enabled},
                        {"timeout_ms", game_thread.timeout_ms},
                        {"max_queued", game_thread.max_queued},
                        {"jobs_per_pump", game_thread.jobs_per_pump},
                        {"pump_budget_us", game_thread.pump_budget_us},
                        {"direct_fallback", game_thread.direct_fallback}};

    json extra = json::object();
    for (const auto& [name, spec] : ue.extra_globals) {
        extra[name] = GlobalToJson(spec);
    }

    j["ue"] = {{"profile", ue.profile},
               {"auto_tune", ue.auto_tune},
               {"static_find_object", FunctionToJson(ue.static_find_object)},
               {"get_objects_of_class", FunctionToJson(ue.get_objects_of_class)},
               {"process_event", FunctionToJson(ue.process_event)},
               {"names", {{"style", ue.names.style},
                          {"resolve", ue.names.resolve},
                          {"offset", ue.names.offset},
                          {"signature", ue.names.signature},
                          {"fname_size", ue.names.fname_size},
                          {"block_table_offset", ue.names.block_table_offset},
                          {"block_bits", ue.names.block_bits},
                          {"stride", ue.names.stride},
                          {"codec", ue.names.codec},
                          {"abi", ue.names.abi},
                          {"max_chars", ue.names.max_chars},
                          {"game_thread", ue.names.game_thread},
                          {"validate", ue.names.validate},
                          {"pool_offset", ue.names.pool_offset},
                          {"decrypt", ue.names.decrypt},
                          {"decrypt_key", ue.names.decrypt_key}}},
               {"objects", {{"style", ue.objects.style},
                            {"resolve", ue.objects.resolve},
                            {"offset", ue.objects.offset},
                            {"signature", ue.objects.signature},
                            {"objects_offset", ue.objects.objects_offset},
                            {"item_size", ue.objects.item_size},
                            {"chunk_bits", ue.objects.chunk_bits},
                            {"item_object_offset", ue.objects.item_object_offset},
                            {"max_objects", ue.objects.max_objects},
                            {"empty_chunk_stop", ue.objects.empty_chunk_stop}}},
               {"gworld", GlobalToJson(ue.gworld)},
               {"gengine", GlobalToJson(ue.gengine)},
               {"extra_globals", extra},
               {"layout", LayoutToJson(ue.layout)}};

    return j.dump(2);
}

void Config::ApplyRuntimeJson(const nlohmann::json& root) {
    if (!root.is_object()) {
        return;
    }

    if (root.contains("game_thread") && root["game_thread"].is_object()) {
        const auto& g = root["game_thread"];
        game_thread.enabled = BoolOr(g, "enabled", game_thread.enabled);
        game_thread.timeout_ms = IntOr(g, "timeout_ms", game_thread.timeout_ms);
        game_thread.max_queued = IntOr(g, "max_queued", game_thread.max_queued);
        game_thread.jobs_per_pump = IntOr(g, "jobs_per_pump", game_thread.jobs_per_pump);
        game_thread.pump_budget_us = IntOr(g, "pump_budget_us", game_thread.pump_budget_us);
        game_thread.direct_fallback = BoolOr(g, "direct_fallback", game_thread.direct_fallback);
    }

    if (root.contains("safety") && root["safety"].is_object()) {
        const auto& s = root["safety"];
        safety.allow_raw_calls = BoolOr(s, "allow_raw_calls", safety.allow_raw_calls);
        safety.allow_any_free = BoolOr(s, "allow_any_free", safety.allow_any_free);
        safety.allow_self_unload = BoolOr(s, "allow_self_unload", safety.allow_self_unload);
        safety.allow_exec_alloc = BoolOr(s, "allow_exec_alloc", safety.allow_exec_alloc);
        safety.require_confirm = BoolOr(s, "require_confirm", safety.require_confirm);
        safety.max_read_bytes = static_cast<size_t>(UIntOr(s, "max_read_bytes", safety.max_read_bytes));
        safety.max_transfer_bytes = static_cast<size_t>(UIntOr(s, "max_transfer_bytes", safety.max_transfer_bytes));
    }

    if (!root.contains("ue") || !root["ue"].is_object()) {
        return;
    }

    const auto& u = root["ue"];
    const bool profileChanged = u.contains("profile") && u["profile"].is_string();
    if (profileChanged) {
        ue.profile = u["profile"].get<std::string>();
        ue.layout = ue::LayoutForProfile(ue.profile);
    }
    ue.auto_tune = BoolOr(u, "auto_tune", ue.auto_tune);

    if (u.contains("static_find_object")) ue.static_find_object = ReadFunction(u["static_find_object"], ue.static_find_object);
    if (u.contains("get_objects_of_class")) ue.get_objects_of_class = ReadFunction(u["get_objects_of_class"], ue.get_objects_of_class);
    if (u.contains("process_event")) ue.process_event = ReadFunction(u["process_event"], ue.process_event);

    if (u.contains("names") && u["names"].is_object()) {
        const auto& n = u["names"];
        ue.names.style = StringOr(n, "style", ue.names.style);
        ue.names.resolve = StringOr(n, "resolve", ue.names.resolve);
        ue.names.offset = UIntOr(n, "offset", ue.names.offset);
        ue.names.signature = StringOr(n, "signature", ue.names.signature);
        ue.names.fname_size = IntOr(n, "fname_size", ue.names.fname_size);
        ue.names.block_table_offset = IntOr(n, "block_table_offset", ue.names.block_table_offset);
        ue.names.block_bits = IntOr(n, "block_bits", ue.names.block_bits);
        ue.names.stride = IntOr(n, "stride", ue.names.stride);
        ue.names.codec = StringOr(n, "codec", ue.names.codec);
        ue.names.abi = StringOr(n, "abi", ue.names.abi);
        ue.names.max_chars = IntOr(n, "max_chars", ue.names.max_chars);
        ue.names.game_thread = BoolOr(n, "game_thread", ue.names.game_thread);
        ue.names.validate = BoolOr(n, "validate", ue.names.validate);
        ue.names.pool_offset = UIntOr(n, "pool_offset", ue.names.pool_offset);
        ue.names.decrypt = StringOr(n, "decrypt", ue.names.decrypt);
        ue.names.decrypt_key = UIntOr(n, "decrypt_key", ue.names.decrypt_key);
    }

    if (u.contains("objects") && u["objects"].is_object()) {
        const auto& o = u["objects"];
        ue.objects.style = StringOr(o, "style", ue.objects.style);
        ue.objects.resolve = StringOr(o, "resolve", ue.objects.resolve);
        ue.objects.offset = UIntOr(o, "offset", ue.objects.offset);
        ue.objects.signature = StringOr(o, "signature", ue.objects.signature);
        ue.objects.objects_offset = UIntOr(o, "objects_offset", ue.objects.objects_offset);
        ue.objects.item_size = IntOr(o, "item_size", ue.objects.item_size);
        ue.objects.chunk_bits = IntOr(o, "chunk_bits", ue.objects.chunk_bits);
        ue.objects.item_object_offset = IntOr(o, "item_object_offset", ue.objects.item_object_offset);
        ue.objects.max_objects = IntOr(o, "max_objects", ue.objects.max_objects);
        ue.objects.empty_chunk_stop = IntOr(o, "empty_chunk_stop", ue.objects.empty_chunk_stop);
    }

    if (u.contains("gworld")) ue.gworld = ReadGlobal(u["gworld"], ue.gworld);
    if (u.contains("gengine")) ue.gengine = ReadGlobal(u["gengine"], ue.gengine);

    if (u.contains("extra_globals") && u["extra_globals"].is_object()) {
        for (auto it = u["extra_globals"].begin(); it != u["extra_globals"].end(); ++it) {
            ue.extra_globals[it.key()] = ReadGlobal(it.value(), ue.extra_globals[it.key()]);
        }
    }

    if (u.contains("layout")) {
        ApplyLayoutJson(ue.layout, u["layout"]);
    }

    if (ue.names.fname_size != 4 && ue.names.fname_size != 8) {
        ue.names.fname_size = ue.layout.fname_size;
    }
    ue.layout.fname_size = ue.names.fname_size;
}

bool Config::Save() {
    try {
        fs::create_directories(directory);
        const std::string temp = path + ".tmp";
        {
            std::ofstream out(temp, std::ios::trunc);
            if (!out) {
                return false;
            }
            out << Serialize();
        }
        std::error_code ec;
        fs::rename(temp, path, ec);
        if (ec) {
            fs::remove(path, ec);
            fs::rename(temp, path, ec);
        }
        return !ec;
    } catch (...) {
        return false;
    }
}

}

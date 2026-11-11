#include "ue/context.h"

#include "core/log.h"
#include "core/memory.h"
#include "core/modules.h"
#include "core/scanner.h"
#include "core/strings.h"

#include <algorithm>
#include <set>
#include <unordered_set>

namespace fmcp::ue {

namespace {

std::atomic<bool> g_nameAllocWarned{false};
std::atomic<int> g_nameFaultLogged{0};
std::atomic<int> g_nameRejectedLogged{0};
std::atomic<int> g_nameKismetLogged{0};

struct NameCallState {
    struct FNameValue {
        uint32_t index = 0;
        uint32_t number = 0;
    } fname;
    struct FStringLayout {
        wchar_t* data = nullptr;
        int32_t num = 0;
        int32_t max = 0;
    } out;
    std::wstring buffer;
    bool ok = false;
};

uint32_t ByteSwap32(uint32_t value) {
    return ((value & 0x000000FFu) << 24) | ((value & 0x0000FF00u) << 8) |
           ((value & 0x00FF0000u) >> 8) | ((value & 0xFF000000u) >> 24);
}

uint32_t DecryptNameIndex(uint32_t raw, uint32_t key) {
    if (raw == 0) {
        return 0;
    }
    const uint32_t decrypted = ByteSwap32((raw - 1) ^ key) + 1;
    return decrypted ? decrypted : 0x47E8E291u;
}

uint32_t RotateLeft32(uint32_t value, int count) {
    return (value << count) | (value >> (32 - count));
}

uint32_t SeedNameKey(uint32_t length) {
    const uint32_t mixed = length * 0x2310u + 0x670073u;
    return ((mixed >> 23) ^ (length << 16)) ^ mixed;
}

uint32_t NextNameKey(uint32_t value) {
    const uint32_t mixed = value * 0x2310u + 0x670073u;
    return ((mixed >> 23) ^ RotateLeft32(value, 16)) ^ mixed;
}

std::string DecryptNameEntry(uintptr_t entry, uint16_t header, int32_t length) {
    if (length <= 0 || length > 1024) {
        return {};
    }

    const bool wide = (header & 1) != 0;
    const size_t bytes = static_cast<size_t>(length) * (wide ? 2u : 1u);
    std::vector<uint8_t> encrypted(bytes);
    if (!mem::Read(entry + 2, encrypted.data(), bytes)) {
        return {};
    }

    std::vector<uint8_t> plain(bytes);
    uint32_t key = SeedNameKey(static_cast<uint32_t>(length));
    for (size_t i = 0; i < bytes; i += 2) {
        plain[i] = encrypted[i] ^ static_cast<uint8_t>(key) ^ 0xB1;
        key = NextNameKey(key);
    }
    for (size_t i = 1; i < bytes; i += 2) {
        plain[i] = encrypted[i] ^ static_cast<uint8_t>(key) ^ 0xB1;
        key = NextNameKey(key);
    }

    if (wide) {
        std::wstring text;
        text.reserve(static_cast<size_t>(length));
        for (int32_t i = 0; i < length; ++i) {
            const wchar_t ch = static_cast<wchar_t>(
                plain[static_cast<size_t>(i) * 2] |
                (plain[static_cast<size_t>(i) * 2 + 1] << 8));
            if (ch == 0) {
                break;
            }
            text.push_back(ch);
        }
        return str::Narrow(text);
    }

    std::string text;
    text.reserve(static_cast<size_t>(length));
    for (int32_t i = 0; i < length; ++i) {
        const char ch = static_cast<char>(plain[static_cast<size_t>(i)]);
        if (ch == 0) {
            break;
        }
        text.push_back(ch);
    }
    return text;
}

#if defined(_MSC_VER)
__declspec(noinline)
#endif
bool InvokeFNameFunction(uintptr_t function, bool valueAbi, void* fname, void* out) {
    __try {
        using Fn = void (*)(void*, void*);
        auto fn = reinterpret_cast<Fn>(function);
        if (valueAbi) {
            fn(out, fname);
        } else {
            fn(fname, out);
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

#if defined(_MSC_VER)
__declspec(noinline)
#endif
uintptr_t InvokeStaticFindObject(uintptr_t function, uintptr_t classObject, uintptr_t outer,
                                 const void* name, bool exactClass, bool viewAbi,
                                 bool* faulted) {
    *faulted = false;
    __try {
        if (viewAbi) {
            using Fn = uintptr_t (*)(uintptr_t, uintptr_t, const std::wstring_view*, bool);
            return reinterpret_cast<Fn>(function)(classObject, outer,
                                                  static_cast<const std::wstring_view*>(name),
                                                  exactClass);
        }
        using Fn = uintptr_t (*)(uintptr_t, uintptr_t, const wchar_t*, bool);
        return reinterpret_cast<Fn>(function)(classObject, outer,
                                              static_cast<const wchar_t*>(name), exactClass);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *faulted = true;
        return 0;
    }
}

uintptr_t ResolveAddressSpec(uintptr_t moduleBase, size_t moduleSize, const std::string& resolve,
                             uint64_t offset, const std::string& signature, const char* label,
                             bool requireExecutable, std::string* error) {
    if (resolve.empty() || resolve == "off" || resolve == "none") {
        return 0;
    }

    if (resolve == "offset" || resolve == "rva") {
        if (offset == 0) {
            if (error) *error = str::Format("%s offset is zero", label);
            return 0;
        }
        if (offset >= moduleSize) {
            if (error) *error = str::Format("%s offset 0x%llX is outside the module", label,
                                            static_cast<unsigned long long>(offset));
            return 0;
        }
        const uintptr_t target = moduleBase + static_cast<uintptr_t>(offset);
        if (requireExecutable && !modules::IsExecutableAddress(target, 1)) {
            if (error) *error = str::Format("%s target is not executable", label);
            return 0;
        }
        if (requireExecutable && !signature.empty()) {
            std::string parseError;
            auto expected = scan::ParsePattern(signature, &parseError);
            if (!expected) {
                if (error) *error = str::Format("%s signature parse failed: %s", label, parseError.c_str());
                return 0;
            }
            if (expected->size() > 4096) {
                if (error) *error = str::Format("%s signature is too large", label);
                return 0;
            }
            std::vector<uint8_t> actual(expected->size());
            if (!mem::Read(target, actual.data(), actual.size())) {
                if (error) *error = str::Format("%s target is unreadable for signature verification", label);
                return 0;
            }
            for (size_t i = 0; i < expected->size(); ++i) {
                if ((actual[i] & (*expected)[i].mask) != ((*expected)[i].value & (*expected)[i].mask)) {
                    if (error) *error = str::Format("%s signature mismatch at 0x%llX (offset 0x%llX)",
                                                    label,
                                                    static_cast<unsigned long long>(target + i),
                                                    static_cast<unsigned long long>(offset + i));
                    return 0;
                }
            }
        }
        return target;
    }

    if (resolve == "signature" || resolve == "pattern") {
        if (signature.empty()) {
            if (error) *error = str::Format("%s signature is empty", label);
            return 0;
        }
        std::string parseError;
        auto pattern = scan::ParsePattern(signature, &parseError);
        if (!pattern) {
            if (error) *error = str::Format("%s signature parse failed: %s", label, parseError.c_str());
            return 0;
        }
        scan::Request request;
        request.start = moduleBase;
        request.end = moduleBase + moduleSize;
        request.pattern = std::move(*pattern);
        request.maxResults = 8;
        request.maxBytes = moduleSize;
        auto result = scan::Search(request);
        if (!result.error.empty()) {
            if (error) *error = str::Format("%s scan failed: %s", label, result.error.c_str());
            return 0;
        }
        for (uintptr_t match : result.matches) {
            if (!requireExecutable || modules::IsExecutableAddress(match, 1)) {
                return match;
            }
        }
        if (error) *error = str::Format("%s signature did not match", label);
        return 0;
    }

    if (error) *error = str::Format("%s has unsupported resolve mode '%s'", label, resolve.c_str());
    return 0;
}

#if defined(_MSC_VER)
__declspec(noinline)
#endif
bool InvokeProcessEventThunk(uintptr_t function, uintptr_t object, uintptr_t ufunction, void* params,
                             uint64_t* result) {
    __try {
        using Fn = uint64_t (*)(uintptr_t, uintptr_t, void*);
        *result = reinterpret_cast<Fn>(function)(object, ufunction, params);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool IsSaneOffset(int value, int limit = 0x2000) {
    return value >= 0 && value < limit;
}

bool LooksLikeUFunction(const FunctionInfo& info) {
    return info.class_name.find("Function") != std::string::npos;
}

}

namespace {
UeContext* g_context = nullptr;
}

UeContext& UeContext::Get() {
    if (!g_context) {
        g_context = new UeContext();
    }
    return *g_context;
}

void UeContext::Invalidate() {
    resolved_once_ = false;
    report_ = ResolveReport{};
    {
        std::lock_guard lock(name_mutex_);
        name_cache_.clear();
        name_faults_.clear();
    }
}

void UeContext::Shutdown() {
    GameThread::Get().RemoveHook();
    GameThread::Get().Shutdown();
}

uintptr_t UeContext::ResolveSpec(const FunctionSpec& spec, const char* label, bool requireExecutable,
                                 std::string* error) {
    return ResolveAddressSpec(module_base_, module_size_, spec.resolve, spec.offset, spec.signature,
                              label, requireExecutable, error);
}

bool UeContext::Resolve(bool force) {
    if (resolved_once_ && !force) {
        return true;
    }

    if (force) {
        auto& gameThread = GameThread::Get();
        if (!gameThread.RemoveHook() || !gameThread.WaitIdle(2000)) {
            report_.warnings.emplace_back(
                "a game-thread call did not finish; UE re-resolution was aborted to avoid a race");
            resolved_once_ = false;
            return false;
        }
    }

    Invalidate();
    const Config& config = Config::Get();

    const auto* main = modules::Main();
    if (!main) {
        report_.warnings.emplace_back("main module is unavailable");
        return false;
    }

    module_base_ = main->base;
    module_size_ = main->size;
    layout_ = config.ue.layout;
    if (layout_.fname_size != 4 && layout_.fname_size != 8) {
        layout_.fname_size = config.ue.names.fname_size == 4 ? 4 : 8;
    }

    report_.messages.emplace_back(str::Format("main module %s base=%s size=0x%llX",
                                              main->name.c_str(),
                                              mem::FormatAddress(module_base_).c_str(),
                                              static_cast<unsigned long long>(module_size_)));
    FMCP_LOGI("Resolving UE pointers");

    std::string error;
    static_find_object_ = ResolveSpec(config.ue.static_find_object, "static_find_object", true, &error);
    if (static_find_object_) {
        report_.static_find_object = true;
    } else if (!error.empty() && config.ue.static_find_object.resolve != "off") {
        report_.warnings.emplace_back(error);
    }

    error.clear();
    get_objects_of_class_ = ResolveSpec(config.ue.get_objects_of_class, "get_objects_of_class", true, &error);
    if (get_objects_of_class_) {
        report_.get_objects_of_class = true;
    } else if (!error.empty() && config.ue.get_objects_of_class.resolve != "off") {
        report_.warnings.emplace_back(error);
    }

    error.clear();
    process_event_ = ResolveSpec(config.ue.process_event, "process_event", true, &error);
    if (process_event_) {
        report_.process_event = true;
        GameThread::Get().SetDirectTarget(process_event_);
    } else if (!error.empty() && config.ue.process_event.resolve != "off") {
        report_.warnings.emplace_back(error);
    }

    ResolveNames(&error);
    if (!error.empty()) {
        report_.warnings.emplace_back(error);
    }
    error.clear();

    ResolveObjects(&error);
    if (!error.empty()) {
        report_.warnings.emplace_back(error);
    }
    error.clear();

    RefreshMetaClasses();

    gworld_slot_ = 0;
    gengine_slot_ = 0;
    {
        std::string globalError;
        const uintptr_t world = ReadNamedGlobal("gworld", &globalError).value_or(0);
        report_.gworld = world != 0;
        if (!world && !globalError.empty() && config.ue.gworld.resolve != "off") {
            report_.warnings.emplace_back(globalError);
        }
        globalError.clear();
        const uintptr_t engine = ReadNamedGlobal("gengine", &globalError).value_or(0);
        report_.gengine = engine != 0;
        if (!engine && !globalError.empty() && config.ue.gengine.resolve != "off") {
            report_.warnings.emplace_back(globalError);
        }
        FMCP_LOGI("Globals: gengine slot=%s value=%s; gworld slot=%s value=%s",
                  mem::FormatAddress(gengine_slot_).c_str(), mem::FormatAddress(engine).c_str(),
                  mem::FormatAddress(gworld_slot_).c_str(), mem::FormatAddress(world).c_str());
    }

    const std::string nameStyle = str::ToLower(config.ue.names.style);
    const bool opaqueNames = nameStyle == "function" || nameStyle == "fname_function" ||
                             nameStyle == "fn" || nameStyle == "kismet" ||
                             nameStyle == "static_name" || nameStyle == "kismet_static" ||
                             nameStyle == "gnames" || nameStyle == "gnames_direct" ||
                             nameStyle == "direct";
    if (config.ue.auto_tune && static_find_object_ && report_.names && !opaqueNames) {
        std::string tuneError;
        if (AutoTuneLayout(&tuneError)) {
            report_.messages.emplace_back("reflection layout auto-tuned");
        } else if (!tuneError.empty()) {
            FMCP_LOGD("AutoTune: %s", tuneError.c_str());
        }
    } else if (config.ue.auto_tune && opaqueNames) {
        report_.warnings.emplace_back(
            "layout auto-tune skipped for opaque FName IDs; set layout offsets from your dumper");
    }

    const bool coreLayout = layout_.object_class > 0 && IsSaneOffset(layout_.object_class) &&
                            layout_.object_name > 0 && IsSaneOffset(layout_.object_name) &&
                            layout_.object_outer > 0 && IsSaneOffset(layout_.object_outer) &&
                            layout_.fname_size >= 4 && layout_.fname_size <= 8 &&
                            layout_.ufield_next > 0 && IsSaneOffset(layout_.ufield_next);
    report_.layout = coreLayout;
    report_.properties = coreLayout && report_.names && layout_.HasPropertyChain();
    report_.functions = coreLayout && report_.names && layout_.ustruct_children > 0 &&
                        layout_.ufield_next > 0;

    if (!report_.names) {
        report_.warnings.emplace_back("name backend is off/unresolved; names show as Name_<index>");
    }
    if (!report_.properties) {
        report_.warnings.emplace_back(
            "property reflection is not configured; raw process_event/call_address still work");
    }

    {
        auto& gameThread = GameThread::Get();
        gameThread.Configure(config.game_thread.timeout_ms, config.game_thread.max_queued,
                             config.game_thread.jobs_per_pump, config.game_thread.pump_budget_us);
        if (!config.game_thread.enabled || !config.ue.process_event.hook) {
            gameThread.RemoveHook();
        } else if (process_event_) {
            std::string hookError;
            if (gameThread.Install(process_event_, config.game_thread.timeout_ms,
                                   config.game_thread.max_queued, config.game_thread.jobs_per_pump,
                                   config.game_thread.pump_budget_us, &hookError)) {
                report_.game_thread = true;
            } else {
                report_.warnings.emplace_back("ProcessEvent hook failed: " + hookError);
            }
        } else {
            report_.warnings.emplace_back(
                "game-thread hook unavailable; set ue.process_event or enable direct_fallback");
        }
    }

    resolved_once_ = true;
    report_.resolved = true;

    for (const auto& warning : report_.warnings) {
        FMCP_LOGW("UE: %s", warning.c_str());
    }
    for (const auto& message : report_.messages) {
        FMCP_LOGI("UE: %s", message.c_str());
    }

    return true;
}

bool UeContext::ResolveNames(std::string* error) {
    const Config& config = Config::Get();
    names_base_ = 0;
    names_table_ = 0;
    names_function_ = 0;
    kismet_cdo_ = 0;
    kismet_function_ = 0;
    gnames_direct_ = false;

    const std::string style = str::ToLower(config.ue.names.style);
    if (style == "off") {
        return false;
    }

    layout_.fname_size = config.ue.names.fname_size == 4 ? 4 : 8;

    if (style == "gnames" || style == "gnames_direct" || style == "direct") {
        if (config.ue.names.pool_offset == 0) {
            if (error) *error = "gnames backend requires names.pool_offset";
            return false;
        }
        const uintptr_t gnames = module_base_ + static_cast<uintptr_t>(config.ue.names.pool_offset);
        const uint32_t blockCount = mem::ReadOr<uint32_t>(gnames, 0) + 1;
        if (blockCount <= 1) {
            if (error) *error = "GNames block count is unreadable or empty";
            return false;
        }
        gnames_direct_ = true;

        {
            std::lock_guard lock(name_mutex_);
            name_cache_.clear();
            name_faults_.clear();
        }

        int decoded = 0;
        std::string sample;
        for (uint32_t index = 1; index <= 32 && decoded < 4; ++index) {
            const std::string name = ParseGNamesEntry(index);
            if (!name.empty() && name.rfind("Name_", 0) != 0) {
                ++decoded;
                if (!sample.empty()) sample += ", ";
                sample += str::Format("%u=%s", index, name.c_str());
            }
        }

        report_.names = true;
        report_.messages.emplace_back(str::Format(
            "names style=gnames pool=%s blocks=%u sample=[%s]",
            mem::FormatAddress(gnames).c_str(), blockCount, sample.c_str()));
        FMCP_LOGI("GNames at %s blocks=%u sample=[%s]", mem::FormatAddress(gnames).c_str(),
                  blockCount, sample.c_str());
        return true;
    }

    if (style == "kismet" || style == "static_name" || style == "kismet_static") {
        auto findFirst = [&](std::initializer_list<const char*> paths) -> uintptr_t {
            for (const char* path : paths) {
                const uintptr_t object = FindObjectPath(path);
                if (object) {
                    return object;
                }
            }
            return 0;
        };

        kismet_cdo_ = findFirst({"Engine.Default__KismetStringLibrary",
                                 "Default__KismetStringLibrary"});
        kismet_function_ = findFirst({"/Script/Engine.KismetStringLibrary.Conv_NameToString",
                                      "KismetStringLibrary.Conv_NameToString",
                                      "Engine.KismetStringLibrary.Conv_NameToString"});
        if (!kismet_cdo_ || !kismet_function_) {
            if (error) {
                *error = str::Format("kismet names unresolved (cdo=%s function=%s)",
                                     mem::FormatAddress(kismet_cdo_).c_str(),
                                     mem::FormatAddress(kismet_function_).c_str());
            }
            kismet_cdo_ = 0;
            kismet_function_ = 0;
            return false;
        }

        {
            std::lock_guard lock(name_mutex_);
            name_cache_.clear();
            name_faults_.clear();
        }

        FMCP_LOGI("Kismet names: cdo=%s Conv_NameToString=%s",
                  mem::FormatAddress(kismet_cdo_).c_str(),
                  mem::FormatAddress(kismet_function_).c_str());
        report_.names = true;
        report_.messages.emplace_back(str::Format(
            "names style=kismet cdo=%s function=%s",
            mem::FormatAddress(kismet_cdo_).c_str(),
            mem::FormatAddress(kismet_function_).c_str()));
        return true;
    }

    if (config.ue.names.resolve == "off") {
        return false;
    }

    if (style == "function" || style == "fname_function" || style == "fn") {
        names_function_ = ResolveAddressSpec(module_base_, module_size_, config.ue.names.resolve,
                                             config.ue.names.offset, config.ue.names.signature,
                                             "names.function", true, error);
        if (!names_function_) {
            return false;
        }
        const std::string abi = str::ToLower(config.ue.names.abi);
        if (abi != "fstring_ref" && abi != "ref" && abi != "fstring_value" && abi != "value") {
            if (error) *error = "unsupported names.abi: " + config.ue.names.abi;
            names_function_ = 0;
            return false;
        }

        {
            std::lock_guard lock(name_mutex_);
            name_cache_.clear();
            name_faults_.clear();
        }

        FMCP_LOGI("FNameToString resolved at %s (abi=%s); FName IDs are opaque and will be "
                  "validated on the first real object lookup",
                  mem::FormatAddress(names_function_).c_str(), config.ue.names.abi.c_str());
        report_.names = true;
        report_.messages.emplace_back(str::Format(
            "names function=%s abi=%s (opaque IDs; no synthetic validation)",
            mem::FormatAddress(names_function_).c_str(), config.ue.names.abi.c_str()));
        return true;
    }

    names_base_ = ResolveAddressSpec(module_base_, module_size_, config.ue.names.resolve,
                                     config.ue.names.offset, config.ue.names.signature, "names",
                                     false, error);
    if (!names_base_) {
        return false;
    }

    const std::string& codec = config.ue.names.codec;
    if (!codec.empty() && codec != "plain" && codec != "none") {
        if (error) *error = "unsupported names.codec: " + codec;
        return false;
    }

    if (style == "pool") {
        names_table_ = names_base_ + static_cast<uintptr_t>(config.ue.names.block_table_offset);
    } else if (style == "pool_blocks") {
        names_table_ = names_base_;
    } else if (style == "table_v2" || style == "table") {
        uintptr_t table = 0;
        mem::Read(names_base_, table);
        names_table_ = mem::IsReadable(table, sizeof(uintptr_t)) ? table : names_base_;
    } else {
        if (error) *error = "unsupported names.style: " + style;
        return false;
    }

    if (!mem::IsReadable(names_table_, sizeof(uintptr_t))) {
        if (error) *error = "names table is not readable";
        return false;
    }

    {
        std::lock_guard lock(name_mutex_);
        name_cache_.clear();
        name_faults_.clear();
    }

    int resolved = 0;
    std::string sample;
    for (uint32_t index = 1; index <= 16 && resolved < 4; ++index) {
        const std::string name = ParseNameEntry(index);
        if (!name.empty() && name.rfind("Name_", 0) != 0) {
            ++resolved;
            if (!sample.empty()) sample += ", ";
            sample += str::Format("%u=%s", index, name.c_str());
        }
    }

    if (resolved == 0) {
        if (error) *error = "name table resolved but no plausible names were decoded";
        FMCP_LOGW("Names: no plausible entries found at table %s",
                  mem::FormatAddress(names_table_).c_str());
        report_.names = false;
        names_table_ = 0;
        return false;
    }

    report_.names = true;
    report_.messages.emplace_back(str::Format("names style=%s table=%s sample=[%s]",
                                              style.c_str(),
                                              mem::FormatAddress(names_table_).c_str(),
                                              sample.c_str()));
    return true;
}

bool UeContext::ResolveObjects(std::string* error) {
    const Config& config = Config::Get();
    objects_base_ = 0;
    objects_table_ = 0;

    if (config.ue.objects.style == "off" || config.ue.objects.resolve == "off") {
        return false;
    }

    objects_base_ = ResolveAddressSpec(module_base_, module_size_, config.ue.objects.resolve,
                                       config.ue.objects.offset, config.ue.objects.signature,
                                       "objects", false, error);
    if (!objects_base_) {
        return false;
    }

    if (config.ue.objects.style == "uobject_array") {
        uintptr_t table = 0;
        if (!mem::Read(objects_base_ + config.ue.objects.objects_offset, table)) {
            if (error) *error = "cannot read object array chunk table pointer";
            return false;
        }
        objects_table_ = table;
    } else if (config.ue.objects.style == "chunk_table") {
        objects_table_ = objects_base_;
    } else if (config.ue.objects.style == "chunk_table_global") {
        uintptr_t table = 0;
        if (!mem::Read(objects_base_, table)) {
            if (error) *error = "cannot read object chunk table pointer";
            return false;
        }
        objects_table_ = table;
    } else {
        if (error) *error = "unsupported objects.style: " + config.ue.objects.style;
        return false;
    }

    if (!mem::IsReadable(objects_table_, sizeof(uintptr_t))) {
        if (error) *error = "object chunk table is not readable";
        return false;
    }

    report_.objects = true;
    report_.messages.emplace_back(str::Format("objects style=%s table=%s",
                                              config.ue.objects.style.c_str(),
                                              mem::FormatAddress(objects_table_).c_str()));
    return true;
}

void UeContext::RefreshMetaClasses() {
    class_meta_ = 0;
    function_meta_ = 0;
    world_meta_ = 0;
    if (!static_find_object_) {
        return;
    }

    for (const char* path : {"Class", "/Script/CoreUObject.Class", "CoreUObject.Class"}) {
        class_meta_ = FindObjectPath(path);
        if (class_meta_ && IsValidObject(class_meta_)) break;
        class_meta_ = 0;
    }
    for (const char* path : {"Function", "/Script/CoreUObject.Function", "CoreUObject.Function"}) {
        function_meta_ = FindObjectPath(path);
        if (function_meta_ && IsValidObject(function_meta_)) break;
        function_meta_ = 0;
    }
    for (const char* path : {"World", "/Script/Engine.World", "Engine.World"}) {
        world_meta_ = FindObjectPath(path);
        if (world_meta_ && IsValidObject(world_meta_)) break;
        world_meta_ = 0;
    }
}

bool UeContext::ValidateNameIndex(uint32_t raw) const {
    const auto& spec = Config::Get().ue.names;
    if (!spec.validate || spec.pool_offset == 0) {
        return true;
    }

    if (raw == 0) {
        return true;
    }

    const std::string decrypt = str::ToLower(spec.decrypt);
    uint32_t index = raw;
    if (decrypt == "fortnite") {
        index = DecryptNameIndex(raw, static_cast<uint32_t>(spec.decrypt_key));
    } else if (!decrypt.empty() && decrypt != "none" && decrypt != "plain") {
        return true;
    }

    const uintptr_t gnames = module_base_ + static_cast<uintptr_t>(spec.pool_offset);
    const uint32_t blockCount = mem::ReadOr<uint32_t>(gnames, 0) + 1;
    if (blockCount <= 1) {
        return false;
    }

    const int bits = std::clamp(spec.block_bits, 8, 24);
    const uint32_t mask = (1u << bits) - 1u;
    const uintptr_t table = gnames + static_cast<uintptr_t>(spec.block_table_offset);
    const uintptr_t stride = static_cast<uintptr_t>(std::max(spec.stride, 1));

    auto entryFor = [&](uint32_t value, uintptr_t& entry) -> bool {
        const uint32_t block = value >> bits;
        if (block >= blockCount) {
            return false;
        }
        uintptr_t blockPtr = 0;
        if (!mem::Read(table + static_cast<uintptr_t>(block) * sizeof(uintptr_t), blockPtr) ||
            !mem::IsCanonical(blockPtr)) {
            return false;
        }
        entry = blockPtr + static_cast<uintptr_t>(value & mask) * stride;
        return mem::IsReadable(entry, 2);
    };

    uintptr_t entry = 0;
    if (!entryFor(index, entry)) {
        return false;
    }

    const uint16_t header = mem::ReadOr<uint16_t>(entry, 0);
    const int32_t length = (header >> 6) ^ 0x117;
    if (length != 0) {
        return true;
    }

    const uint32_t redirectRaw = mem::ReadOr<uint32_t>(entry + 2, 0);
    const uint32_t redirect = decrypt == "fortnite"
                                  ? DecryptNameIndex(redirectRaw, static_cast<uint32_t>(spec.decrypt_key))
                                  : redirectRaw;
    if (redirect == 0 || !entryFor(redirect, entry)) {
        return false;
    }
    const uint16_t redirectHeader = mem::ReadOr<uint16_t>(entry, 0);
    return ((redirectHeader >> 6) ^ 0x117) != 0;
}

std::string UeContext::ParseGNamesEntry(uint32_t rawIndex) {
    const auto& spec = Config::Get().ue.names;
    if (spec.pool_offset == 0 || rawIndex == 0) {
        return {};
    }

    const std::string decrypt = str::ToLower(spec.decrypt);
    uint32_t index = rawIndex;
    if (decrypt == "fortnite") {
        index = DecryptNameIndex(rawIndex, static_cast<uint32_t>(spec.decrypt_key));
    } else if (!decrypt.empty() && decrypt != "none" && decrypt != "plain") {
        return {};
    }
    if (index == 0) {
        return {};
    }

    const uintptr_t gnames = module_base_ + static_cast<uintptr_t>(spec.pool_offset);
    const uint32_t blockCount = mem::ReadOr<uint32_t>(gnames, 0) + 1;
    if (blockCount <= 1) {
        return {};
    }

    const int bits = std::clamp(spec.block_bits, 8, 24);
    const uint32_t mask = (1u << bits) - 1u;
    const uintptr_t table = gnames + static_cast<uintptr_t>(spec.block_table_offset);
    const uintptr_t stride = static_cast<uintptr_t>(std::max(spec.stride, 1));

    auto entryFor = [&](uint32_t value, uintptr_t& entry) -> bool {
        const uint32_t block = value >> bits;
        if (block >= blockCount) {
            return false;
        }
        uintptr_t blockPtr = 0;
        if (!mem::Read(table + static_cast<uintptr_t>(block) * sizeof(uintptr_t), blockPtr) ||
            !mem::IsCanonical(blockPtr)) {
            return false;
        }
        entry = blockPtr + static_cast<uintptr_t>(value & mask) * stride;
        return mem::IsReadable(entry, 2);
    };

    uintptr_t entry = 0;
    if (!entryFor(index, entry)) {
        return {};
    }

    uint16_t header = mem::ReadOr<uint16_t>(entry, 0);
    int32_t length = (header >> 6) ^ 0x117;
    if (length == 0) {
        const uint32_t redirectRaw = mem::ReadOr<uint32_t>(entry + 2, 0);
        const uint32_t redirect = decrypt == "fortnite"
                                      ? DecryptNameIndex(redirectRaw, static_cast<uint32_t>(spec.decrypt_key))
                                      : redirectRaw;
        if (redirect == 0 || !entryFor(redirect, entry)) {
            return {};
        }
        header = mem::ReadOr<uint16_t>(entry, 0);
        length = (header >> 6) ^ 0x117;
        if (length == 0) {
            return {};
        }
    }

    std::string out = DecryptNameEntry(entry, header, length);
    if (out.empty()) {
        return {};
    }

    for (char& ch : out) {
        const unsigned char value = static_cast<unsigned char>(ch);
        if (value < 32 || value > 126) {
            ch = '_';
        }
    }
    return out;
}

std::string UeContext::CallKismetName(uint32_t index, uint32_t number, bool* faulted) {
    if (faulted) *faulted = false;
    if (!kismet_cdo_ || !kismet_function_) {
        return {};
    }

    const uint64_t key = (static_cast<uint64_t>(number) << 32) | index;
    {
        std::lock_guard lock(name_mutex_);
        if (name_faults_.find(key) != name_faults_.end()) {
            if (faulted) *faulted = true;
            return {};
        }
    }

    if (!ValidateNameIndex(index)) {
        if (faulted) *faulted = true;
        {
            std::lock_guard lock(name_mutex_);
            if (name_faults_.size() < 8192) {
                name_faults_.insert(key);
            }
        }
        if (g_nameRejectedLogged.fetch_add(1) < 16) {
            FMCP_LOGW("FName index 0x%X rejected by GNames validation; engine call skipped", index);
        }
        return {};
    }

    auto buffer = std::make_shared<std::vector<uint8_t>>(0x100, 0);
    std::memcpy(buffer->data(), &index, sizeof(index));
    std::memcpy(buffer->data() + 4, &number, sizeof(number));

    std::string error;
    const bool ran = RunOnGameThread(
        [this, buffer] {
            if (!IsValidObject(kismet_cdo_) || !IsValidObject(kismet_function_)) {
                return;
            }
            ProcessEventNow(kismet_cdo_, kismet_function_, buffer->data());
        },
        false, &error);
    if (!ran) {
        if (g_nameKismetLogged.fetch_add(1) < 4) {
            FMCP_LOGW("Kismet name resolution failed: %s", error.c_str());
        }
        return {};
    }

    const int maxChars = std::clamp(Config::Get().ue.names.max_chars, 32, 8192);
    for (size_t offset = 0; offset + 0x10 <= buffer->size(); offset += 8) {
        wchar_t* data = nullptr;
        int32_t num = 0;
        int32_t max = 0;
        std::memcpy(&data, buffer->data() + offset, sizeof(data));
        std::memcpy(&num, buffer->data() + offset + 8, sizeof(num));
        std::memcpy(&max, buffer->data() + offset + 12, sizeof(max));
        if (!data || num <= 0 || num > maxChars || max < num) {
            continue;
        }

        auto text = mem::ReadWString(reinterpret_cast<uintptr_t>(data),
                                     static_cast<size_t>(num));
        if (!text || text->empty()) {
            continue;
        }

        if (!g_nameAllocWarned.exchange(true)) {
            FMCP_LOGW("Kismet name backend allocates engine FStrings; unique names are leaked up to "
                      "the name-cache limit");
        }

        std::string result = str::Narrow(*text);
        for (char& c : result) {
            const unsigned char uc = static_cast<unsigned char>(c);
            if (uc < 32 || uc > 126) {
                c = '_';
            }
        }
        return result;
    }

    return {};
}

std::string UeContext::CallNameFunction(uint32_t index, uint32_t number, bool* faulted) {
    if (faulted) *faulted = false;
    if (gnames_direct_) {
        return ParseGNamesEntry(index);
    }
    if (kismet_function_) {
        return CallKismetName(index, number, faulted);
    }
    if (!names_function_) {
        return {};
    }

    const uint64_t key = (static_cast<uint64_t>(number) << 32) | index;
    {
        std::lock_guard lock(name_mutex_);
        if (name_faults_.find(key) != name_faults_.end()) {
            if (faulted) *faulted = true;
            return {};
        }
    }

    if (!ValidateNameIndex(index)) {
        if (faulted) *faulted = true;
        {
            std::lock_guard lock(name_mutex_);
            if (name_faults_.size() < 8192) {
                name_faults_.insert(key);
            }
        }
        if (g_nameRejectedLogged.fetch_add(1) < 16) {
            FMCP_LOGW("FName index 0x%X rejected by name-pool validation; engine call skipped",
                      index);
        }
        return {};
    }

    const Config& config = Config::Get();
    const int maxChars = std::clamp(std::max(config.ue.names.max_chars, 2048), 32, 8192);
    const std::string abi = str::ToLower(config.ue.names.abi);
    const bool valueAbi = abi == "fstring_value" || abi == "value";

    auto state = std::make_shared<NameCallState>();
    state->buffer.assign(static_cast<size_t>(maxChars), L'\0');
    state->fname = {index, number};
    state->out = valueAbi ? NameCallState::FStringLayout{}
                          : NameCallState::FStringLayout{state->buffer.data(), 0,
                                                         static_cast<int32_t>(state->buffer.size())};

    auto invoke = [state, valueAbi, function = names_function_] {
        state->ok = InvokeFNameFunction(function, valueAbi, &state->fname, &state->out);
    };

    bool invoked = false;
    auto& gameThread = GameThread::Get();
    if (config.ue.names.game_thread && gameThread.Hooked()) {
        std::string gameThreadError;
        const GameThreadStatus status = gameThread.Run(invoke, &gameThreadError);
        if (status == GameThreadStatus::Ok) {
            invoked = true;
        } else if (status != GameThreadStatus::NotInstalled) {
            FMCP_LOGW("name resolution on the game thread failed: %s", gameThreadError.c_str());
            return {};
        }
    }
    if (!invoked) {
        invoke();
    }

    if (!state->ok) {
        if (faulted) *faulted = true;
        {
            std::lock_guard lock(name_mutex_);
            if (name_faults_.size() < 8192) {
                name_faults_.insert(key);
            }
        }
        if (g_nameFaultLogged.fetch_add(1) < 16) {
            FMCP_LOGW("FNameToString faulted (raw index=0x%X number=0x%X); ID cached as invalid",
                      index, number);
        }
        return {};
    }

    const wchar_t* data = state->out.data ? state->out.data : state->buffer.data();
    if (!data) {
        return {};
    }

    auto text = mem::ReadWString(reinterpret_cast<uintptr_t>(data),
                                 static_cast<size_t>(maxChars));
    if (!text || text->empty()) {
        return {};
    }

    if (state->out.data && state->out.data != state->buffer.data()) {
        if (!g_nameAllocWarned.exchange(true)) {
            FMCP_LOGW("FNameToString returned an engine-allocated FString; names may leak slowly "
                      "(configure a GNames table backend for zero-allocation names)");
        }
    }

    std::string result = str::Narrow(*text);
    for (char& c : result) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 32 || uc > 126) {
            c = '_';
        }
    }
    return result;
}

UeContext::FNameLookup UeContext::LookupFName(uint32_t index, uint32_t number) {
    FNameLookup result;
    if (!names_function_ && !kismet_function_ && !gnames_direct_) {
        return result;
    }
    result.backend = true;

    const uint64_t key = (static_cast<uint64_t>(number) << 32) | index;
    {
        std::lock_guard lock(name_mutex_);
        const auto it = name_cache_.find(key);
        if (it != name_cache_.end()) {
            result.name = it->second;
            return result;
        }
        if (name_faults_.find(key) != name_faults_.end()) {
            result.faulted = true;
            return result;
        }
    }

    result.name = CallNameFunction(index, number, &result.faulted);
    if (!result.name.empty()) {
        std::lock_guard lock(name_mutex_);
        if (name_cache_.size() < 262144) {
            name_cache_.emplace(key, result.name);
        }
    }
    return result;
}

std::string UeContext::ParseNameEntry(uint32_t index) {
    if (!names_table_) {
        return {};
    }

    const Config& config = Config::Get();
    const std::string& style = config.ue.names.style;

    if (style == "table_v2") {
        uintptr_t entry = 0;
        if (!mem::Read(names_table_ + static_cast<uintptr_t>(index) * 8, entry) ||
            !mem::IsCanonical(entry)) {
            return {};
        }
        return ParseTableV2Entry(entry);
    }

    if (style == "table") {
        uintptr_t entry = 0;
        if (!mem::Read(names_table_ + static_cast<uintptr_t>(index) * 8, entry) ||
            !mem::IsCanonical(entry)) {
            return {};
        }
        return ParsePoolEntry(entry);
    }

    const int blockBits = std::clamp(config.ue.names.block_bits, 8, 24);
    const int stride = std::max(config.ue.names.stride, 1);
    const uint32_t blockIndex = index >> blockBits;
    if (blockIndex > 8192) {
        return {};
    }
    const uint32_t within = index & ((1u << blockBits) - 1u);

    uintptr_t block = 0;
    if (!mem::Read(names_table_ + static_cast<uintptr_t>(blockIndex) * 8, block) ||
        !mem::IsCanonical(block)) {
        return {};
    }

    return ParsePoolEntry(block + static_cast<uintptr_t>(within) * static_cast<uintptr_t>(stride));
}

std::string UeContext::ParsePoolEntry(uintptr_t entry) {
    if (!mem::IsReadable(entry, 2)) {
        return {};
    }

    const uint16_t header = mem::ReadOr<uint16_t>(entry, 0);
    const int wide = header & 1;

    int length = 0;
    size_t dataOffset = 2;

    const int first = header >> 6;
    const int second = header & 0x3FF;
    const int third = (header >> 5) & 0x3FF;

    for (int candidate : {first, second, third}) {
        if (candidate > 0 && candidate <= 1024) {
            length = candidate;
            break;
        }
    }
    if (length <= 0 || !mem::IsReadable(entry + dataOffset, static_cast<size_t>(length) * (wide ? 2 : 1) + 2)) {
        return {};
    }

    std::string out;
    out.reserve(static_cast<size_t>(length));
    int bad = 0;
    for (int i = 0; i < length; ++i) {
        wchar_t value = 0;
        if (wide) {
            value = static_cast<wchar_t>(mem::ReadOr<uint16_t>(entry + dataOffset + static_cast<size_t>(i) * 2, 0));
        } else {
            value = static_cast<wchar_t>(mem::ReadOr<uint8_t>(entry + dataOffset + static_cast<size_t>(i), 0));
        }
        if (value == 0) {
            break;
        }
        if (value < 32 || value > 126) {
            ++bad;
            out.push_back('_');
        } else {
            out.push_back(static_cast<char>(value));
        }
    }

    if (out.empty() || bad > std::max(2, length / 3)) {
        return {};
    }
    return out;
}

std::string UeContext::ParseTableV2Entry(uintptr_t entry) {
    if (!mem::IsReadable(entry, 8)) {
        return {};
    }

    const uint32_t flags = mem::ReadOr<uint32_t>(entry, 0);
    const int32_t length = mem::ReadOr<int32_t>(entry + 4, 0);
    if (length <= 0 || length > 1024) {
        return {};
    }

    const bool wide = (flags & 1) != 0;
    const uintptr_t data = entry + 8;
    if (!mem::IsReadable(data, static_cast<size_t>(length) * (wide ? 2 : 1))) {
        return {};
    }

    std::string out;
    out.reserve(static_cast<size_t>(length));
    for (int i = 0; i < length; ++i) {
        char c = 0;
        if (wide) {
            c = static_cast<char>(
                mem::ReadOr<uint16_t>(data + static_cast<size_t>(i) * 2, 0) & 0x7F);
        } else {
            c = static_cast<char>(mem::ReadOr<uint8_t>(data + static_cast<size_t>(i), 0));
        }
        if (c == 0) break;
        out.push_back(c >= 32 && c <= 126 ? c : '_');
    }
    return out;
}

std::string UeContext::NameFromIndex(uint32_t index) {
    if (index == 0) {
        return "None";
    }

    if (names_function_ || kismet_function_ || gnames_direct_) {
        const uint64_t key = index;
        {
            std::lock_guard lock(name_mutex_);
            auto it = name_cache_.find(key);
            if (it != name_cache_.end()) {
                return it->second;
            }
        }

        std::string name = CallNameFunction(index, 0);
        if (name.empty()) {
            return "Name_" + std::to_string(index);
        }

        {
            std::lock_guard lock(name_mutex_);
            if (name_cache_.size() < 262144) {
                name_cache_.emplace(key, name);
            }
        }
        return name;
    }

    if (!names_table_) {
        return "Name_" + std::to_string(index);
    }

    {
        std::lock_guard lock(name_mutex_);
        auto it = name_cache_.find(static_cast<uint64_t>(index));
        if (it != name_cache_.end()) {
            return it->second;
        }
    }

    std::string name = ParseNameEntry(index);
    if (name.empty()) {
        return "Name_" + std::to_string(index);
    }

    {
        std::lock_guard lock(name_mutex_);
        if (name_cache_.size() < 262144) {
            name_cache_.emplace(static_cast<uint64_t>(index), name);
        }
    }
    return name;
}

std::string UeContext::NameFromFName(uintptr_t address) {
    if (!address || !mem::IsReadable(address, static_cast<size_t>(layout_.fname_size))) {
        return {};
    }
    const uint32_t index = mem::ReadOr<uint32_t>(address, 0);
    const uint32_t number = layout_.fname_size >= 8 ? mem::ReadOr<uint32_t>(address + 4, 0) : 0;

    if (names_function_ || kismet_function_ || gnames_direct_) {
        if (number == 0) {
            return NameFromIndex(index);
        }

        const uint64_t key = (static_cast<uint64_t>(number) << 32) | index;
        {
            std::lock_guard lock(name_mutex_);
            auto it = name_cache_.find(key);
            if (it != name_cache_.end()) {
                return it->second;
            }
        }

        std::string name = CallNameFunction(index, number);
        if (name.empty()) {
            name = "Name_" + std::to_string(index);
        } else {
            std::lock_guard lock(name_mutex_);
            if (name_cache_.size() < 262144) {
                name_cache_.emplace(key, name);
            }
        }
        return name;
    }

    std::string name = NameFromIndex(index);
    if (number != 0) {
        name += "_" + std::to_string(number - 1);
    }
    return name;
}

std::string UeContext::ObjectName(uintptr_t object) {
    if (!object) {
        return {};
    }
    return NameFromFName(object + static_cast<uintptr_t>(layout_.object_name));
}

std::string UeContext::ClassName(uintptr_t object) {
    const uintptr_t classObject = ClassOf(object);
    return classObject ? ObjectName(classObject) : std::string{};
}

std::string UeContext::ObjectPath(uintptr_t object, int maxDepth) {
    if (!mem::IsCanonical(object)) {
        return {};
    }

    std::vector<std::string> parts;
    std::unordered_set<uintptr_t> visited;
    uintptr_t current = object;
    int depth = 0;

    while (current && depth++ < maxDepth && visited.insert(current).second) {
        const uintptr_t outer = OuterOf(current);
        const std::string name = ObjectName(current);
        if (name.empty() || name.rfind("Name_", 0) == 0) {
            if (parts.empty()) {
                return name;
            }
            break;
        }
        parts.push_back(name);
        if (!outer) {
            break;
        }
        current = outer;
    }

    std::string path;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        if (!path.empty()) path += ".";
        path += *it;
    }
    return path;
}

bool UeContext::IsValidObject(uintptr_t object) const {
    if (!mem::IsCanonical(object) || (object & 7) != 0) {
        return false;
    }

    const size_t minimum = static_cast<size_t>(
        std::max({layout_.object_class, layout_.object_outer, layout_.object_name}) + 8);
    if (!mem::IsReadable(object, minimum)) {
        return false;
    }

    uintptr_t vtable = 0;
    uintptr_t classObject = 0;
    if (!mem::Read(object + static_cast<uintptr_t>(layout_.object_vtable), vtable) ||
        !vtable || !mem::IsReadable(vtable, sizeof(uintptr_t))) {
        return false;
    }
    if (!mem::Read(object + static_cast<uintptr_t>(layout_.object_class), classObject) ||
        !mem::IsCanonical(classObject) || (classObject & 7) != 0) {
        return false;
    }
    if (!mem::IsReadable(classObject, 0x20)) {
        return false;
    }
    uintptr_t classVtable = 0;
    if (!mem::Read(classObject + static_cast<uintptr_t>(layout_.object_vtable), classVtable) ||
        !classVtable || !mem::IsReadable(classVtable, sizeof(uintptr_t))) {
        return false;
    }

    return true;
}

uintptr_t UeContext::ClassOf(uintptr_t object) const {
    if (!object) return 0;
    return mem::ReadOr<uintptr_t>(object + static_cast<uintptr_t>(layout_.object_class), 0);
}

uintptr_t UeContext::OuterOf(uintptr_t object) const {
    if (!object) return 0;
    return mem::ReadOr<uintptr_t>(object + static_cast<uintptr_t>(layout_.object_outer), 0);
}

uint32_t UeContext::NameIndex(uintptr_t object) const {
    if (!object) return 0;
    return mem::ReadOr<uint32_t>(object + static_cast<uintptr_t>(layout_.object_name), 0);
}

bool UeContext::IsA(uintptr_t object, uintptr_t classObject) const {
    if (!object || !classObject) {
        return false;
    }

    uintptr_t current = ClassOf(object);
    if (!current) {
        return false;
    }
    if (current == classObject) {
        return true;
    }
    if (layout_.ustruct_super <= 0) {
        return false;
    }

    std::unordered_set<uintptr_t> visited;
    for (int depth = 0; depth < 256; ++depth) {
        if (!current || !visited.insert(current).second) {
            break;
        }
        if (current == classObject) {
            return true;
        }
        const uintptr_t super = StructSuper(current);
        if (!super || super == current) {
            break;
        }
        current = super;
    }
    return false;
}

bool UeContext::IsClassObject(uintptr_t object) {
    if (!IsValidObject(object)) {
        return false;
    }
    if (class_meta_ && IsA(object, class_meta_)) {
        return true;
    }
    const std::string className = ClassName(object);
    return className == "Class" || className == "BlueprintGeneratedClass" ||
           className == "WidgetBlueprintGeneratedClass" ||
           className == "AnimBlueprintGeneratedClass";
}

uintptr_t UeContext::FindObjectRaw(uintptr_t classObject, uintptr_t outer,
                                   const std::wstring& name, bool exactClass) {
    if (!static_find_object_ || name.empty()) {
        return 0;
    }

    const auto& cfg = Config::Get().ue.static_find_object;
    const bool viewAbi = cfg.name_arg == "wstring_view_ptr" || cfg.name_arg == "string_view_ptr";
    const std::wstring_view view(name);

    bool faulted = false;
    const uintptr_t result = InvokeStaticFindObject(static_find_object_, classObject, outer,
                                                    viewAbi ? static_cast<const void*>(&view)
                                                            : static_cast<const void*>(name.c_str()),
                                                    exactClass, viewAbi, &faulted);
    if (faulted) {
        FMCP_LOGW("StaticFindObject faulted for name '%s'", str::Narrow(name).c_str());
        return 0;
    }
    return result;
}

std::vector<std::string> UeContext::PathCandidates(const std::string& path) {
    std::vector<std::string> out;
    std::string trimmed = str::Trim(path);
    if (trimmed.empty()) {
        return out;
    }

    auto add = [&](std::string candidate) {
        if (candidate.empty()) return;
        for (const auto& existing : out) {
            if (str::IEquals(existing, candidate)) return;
        }
        out.push_back(std::move(candidate));
    };

    add(trimmed);

    if (trimmed.find('/') == std::string::npos && trimmed.find('.') != std::string::npos) {
        add("/Script/" + trimmed);
    }
    if (trimmed[0] != '/' && trimmed.find('/') != std::string::npos) {
        add("/" + trimmed);
    }
    if (trimmed.find('/') == std::string::npos && trimmed.find('.') == std::string::npos) {
        add("/Script/Engine." + trimmed);
    }

    return out;
}

uintptr_t UeContext::FindObjectPath(const std::string& path, uintptr_t classObject, uintptr_t outer,
                                    std::vector<std::string>* tried) {
    if (!static_find_object_) {
        return 0;
    }

    for (const auto& candidate : PathCandidates(path)) {
        if (tried) tried->push_back(candidate);
        const std::wstring wide = str::Widen(candidate);
        const uintptr_t result = FindObjectRaw(classObject, outer, wide, false);
        if (result && IsValidObject(result)) {
            return result;
        }
    }
    return 0;
}

ObjectInfo UeContext::DescribeObject(uintptr_t object) {
    ObjectInfo info;
    info.address = object;
    if (!IsValidObject(object)) {
        return info;
    }

    info.class_address = ClassOf(object);
    info.outer = OuterOf(object);
    info.name_index = NameIndex(object);
    info.name_raw = mem::ReadOr<uint64_t>(object + static_cast<uintptr_t>(layout_.object_name), 0);
    info.internal_index = mem::ReadOr<int32_t>(object + static_cast<uintptr_t>(layout_.object_internal_index), 0);
    info.flags = mem::ReadOr<uint32_t>(object + static_cast<uintptr_t>(layout_.object_flags), 0);
    info.name = ObjectName(object);
    info.class_name = info.class_address ? ObjectName(info.class_address) : std::string{};
    info.path = ObjectPath(object);
    return info;
}

bool UeContext::GameThreadHooked() const {
    return GameThread::Get().Hooked();
}

bool UeContext::RunOnGameThread(const std::function<void()>& job, bool allowDirect,
                                std::string* error, bool* usedDirect) {
    if (usedDirect) *usedDirect = false;

    auto& gt = GameThread::Get();
    if (gt.Hooked()) {
        const GameThreadStatus status = gt.Run(job, error);
        if (status == GameThreadStatus::Ok) {
            return true;
        }
        if (status == GameThreadStatus::NotInstalled) {
            if (!allowDirect) {
                if (error) *error = "game-thread hook is not installed";
                return false;
            }
        } else {
            return false;
        }
    }

    if (!allowDirect) {
        if (error) {
            *error = "game-thread hook is not installed; enable ue.process_event or "
                     "game_thread.direct_fallback (unsafe)";
        }
        return false;
    }

    try {
        job();
        if (usedDirect) *usedDirect = true;
        return true;
    } catch (const std::exception& e) {
        if (error) *error = e.what();
        return false;
    }
}

uint64_t UeContext::ProcessEventNow(uintptr_t object, uintptr_t function, void* params) {
    auto& gt = GameThread::Get();
    if (gt.Hooked()) {
        return gt.InvokeProcessEvent(object, function, params);
    }
    return ProcessEventNowDirect(object, function, params);
}

uint64_t UeContext::ProcessEventNowDirect(uintptr_t object, uintptr_t function, void* params) {
    if (!process_event_) {
        return 0;
    }
    uint64_t result = 0;
    if (!InvokeProcessEventThunk(process_event_, object, function, params, &result)) {
        FMCP_LOGW("ProcessEvent faulted (object=%s function=%s)",
                  mem::FormatAddress(object).c_str(), mem::FormatAddress(function).c_str());
        return 0;
    }
    return result;
}

nlohmann::json UeContext::Status() {
    using nlohmann::json;
    json j;

    j["resolved"] = report_.resolved;
    j["flags"] = {{"static_find_object", report_.static_find_object},
                  {"get_objects_of_class", report_.get_objects_of_class},
                  {"process_event", report_.process_event},
                  {"names", report_.names},
                  {"objects", report_.objects},
                  {"layout", report_.layout},
                  {"properties", report_.properties},
                  {"functions", report_.functions},
                  {"game_thread", report_.game_thread},
                  {"gworld", report_.gworld},
                  {"gengine", report_.gengine}};

    j["module"] = {{"base", mem::FormatAddress(module_base_)}, {"size", module_size_}};
    j["functions"] = {{"static_find_object", mem::FormatAddress(static_find_object_)},
                      {"get_objects_of_class", mem::FormatAddress(get_objects_of_class_)},
                      {"process_event", mem::FormatAddress(process_event_)}};
    j["names"] = {{"ready", report_.names},
                  {"style", Config::Get().ue.names.style},
                  {"abi", Config::Get().ue.names.abi},
                  {"game_thread", Config::Get().ue.names.game_thread},
                  {"validate", Config::Get().ue.names.validate},
                  {"base", mem::FormatAddress(names_base_)},
                  {"table", mem::FormatAddress(names_table_)},
                  {"function", mem::FormatAddress(names_function_)},
                  {"cdo", mem::FormatAddress(kismet_cdo_)},
                  {"kismet_function", mem::FormatAddress(kismet_function_)},
                  {"gnames_direct", gnames_direct_}};

    const std::string nameStyle = str::ToLower(Config::Get().ue.names.style);
    const bool opaqueNames = nameStyle == "function" || nameStyle == "fname_function" ||
                             nameStyle == "fn" || nameStyle == "kismet" ||
                             nameStyle == "static_name" || nameStyle == "kismet_static";
    if (report_.names && !opaqueNames) {
        json samples = json::array();
        for (uint32_t index = 0; index < 32 && samples.size() < 6; ++index) {
            const std::string name = NameFromIndex(index);
            if (!name.empty() && name.rfind("Name_", 0) != 0) {
                samples.push_back({{"index", index}, {"name", name}});
            }
        }
        j["names"]["samples"] = std::move(samples);
    } else if (report_.names && opaqueNames) {
        j["names"]["samples_note"] = "opaque FName IDs; see globals/object names for validation";
    }

    j["objects"] = {{"ready", report_.objects},
                    {"style", Config::Get().ue.objects.style},
                    {"table", mem::FormatAddress(objects_table_)}};

    j["layout"] = {{"preset", Config::Get().ue.profile},
                   {"object_class", layout_.object_class},
                   {"object_name", layout_.object_name},
                   {"object_outer", layout_.object_outer},
                   {"find_size", layout_.fname_size},
                   {"ustruct_super", layout_.ustruct_super},
                   {"ustruct_children", layout_.ustruct_children},
                   {"ustruct_child_properties", layout_.ustruct_child_properties},
                   {"ffield_next", layout_.ffield_next},
                   {"ffield_name", layout_.ffield_name},
                   {"fproperty_offset", layout_.fproperty_offset},
                   {"fortnite_property_decoders", layout_.fortnite_property_decoders},
                   {"has_property_chain", layout_.HasPropertyChain()}};

    json warnings = json::array();
    for (const auto& warning : report_.warnings) warnings.push_back(warning);
    j["warnings"] = std::move(warnings);

    json messages = json::array();
    for (const auto& message : report_.messages) messages.push_back(message);
    j["messages"] = std::move(messages);

    auto& gt = GameThread::Get();
    j["game_thread"] = {{"hooked", gt.Hooked()},
                        {"target", mem::FormatAddress(gt.Target())},
                        {"pending", gt.Pending()},
                        {"executed", gt.ExecutedJobs()},
                        {"timeout_ms", gt.TimeoutMs()},
                        {"direct_fallback", Config::Get().game_thread.direct_fallback}};

    std::string globalError;
    const uintptr_t world = GWorld(&globalError);
    const uintptr_t engine = GEngine(&globalError);
    const bool worldValid = world && IsValidObject(world);
    const bool engineValid = engine && IsValidObject(engine);

    auto describeGlobal = [&](uintptr_t object, bool valid, uintptr_t slot) {
        const uint64_t rawName =
            object ? mem::ReadOr<uint64_t>(object + static_cast<uintptr_t>(layout_.object_name), 0) : 0;
        const uint32_t nameIndex = static_cast<uint32_t>(rawName);
        const uint32_t nameNumber = layout_.fname_size >= 8 ? static_cast<uint32_t>(rawName >> 32) : 0;

        std::string name;
        bool nameFaulted = false;
        if (valid) {
            if (names_function_ || kismet_function_ || gnames_direct_) {
                auto lookup = LookupFName(nameIndex, nameNumber);
                name = std::move(lookup.name);
                nameFaulted = lookup.faulted;
            } else {
                name = ObjectName(object);
            }
        }

        return json{{"slot", mem::FormatAddress(slot)},
                    {"value", mem::FormatAddress(object)},
                    {"canonical", mem::IsCanonical(object)},
                    {"readable", object != 0 && mem::IsReadable(object, 0x28)},
                    {"valid", valid},
                    {"class", mem::FormatAddress(object ? ClassOf(object) : 0)},
                    {"outer", mem::FormatAddress(object ? OuterOf(object) : 0)},
                    {"name_raw", mem::FormatAddress(static_cast<uintptr_t>(rawName))},
                    {"name_index", nameIndex},
                    {"name_faulted", nameFaulted},
                    {"name", std::move(name)}};
    };

    j["globals"] = {{"gworld", describeGlobal(world, worldValid, gworld_slot_)},
                    {"gengine", describeGlobal(engine, engineValid, gengine_slot_)}};

    const Config& config = Config::Get();
    if (config.ue.gworld.resolve == "chain") {
        json chain = json::array();
        uintptr_t current = engine;
        chain.push_back({{"hop", 0}, {"value", mem::FormatAddress(current)},
                         {"canonical", mem::IsCanonical(current)}});
        for (size_t i = 0; i < config.ue.gworld.chain.size(); ++i) {
            const uint64_t offset = config.ue.gworld.chain[i];
            const bool readable = current != 0 && offset <= 0x10000000 &&
                                  mem::IsReadable(current + static_cast<uintptr_t>(offset),
                                                  sizeof(uintptr_t));
            const uintptr_t next =
                readable ? mem::ReadOr<uintptr_t>(current + static_cast<uintptr_t>(offset), 0) : 0;
            chain.push_back({{"hop", i + 1},
                             {"offset", offset},
                             {"from", mem::FormatAddress(current)},
                             {"readable", readable},
                             {"value", mem::FormatAddress(next)},
                             {"canonical", mem::IsCanonical(next)}});
            current = next;
            if (!current) break;
        }
        j["globals"]["gworld"]["chain"] = std::move(chain);
    }

    return j;
}

}

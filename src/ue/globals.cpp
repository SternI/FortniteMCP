#include "ue/context.h"

#include "core/log.h"
#include "core/memory.h"
#include "core/modules.h"
#include "core/scanner.h"
#include "core/strings.h"

#include <windows.h>

namespace fmcp::ue {

namespace {

uintptr_t ResolveGlobalSlot(uintptr_t moduleBase, size_t moduleSize, const GlobalSpec& spec,
                            const char* label, std::string* error) {
    if (spec.resolve.empty() || spec.resolve == "off" || spec.resolve == "none") {
        return 0;
    }

    if (spec.resolve == "offset" || spec.resolve == "rva") {
        if (spec.offset == 0) {
            if (error) *error = str::Format("%s offset is zero", label);
            return 0;
        }
        if (spec.offset >= moduleSize) {
            if (error) *error = str::Format("%s offset is outside the module", label);
            return 0;
        }
        return moduleBase + static_cast<uintptr_t>(spec.offset);
    }

    if (spec.resolve == "signature" || spec.resolve == "pattern") {
        std::string parseError;
        auto pattern = scan::ParsePattern(spec.signature, &parseError);
        if (!pattern) {
            if (error) *error = str::Format("%s signature parse failed: %s", label, parseError.c_str());
            return 0;
        }
        scan::Request request;
        request.start = moduleBase;
        request.end = moduleBase + moduleSize;
        request.pattern = std::move(*pattern);
        request.maxResults = 4;
        request.maxBytes = moduleSize;
        const auto result = scan::Search(request);
        if (!result.matches.empty()) {
            return result.matches.front();
        }
        if (error) *error = str::Format("%s signature did not match", label);
        return 0;
    }

    if (error) *error = str::Format("%s uses unsupported resolve mode '%s'", label, spec.resolve.c_str());
    return 0;
}

bool ApplyDecode(uintptr_t& value, const std::string& chain, std::string* error) {
    if (chain.empty() || chain == "none" || chain == "plain") {
        return true;
    }

    for (const auto& rawStep : str::Split(chain, ',')) {
        const size_t colon = rawStep.find(':');
        const std::string op = str::ToLower(str::Trim(
            colon == std::string::npos ? rawStep : rawStep.substr(0, colon)));
        const std::string arg = colon == std::string::npos ? std::string{} : str::Trim(rawStep.substr(colon + 1));

        uint64_t number = 0;
        if (!arg.empty()) {
            const auto parsed = str::ParseUint(arg);
            if (!parsed) {
                if (error) *error = "invalid decode argument: " + rawStep;
                return false;
            }
            number = *parsed;
        }

        const uint64_t v = static_cast<uint64_t>(value);
        if (op == "add") {
            value = static_cast<uintptr_t>(v + number);
        } else if (op == "sub") {
            value = static_cast<uintptr_t>(v - number);
        } else if (op == "xor") {
            value = static_cast<uintptr_t>(v ^ number);
        } else if (op == "and") {
            value = static_cast<uintptr_t>(v & number);
        } else if (op == "or") {
            value = static_cast<uintptr_t>(v | number);
        } else if (op == "not") {
            value = static_cast<uintptr_t>(~v);
        } else if (op == "rotl") {
            value = static_cast<uintptr_t>(_rotl64(v, static_cast<int>(number & 63)));
        } else if (op == "rotr") {
            value = static_cast<uintptr_t>(_rotr64(v, static_cast<int>(number & 63)));
        } else if (op == "swap32") {
            value = static_cast<uintptr_t>(_byteswap_ulong(static_cast<uint32_t>(v)));
        } else if (op == "swap64") {
            value = static_cast<uintptr_t>(_byteswap_uint64(v));
        } else {
            if (error) *error = "unknown decode operation: " + op;
            return false;
        }
    }
    return true;
}

}

uintptr_t UeContext::ReadGlobalRaw(uintptr_t slot, std::string* error) {
    if (!slot) {
        if (error) *error = "global slot is unresolved";
        return 0;
    }
    if (!mem::IsReadable(slot, sizeof(uintptr_t))) {
        if (error) *error = "global slot is not readable";
        return 0;
    }
    const uintptr_t value = mem::ReadOr<uintptr_t>(slot, 0);
    if (!value) {
        if (error) *error = "global value is null";
        return 0;
    }
    return value;
}

uintptr_t UeContext::ReadGlobalBySpec(const GlobalSpec& spec, uintptr_t slot, std::string* error) {
    uintptr_t value = ReadGlobalRaw(slot, error);
    if (!value) {
        return 0;
    }
    if (!ApplyDecode(value, spec.decode, error)) {
        return 0;
    }
    return value;
}

uintptr_t UeContext::ReadGlobalValue(const std::string& name, int depth, std::string* error) {
    if (depth > 8) {
        if (error) *error = "global chain is too deep or cyclic";
        return 0;
    }

    const Config& config = Config::Get();
    const GlobalSpec* spec = nullptr;

    if (name == "gworld" || name == "gworld_slot") {
        spec = &config.ue.gworld;
    } else if (name == "gengine" || name == "gengine_slot") {
        spec = &config.ue.gengine;
    } else {
        const auto it = config.ue.extra_globals.find(name);
        if (it == config.ue.extra_globals.end()) {
            if (error) *error = "unknown global: " + name;
            return 0;
        }
        spec = &it->second;
    }

    if (spec->resolve == "chain") {
        std::string baseName = spec->from.empty() ? "gengine" : spec->from;
        if (baseName == name) {
            if (error) *error = name + " chain refers to itself";
            return 0;
        }

        uintptr_t value = ReadGlobalValue(baseName, depth + 1, error);
        if (!value) {
            if (error && error->empty()) *error = "chain base " + baseName + " is null";
            return 0;
        }

        for (size_t i = 0; i < spec->chain.size(); ++i) {
            const uint64_t offset = spec->chain[i];
            if (offset > 0x10000000) {
                if (error) *error = str::Format("%s chain offset %zu is implausible", name.c_str(), i);
                return 0;
            }
            if (!mem::IsReadable(value + static_cast<uintptr_t>(offset), sizeof(uintptr_t))) {
                if (error) *error = str::Format("%s chain hop %zu is unreadable", name.c_str(), i);
                return 0;
            }
            const uintptr_t next = mem::ReadOr<uintptr_t>(value + static_cast<uintptr_t>(offset), 0);
            if (!next) {
                if (error) *error = str::Format("%s chain hop %zu is null", name.c_str(), i);
                return 0;
            }
            value = next;
        }

        if (!ApplyDecode(value, spec->decode, error)) {
            return 0;
        }
        return value;
    }

    uintptr_t slot = 0;
    if (name == "gworld" || name == "gworld_slot") {
        if (!gworld_slot_) {
            gworld_slot_ = ResolveGlobalSlot(module_base_, module_size_, *spec, "gworld", error);
        }
        slot = gworld_slot_;
    } else if (name == "gengine" || name == "gengine_slot") {
        if (!gengine_slot_) {
            gengine_slot_ = ResolveGlobalSlot(module_base_, module_size_, *spec, "gengine", error);
        }
        slot = gengine_slot_;
    } else {
        slot = ResolveGlobalSlot(module_base_, module_size_, *spec, name.c_str(), error);
    }

    return ReadGlobalBySpec(*spec, slot, error);
}

std::optional<uintptr_t> UeContext::ReadNamedGlobal(const std::string& name, std::string* error) {
    const uintptr_t value = ReadGlobalValue(name, 0, error);
    return value ? std::optional<uintptr_t>(value) : std::nullopt;
}

uintptr_t UeContext::GWorld(std::string* error) {
    return ReadNamedGlobal("gworld", error).value_or(0);
}

uintptr_t UeContext::GEngine(std::string* error) {
    return ReadNamedGlobal("gengine", error).value_or(0);
}

}

#include "ue/context.h"

#include "core/log.h"
#include "core/memory.h"
#include "core/strings.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <unordered_set>

namespace fmcp::ue {

namespace {

constexpr uint64_t CPF_OutParm = 0x0000000000000100ull;
constexpr uint64_t CPF_ReturnParm = 0x0000000000000400ull;
constexpr uint32_t RF_ClassDefaultObject = 0x00000010;

bool TypeIs(const std::string& type, const char* name) {
    return type == name || str::EndsWith(type, name);
}

bool IsSignedType(const std::string& type) {
    return TypeIs(type, "Int8Property") || TypeIs(type, "Int16Property") ||
           TypeIs(type, "IntProperty") || TypeIs(type, "Int64Property") ||
           TypeIs(type, "EnumProperty");
}

bool IsUnsignedType(const std::string& type) {
    return TypeIs(type, "UInt16Property") || TypeIs(type, "UInt32Property") ||
           TypeIs(type, "UInt64Property") || TypeIs(type, "ByteProperty");
}

bool IsFloatType(const std::string& type) {
    return TypeIs(type, "FloatProperty") || TypeIs(type, "DoubleProperty");
}

bool IsObjectType(const std::string& type) {
    return TypeIs(type, "ObjectProperty") || TypeIs(type, "ClassProperty") ||
           TypeIs(type, "InterfaceProperty") || TypeIs(type, "WeakObjectProperty") ||
           TypeIs(type, "LazyObjectProperty") || TypeIs(type, "SoftObjectProperty");
}

bool IsStructType(const std::string& type) {
    return TypeIs(type, "StructProperty");
}

bool IsArrayType(const std::string& type) {
    return TypeIs(type, "ArrayProperty");
}

bool IsBoolType(const std::string& type) {
    return TypeIs(type, "BoolProperty");
}

bool IsNameType(const std::string& type) {
    return TypeIs(type, "NameProperty");
}

bool IsStringType(const std::string& type) {
    return TypeIs(type, "StrProperty");
}

uint32_t Rol32(uint32_t value, int bits) {
    return _rotl(value, bits);
}

int32_t DecodeFortniteSize(uint32_t raw, const Layout& layout) {
    if (!layout.fortnite_property_decoders) {
        return static_cast<int32_t>(raw);
    }

    const int32_t candidates[] = {
        static_cast<int32_t>(Rol32((raw - 0x7DA68E1Fu) ^ 0x84077E16u, 0x19)),
        static_cast<int32_t>(_byteswap_ulong(0x100123Bu ^ raw) - 0x2458738E),
        static_cast<int32_t>(raw),
    };
    for (int32_t value : candidates) {
        if (value > 0 && value <= 0x1000000) {
            return value;
        }
    }
    return 0;
}

int32_t DecodeFortniteOffset(uint32_t raw, const Layout& layout) {
    if (!layout.fortnite_property_decoders) {
        return static_cast<int32_t>(raw);
    }

    const int32_t candidates[] = {
        static_cast<int32_t>(Rol32((raw + 0x69534879u) ^ 0x6B0154AEu, 0x19)),
        static_cast<int32_t>(_byteswap_ulong(0x100123Bu ^ raw) + 0x57D06A55),
        static_cast<int32_t>(raw),
    };
    for (int32_t value : candidates) {
        if (value >= 0 && value <= 0x1000000) {
            return value;
        }
    }
    return -1;
}

uint64_t DecodeFortniteFlags(uint64_t raw, const Layout& layout) {
    if (!layout.fortnite_property_decoders) {
        return raw;
    }
    if (raw == 0) {
        return 0;
    }
    return _rotl64((raw + 0xB25DD23Cull) ^ 0xB40C6531ull, 0x3C);
}

bool ReadFStringAt(uintptr_t address, std::string& out, int32_t* lengthOut, std::string* error) {
    struct FString {
        uintptr_t data;
        int32_t num;
        int32_t max;
    } value{};
    if (!mem::Read(address, value)) {
        if (error) *error = "FString header is unreadable";
        return false;
    }

    if (value.num < 0 || value.num > 0x100000) {
        if (error) *error = "FString length is invalid";
        return false;
    }
    if (value.num <= 1 || !value.data) {
        out.clear();
        if (lengthOut) *lengthOut = value.num;
        return true;
    }

    const int32_t chars = std::min(value.num - 1, 65536);
    if (!mem::IsReadable(value.data, static_cast<size_t>(chars) * sizeof(wchar_t))) {
        if (error) *error = "FString data is unreadable";
        return false;
    }

    out.clear();
    out.reserve(static_cast<size_t>(chars));
    for (int32_t i = 0; i < chars; ++i) {
        const wchar_t c = mem::ReadOr<wchar_t>(value.data + static_cast<uintptr_t>(i) * sizeof(wchar_t), 0);
        if (c == 0) break;
        out += str::Narrow(std::wstring(1, c));
    }

    if (lengthOut) *lengthOut = value.num;
    return true;
}

std::optional<int64_t> JsonToSigned(const nlohmann::json& value) {
    if (value.is_number_integer()) return value.get<int64_t>();
    if (value.is_number_unsigned()) return static_cast<int64_t>(value.get<uint64_t>());
    if (value.is_boolean()) return value.get<bool>() ? 1 : 0;
    if (value.is_string()) {
        const auto parsed = str::ParseUint(value.get<std::string>(), static_cast<uint64_t>(INT64_MAX));
        if (parsed) return static_cast<int64_t>(*parsed);
    }
    return std::nullopt;
}

std::optional<uint64_t> JsonToUnsigned(const nlohmann::json& value) {
    if (value.is_number_unsigned()) return value.get<uint64_t>();
    if (value.is_number_integer()) {
        const int64_t signedValue = value.get<int64_t>();
        if (signedValue < 0) return std::nullopt;
        return static_cast<uint64_t>(signedValue);
    }
    if (value.is_boolean()) return value.get<bool>() ? 1ull : 0ull;
    if (value.is_string()) return str::ParseUint(value.get<std::string>());
    return std::nullopt;
}

std::optional<double> JsonToDouble(const nlohmann::json& value) {
    if (value.is_number()) return value.get<double>();
    if (value.is_string()) {
        try {
            return std::stod(value.get<std::string>());
        } catch (...) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

bool VectorComponents(const nlohmann::json& value, size_t count, std::vector<double>& out) {
    out.clear();
    if (value.is_array() && value.size() == count) {
        for (const auto& item : value) {
            auto number = JsonToDouble(item);
            if (!number) return false;
            out.push_back(*number);
        }
        return true;
    }

    if (value.is_object()) {
        static const char* keys[] = {"x", "y", "z", "w"};
        for (size_t i = 0; i < count; ++i) {
            if (!value.contains(keys[i])) return false;
            auto number = JsonToDouble(value[keys[i]]);
            if (!number) return false;
            out.push_back(*number);
        }
        return true;
    }

    return false;
}

bool ReadObjectRef(UeContext& ctx, uintptr_t address, nlohmann::json& out) {
    const uintptr_t object = mem::ReadOr<uintptr_t>(address, 0);
    if (!object) {
        out = nullptr;
        return true;
    }
    if (ctx.IsValidObject(object)) {
        const ObjectInfo info = ctx.DescribeObject(object);
        out = {{"address", mem::FormatAddress(object)},
               {"name", info.name},
               {"class", info.class_name},
               {"path", info.path}};
    } else {
        out = {{"address", mem::FormatAddress(object)}, {"valid", false}};
    }
    return true;
}

std::string raw_hex(uintptr_t address, size_t size) {
    if (!address || size == 0) return {};
    std::vector<uint8_t> bytes(std::min<size_t>(size, 512));
    if (!mem::Read(address, bytes.data(), bytes.size())) {
        return {};
    }
    return str::Hex(bytes.data(), bytes.size());
}

bool ReadValueAt(UeContext& ctx, uintptr_t base, const PropertyInfo& prop, nlohmann::json& out,
                 std::string* error, int depth = 0) {
    if (depth > 3) {
        if (error) *error = "value nesting is too deep";
        return false;
    }
    if (base == 0 || prop.offset < 0) {
        if (error) *error = "invalid value base/offset";
        return false;
    }

    const Layout& layout = ctx.CurrentLayout();
    const uintptr_t address = base + static_cast<uintptr_t>(prop.offset);
    const size_t totalSize = static_cast<size_t>(std::max(prop.size, 1)) *
                             static_cast<size_t>(std::max(prop.array_dim, 1));
    const std::string& type = prop.type;

    if (IsBoolType(type)) {
        uint8_t byte = mem::ReadOr<uint8_t>(address, 0);
        uint8_t mask = 1;
        if (layout.bool_byte_mask >= 0) {
            const int byteOffset = std::max(layout.bool_byte_offset, 0);
            byte = mem::ReadOr<uint8_t>(address + static_cast<uintptr_t>(byteOffset), 0);
            const uint8_t byteMask = static_cast<uint8_t>(
                mem::ReadOr<uint8_t>(prop.address + static_cast<uintptr_t>(layout.bool_byte_mask), 0));
            const uint8_t fieldMask = layout.bool_field_mask >= 0
                ? mem::ReadOr<uint8_t>(prop.address + static_cast<uintptr_t>(layout.bool_field_mask), 0)
                : byteMask;
            mask = byteMask ? byteMask : (fieldMask ? fieldMask : 1);
        }
        out = (byte & mask) != 0;
        return true;
    }

    if (IsSignedType(type)) {
        const int bits = prop.size >= 8 ? 64 : (prop.size == 4 ? 32 : (prop.size == 2 ? 16 : 8));
        if (bits == 64) out = mem::ReadOr<int64_t>(address, 0);
        else if (bits == 32) out = mem::ReadOr<int32_t>(address, 0);
        else if (bits == 16) out = mem::ReadOr<int16_t>(address, 0);
        else out = mem::ReadOr<int8_t>(address, 0);
        return true;
    }

    if (IsUnsignedType(type)) {
        const int bits = prop.size >= 8 ? 64 : (prop.size == 4 ? 32 : (prop.size == 2 ? 16 : 8));
        if (bits == 64) out = mem::ReadOr<uint64_t>(address, 0);
        else if (bits == 32) out = mem::ReadOr<uint32_t>(address, 0);
        else if (bits == 16) out = mem::ReadOr<uint16_t>(address, 0);
        else out = mem::ReadOr<uint8_t>(address, 0);
        return true;
    }

    if (TypeIs(type, "FloatProperty")) {
        out = mem::ReadOr<float>(address, 0.0f);
        return true;
    }
    if (TypeIs(type, "DoubleProperty")) {
        out = mem::ReadOr<double>(address, 0.0);
        return true;
    }

    if (IsObjectType(type)) {
        if (TypeIs(type, "WeakObjectProperty") || TypeIs(type, "LazyObjectProperty") ||
            TypeIs(type, "SoftObjectProperty")) {
            out = {{"raw_hex", raw_hex(address, std::max(prop.size, 8))}};
            return true;
        }
        return ReadObjectRef(ctx, address, out);
    }

    if (IsNameType(type)) {
        const uint32_t index = mem::ReadOr<uint32_t>(address, 0);
        nlohmann::json name = {{"index", index}, {"name", ctx.NameFromIndex(index)}};
        if (layout.fname_size >= 8) {
            name["number"] = mem::ReadOr<uint32_t>(address + 4, 0);
        }
        out = std::move(name);
        return true;
    }

    if (IsStringType(type)) {
        std::string text;
        int32_t length = 0;
        std::string stringError;
        if (ReadFStringAt(address, text, &length, &stringError)) {
            out = {{"value", text}, {"length", length}};
        } else {
            out = {{"error", stringError}, {"raw_hex", raw_hex(address, std::min<size_t>(totalSize, 16))}};
        }
        return true;
    }

    if (TypeIs(type, "EnumProperty")) {
        if (prop.size == 1) out = mem::ReadOr<uint8_t>(address, 0);
        else if (prop.size == 2) out = mem::ReadOr<int16_t>(address, 0);
        else if (prop.size == 8) out = mem::ReadOr<int64_t>(address, 0);
        else out = mem::ReadOr<int32_t>(address, 0);
        return true;
    }

    if (IsStructType(type)) {
        const std::string& name = prop.payload_name;
        if (name.find("Vector4") != std::string::npos || name.find("Quat") != std::string::npos) {
            const bool doubles = layout.large_world_coords && totalSize >= 32;
            std::vector<double> values(4);
            for (int i = 0; i < 4; ++i) {
                values[i] = doubles
                    ? mem::ReadOr<double>(address + static_cast<uintptr_t>(i) * 8, 0.0)
                    : static_cast<double>(mem::ReadOr<float>(address + static_cast<uintptr_t>(i) * 4, 0.0f));
            }
            out = {{"struct", name}, {"x", values[0]}, {"y", values[1]}, {"z", values[2]}, {"w", values[3]}};
            return true;
        }
        if (name.find("Vector2D") != std::string::npos) {
            const bool doubles = layout.large_world_coords && totalSize >= 16;
            out = {{"struct", name},
                   {"x", doubles ? mem::ReadOr<double>(address, 0.0) : static_cast<double>(mem::ReadOr<float>(address, 0.0f))},
                   {"y", doubles ? mem::ReadOr<double>(address + 8, 0.0) : static_cast<double>(mem::ReadOr<float>(address + 4, 0.0f))}};
            return true;
        }
        if (name.find("Vector") != std::string::npos || name.find("Rotator") != std::string::npos) {
            const bool doubles = layout.large_world_coords && totalSize >= 24;
            out = {{"struct", name},
                   {"x", doubles ? mem::ReadOr<double>(address, 0.0) : static_cast<double>(mem::ReadOr<float>(address, 0.0f))},
                   {"y", doubles ? mem::ReadOr<double>(address + 8, 0.0) : static_cast<double>(mem::ReadOr<float>(address + 4, 0.0f))},
                   {"z", doubles ? mem::ReadOr<double>(address + 16, 0.0) : static_cast<double>(mem::ReadOr<float>(address + 8, 0.0f))}};
            return true;
        }
        if (name.find("LinearColor") != std::string::npos) {
            out = {{"struct", name},
                   {"r", mem::ReadOr<float>(address, 0.0f)},
                   {"g", mem::ReadOr<float>(address + 4, 0.0f)},
                   {"b", mem::ReadOr<float>(address + 8, 0.0f)},
                   {"a", mem::ReadOr<float>(address + 12, 0.0f)}};
            return true;
        }
        if (name.find("Guid") != std::string::npos) {
            out = {{"struct", name},
                   {"a", mem::ReadOr<uint32_t>(address, 0)},
                   {"b", mem::ReadOr<uint32_t>(address + 4, 0)},
                   {"c", mem::ReadOr<uint32_t>(address + 8, 0)},
                   {"d", mem::ReadOr<uint32_t>(address + 12, 0)}};
            return true;
        }

        out = {{"struct", name}, {"size", totalSize}, {"raw_hex", raw_hex(address, totalSize)}};
        return true;
    }

    if (IsArrayType(type)) {
        struct ArrayHeader {
            uintptr_t data;
            int32_t num;
            int32_t max;
        } array{};
        if (!mem::Read(address, array)) {
            if (error) *error = "array header is unreadable";
            return false;
        }
        nlohmann::json result = {{"count", array.num}, {"max", array.max},
                                 {"data", mem::FormatAddress(array.data)}};

        if (array.data && array.num > 0 && array.num <= 1000000 && prop.payload) {
            PropertyInfo inner;
            if (ctx.DecodeProperty(prop.payload, inner)) {
                result["inner_type"] = inner.type;
                const int32_t limit = std::min(array.num, 32);
                const size_t stride = static_cast<size_t>(std::max(inner.size, 1));
                if (mem::IsReadable(array.data, static_cast<size_t>(limit) * stride)) {
                    nlohmann::json elements = nlohmann::json::array();
                    PropertyInfo elementProp = inner;
                    elementProp.offset = 0;
                    for (int32_t i = 0; i < limit; ++i) {
                        nlohmann::json element;
                        std::string elementError;
                        if (ReadValueAt(ctx, array.data + static_cast<uintptr_t>(i) * stride,
                                        elementProp, element, &elementError, depth + 1)) {
                            elements.push_back(std::move(element));
                        } else {
                            elements.push_back(elementError);
                        }
                    }
                    result["elements"] = std::move(elements);
                }
            }
        }
        out = std::move(result);
        return true;
    }

    out = {{"size", totalSize}, {"raw_hex", raw_hex(address, totalSize)}};
    return true;
}

bool WriteObjectRef(UeContext& ctx, uintptr_t address, const nlohmann::json& value,
                    std::string* error) {
    if (value.is_null()) {
        return mem::Write<uintptr_t>(address, 0);
    }

    uintptr_t objectValue = 0;
    if (value.is_string()) {
        const std::string text = value.get<std::string>();
        if (auto addressValue = str::ParseUint(text)) {
            objectValue = static_cast<uintptr_t>(*addressValue);
        } else {
            objectValue = ctx.FindObjectPath(text);
            if (!objectValue) {
                if (error) *error = "object path not found: " + text;
                return false;
            }
        }
    } else if (auto number = JsonToUnsigned(value)) {
        objectValue = static_cast<uintptr_t>(*number);
    } else {
        if (error) *error = "object value must be null, address, or path";
        return false;
    }

    if (objectValue && !ctx.IsValidObject(objectValue)) {
        if (error) *error = "object pointer is not a valid UObject";
        return false;
    }
    return mem::Write<uintptr_t>(address, objectValue);
}

bool WriteStructValue(UeContext& ctx, uintptr_t address, const PropertyInfo& prop,
                      const nlohmann::json& value, std::string* error) {
    const Layout& layout = ctx.CurrentLayout();
    const std::string& name = prop.payload_name;
    const size_t size = static_cast<size_t>(std::max(prop.size, 1));

    if (name.find("LinearColor") != std::string::npos) {
        std::vector<double> values;
        if (!VectorComponents(value, 4, values)) {
            if (error) *error = "LinearColor requires {r,g,b,a}";
            return false;
        }
        for (int i = 0; i < 4; ++i) {
            mem::Write<float>(address + static_cast<uintptr_t>(i) * 4, static_cast<float>(values[i]));
        }
        return true;
    }

    if (name.find("Guid") != std::string::npos) {
        std::vector<double> values;
        if (!VectorComponents(value, 4, values)) {
            if (error) *error = "Guid requires {a,b,c,d}";
            return false;
        }
        for (int i = 0; i < 4; ++i) {
            mem::Write<uint32_t>(address + static_cast<uintptr_t>(i) * 4,
                                 static_cast<uint32_t>(values[i]));
        }
        return true;
    }

    size_t count = 0;
    if (name.find("Vector4") != std::string::npos || name.find("Quat") != std::string::npos) {
        count = 4;
    } else if (name.find("Vector") != std::string::npos || name.find("Rotator") != std::string::npos) {
        count = 3;
    } else if (name.find("Vector2D") != std::string::npos) {
        count = 2;
    }

    if (count > 0) {
        std::vector<double> values;
        if (!VectorComponents(value, count, values)) {
            if (error) *error = "struct value requires " + std::to_string(count) + " components";
            return false;
        }
        const bool doubles = layout.large_world_coords && size >= count * 8;
        for (size_t i = 0; i < count; ++i) {
            if (doubles) {
                mem::Write<double>(address + static_cast<uintptr_t>(i) * 8, values[i]);
            } else {
                mem::Write<float>(address + static_cast<uintptr_t>(i) * 4, static_cast<float>(values[i]));
            }
        }
        return true;
    }

    if (value.is_object() && value.contains("raw_hex")) {
        auto bytes = str::Unhex(value["raw_hex"].get<std::string>());
        if (!bytes) {
            if (error) *error = "invalid raw_hex";
            return false;
        }
        if (bytes->size() > size) {
            if (error) *error = "raw_hex is larger than the property";
            return false;
        }
        return mem::Write(address, static_cast<const void*>(bytes->data()), bytes->size());
    }

    if (error) *error = "unsupported struct type; pass raw_hex";
    return false;
}

bool WriteScalarAt(UeContext& ctx, uintptr_t address, const PropertyInfo& prop,
                   const nlohmann::json& value, std::string* error) {
    const std::string& type = prop.type;
    const Layout& layout = ctx.CurrentLayout();

    if (IsBoolType(type)) {
        bool enabled = false;
        if (value.is_boolean()) {
            enabled = value.get<bool>();
        } else if (auto number = JsonToUnsigned(value)) {
            enabled = *number != 0;
        } else {
            if (error) *error = "bool value expected";
            return false;
        }

        uintptr_t byteAddress = address;
        uint8_t mask = 1;
        if (layout.bool_byte_mask >= 0) {
            byteAddress = address + static_cast<uintptr_t>(std::max(layout.bool_byte_offset, 0));
            mask = mem::ReadOr<uint8_t>(prop.address + static_cast<uintptr_t>(layout.bool_byte_mask), 1);
            if (!mask) mask = 1;
        }
        uint8_t byte = mem::ReadOr<uint8_t>(byteAddress, 0);
        byte = enabled ? static_cast<uint8_t>(byte | mask) : static_cast<uint8_t>(byte & ~mask);
        return mem::Write<uint8_t>(byteAddress, byte);
    }

    if (IsSignedType(type)) {
        const auto number = JsonToSigned(value);
        if (!number) {
            if (error) *error = "signed integer expected";
            return false;
        }
        if (prop.size >= 8) return mem::Write<int64_t>(address, *number);
        if (prop.size == 4) {
            if (*number < INT32_MIN || *number > INT32_MAX) { if (error) *error = "int32 out of range"; return false; }
            return mem::Write<int32_t>(address, static_cast<int32_t>(*number));
        }
        if (prop.size == 2) {
            if (*number < INT16_MIN || *number > INT16_MAX) { if (error) *error = "int16 out of range"; return false; }
            return mem::Write<int16_t>(address, static_cast<int16_t>(*number));
        }
        if (*number < INT8_MIN || *number > INT8_MAX) { if (error) *error = "int8 out of range"; return false; }
        return mem::Write<int8_t>(address, static_cast<int8_t>(*number));
    }

    if (IsUnsignedType(type)) {
        const auto number = JsonToUnsigned(value);
        if (!number) {
            if (error) *error = "unsigned integer expected";
            return false;
        }
        if (prop.size >= 8) return mem::Write<uint64_t>(address, *number);
        if (prop.size == 4) {
            if (*number > UINT32_MAX) { if (error) *error = "uint32 out of range"; return false; }
            return mem::Write<uint32_t>(address, static_cast<uint32_t>(*number));
        }
        if (prop.size == 2) {
            if (*number > UINT16_MAX) { if (error) *error = "uint16 out of range"; return false; }
            return mem::Write<uint16_t>(address, static_cast<uint16_t>(*number));
        }
        if (*number > UINT8_MAX) { if (error) *error = "uint8 out of range"; return false; }
        return mem::Write<uint8_t>(address, static_cast<uint8_t>(*number));
    }

    if (TypeIs(type, "FloatProperty")) {
        const auto number = JsonToDouble(value);
        if (!number) { if (error) *error = "number expected"; return false; }
        return mem::Write<float>(address, static_cast<float>(*number));
    }
    if (TypeIs(type, "DoubleProperty")) {
        const auto number = JsonToDouble(value);
        if (!number) { if (error) *error = "number expected"; return false; }
        return mem::Write<double>(address, *number);
    }

    if (IsObjectType(type)) {
        if (TypeIs(type, "WeakObjectProperty") || TypeIs(type, "SoftObjectProperty") ||
            TypeIs(type, "LazyObjectProperty")) {
            if (value.is_object() && value.contains("raw_hex")) {
                auto bytes = str::Unhex(value["raw_hex"].get<std::string>());
                if (!bytes || bytes->size() > static_cast<size_t>(std::max(prop.size, 8))) {
                    if (error) *error = "invalid raw_hex";
                    return false;
                }
                return mem::Write(address, static_cast<const void*>(bytes->data()), bytes->size());
            }
            if (error) *error = "weak/soft object writes require raw_hex";
            return false;
        }
        return WriteObjectRef(ctx, address, value, error);
    }

    if (IsNameType(type)) {
        uint32_t index = 0;
        uint32_t number = 0;
        if (value.is_number_unsigned()) {
            index = value.get<uint32_t>();
        } else if (value.is_object() && value.contains("index")) {
            index = value["index"].get<uint32_t>();
            if (value.contains("number")) number = value["number"].get<uint32_t>();
        } else {
            if (error) *error = "FName value requires {index, number}";
            return false;
        }
        if (!mem::Write<uint32_t>(address, index)) return false;
        if (layout.fname_size >= 8) {
            return mem::Write<uint32_t>(address + 4, number);
        }
        return true;
    }

    if (IsStructType(type)) {
        return WriteStructValue(ctx, address, prop, value, error);
    }

    if (value.is_object() && value.contains("raw_hex")) {
        auto bytes = str::Unhex(value["raw_hex"].get<std::string>());
        if (!bytes) {
            if (error) *error = "invalid raw_hex";
            return false;
        }
        const size_t limit = static_cast<size_t>(std::max(prop.size, 1)) * static_cast<size_t>(std::max(prop.array_dim, 1));
        if (bytes->size() > limit) {
            if (error) *error = "raw_hex exceeds property size";
            return false;
        }
        return mem::Write(address, static_cast<const void*>(bytes->data()), bytes->size());
    }

    if (error) *error = "unsupported property type: " + type;
    return false;
}

}

std::string UeContext::FieldName(uintptr_t field) {
    if (!field || layout_.ffield_name <= 0) {
        return {};
    }
    return NameFromFName(field + static_cast<uintptr_t>(layout_.ffield_name));
}

std::string UeContext::FieldTypeName(uintptr_t field) {
    if (!field || layout_.ffield_class <= 0) {
        return {};
    }
    const uintptr_t fieldClass = mem::ReadOr<uintptr_t>(
        field + static_cast<uintptr_t>(layout_.ffield_class), 0);
    if (!fieldClass) {
        return {};
    }
    const uintptr_t nameAddress = fieldClass + static_cast<uintptr_t>(std::max(layout_.ffieldclass_name, 0));
    std::string name = NameFromFName(nameAddress);
    if (name.rfind("Name_", 0) == 0) {
        return {};
    }
    return name;
}

uintptr_t UeContext::TargetStruct(uintptr_t objectOrClass) {
    if (!objectOrClass) {
        return 0;
    }
    if (IsClassObject(objectOrClass)) {
        return objectOrClass;
    }
    if (function_meta_ && IsA(objectOrClass, function_meta_)) {
        return objectOrClass;
    }
    if (ClassName(objectOrClass).find("Function") != std::string::npos) {
        return objectOrClass;
    }
    return ClassOf(objectOrClass);
}

bool UeContext::DecodeProperty(uintptr_t property, PropertyInfo& info) {
    if (!property || !mem::IsReadable(property, 0x20)) {
        return false;
    }

    info = PropertyInfo{};
    info.address = property;
    info.name = FieldName(property);
    info.type = FieldTypeName(property);

    const uint32_t rawDim = layout_.fproperty_array_dim > 0
        ? mem::ReadOr<uint32_t>(property + static_cast<uintptr_t>(layout_.fproperty_array_dim), 1)
        : 1;
    info.array_dim = (rawDim == 0 || rawDim > 0x10000) ? 1 : static_cast<int32_t>(rawDim);

    const uint32_t rawSize = layout_.fproperty_element_size > 0
        ? mem::ReadOr<uint32_t>(property + static_cast<uintptr_t>(layout_.fproperty_element_size), 0)
        : 0;
    const uint32_t rawOffset = layout_.fproperty_offset > 0
        ? mem::ReadOr<uint32_t>(property + static_cast<uintptr_t>(layout_.fproperty_offset), 0)
        : 0;

    info.size = DecodeFortniteSize(rawSize, layout_);
    info.offset = DecodeFortniteOffset(rawOffset, layout_);
    info.flags = layout_.fproperty_flags > 0
        ? DecodeFortniteFlags(mem::ReadOr<uint64_t>(property + static_cast<uintptr_t>(layout_.fproperty_flags), 0), layout_)
        : 0;

    if (IsBoolType(info.type) && info.size <= 0) {
        info.size = 1;
    }
    if (info.size <= 0 || info.size > 0x1000000 || info.offset < 0 || info.offset > 0x1000000) {
        return false;
    }

    if (layout_.property_payload > 0) {
        info.payload = mem::ReadOr<uintptr_t>(property + static_cast<uintptr_t>(layout_.property_payload), 0);
        if (info.payload && mem::IsCanonical(info.payload)) {
            if (IsStructType(info.type) || IsObjectType(info.type) || IsArrayType(info.type)) {
                if (IsArrayType(info.type)) {
                    PropertyInfo inner;
                    if (DecodeProperty(info.payload, inner)) {
                        info.payload_name = inner.type;
                    }
                } else if (IsValidObject(info.payload)) {
                    info.payload_name = ObjectName(info.payload);
                }
            }
        }
    }

    return !info.name.empty();
}

std::vector<PropertyInfo> UeContext::ListProperties(uintptr_t target, bool includeInherited,
                                                     std::string* error) {
    std::vector<PropertyInfo> result;
    uintptr_t structObject = TargetStruct(target);
    if (!structObject || !layout_.ustruct_child_properties) {
        if (error) *error = "property chain is not configured";
        return result;
    }

    std::unordered_set<uintptr_t> seen;
    std::unordered_set<std::string> seenNames;
    std::unordered_set<uintptr_t> structs;
    int depth = 0;

    while (structObject && depth++ < 128 && structs.insert(structObject).second) {
        if (layout_.child_properties_is_array) {
            uintptr_t data = 0;
            int32_t num = 0;
            if (mem::Read(structObject + static_cast<uintptr_t>(layout_.ustruct_child_properties), data) &&
                mem::Read(structObject + static_cast<uintptr_t>(layout_.ustruct_child_properties) + 8, num)) {
                if (data && num > 0 && num <= 8192) {
                    for (int32_t i = 0; i < num; ++i) {
                        const uintptr_t property = mem::ReadOr<uintptr_t>(
                            data + static_cast<uintptr_t>(i) * sizeof(uintptr_t), 0);
                        if (!property || !seen.insert(property).second) continue;
                        PropertyInfo info;
                        if (DecodeProperty(property, info) && seenNames.insert(info.name).second) {
                            result.push_back(std::move(info));
                        }
                    }
                }
            }
        } else {
            uintptr_t property = StructChildProperties(structObject);
            int guard = 0;
            while (property && guard++ < 8192 && seen.insert(property).second) {
                PropertyInfo info;
                if (DecodeProperty(property, info) && seenNames.insert(info.name).second) {
                    result.push_back(std::move(info));
                }
                property = FieldNext(property);
            }
        }

        if (!includeInherited) {
            break;
        }
        structObject = StructSuper(structObject);
    }

    if (result.empty() && !layout_.HasPropertyChain()) {
        if (error) *error = "property chain is not available";
    }
    return result;
}

bool UeContext::FindProperty(uintptr_t target, const std::string& name, bool includeInherited,
                             PropertyInfo& out) {
    if (name.empty()) {
        return false;
    }
    for (const auto& property : ListProperties(target, includeInherited, nullptr)) {
        if (str::IEquals(property.name, name)) {
            out = property;
            return true;
        }
    }
    return false;
}

bool UeContext::ReadPropertyValue(uintptr_t object, const PropertyInfo& property,
                                  nlohmann::json& out, std::string* error) {
    if (!IsValidObject(object)) {
        if (error) *error = "object is invalid";
        return false;
    }

    uintptr_t base = object;
    if (IsClassObject(object)) {
        uintptr_t cdo = 0;
        if (layout_.uclass_class_default_object > 0) {
            cdo = mem::ReadOr<uintptr_t>(
                object + static_cast<uintptr_t>(layout_.uclass_class_default_object), 0);
        }
        if (!cdo) {
            auto query = ObjectsOfClass(object, false, 0, 4096, nullptr);
            for (uintptr_t candidate : query.objects) {
                const uint32_t flags = mem::ReadOr<uint32_t>(
                    candidate + static_cast<uintptr_t>(layout_.object_flags), 0);
                if ((flags & RF_ClassDefaultObject) != 0) {
                    cdo = candidate;
                    break;
                }
            }
        }
        if (!cdo || !IsValidObject(cdo)) {
            if (error) *error = "class default object could not be resolved";
            return false;
        }
        base = cdo;
    }

    return ReadValueAt(*this, base, property, out, error);
}

bool UeContext::WritePropertyRaw(uintptr_t object, const PropertyInfo& property,
                                 const std::vector<uint8_t>& bytes, std::string* error) {
    if (!IsValidObject(object)) {
        if (error) *error = "object is invalid";
        return false;
    }
    const size_t limit = static_cast<size_t>(std::max(property.size, 1)) *
                         static_cast<size_t>(std::max(property.array_dim, 1));
    if (bytes.size() > limit) {
        if (error) *error = "raw data is larger than the property";
        return false;
    }
    return mem::Write(object + static_cast<uintptr_t>(property.offset),
                     static_cast<const void*>(bytes.data()), bytes.size());
}

bool UeContext::WritePropertyValue(uintptr_t object, const PropertyInfo& property,
                                   const nlohmann::json& value, std::string* error) {
    if (!IsValidObject(object)) {
        if (error) *error = "object is invalid";
        return false;
    }
    if (IsStringType(property.type) || IsArrayType(property.type) ||
        TypeIs(property.type, "TextProperty") || TypeIs(property.type, "DelegateProperty") ||
        TypeIs(property.type, "MulticastDelegateProperty")) {
        if (value.is_object() && value.contains("raw_hex") && !IsStringType(property.type)) {
            auto bytes = str::Unhex(value["raw_hex"].get<std::string>());
            if (!bytes) {
                if (error) *error = "invalid raw_hex";
                return false;
            }
            return WritePropertyRaw(object, property, *bytes, error);
        }
        if (error) *error = "this property type must be written with raw_hex or dedicated engine code";
        return false;
    }

    uintptr_t base = object;
    if (IsClassObject(object)) {
        uintptr_t cdo = 0;
        if (layout_.uclass_class_default_object > 0) {
            cdo = mem::ReadOr<uintptr_t>(
                object + static_cast<uintptr_t>(layout_.uclass_class_default_object), 0);
        }
        if (!cdo) {
            if (error) *error = "class default object is unknown; pass the CDO address instead";
            return false;
        }
        base = cdo;
    }

    return WriteScalarAt(*this, base + static_cast<uintptr_t>(property.offset), property, value, error);
}

bool UeContext::DecodeFunction(uintptr_t function, FunctionInfo& out) {
    if (!IsValidObject(function)) {
        return false;
    }

    std::string className = ClassName(function);
    if (function_meta_) {
        if (!IsA(function, function_meta_)) {
            return false;
        }
    } else if (className.find("Function") == std::string::npos) {
        return false;
    }

    out = FunctionInfo{};
    out.address = function;
    out.name = ObjectName(function);
    out.class_name = std::move(className);
    out.flags = layout_.ufunction_flags >= 0
        ? mem::ReadOr<uint32_t>(function + static_cast<uintptr_t>(layout_.ufunction_flags), 0)
        : 0;
    out.path = ObjectPath(function);
    return !out.name.empty();
}

std::vector<FunctionInfo> UeContext::ListFunctions(uintptr_t target, bool includeInherited,
                                                    std::string* error) {
    std::vector<FunctionInfo> result;
    uintptr_t structObject = TargetStruct(target);
    if (!structObject || !layout_.ustruct_children) {
        if (error) *error = "struct children are not configured";
        return result;
    }

    std::unordered_set<uintptr_t> structs;
    std::unordered_set<std::string> names;
    int depth = 0;

    while (structObject && depth++ < 128 && structs.insert(structObject).second) {
        std::vector<uintptr_t> fields;

        if (layout_.children_is_array) {
            uintptr_t data = 0;
            int32_t num = 0;
            if (mem::Read(structObject + static_cast<uintptr_t>(layout_.ustruct_children), data) &&
                mem::Read(structObject + static_cast<uintptr_t>(layout_.ustruct_children) + 8, num)) {
                if (data && num > 0 && num <= 65536) {
                    for (int32_t i = 0; i < num; ++i) {
                        const uintptr_t field = mem::ReadOr<uintptr_t>(
                            data + static_cast<uintptr_t>(i) * sizeof(uintptr_t), 0);
                        if (field) fields.push_back(field);
                    }
                }
            }
        } else {
            uintptr_t field = StructChildren(structObject);
            int guard = 0;
            while (field && guard++ < 65536) {
                fields.push_back(field);
                field = mem::ReadOr<uintptr_t>(field + static_cast<uintptr_t>(layout_.ufield_next), 0);
            }
        }

        for (uintptr_t field : fields) {
            FunctionInfo info;
            if (DecodeFunction(field, info) && names.insert(info.name).second) {
                result.push_back(std::move(info));
            }
        }

        if (!includeInherited) {
            break;
        }
        structObject = StructSuper(structObject);
    }

    return result;
}

uintptr_t UeContext::FindFunction(uintptr_t target, const std::string& name, bool includeInherited) {
    if (name.empty()) return 0;
    for (const auto& function : ListFunctions(target, includeInherited, nullptr)) {
        if (str::IEquals(function.name, name) || str::IEquals(function.path, name) ||
            str::EndsWith(str::ToLower(function.path), str::ToLower("." + name))) {
            return function.address;
        }
    }
    return 0;
}

int32_t UeContext::FunctionParmsSize(uintptr_t function, std::string* error) {
    if (!IsValidObject(function)) {
        if (error) *error = "function is invalid";
        return 0;
    }

    int32_t configured = 0;
    if (layout_.ufunction_parms_size > 0) {
        configured = mem::ReadOr<uint16_t>(
            function + static_cast<uintptr_t>(layout_.ufunction_parms_size), 0);
    }

    const auto properties = ListProperties(function, false, nullptr);
    int32_t computed = 0;
    for (const auto& property : properties) {
        const int64_t end = static_cast<int64_t>(property.offset) +
                            static_cast<int64_t>(property.size) * std::max(property.array_dim, 1);
        if (end > INT32_MAX) {
            if (error) *error = "parameter size overflow";
            return 0;
        }
        computed = std::max<int32_t>(computed, static_cast<int32_t>(end));
    }
    if (computed > 0) {
        computed = (computed + 15) & ~15;
    }

    const int32_t result = std::max(configured, computed);
    if (result > 0x100000) {
        if (error) *error = "parameter size is implausible";
        return 0;
    }
    return result;
}

bool UeContext::WriteParamValue(uintptr_t params, const PropertyInfo& property,
                                const nlohmann::json& value,
                                std::vector<std::wstring>& stringKeepAlive,
                                std::vector<std::vector<wchar_t>>& bufferKeepAlive,
                                std::string* error) {
    (void)bufferKeepAlive;
    if (!params) {
        if (error) *error = "parameter buffer is null";
        return false;
    }

    const uintptr_t address = params + static_cast<uintptr_t>(property.offset);

    if (IsStringType(property.type)) {
        std::string text;
        if (value.is_string()) {
            text = value.get<std::string>();
        } else if (value.is_object() && value.contains("value")) {
            text = value["value"].get<std::string>();
        } else if (!value.is_null()) {
            if (error) *error = "string parameter expected";
            return false;
        }

        const std::wstring wide = str::Widen(text);
        if (wide.size() > 2040) {
            if (error) *error = "string parameter is too long (max 2040 chars)";
            return false;
        }

        stringKeepAlive.emplace_back(2048, L'\0');
        std::wstring& buffer = stringKeepAlive.back();
        std::copy(wide.begin(), wide.end(), buffer.begin());
        buffer[wide.size()] = L'\0';

        struct FString {
            wchar_t* data;
            int32_t num;
            int32_t max;
        } string{};
        string.data = buffer.data();
        string.num = static_cast<int32_t>(wide.size() + 1);
        string.max = static_cast<int32_t>(buffer.size());

        return mem::Write(address, string);
    }

    if (IsNameType(property.type)) {
        uint32_t index = 0;
        uint32_t number = 0;
        if (value.is_number_unsigned()) {
            index = value.get<uint32_t>();
        } else if (value.is_object() && value.contains("index")) {
            index = value["index"].get<uint32_t>();
            if (value.contains("number")) number = value["number"].get<uint32_t>();
        } else {
            if (error) *error = "FName parameter requires {index, number}";
            return false;
        }
        if (!mem::Write<uint32_t>(address, index)) return false;
        if (layout_.fname_size >= 8) {
            return mem::Write<uint32_t>(address + 4, number);
        }
        return true;
    }

    if (IsObjectType(property.type)) {
        return WriteObjectRef(*this, address, value, error);
    }

    return WriteScalarAt(*this, address, property, value, error);
}

bool UeContext::ReadParamValue(uintptr_t params, const PropertyInfo& property,
                               nlohmann::json& out, std::string* error) {
    return ReadValueAt(*this, params, property, out, error);
}

bool UeContext::IsPropertyCandidate(uintptr_t address) {
    if (!mem::IsCanonical(address) || !mem::IsReadable(address, 0x20) ||
        layout_.ffield_name <= 0) {
        return false;
    }
    const uint32_t index = mem::ReadOr<uint32_t>(
        address + static_cast<uintptr_t>(layout_.ffield_name), 0);
    if (index == 0 || index > 0x800000) {
        return false;
    }
    const std::string name = NameFromIndex(index);
    if (name.empty() || name.rfind("Name_", 0) == 0 || name.size() > 128) {
        return false;
    }
    for (char c : name) {
        if (c < 32 || c > 126) return false;
    }

    if (layout_.ffield_class > 0) {
        const std::string type = FieldTypeName(address);
        if (!type.empty() && type.find("Property") == std::string::npos) {
            return false;
        }
    }
    return true;
}

bool UeContext::AutoTuneFieldFields(uintptr_t firstProperty, std::string* error) {
    (void)error;
    if (!firstProperty || !IsPropertyCandidate(firstProperty)) {
        return false;
    }

    if (layout_.ffield_name <= 0) {
        for (int offset = 0; offset <= 0x40; offset += 4) {
            const uint32_t index = mem::ReadOr<uint32_t>(firstProperty + static_cast<uintptr_t>(offset), 0);
            if (index == 0 || index > 0x800000) continue;
            const std::string name = NameFromIndex(index);
            if (!name.empty() && name.rfind("Name_", 0) != 0 && name.size() <= 128) {
                layout_.ffield_name = offset;
                FMCP_LOGI("AutoTune: FField::Name -> 0x%X", offset);
                break;
            }
        }
    }

    if (layout_.ffield_next <= 0) {
        int bestOffset = -1;
        int bestLength = 0;
        for (int offset = 8; offset <= 0x40; offset += 8) {
            uintptr_t current = firstProperty;
            int length = 0;
            for (int depth = 0; depth < 16; ++depth) {
                const uintptr_t next = mem::ReadOr<uintptr_t>(current + static_cast<uintptr_t>(offset), 0);
                if (!next || !IsPropertyCandidate(next)) break;
                current = next;
                ++length;
            }
            if (length > bestLength) {
                bestLength = length;
                bestOffset = offset;
            }
        }
        if (bestOffset > 0) {
            layout_.ffield_next = bestOffset;
            FMCP_LOGI("AutoTune: FField::Next -> 0x%X (chain %d)", bestOffset, bestLength);
        }
    }

    if (layout_.ffield_class <= 0) {
        for (int offset = 0; offset <= 0x20; offset += 8) {
            const uintptr_t fieldClass = mem::ReadOr<uintptr_t>(
                firstProperty + static_cast<uintptr_t>(offset), 0);
            if (!fieldClass || !mem::IsCanonical(fieldClass)) continue;
            const uintptr_t nameAddress = fieldClass +
                static_cast<uintptr_t>(std::max(layout_.ffieldclass_name, 0));
            const std::string type = NameFromFName(nameAddress);
            if (type.find("Property") != std::string::npos) {
                layout_.ffield_class = offset;
                FMCP_LOGI("AutoTune: FField::ClassPrivate -> 0x%X (%s)", offset, type.c_str());
                break;
            }
        }
    }

    return layout_.ffield_name > 0 && layout_.ffield_next > 0;
}

bool UeContext::AutoTuneStructFields(uintptr_t actorClass, std::string* error) {
    (void)error;
    const uintptr_t actorMeta = ClassOf(actorClass);
    const int start = std::max(layout_.ufield_next + 8, 0x30);
    int superOffset = layout_.ustruct_super;
    int childrenOffset = layout_.ustruct_children;
    int propertiesOffset = layout_.ustruct_child_properties;
    bool childrenArray = layout_.children_is_array;
    bool propertiesArray = layout_.child_properties_is_array;

    for (int offset = start; offset <= 0x200; offset += 8) {
        uintptr_t value = 0;
        if (!mem::Read(actorClass + static_cast<uintptr_t>(offset), value) || !value ||
            !mem::IsCanonical(value)) {
            continue;
        }

        if (superOffset <= 0 && IsValidObject(value) && ClassOf(value) == actorMeta) {
            const std::string name = ObjectName(value);
            if (name == "Object" || name == "CoreUObject.Object" || name.find("Object") != std::string::npos) {
                superOffset = offset;
                FMCP_LOGI("AutoTune: UStruct::SuperStruct -> 0x%X", offset);
                continue;
            }
        }

        if (childrenOffset <= 0) {
            if (IsValidObject(value) && OuterOf(value) == actorClass) {
                childrenOffset = offset;
                childrenArray = false;
                FMCP_LOGI("AutoTune: UStruct::Children -> 0x%X", offset);
                continue;
            }
            int32_t count = mem::ReadOr<int32_t>(actorClass + static_cast<uintptr_t>(offset) + 8, 0);
            if (count > 0 && count <= 65536 && !childrenArray) {
                const uintptr_t first = mem::ReadOr<uintptr_t>(value, 0);
                if (IsValidObject(first) && OuterOf(first) == actorClass) {
                    childrenOffset = offset;
                    childrenArray = true;
                    FMCP_LOGI("AutoTune: UStruct::Children -> 0x%X (array)", offset);
                    continue;
                }
            }
        }

        if (propertiesOffset <= 0) {
            if (IsPropertyCandidate(value)) {
                propertiesOffset = offset;
                propertiesArray = false;
                FMCP_LOGI("AutoTune: UStruct::ChildProperties -> 0x%X", offset);
                continue;
            }
            int32_t count = mem::ReadOr<int32_t>(actorClass + static_cast<uintptr_t>(offset) + 8, 0);
            if (count > 0 && count <= 65536 && !propertiesArray) {
                const uintptr_t first = mem::ReadOr<uintptr_t>(value, 0);
                if (IsPropertyCandidate(first)) {
                    propertiesOffset = offset;
                    propertiesArray = true;
                    FMCP_LOGI("AutoTune: UStruct::ChildProperties -> 0x%X (array)", offset);
                }
            }
        }
    }

    if (propertiesOffset > 0 && layout_.ffield_next <= 0) {
        uintptr_t firstProperty = 0;
        if (propertiesArray) {
            const uintptr_t data = mem::ReadOr<uintptr_t>(
                actorClass + static_cast<uintptr_t>(propertiesOffset), 0);
            firstProperty = mem::ReadOr<uintptr_t>(data, 0);
        } else {
            firstProperty = mem::ReadOr<uintptr_t>(
                actorClass + static_cast<uintptr_t>(propertiesOffset), 0);
        }
        if (firstProperty) {
            AutoTuneFieldFields(firstProperty, nullptr);
        }
    }

    layout_.ustruct_super = superOffset;
    layout_.ustruct_children = childrenOffset;
    layout_.ustruct_child_properties = propertiesOffset;
    layout_.children_is_array = childrenArray;
    layout_.child_properties_is_array = propertiesArray;

    return layout_.ustruct_children > 0 && layout_.ustruct_child_properties > 0 &&
           layout_.ffield_name > 0 && layout_.ffield_next > 0;
}

bool UeContext::AutoTuneLayout(std::string* error) {
    if (!static_find_object_ || !report_.names) {
        if (error) *error = "auto tune requires static_find_object and names";
        return false;
    }
    if (layout_.HasPropertyChain() && layout_.ustruct_children > 0 && layout_.ustruct_super > 0) {
        return true;
    }

    uintptr_t actorClass = FindObjectPath("Engine.Actor");
    if (!actorClass) actorClass = FindObjectPath("/Script/Engine.Actor");
    if (!actorClass) {
        if (error) *error = "Engine.Actor was not found";
        return false;
    }

    if (!AutoTuneStructFields(actorClass, error)) {
        if (error && error->empty()) *error = "UStruct field probe failed";
        return false;
    }

    const bool ok = layout_.HasPropertyChain() && layout_.ustruct_children > 0;
    if (ok) {
        report_.messages.emplace_back(str::Format(
            "layout tuned: super=0x%X children=0x%X%s child_properties=0x%X%s ffield_next=0x%X ffield_name=0x%X",
            layout_.ustruct_super, layout_.ustruct_children, layout_.children_is_array ? "(array)" : "",
            layout_.ustruct_child_properties, layout_.child_properties_is_array ? "(array)" : "",
            layout_.ffield_next, layout_.ffield_name));
    }
    return ok;
}

}

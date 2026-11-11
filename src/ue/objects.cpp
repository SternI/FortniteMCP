#include "ue/context.h"

#include "core/log.h"
#include "core/memory.h"
#include "core/strings.h"

#include <algorithm>
#include <cstring>

namespace fmcp::ue {

namespace {

#if defined(_MSC_VER)
__declspec(noinline)
#endif
bool InvokeGetObjectsOfClass(uintptr_t function, uintptr_t classObject, void* out,
                             bool includeDerived, uint32_t excludeFlags) {
    __try {
        using Fn = void (*)(uintptr_t, void*, bool, uint32_t, uint32_t);
        reinterpret_cast<Fn>(function)(classObject, out, includeDerived, excludeFlags, 0);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}

uintptr_t UeContext::StructChildProperties(uintptr_t structObject) const {
    if (!structObject || layout_.ustruct_child_properties <= 0) {
        return 0;
    }
    return mem::ReadOr<uintptr_t>(structObject + static_cast<uintptr_t>(layout_.ustruct_child_properties), 0);
}

uintptr_t UeContext::StructChildren(uintptr_t structObject) const {
    if (!structObject || layout_.ustruct_children <= 0) {
        return 0;
    }
    return mem::ReadOr<uintptr_t>(structObject + static_cast<uintptr_t>(layout_.ustruct_children), 0);
}

uintptr_t UeContext::StructSuper(uintptr_t structObject) const {
    if (!structObject || layout_.ustruct_super <= 0) {
        return 0;
    }
    return mem::ReadOr<uintptr_t>(structObject + static_cast<uintptr_t>(layout_.ustruct_super), 0);
}

uintptr_t UeContext::FieldNext(uintptr_t field) const {
    if (!field || layout_.ffield_next <= 0) {
        return 0;
    }
    return mem::ReadOr<uintptr_t>(field + static_cast<uintptr_t>(layout_.ffield_next), 0);
}

UeContext::ObjectQuery UeContext::ObjectsOfClass(uintptr_t classObject, bool includeDerived,
                                                  uint32_t excludeFlags, size_t maxResults,
                                                  std::string* error) {
    ObjectQuery result;
    if (!IsValidObject(classObject)) {
        if (error) *error = "class object is invalid";
        return result;
    }

    maxResults = std::clamp<size_t>(maxResults, 1, 200000);

    if (get_objects_of_class_) {
        struct ArrayOut {
            uintptr_t data;
            int32_t num;
            int32_t max;
        };

        constexpr int32_t kCapacity = 262144;
        std::vector<uintptr_t> storage(static_cast<size_t>(kCapacity));
        ArrayOut out{reinterpret_cast<uintptr_t>(storage.data()), 0, kCapacity};

        if (!InvokeGetObjectsOfClass(get_objects_of_class_, classObject, &out, includeDerived,
                                     excludeFlags)) {
            if (error) *error = "GetObjectsOfClass faulted";
            FMCP_LOGW("GetObjectsOfClass faulted");
            return result;
        }

        if (out.num < 0 || out.num > 8000000 || !out.data) {
            if (error) *error = "native GetObjectsOfClass returned an invalid array";
            return result;
        }

        const bool engineAllocated = out.data != reinterpret_cast<uintptr_t>(storage.data());
        if (engineAllocated) {
            FMCP_LOGW("GetObjectsOfClass reallocated beyond %d entries; engine allocation will leak",
                      kCapacity);
        }

        const int32_t count = out.num;
        if (!mem::IsReadable(out.data, static_cast<size_t>(count) * sizeof(uintptr_t))) {
            if (error) *error = "native GetObjectsOfClass array is unreadable";
            return result;
        }

        result.total = static_cast<size_t>(count);
        result.objects.reserve(std::min<size_t>(result.total, maxResults));

        for (int32_t i = 0; i < count && result.objects.size() < maxResults; ++i) {
            const uintptr_t object = mem::ReadOr<uintptr_t>(
                out.data + static_cast<uintptr_t>(i) * sizeof(uintptr_t), 0);
            if (object && IsValidObject(object)) {
                result.objects.push_back(object);
            }
        }

        result.truncated = result.total > result.objects.size();
        return result;
    }

    if (!report_.objects) {
        if (error) *error = "neither get_objects_of_class nor an object array is configured";
        return result;
    }

    const Config& config = Config::Get();
    const int chunkBits = std::clamp(config.ue.objects.chunk_bits, 8, 24);
    const size_t chunkSize = static_cast<size_t>(1) << chunkBits;
    const int itemSize = std::clamp(config.ue.objects.item_size, 8, 0x200);
    const int itemOffset = config.ue.objects.item_object_offset;
    if (itemOffset < 0 || static_cast<size_t>(itemOffset) + sizeof(uintptr_t) > static_cast<size_t>(itemSize)) {
        if (error) *error = "invalid object item layout";
        return result;
    }

    const size_t maxObjects = static_cast<size_t>(std::max(config.ue.objects.max_objects, 0));
    const size_t chunkCount = (maxObjects + chunkSize - 1) / chunkSize;
    const int emptyStop = std::max(config.ue.objects.empty_chunk_stop, 1);
    int emptyRun = 0;

    constexpr size_t kChunkBlockItems = 4096;
    std::vector<uint8_t> buffer(static_cast<size_t>(itemSize) * kChunkBlockItems);

    for (size_t chunkIndex = 0; chunkIndex < chunkCount; ++chunkIndex) {
        uintptr_t chunk = 0;
        if (!mem::Read(objects_table_ + chunkIndex * sizeof(uintptr_t), chunk) ||
            !mem::IsCanonical(chunk)) {
            if (++emptyRun >= emptyStop) {
                break;
            }
            continue;
        }
        emptyRun = 0;

        for (size_t item = 0; item < chunkSize;) {
            const size_t count = std::min(kChunkBlockItems, chunkSize - item);
            const size_t bytes = count * static_cast<size_t>(itemSize);
            if (!mem::Read(chunk + item * static_cast<size_t>(itemSize), buffer.data(), bytes)) {
                item += count;
                continue;
            }

            for (size_t i = 0; i < count; ++i) {
                const auto* base = buffer.data() + i * static_cast<size_t>(itemSize);
                uintptr_t object = 0;
                memcpy(&object, base + itemOffset, sizeof(object));
                if (!object || !IsValidObject(object)) {
                    continue;
                }

                const uint32_t flags = mem::ReadOr<uint32_t>(
                    object + static_cast<uintptr_t>(layout_.object_flags), 0);
                if (excludeFlags && (flags & excludeFlags) != 0) {
                    continue;
                }

                bool match = false;
                if (includeDerived) {
                    match = IsA(object, classObject);
                } else {
                    match = ClassOf(object) == classObject;
                }
                if (!match) {
                    continue;
                }

                ++result.total;
                if (result.objects.size() < maxResults) {
                    result.objects.push_back(object);
                } else {
                    result.truncated = true;
                    return result;
                }
            }

            item += count;
        }
    }

    return result;
}

UeContext::ObjectQuery UeContext::IterateObjects(size_t maxResults, std::string* error) {
    ObjectQuery result;
    if (!report_.objects) {
        if (error) *error = "object array is not configured";
        return result;
    }

    maxResults = std::clamp<size_t>(maxResults, 1, 200000);

    const Config& config = Config::Get();
    const int chunkBits = std::clamp(config.ue.objects.chunk_bits, 8, 24);
    const size_t chunkSize = static_cast<size_t>(1) << chunkBits;
    const int itemSize = std::clamp(config.ue.objects.item_size, 8, 0x200);
    const int itemOffset = config.ue.objects.item_object_offset;
    if (itemOffset < 0 || static_cast<size_t>(itemOffset) + sizeof(uintptr_t) > static_cast<size_t>(itemSize)) {
        if (error) *error = "invalid object item layout";
        return result;
    }

    const size_t maxObjects = static_cast<size_t>(std::max(config.ue.objects.max_objects, 0));
    const size_t chunkCount = (maxObjects + chunkSize - 1) / chunkSize;
    const int emptyStop = std::max(config.ue.objects.empty_chunk_stop, 1);
    int emptyRun = 0;

    constexpr size_t kChunkBlockItems = 4096;
    std::vector<uint8_t> buffer(static_cast<size_t>(itemSize) * kChunkBlockItems);

    for (size_t chunkIndex = 0; chunkIndex < chunkCount; ++chunkIndex) {
        uintptr_t chunk = 0;
        if (!mem::Read(objects_table_ + chunkIndex * sizeof(uintptr_t), chunk) ||
            !mem::IsCanonical(chunk)) {
            if (++emptyRun >= emptyStop) break;
            continue;
        }
        emptyRun = 0;

        for (size_t item = 0; item < chunkSize;) {
            const size_t count = std::min(kChunkBlockItems, chunkSize - item);
            const size_t bytes = count * static_cast<size_t>(itemSize);
            if (!mem::Read(chunk + item * static_cast<size_t>(itemSize), buffer.data(), bytes)) {
                item += count;
                continue;
            }

            for (size_t i = 0; i < count; ++i) {
                const auto* base = buffer.data() + i * static_cast<size_t>(itemSize);
                uintptr_t object = 0;
                memcpy(&object, base + itemOffset, sizeof(object));
                if (!object || !IsValidObject(object)) {
                    continue;
                }
                ++result.total;
                if (result.objects.size() < maxResults) {
                    result.objects.push_back(object);
                } else {
                    result.truncated = true;
                    return result;
                }
            }

            item += count;
        }
    }

    return result;
}

}

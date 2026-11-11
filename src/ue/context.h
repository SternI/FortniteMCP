#pragma once

#include "core/config.h"
#include "ue/game_thread.h"
#include "ue/layout.h"

#include <cstdint>
#include <functional>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace fmcp::ue {

struct ObjectInfo {
    uintptr_t address = 0;
    uintptr_t class_address = 0;
    uintptr_t outer = 0;
    uint32_t name_index = 0;
    uint64_t name_raw = 0;
    int32_t internal_index = 0;
    uint32_t flags = 0;
    std::string name;
    std::string class_name;
    std::string path;
};

struct PropertyInfo {
    uintptr_t address = 0;
    std::string name;
    std::string type;
    int32_t offset = 0;
    int32_t size = 0;
    int32_t array_dim = 1;
    uint64_t flags = 0;
    uintptr_t payload = 0;
    std::string payload_name;
};

struct FunctionInfo {
    uintptr_t address = 0;
    std::string name;
    std::string path;
    uint32_t flags = 0;
    std::string class_name;
};

struct ResolveReport {
    bool resolved = false;
    bool static_find_object = false;
    bool get_objects_of_class = false;
    bool process_event = false;
    bool names = false;
    bool objects = false;
    bool layout = false;
    bool properties = false;
    bool functions = false;
    bool game_thread = false;
    bool gworld = false;
    bool gengine = false;
    std::vector<std::string> messages;
    std::vector<std::string> warnings;
};

class UeContext {
public:
    static UeContext& Get();

    bool Resolve(bool force = false);
    void Shutdown();
    void Invalidate();

    [[nodiscard]] const ResolveReport& Report() const { return report_; }
    [[nodiscard]] const Layout& CurrentLayout() const { return layout_; }
    [[nodiscard]] bool NamesReady() const { return report_.names; }
    [[nodiscard]] bool ObjectsReady() const { return report_.objects; }
    [[nodiscard]] bool PropertiesReady() const { return report_.properties; }
    [[nodiscard]] bool FunctionsReady() const { return report_.functions; }
    [[nodiscard]] bool GameThreadHooked() const;
    [[nodiscard]] uintptr_t ModuleBase() const { return module_base_; }
    [[nodiscard]] size_t ModuleSize() const { return module_size_; }
    [[nodiscard]] uintptr_t StaticFindObjectAddress() const { return static_find_object_; }
    [[nodiscard]] uintptr_t GetObjectsOfClassAddress() const { return get_objects_of_class_; }
    [[nodiscard]] uintptr_t ProcessEventAddress() const { return process_event_; }
    [[nodiscard]] uintptr_t NamesBase() const { return names_base_; }
    [[nodiscard]] uintptr_t NamesTable() const { return names_table_; }
    [[nodiscard]] uintptr_t NamesFunctionAddress() const { return names_function_; }
    [[nodiscard]] uintptr_t ObjectsTable() const { return objects_table_; }
    [[nodiscard]] uintptr_t GWorldSlot() const { return gworld_slot_; }
    [[nodiscard]] uintptr_t GEngineSlot() const { return gengine_slot_; }

    nlohmann::json Status();

    struct FNameLookup {
        bool backend = false;
        bool faulted = false;
        std::string name;
    };

    std::string NameFromIndex(uint32_t index);
    std::string NameFromFName(uintptr_t address);
    FNameLookup LookupFName(uint32_t index, uint32_t number);
    std::string ObjectName(uintptr_t object);
    std::string ClassName(uintptr_t object);
    std::string ObjectPath(uintptr_t object, int maxDepth = 24);

    bool IsValidObject(uintptr_t object) const;
    bool IsClassObject(uintptr_t object);
    uintptr_t ClassOf(uintptr_t object) const;
    uintptr_t OuterOf(uintptr_t object) const;
    uint32_t NameIndex(uintptr_t object) const;
    bool IsA(uintptr_t object, uintptr_t classObject) const;

    uintptr_t FindObjectRaw(uintptr_t classObject, uintptr_t outer, const std::wstring& name,
                            bool exactClass = false);
    uintptr_t FindObjectPath(const std::string& path, uintptr_t classObject = 0,
                             uintptr_t outer = 0, std::vector<std::string>* tried = nullptr);
    std::vector<std::string> PathCandidates(const std::string& path);

    struct ObjectQuery {
        std::vector<uintptr_t> objects;
        size_t total = 0;
        bool truncated = false;
    };
    ObjectQuery ObjectsOfClass(uintptr_t classObject, bool includeDerived, uint32_t excludeFlags,
                               size_t maxResults, std::string* error);
    ObjectQuery IterateObjects(size_t maxResults, std::string* error);

    ObjectInfo DescribeObject(uintptr_t object);

    uintptr_t TargetStruct(uintptr_t objectOrClass);
    uintptr_t StructChildProperties(uintptr_t structObject) const;
    uintptr_t StructChildren(uintptr_t structObject) const;
    uintptr_t StructSuper(uintptr_t structObject) const;
    uintptr_t FieldNext(uintptr_t field) const;
    std::string FieldName(uintptr_t field);
    std::string FieldTypeName(uintptr_t field);
    bool DecodeProperty(uintptr_t property, PropertyInfo& info);
    std::vector<PropertyInfo> ListProperties(uintptr_t target, bool includeInherited,
                                             std::string* error);
    bool FindProperty(uintptr_t target, const std::string& name, bool includeInherited,
                      PropertyInfo& out);
    bool ReadPropertyValue(uintptr_t object, const PropertyInfo& property, nlohmann::json& out,
                           std::string* error);
    bool WritePropertyValue(uintptr_t object, const PropertyInfo& property,
                            const nlohmann::json& value, std::string* error);
    bool WritePropertyRaw(uintptr_t object, const PropertyInfo& property,
                          const std::vector<uint8_t>& bytes, std::string* error);

    std::vector<FunctionInfo> ListFunctions(uintptr_t target, bool includeInherited,
                                            std::string* error);
    uintptr_t FindFunction(uintptr_t target, const std::string& name, bool includeInherited);
    bool DecodeFunction(uintptr_t function, FunctionInfo& out);
    int32_t FunctionParmsSize(uintptr_t function, std::string* error);

    bool WriteParamValue(uintptr_t params, const PropertyInfo& property,
                         const nlohmann::json& value, std::vector<std::wstring>& stringKeepAlive,
                         std::vector<std::vector<wchar_t>>& bufferKeepAlive, std::string* error);
    bool ReadParamValue(uintptr_t params, const PropertyInfo& property, nlohmann::json& out,
                        std::string* error);

    uintptr_t ReadGlobalRaw(uintptr_t slot, std::string* error);
    uintptr_t ReadGlobalBySpec(const GlobalSpec& spec, uintptr_t slot, std::string* error);
    std::optional<uintptr_t> ReadNamedGlobal(const std::string& name, std::string* error);
    uintptr_t GWorld(std::string* error = nullptr);
    uintptr_t GEngine(std::string* error = nullptr);

    bool RunOnGameThread(const std::function<void()>& job, bool allowDirect, std::string* error,
                         bool* usedDirect = nullptr);
    uint64_t ProcessEventNow(uintptr_t object, uintptr_t function, void* params);
    uint64_t ProcessEventNowDirect(uintptr_t object, uintptr_t function, void* params);

    bool AutoTuneLayout(std::string* error);

private:
    UeContext() = default;

    uintptr_t ResolveSpec(const FunctionSpec& spec, const char* label, bool requireExecutable,
                          std::string* error);
    bool ResolveNames(std::string* error);
    bool ResolveObjects(std::string* error);
    void RefreshMetaClasses();
    std::string ParseNameEntry(uint32_t index);
    std::string ParsePoolEntry(uintptr_t entry);
    std::string ParseTableV2Entry(uintptr_t entry);
    uintptr_t ReadGlobalValue(const std::string& name, int depth, std::string* error);
    std::string CallNameFunction(uint32_t index, uint32_t number, bool* faulted = nullptr);
    std::string CallKismetName(uint32_t index, uint32_t number, bool* faulted = nullptr);
    std::string ParseGNamesEntry(uint32_t rawIndex);
    bool ValidateNameIndex(uint32_t raw) const;
    bool IsPropertyCandidate(uintptr_t address);
    bool AutoTuneStructFields(uintptr_t actorClass, std::string* error);
    bool AutoTuneFieldFields(uintptr_t firstProperty, std::string* error);

    ResolveReport report_;
    Layout layout_{};
    uintptr_t module_base_ = 0;
    size_t module_size_ = 0;
    uintptr_t static_find_object_ = 0;
    uintptr_t get_objects_of_class_ = 0;
    uintptr_t process_event_ = 0;
    uintptr_t names_base_ = 0;
    uintptr_t names_table_ = 0;
    uintptr_t names_function_ = 0;
    uintptr_t kismet_cdo_ = 0;
    uintptr_t kismet_function_ = 0;
    bool gnames_direct_ = false;
    uintptr_t objects_base_ = 0;
    uintptr_t objects_table_ = 0;
    uintptr_t gworld_slot_ = 0;
    uintptr_t gengine_slot_ = 0;
    uintptr_t class_meta_ = 0;
    uintptr_t function_meta_ = 0;
    uintptr_t world_meta_ = 0;
    bool resolved_once_ = false;
    std::string last_name_warning_;
    mutable std::mutex name_mutex_;
    std::unordered_map<uint64_t, std::string> name_cache_;
    std::unordered_set<uint64_t> name_faults_;
};

}

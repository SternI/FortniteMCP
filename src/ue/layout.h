#pragma once

#include <cstdint>
#include <string>

namespace fmcp::ue {

struct Layout {
    int object_vtable = 0x00;
    int object_flags = 0x08;
    int object_internal_index = 0x0C;
    int object_class = 0x10;
    int object_name = 0x18;
    int object_outer = 0x20;
    int fname_size = 8;

    int ufield_next = 0x28;
    int ustruct_super = 0x30;
    int ustruct_children = 0x38;
    int ustruct_child_properties = 0x78;
    int ustruct_properties_size = 0x40;
    int ustruct_min_alignment = 0x44;
    int uclass_class_cast_flags = 0xB8;
    int uclass_class_default_object = 0x00;

    int ffield_class = 0x08;
    int ffield_owner = 0x10;
    int ffield_next = 0x18;
    int ffield_name = 0x20;
    int ffieldclass_name = 0x00;

    int fproperty_array_dim = 0x30;
    int fproperty_element_size = 0x34;
    int fproperty_flags = 0x38;
    int fproperty_offset = 0x44;

    int ufunction_flags = 0xB0;
    int ufunction_parms_size = 0xB6;
    int ufunction_return_offset = 0xB8;
    int ufunction_func = 0xC0;

    int bool_field_size = 0x70;
    int bool_byte_offset = 0x71;
    int bool_byte_mask = 0x72;
    int bool_field_mask = 0x73;

    int property_payload = 0x70;

    bool fortnite_property_decoders = false;
    bool large_world_coords = false;
    bool children_is_array = false;
    bool child_properties_is_array = false;

    [[nodiscard]] bool HasName() const { return object_name > 0 && fname_size >= 4; }
    [[nodiscard]] bool HasStructChain() const { return ustruct_super > 0 && ustruct_children > 0; }
    [[nodiscard]] bool HasPropertyChain() const { return ustruct_child_properties > 0 && ffield_next > 0 && ffield_name > 0; }
};

Layout LayoutForProfile(std::string_view profile);

}

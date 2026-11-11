#include "ue/layout.h"

namespace fmcp::ue {

Layout LayoutForProfile(std::string_view profile) {
    Layout l;

    if (profile == "fortnite" || profile == "fortnite-ue6" || profile == "ue6-fortnite") {
        l.object_flags = 0x08;
        l.object_internal_index = 0x0C;
        l.object_class = 0x10;
        l.object_outer = 0x18;
        l.object_name = 0x20;
        l.fname_size = 8;

        l.ufield_next = 0x28;
        l.ustruct_super = 0x00;
        l.ustruct_children = 0x00;
        l.ustruct_child_properties = 0x00;
        l.ustruct_properties_size = 0x70;
        l.ustruct_min_alignment = 0x00;
        l.uclass_class_cast_flags = 0xB8;

        l.ffield_class = 0x00;
        l.ffield_owner = 0x00;
        l.ffield_next = 0x00;
        l.ffield_name = 0x18;
        l.ffieldclass_name = 0x04;

        l.fproperty_array_dim = 0x2C;
        l.fproperty_element_size = 0x60;
        l.fproperty_flags = 0x30;
        l.fproperty_offset = 0x3C;

        l.ufunction_flags = 0xCC;
        l.ufunction_parms_size = 0x00;
        l.ufunction_return_offset = 0x00;
        l.ufunction_func = 0xE0;

        l.bool_field_size = -1;
        l.bool_byte_offset = -1;
        l.bool_byte_mask = -1;
        l.bool_field_mask = -1;
        l.property_payload = -1;

        l.fortnite_property_decoders = true;
        l.large_world_coords = true;
        return l;
    }

    l.large_world_coords = (profile == "ue5" || profile == "ue6");
    return l;
}

}

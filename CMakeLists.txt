cmake_minimum_required(VERSION 3.24)

project(FortniteMCP VERSION 1.0.0 LANGUAGES C CXX)

if(NOT MSVC)
    message(FATAL_ERROR "FortniteMCP targets Windows x64 with MSVC.")
endif()

enable_language(ASM_MASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")

add_library(minhook STATIC
    third_party/minhook/src/buffer.c
    third_party/minhook/src/hook.c
    third_party/minhook/src/trampoline.c
    third_party/minhook/src/hde/hde64.c
)
target_include_directories(minhook PUBLIC
    third_party/minhook/include
    third_party/minhook/src
)
target_compile_definitions(minhook PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

set(FMCP_CORE_SOURCES
    src/core/allocator.cpp
    src/core/base64.cpp
    src/core/config.cpp
    src/core/lifecycle.cpp
    src/core/log.cpp
    src/core/memory.cpp
    src/core/modules.cpp
    src/core/patches.cpp
    src/core/process.cpp
    src/core/scanner.cpp
    src/core/strings.cpp
)

set(FMCP_MCP_SOURCES
    src/mcp/http_server.cpp
    src/mcp/json_rpc.cpp
    src/mcp/tools.cpp
    src/mcp/tools_input.cpp
    src/mcp/tools_memory.cpp
    src/mcp/tools_system.cpp
    src/mcp/tools_ue.cpp
)

set(FMCP_UE_SOURCES
    src/ue/context.cpp
    src/ue/layout.cpp
    src/ue/game_thread.cpp
    src/ue/globals.cpp
    src/ue/input.cpp
    src/ue/objects.cpp
    src/ue/properties.cpp
    src/features/dll_manager.cpp
)

add_library(fortnite_mcp SHARED
    src/bootstrap.cpp
    src/dllmain.cpp
    src/core/call_x64.asm
    ${FMCP_CORE_SOURCES}
    ${FMCP_MCP_SOURCES}
    ${FMCP_UE_SOURCES}
)
set_target_properties(fortnite_mcp PROPERTIES OUTPUT_NAME "FortniteMCP")
target_include_directories(fortnite_mcp PRIVATE
    src
    third_party/json
    third_party/minhook/include
)
target_compile_definitions(fortnite_mcp PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WINDOWS
    _USRDLL
    _CRT_SECURE_NO_WARNINGS
    FMCP_VERSION="${PROJECT_VERSION}"
)
target_compile_options(fortnite_mcp PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:/W4>
    $<$<COMPILE_LANGUAGE:CXX>:/permissive->
    $<$<COMPILE_LANGUAGE:CXX>:/EHsc>
    $<$<COMPILE_LANGUAGE:CXX>:/GR>
    $<$<COMPILE_LANGUAGE:CXX>:/guard:cf->
    $<$<COMPILE_LANGUAGE:CXX>:/Zc:preprocessor>
    $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
    $<$<COMPILE_LANGUAGE:CXX>:/d2FH4->
)
target_link_libraries(fortnite_mcp PRIVATE minhook ws2_32 bcrypt)
target_link_options(fortnite_mcp PRIVATE "/MAP:${CMAKE_BINARY_DIR}/bin/FortniteMCP.map" "/MAPINFO:EXPORTS")

add_executable(FortniteMCPTestHost tests/host.cpp)
set_target_properties(FortniteMCPTestHost PROPERTIES OUTPUT_NAME "FortniteMCPTestHost")
target_compile_definitions(FortniteMCPTestHost PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(FortniteMCPTestHost PRIVATE /W4 /permissive- /utf-8)

add_executable(FortniteMCPBridge src/bridge/main.cpp)
set_target_properties(FortniteMCPBridge PROPERTIES OUTPUT_NAME "FortniteMCPBridge")
target_compile_definitions(FortniteMCPBridge PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CONSOLE
    _CRT_SECURE_NO_WARNINGS
)
target_compile_options(FortniteMCPBridge PRIVATE /W4 /permissive- /EHsc /utf-8)
target_link_libraries(FortniteMCPBridge PRIVATE winhttp shell32)

set_target_properties(fortnite_mcp PROPERTIES
    LINK_FLAGS "/SUBSYSTEM:WINDOWS /DYNAMICBASE /NXCOMPAT"
    PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
set_target_properties(FortniteMCPBridge PROPERTIES
    LINK_FLAGS "/SUBSYSTEM:CONSOLE /DYNAMICBASE /NXCOMPAT"
    PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
set_target_properties(FortniteMCPTestHost PROPERTIES
    LINK_FLAGS "/SUBSYSTEM:CONSOLE /DYNAMICBASE /NXCOMPAT"
    PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
foreach(cfg debug release relwithdebinfo minsizerel)
    string(TOUPPER "${cfg}" CFG)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CFG} "${CMAKE_BINARY_DIR}/bin")
endforeach()

configure_file(config.example.json "${CMAKE_BINARY_DIR}/bin/config.example.json" COPYONLY)
configure_file(configs/fortnite.example.json "${CMAKE_BINARY_DIR}/bin/fortnite.example.json" COPYONLY)
configure_file(configs/fortnite-42.30.example.json "${CMAKE_BINARY_DIR}/bin/fortnite-42.30.example.json" COPYONLY)

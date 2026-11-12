# FortniteMCP

An in-process MCP server for Unreal Engine game research and automated testing.

`FortniteMCP.dll` is injected into an **offline/private** game build. It exposes a local MCP endpoint
that MCP clients and coding agents can use to inspect memory, walk UE reflection, call UFunctions,
drive keyboard/mouse input, and load helper DLLs.

#### Cool discord server to talk: https://discord.gg/x5NhV5h7BF

> **Authorized use only.** Run this against an offline/private build you own, with anti-cheat disabled.
> The included loader only targets a game process you started locally; this project contains no
> anti-cheat bypass, no hardware-ID spoofing, and no remote/network injection. The matchmaking helpers
> are for private sessions you control, not public matches or other players. Memory writes and raw
> calls can crash the process. Nothing here is affiliated with Epic Games.

## What it can do

- Safe typed/hex/base64 memory reads and writes, tracked undo patches, IDA-style pattern scanning,
  pointer chains, and tracked allocations.
- UE reflection: StaticFindObject/FindObject, GetObjectsOfClass, object inspection, properties,
  UFunctions, typed/raw ProcessEvent calls including the engine's `uint64_t` return, raw function calls,
  and globals (GWorld/GEngine or the `GEngine -> GameViewport -> World` chain).
- Game-thread dispatch for engine calls through a ProcessEvent hook, with a fast path and timeouts.
- Names through a standard FNamePool/table or directly through the engine's `FNameToString`, with caching.
- Game input: keys (press/hold/release), unicode text, relative/absolute mouse, buttons, wheel.
- Load/unload helper DLLs in the game process, plus a response-safe self-eject.
- MCP over loopback HTTP and a stdio bridge for clients that only support stdio.
- Build-specific UE layouts, Fortnite/UE6 obfuscated-property decoders, and runtime layout auto-tuning.

## HTTP API research sidecar

`http_mcp/` is a separate MCP server for web/API research: a local mitmproxy-based HTTPS proxy with
full request/response capture, in-flight intercept and editing, replay, WebSocket frames, HAR/curl
export, and token/JWT inspection. It listens on `127.0.0.1:8080` (proxy) and `127.0.0.1:26065/mcp`.

```
pip install -r http_mcp/requirements.txt
http_mcp\start.cmd
```

See [http_mcp/README.md](http_mcp/README.md) for setup, CA installation, traffic routing, and the tool
reference. The same authorization rule applies: only your own accounts and in-scope services.

## Build

Requirements: Windows x64, Visual Studio 2022 (MSVC + MASM), CMake 3.24+, Ninja.

```bat
scripts\build.bat
```

Outputs:

```
build\release\bin\FortniteMCP.dll
build\release\bin\FortniteMCPBridge.exe
build\release\bin\FortniteMCPTestHost.exe   (development test host)
```

`scripts\clean_build.bat` does a full rebuild.

Dependencies are vendored:

- [nlohmann/json](https://github.com/nlohmann/json) 3.11.3 (MIT)
- [MinHook](https://github.com/TsudaKageyu/minhook) 1.3.4 (BSD-2-Clause)

The DLL is built with the **dynamic CRT** (`/MD`). This is required for manual mapping: the loader
does not create a TLS block for a manually mapped module, so static-CRT thread-local guards and lazy
function-local statics can read zeroed memory. `FortniteMCP` avoids module TLS and lazy singleton
guards, and the injector must call the PE entry point (`_DllMainCRTStartup`) so CRT initializers run.
Do not switch the build back to `/MT` or add `thread_local` / non-trivial function-local statics if you
intend to manual-map it. The game ships compatible VC runtime DLLs (14.50 on 42.30).

## First run

1. Inject `FortniteMCP.dll` with your own injector (the DLL only acts after it is loaded). Both normal
   LoadLibrary injection and manual mapping are supported; see the manual-map note below. This project
   does not bundle an injector.
2. On first start it creates:
   - `%LOCALAPPDATA%\FortniteMCP\config.json`
   - `%LOCALAPPDATA%\FortniteMCP\token.txt`
   - `%LOCALAPPDATA%\FortniteMCP\FortniteMCP.log`
   - `%LOCALAPPDATA%\FortniteMCP\mcp-client.json` (ready-made HTTP config with the token)
3. The server listens on `127.0.0.1:26064` by default. `GET /health` is unauthenticated;
   `POST /mcp` requires `Authorization: Bearer <token>` (or `X-MCP-Token`).
4. Use `status`, `self_test`, `memory_module_info`, and `ue_status` as the first calls.

Set `FORTNITEMCP_CONFIG` to use a different config path. The token is generated on first run and reused.

## Connect an MCP client

### HTTP

Use the generated file (same values, token included):

```json
{
  "mcpServers": {
    "fortnite": {
      "url": "http://127.0.0.1:26064/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

### stdio bridge (max compatibility)

Add the bridge as a stdio MCP server. It reads the token automatically from `token.txt` next to
`FORTNITEMCP_CONFIG`, from `%LOCALAPPDATA%\FortniteMCP\token.txt`, from `FORTNITEMCP_TOKEN`, or from
`--token`.

```json
{
  "mcpServers": {
    "fortnite": {
      "command": "C:\\path\\to\\build\\release\\bin\\FortniteMCPBridge.exe",
      "args": ["--url", "http://127.0.0.1:26064/mcp", "--wait", "15"]
    }
  }
}
```

The bridge only forwards JSON-RPC; keep its stdout clean. It logs errors to stderr.

## UE configuration

Memory tools work immediately. Object/reflection/ProcessEvent tools need build-specific addresses.
Offsets are **RVAs from the main module base**. You can set them in `config.json` and restart, or live
via the `ue_configure` MCP tool (optionally `"save": true`). Hex strings such as `"0x1421F6"` are accepted.

Resolution modes per target:

- `off` - disabled.
- `offset` - `module_base + offset`. If `signature` is also set for a function, the bytes are verified
  at the target before use (recommended).
- `signature` - scan the main module for an IDA pattern; first match wins.
- `chain` - globals only: read another configured global and follow dereferenced offsets.
- `vtable` - reserved (not currently used).

Key sections:

```json
"ue": {
  "profile": "ue5",
  "static_find_object":  { "resolve": "offset", "offset": 0, "name_arg": "wchar_ptr" },
  "get_objects_of_class":{ "resolve": "offset", "offset": 0 },
  "process_event":       { "resolve": "offset", "offset": 0, "signature": "", "hook": true },
  "names":  { "style": "off", "resolve": "offset", "offset": 0, "fname_size": 8 },
  "objects":{ "style": "off", "resolve": "offset", "offset": 0 },
  "gworld": { "resolve": "off", "offset": 0, "signature": "", "decode": "" },
  "gengine":{ "resolve": "off", "offset": 0, "signature": "", "decode": "" },
  "layout": {}
}
```

For **UE6/Fortnite**, the simplest world lookup needs neither a GWorld RVA nor decryption:

```json
"gengine": { "resolve": "offset", "offset": "0x1B098778" },
"gworld":  { "resolve": "chain", "from": "gengine", "chain": ["0xB70", "0x78"], "decode": "" }
```

This reads `GEngine -> GameViewport -> World`. `UGameViewportClient` has `World` at `0x78`.
`ULocalPlayer` also has a `ViewportClient` at `0x78`, but it is a different class and is not part of
this chain.

### Names backends

- `style: "pool"` - standard UE4.23+/UE5 FNamePool; `offset` points at the pool, block table at
  `block_table_offset` (default `0x10`).
- `style: "pool_blocks"` - `offset` points directly at the block-pointer array.
- `style: "table_v2"` - UE6/Fortnite-style pointer name table: the global holds a pointer to an entry
  table; entries are pointers to `{uint32 flags, int32 length, chars}`. Use `fname_size: 4`.
- `style: "table"` - pointer table of small-header entries.
- `style: "function"` - call the engine's `FNameToString` at `offset`/`signature`. This needs no GNames
  address and transparently handles the game's name encoding. Set `fname_size` (4 for Fortnite/UE6)
  and `abi`:
  - `"fstring_ref"` (default) - `void FNameToString(FName*, FString&)`, matching MoonFN's call.
  - `"fstring_value"` - `FString FNameToString(FName)` (hidden sret pointer first).
  Output is read into a preallocated buffer (`max_chars`, minimum 2048). FName IDs can be obfuscated;
  FortniteMCP never fabricates raw IDs, validates them only through real object names, and skips layout
  auto-tuning for this backend. If the engine reallocates the FString despite the capacity, FortniteMCP
  logs a one-time warning and leaves that allocation to the engine (use a table backend if you need
  zero-allocation names).
- `style: "off"` - names show as `Name_<index>`, reflection-by-name is disabled.

`codec` must currently be `plain`/`none` for table backends. Unsupported custom encryption is rejected
rather than guessed.

### StaticFindObject ABI

- `name_arg: "wchar_ptr"` for a standard `const TCHAR*` parameter.
- `name_arg: "wstring_view_ptr"` for the Fortnite string-view-pointer signature used by MoonFN/Dumper.

### Object arrays

`get_objects_of_class` uses the native engine function when configured (recommended). Fallback iteration
requires an object array:

```json
"objects": {
  "style": "uobject_array",
  "resolve": "offset",
  "offset": 0,
  "objects_offset": 16,
  "item_size": 24,
  "chunk_bits": 16,
  "item_object_offset": 0,
  "max_objects": 2000000,
  "empty_chunk_stop": 4
}
```

Use `style: "chunk_table"` if the RVA is the inline chunk table, or `"chunk_table_global"` if it points
to a global holding the chunk table pointer. If native `GetObjectsOfClass` is available, you do not need
this section for `objects_of_class`.

### Layouts

`profile` selects a layout preset and sets sane defaults:

- `ue4`, `ue5` - standard UObject/UStruct/FField/FProperty/UFunction layout, linked child lists.
- `ue6` - standard fields plus large-world-coordinate vectors.
- `fortnite` / `fortnite-ue6` - 4-byte FName, UE6/Fortnite field positions, obfuscated property
  decoders, LWC. UStruct children/child-property/FField offsets are left for auto-tuning or `layout`.
  Layout auto-tuning is skipped when `names.style` is `function`, because encrypted FName IDs cannot be
  safely probed; set layout offsets from your dumper in that mode.
  In the 42.30 SDK, `UStruct::SuperStruct` is `0x40`, `UStruct::Children` is `0x58`, and
  `UClass::ClassDefaultObject` is `0xB0`; those are set in the 42.30 example. FProperty/FField offsets
  still come from your dumper and can change independently.

Override any field under `ue.layout` (names are in `config.example.json`). `auto_tune: true`
(requires working names + StaticFindObject) probes `Engine.Actor` to fill missing struct/field offsets.
If auto-tuning cannot prove a layout, use the values from your SDK dumper/IDA.

Array-style `UStruct::Children` / `ChildProperties` are supported with
`layout.children_is_array` and `layout.child_properties_is_array`.

`ustruct_children` is optional. It is used only by the `list_functions` tool and bare function-name
lookup; set it to `0` when you resolve functions through the SDK YAML or full StaticFindObject paths.
`ustruct_super` is used for class/hierarchy checks; raw calls can bypass the function/object mismatch
validation with `allow_mismatch: true`. `uclass_class_default_object` is only used for property reads on
class objects.

FProperty/FField layouts are only needed for the typed/reflection tools (`call_ufunction`,
`list_properties`, `get_property`, `set_property`, output decoding). Raw `process_event` with an explicit
`parms_size` (and `parms_address` or inline bytes) does not read them. `call_address`, memory tools,
object enumeration, and `find_object` do not need them either. If you drive calls from a generated SDK,
ignore the property/typed tools entirely.

### Globals

A global can be read directly from an RVA, optionally followed by a decode pipeline:

```
add:0x46EB50FF,xor:0x4899E3F4,rotl:60
```

Operations: `add`, `sub`, `xor`, `and`, `or`, `not`, `rotl`, `rotr`, `swap32`, `swap64` (comma
separated, applied in order).

Any global can instead be resolved through a pointer chain:

```json
"gworld": {
  "resolve": "chain",
  "from": "gengine",
  "chain": ["0xB70", "0x78"],
  "decode": ""
}
```

`from` names another configured global (`gengine` or an `extra_globals` entry); each chain item is added
to the current pointer and dereferenced. A null/unreadable hop returns an error instead of a bogus
pointer. Add arbitrary slots under `ue.extra_globals`; chains can reference them too.

### UE6/Fortnite bootstrap

The `fortnite` profile matches the UE6/Fortnite layout family (4-byte FName, obfuscated property fields,
LWC, auto-tuned UStruct fields). Names can come from `FNameToString`, so no GNames address or name
decryption is needed. Start from `configs/fortnite-42.30.example.json` for the reported 42.30 values, or
`configs/fortnite.example.json` as a blank template, and verify every RVA for your exact build.

1. Copy the example to `%LOCALAPPDATA%\FortniteMCP\config.json` (or point `FORTNITEMCP_CONFIG` at it).
2. Fill/verify `static_find_object.offset`, `get_objects_of_class.offset`, `process_event.offset`, and
   `names.offset` (FNameToString). For this layout, `static_find_object.name_arg` is usually
   `"wstring_view_ptr"`.
3. Set `gengine.offset`; `gworld` uses
   `"resolve": "chain", "from": "gengine", "chain": [2928, 120]` (0xB70, 0x78). No GWorld decryption.
4. Inject, call `ue_status`. Look at `warnings`, `names.samples`, `gworld`, and `self_test`.
5. If properties/functions are unavailable, set the FProperty/FField/UFunction layout fields from your
   updated dumper via `ue_configure` (or inspect with `memory_scan`/`memory_read`).

Live update example for the reported 42.30/42.40 builds (verify against your binary first):

```json
{
  "ue": {
    "profile": "fortnite",
    "auto_tune": true,
    "static_find_object": {
      "resolve": "offset", "offset": "0x692FBA", "name_arg": "wstring_view_ptr"
    },
    "get_objects_of_class": { "resolve": "offset", "offset": "0x15617B" },
    "process_event": { "resolve": "offset", "offset": "0x1421F6", "signature": "", "hook": true },
    "names": {
      "style": "gnames", "resolve": "off",
      "fname_size": 8, "validate": true,
      "pool_offset": "0x1AF4CDC8", "block_table_offset": 8,
      "block_bits": 16, "stride": 2,
      "decrypt": "fortnite", "decrypt_key": "0x6F1D17B8"
    },
    "gengine": { "resolve": "offset", "offset": "0x1B098778" },
    "gworld": {
      "resolve": "chain", "from": "gengine", "chain": ["0xB70", "0x78"], "decode": ""
    },
    "layout": {
      "object_class": 16,
      "object_outer": 24,
      "object_name": 32,
      "ustruct_super": 80,
      "ustruct_children": 0,
      "uclass_class_default_object": 256
    }
  },
  "save": true
}
```

42.40 CL-59343437 was verified live: `GEngine -> 0xB70 -> 0x78` reaches the `Frontend` world, and UObject
fields are `ClassPrivate=0x10`, `OuterPrivate=0x18`, `NamePrivate=0x20` (the name is not at `0x18`).
Earlier 42.30 notes used `Name=0x18`, which produces an invalid encrypted FName and a name-call fault.
Offsets are build-specific and your responsibility. Every game update changes them; a wrong
`process_event` address with `hook: true`
can crash the game. Use a signature when possible:

```json
"process_event": {
  "resolve": "offset",
  "offset": "0x1421F6",
  "signature": "40 55 56 57 41 54 41 55 41 56 41 57 48 81 EC"
}
```

When both `offset` and `signature` are present, the pattern is checked at the target before use.

#### Per-build update checklist

- `gengine`, `static_find_object`, `get_objects_of_class`, `process_event`.
- `names.offset` = `FNameToString` (preferred) or the GNames table/address for a table backend.
- World chain offsets `GameViewport`/`World` (42.40 verified: `0xB70` / `0x78`).
- Layout: UObject `ClassPrivate=0x10`, `OuterPrivate=0x18`, `NamePrivate=0x20` on 42.40; `FName` is
  8 bytes. UStruct/FField/FProperty/UFunction offsets and property decoders must come from your dumper.
- StaticFindObject calling ABI (`wchar_ptr` vs `wstring_view_ptr`).
- Optional: object-array config if you do not use native `GetObjectsOfClass`.

If a member offset changed, `ue_status` shows each `gworld` chain hop (`from`, `readable`, `value`,
`canonical`) plus `name_raw` for the resolved objects. Recover the new offsets without restarting:

1. Call `find_pointer_field` with `{"owner": "<gengine value>", "class": "GameViewportClient"}`.
2. Call it again with `{"owner": "<viewport value>", "class": "World"}`.
3. Apply both offsets with `ue_configure` and `{"ue":{"gworld":{"resolve":"chain","from":"gengine","chain":[off1,off2]}}}`.

`FNameToString` calls are SEH-guarded: a bad raw FName returns `faulted: true` from `resolve_fname` and
logs a warning instead of taking the game down; that ID is cached as invalid so it is never retried.

## Tool reference

Groups exposed by `tools/list`:

| Area | Tools |
|---|---|
| Status | `status`, `self_test`, `get_log` |
| Memory | `memory_read`, `memory_read_safe`, `memory_write`, `memory_scan`, `memory_alloc`, `memory_free`, `memory_allocations`, `memory_pointer_chain`, `memory_modules`, `memory_module_info`, `patch_list`, `patch_undo` |
| UE | `find_object`, `objects_of_class`, `object_info`, `list_properties`, `get_property`, `set_property`, `list_functions`, `process_event`, `call_ufunction`, `call_address`, `get_globals`, `resolve_fname`, `find_pointer_field`, `net_stats`, `ue_status`, `ue_configure` |
| Input | `input_window`, `input_key`, `input_text`, `input_mouse` |
| Matchmaking (private sessions) | `matchmaking_play_button`, `matchmaking_start`, `matchmaking_cancel`, `matchmaking_status` |
| DLL / lifecycle | `load_dll`, `unload_dll`, `dll_list`, `shutdown` |

All addresses accept `0x...`, decimal, or `module+offset` (e.g. `Game.exe+0x1234`). Object arguments
accept an address or a path like `Engine.Actor` / `/Script/Engine.Actor`.

### Typical calls

Find and inspect an object:

```json
{"path":"Engine.Actor"}
```

List a class's instances:

```json
{"class":"/Script/Engine.Actor","include_derived":true,"limit":50,"include_cdo":false}
```

Read/write a property:

```json
{"object":"0x7FF6...","property":"Health","include_inherited":true}
{"object":"0x7FF6...","property":"Health","value":100}
```

Raw ProcessEvent (params are caller-built bytes):

```json
{
  "object":"/Script/FortniteGame.FortPlayerController...",
  "function":"ServerSomething",
  "parms_hex":"00000000",
  "decode_outputs":true
}
```

For SDK-driven calls, build the parameter struct with `memory_alloc`/`memory_write` and pass its pointer:

```json
{
  "object":"0x...",
  "function":"0x...",
  "parms_address":"0x...",
  "parms_size": 288,
  "decode_outputs": false
}
```

This path uses only the object, UFunction, and parameter buffer pointers. When `parms_size` is explicit,
FortniteMCP does not read FProperty/FField metadata at all. `call_ufunction` is the optional typed-JSON
wrapper and is the one that needs reflection layout; the property tools are optional as well.

Both `process_event` and `call_ufunction` report the engine's `uint64_t ProcessEvent(...)` return as
`process_event_return` and `process_event_return_hex`. That is separate from a UFunction's own
`ReturnValue`, which appears in `outputs`.

Typed ProcessEvent:

```json
{
  "object":"0x7FF6...",
  "function":"K2_GetActorLocation",
  "args":{},
  "allow_direct":false
}
```

Raw call:

```json
{
  "address":"Game.exe+0x123456",
  "args":[{"type":"int","value":1},{"type":"double","value":2.0}],
  "return_type":"u64"
}
```

Input:

```json
{"keys":["W","Space"],"action":"press","hold_ms":120}
{"action":"move_relative","dx":120,"dy":-30}
{"action":"click","button":"left"}
```

Input is sent only while the game window is foreground; `allow_background` uses window messages for
keys (best effort, generally not raw-input/game friendly). Mouse input never goes to a background window.

### UE6 notes

- Fortnite `FProperty` fields can be obfuscated. The `fortnite` profile decodes element size, offset,
  flags, properties size, and min alignment using the candidates from `MoonFN.Dumper`. Unknown layout
  parts stay unavailable rather than silently using garbage.
- `UStruct::Children` / `ChildProperties` may be arrays in newer builds; enable the array layout flags.
- `UFunction::ParmsSize` is computed from the property chain and combined with the configured field.
  Raw calls can pass an explicit `parms_size`; a smaller-than-reflected buffer is rejected by default.
- `ProcessEvent` is called with its implicit `this` plus `(UFunction*, Parms)` and its `uint64_t` return
  is preserved. The typed `ReturnValue` is decoded from the parameter buffer.
- Typed arrays, non-trivial FString outputs, FName-by-string creation, and some delegates/structs are
  intentionally not marshaled. Use raw `process_event` bytes for those.

## Safety model

- Loopback bind by default; mandatory bearer token unless explicitly disabled; token file is local.
- All memory access is range-validated and SEH/fault-safe for reads. Writes require writable pages unless
  `force: true`; forced writes record undo data.
- Destructive actions (`shutdown`, `unload_dll`, untracked frees) require `confirm: true` when
  `safety.require_confirm` is enabled.
- Engine calls can be routed through a ProcessEvent hook so they execute on the game thread. Without a
  hook they are refused unless `game_thread.direct_fallback` (or per-call `allow_direct`) is enabled;
  direct mode is unsafe and reported in every result.
- The hook has a lock-free fast path, bounded queue/time budget, per-call timeouts, and a drain-before-free
  teardown. Self-eject is refused if an engine call is still running.
- Scan/read/write sizes, result counts, queue sizes, and timeouts are configurable and bounded.
- Input is foreground-gated to avoid typing into unrelated windows.
- No anti-cheat evasion. Use offline builds only.

Things that can still crash the process:

- Calling a wrong function address or a UFunction with a wrong/mismatched object.
- A bad ProcessEvent signature/offset.
- Writing the wrong memory or a bad parameter buffer.
- Waiting for the game thread while the game is frozen; calls time out, but the process may stay busy.

Use `self_test` after injection and after every `ue_configure`. Keep a game backup.

Unloading differs by injection method:

- LoadLibrary/loader injection: `shutdown` can call `FreeLibraryAndExitThread` after stopping threads, but
  the injector must release its own handle for the DLL to actually unload.
- Manual mapping: the module is not in the loader list, so `FreeLibrary` cannot unload it. `shutdown` now
  detects this, stops the server, ignores `unload_self`, and reports `manual_map: true`; eject with the
  injector or terminate the game. The manual-map validation run in this repo exercised this path.

## Development and tests

`FortniteMCPTestHost.exe` loads the DLL in a harmless process so the MCP server can be tested without a
game:

```bat
set FORTNITEMCP_CONFIG=%CD%\build\test\config.json
build\release\bin\FortniteMCPTestHost.exe --seconds 120
python scripts\mcp_smoke_test.py --token <contents of build\test\token.txt>
```

The smoke test covers HTTP auth, tool schemas, typed memory, patches/undo, scanning across chunk
boundaries, pointer chains, raw Win64 calls (including mixed integer/FPU/stack arguments), the
`FNameToString` backend, a synthetic `GEngine -> GameViewport -> World` chain, DLL load/unload, graceful
UE degradation, runtime config, logging, and self-test. `shutdown` is tested separately.

`self_test` inside the game verifies the same core memory/call/thunk paths plus the game-thread queue.

## Layout

```
src/
  bootstrap.cpp, dllmain.cpp     lifecycle and DLL entry
  core/                          config, logging, memory, scanner, patches, call thunk, allocator
  ue/                            UE layout/resolution, names, objects, properties, globals,
                                 game-thread hook, input
  mcp/                           HTTP server, JSON-RPC/MCP, tools
  features/dll_manager.*         tracked LoadLibrary/FreeLibrary
  bridge/main.cpp                stdio <-> HTTP MCP bridge
tests/host.cpp                   DLL test host + synthetic UE fixtures
config.example.json              standard template
configs/fortnite.example.json    UE6/Fortnite blank template
configs/fortnite-42.30.example.json  offsets/fields reported for 42.30
```

## Troubleshooting

- **Crash immediately on manual-map inject (null map in `Config::ResetDefaults` / `[rbx+8]`)**: this was the
  old `/MT` build using TLS-based lazy static guards. Use the current `/MD`, no-TLS build and make sure the
  injector calls the DLL entry point. Rebuild cleanly after changing the runtime library.
- **No server / connection refused**: check the log and that the port is free. If HTTP failed to start,
  the DLL logs the error and stays idle; unload/reload the DLL with your injector or restart the game.
- **401**: copy the token from `token.txt` or use the bridge, which auto-discovers it.
- **UE tools say `static_find_object is not configured`**: fill the UE RVAs; memory tools still work.
- **Properties/functions are empty**: fix layout offsets, enable auto-tune, or configure the name backend.
- **Crash inside FNameToString during startup**: older builds self-tested it with synthetic IDs `1..32`.
  That is invalid when FName IDs are encrypted. Current builds never fabricate IDs; names are validated
  only from real objects. Use the current DLL and do not add a synthetic name test.
- **Names are empty / show Name_N with `style: "function"`**: verify the FNameToString RVA and ABI
  (`fstring_ref` vs `fstring_value`). The function must write into the supplied FString buffer.
- **GWorld is null with a chain**: verify GEngine, then `GameViewport`/`World` offsets. A null hop is
  reported in `get_globals`; this is expected before a world is loaded.
- **ProcessEvent errors about game thread**: set a valid `ue.process_event` so the hook can install, or
  opt into direct fallback (unsafe).
- **Game crashes after injection**: revert the last UE offsets; disable `process_event.hook`; verify the
  signature. Use an offline copy.
- **Self-unload did not unload**: another LoadLibrary handle exists (injector), or a game-thread call was
  still active; see the log.

## How this was built

This project was built with heavy AI assistance under human direction. The author chose the targets,
ran every test on builds they own, and verified the results. Offsets and examples are build-specific;
review the code before loading it into your own process.

## License

MIT. See [LICENSE](LICENSE). Vendored dependencies keep their own licenses: nlohmann/json (MIT)
and MinHook (BSD-2-Clause).

## Authorized use and reporting

This is a local research tool. Use it only on builds and accounts you own, with anti-cheat disabled, and
only where you are authorized to test. Do not use it against public matches, other players, or services
you do not control. See [SECURITY.md](SECURITY.md) for the full policy and how to report an issue in
FortniteMCP itself.

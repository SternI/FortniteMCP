# Contributing

## Build

Requirements: Windows x64, Visual Studio 2022 with the C++ x64 tools and MASM,
CMake 3.24+, Ninja.

```bat
scripts\build.bat
```

`scripts\clean_build.bat` does a clean rebuild.

## Tests

`FortniteMCPTestHost.exe` loads the DLL in a harmless process, so the MCP server can be
tested without the game:

```bat
set FORTNITEMCP_CONFIG=%CD%\build\test\config.json
build\release\bin\FortniteMCPTestHost.exe --seconds 120
python scripts\mcp_smoke_test.py --token <contents of build\test\token.txt>
```

## Code guidelines

- Keep the server loopback-bound with bearer-token auth by default.
- Keep memory access range-checked and fault-tolerant for reads.
- Do not add anti-cheat evasion, process hiding, or remote/network injection.
- The DLL is manual-map friendly: dynamic CRT (`/MD`), no module TLS, and no non-trivial
  function-local statics.
- Do not call reflected enumeration (for example `list_functions`) on Blueprint or
  PlayerController objects in a live game; it is known to kill the client. Use explicit
  UFunction paths instead.

## AI-assisted contributions

AI-assisted contributions are welcome. You are responsible for reviewing, building, and testing
anything you submit, and for following the safety scope below.

## Scope

Contributions are accepted only for authorized offline/private testing and local API
research. Do not submit use cases that target public matches, other players, or services
you do not control.

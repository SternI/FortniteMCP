import argparse
import http.client
import json
import struct
import sys
import time
from pathlib import Path

FAILS = []


def check(name, condition, detail=""):
    print(("PASS " if condition else "FAIL ") + name + ((" :: " + str(detail)) if detail else ""))
    if not condition:
        FAILS.append(name)


class Rpc:
    def __init__(self, host, port, token):
        self.host = host
        self.port = port
        self.token = token
        self.next_id = 1

    def post(self, payload, auth=True, timeout=30):
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if auth:
            headers["Authorization"] = "Bearer " + self.token
        conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        conn.request("POST", "/mcp", body=body, headers=headers)
        response = conn.getresponse()
        data = response.read()
        status = response.status
        conn.close()
        return status, data

    def call(self, name, arguments=None, timeout=30):
        payload = {
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
        self.next_id += 1
        status, data = self.post(payload, timeout=timeout)
        if status != 200:
            return status, True, {"transport_error": data.decode(errors="replace")}
        reply = json.loads(data)
        if "error" in reply:
            return status, True, reply["error"]
        result = reply["result"]
        text = result["content"][0]["text"]
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = {"text": text}
        return status, result.get("isError", False), parsed


def export_rva(pe_path, export_name):
    data = Path(pe_path).read_bytes()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nt = e_lfanew
    num_sections = struct.unpack_from("<H", data, nt + 6)[0]
    opt_size = struct.unpack_from("<H", data, nt + 20)[0]
    opt = nt + 24
    export_dir_rva, export_dir_size = struct.unpack_from("<II", data, opt + 112)
    section_off = opt + opt_size
    sections = []
    for i in range(num_sections):
        off = section_off + i * 40
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append((virtual_address, virtual_size, raw_ptr, raw_size))

    def rva_to_off(rva):
        for va, vsize, raw_ptr, raw_size in sections:
            if va <= rva < va + max(vsize, raw_size):
                return raw_ptr + (rva - va)
        return rva

    exp = rva_to_off(export_dir_rva)
    number_of_names = struct.unpack_from("<I", data, exp + 24)[0]
    address_of_names = struct.unpack_from("<I", data, exp + 32)[0]
    address_of_ordinals = struct.unpack_from("<I", data, exp + 36)[0]
    address_of_functions = struct.unpack_from("<I", data, exp + 28)[0]

    for i in range(number_of_names):
        name_rva = struct.unpack_from("<I", data, rva_to_off(address_of_names) + i * 4)[0]
        name_off = rva_to_off(name_rva)
        end = data.index(b"\0", name_off)
        if data[name_off:end].decode(errors="ignore") == export_name:
            ordinal = struct.unpack_from("<H", data, rva_to_off(address_of_ordinals) + i * 2)[0]
            rva = struct.unpack_from("<I", data, rva_to_off(address_of_functions) + ordinal * 4)[0]
            return rva
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=26064)
    parser.add_argument("--dll", default=str(Path(__file__).resolve().parent.parent / "build/release/bin/FortniteMCP.dll"))
    args = parser.parse_args()

    rpc = Rpc(args.host, args.port, args.token)

    status, data = rpc.post({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                             "params": {"protocolVersion": "2025-06-18", "capabilities": {}}})
    init = json.loads(data)["result"]
    check("initialize", status == 200 and init["serverInfo"]["name"] == "FortniteMCP", init["protocolVersion"])

    status, data = rpc.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
    check("notification is 202", status == 202 and not data, status)

    status, data = rpc.post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = json.loads(data)["result"]["tools"]
    check("tools/list", len(tools) >= 39, len(tools))
    check("tools have schemas", all(isinstance(t.get("inputSchema"), dict) for t in tools))

    status, data = rpc.post({"jsonrpc": "2.0", "id": 90, "method": "ping"}, auth=False)
    check("auth required", status == 401, status)

    status, is_error, st = rpc.call("status")
    check("status", not is_error and st.get("server", {}).get("version") == "1.0.0")
    main_base = st["process"]["main_base"]
    main_name = st["process"]["main_module"]

    status, is_error, modules = rpc.call("memory_modules", {"filter": main_name})
    check("memory_modules", not is_error and modules.get("count", 0) >= 1, modules.get("count"))

    status, is_error, info = rpc.call("memory_module_info", {"name": "main"})
    check("memory_module_info", not is_error and len(info.get("sections", [])) > 0)

    status, is_error, alloc = rpc.call("memory_alloc", {"size": 256, "protection": "rw", "label": "smoke"})
    check("memory_alloc", not is_error and alloc.get("address", "").startswith("0x"), alloc)
    address = alloc.get("address")
    addr_int = int(address, 16)

    status, is_error, written = rpc.call("memory_write", {
        "address": address,
        "bytes_hex": "DEADBEEF11223344",
        "label": "smoke-write",
    })
    check("memory_write", not is_error and written.get("written") == 8, written)
    patch_id = written.get("patch_id")

    status, is_error, read = rpc.call("memory_read", {
        "address": address,
        "size": 16,
        "decode": [{"type": "u32", "offset": 0}, {"type": "u16", "offset": 4}, {"type": "u16", "offset": 6}],
    })
    check("memory_read", not is_error and read.get("hex", "").lower().startswith("deadbeef11223344"), read.get("hex"))
    values = {v["type"] + str(v["offset"]): v["value"] for v in read.get("values", [])}
    check("typed decode", values.get("u320") == 0xEFBEADDE, values)

    status, is_error, scan = rpc.call("memory_scan", {
        "pattern": "DE AD BE EF 11 22 33 44",
        "start": address,
        "end": hex(addr_int + 256),
        "max_results": 4,
    })
    check("memory_scan", not is_error and scan.get("matches_count") == 1, scan)

    ptr_hex = (addr_int + 0x10).to_bytes(8, "little").hex()
    status, is_error, _ = rpc.call("memory_write", {"address": address, "bytes_hex": ptr_hex})
    check("write pointer", not is_error)
    status, is_error, chain = rpc.call("memory_pointer_chain", {
        "base": address,
        "steps": [{"offset": 0, "deref": True}],
        "final_type": "u32",
    })
    check("pointer_chain", not is_error and int(chain.get("final_address", "0"), 16) == addr_int + 0x10, chain.get("final_address"))

    status, is_error, patches = rpc.call("patch_list")
    check("patch_list", not is_error and patches.get("count", 0) >= 1, patches.get("count"))

    if patch_id is not None:
        status, is_error, undo = rpc.call("patch_undo", {"id": patch_id})
        check("patch_undo", not is_error and undo.get("restored") == 1, undo)
        status, is_error, read2 = rpc.call("memory_read", {"address": address, "size": 8})
        check("patch restored", not is_error and read2.get("hex", "").startswith("0000000000000000"), read2.get("hex"))

    status, is_error, freed = rpc.call("memory_free", {"address": address})
    check("memory_free", not is_error and freed.get("freed") == address, freed)

    status, is_error, big = rpc.call("memory_alloc", {"size": 2 * 1024 * 1024, "protection": "rw", "label": "scan-boundary"})
    check("scan allocation", not is_error, big)
    big_addr = int(big.get("address", "0"), 16)
    marker = bytes([0x4D, 0x5A, 0xC3, 0x99, 0x01, 0x02, 0x03, 0x04])
    marker_target = big_addr + 1024 * 1024 - 3
    status, is_error, _ = rpc.call("memory_write", {"address": hex(marker_target), "bytes_hex": marker.hex()})
    check("scan marker write", not is_error)
    status, is_error, boundary = rpc.call("memory_scan", {
        "pattern": "4D 5A C3 99 01 02 03 04",
        "start": hex(big_addr),
        "end": hex(big_addr + 2 * 1024 * 1024),
        "max_results": 8,
    })
    check("scanner boundary", not is_error and boundary.get("matches_count") == 1 and
          int(boundary["matches"][0]["address"], 16) == marker_target, boundary)
    rpc.call("memory_free", {"address": hex(big_addr)})

    status, is_error, bad = rpc.call("memory_read", {"address": "0x10", "size": 8})
    check("invalid read rejected", is_error, bad)

    status, is_error, ue = rpc.call("ue_status")
    check("ue_status", not is_error and ue.get("resolved") is True)

    status, is_error, find = rpc.call("find_object", {"path": "Engine.Actor"})
    check("UE tools degrade gracefully", is_error, find)

    status, is_error, pe = rpc.call("process_event", {"object": "0x1000", "function": "0x1000"})
    check("process_event degrades gracefully", is_error, pe)

    status, is_error, cfg = rpc.call("ue_configure", {"game_thread": {"timeout_ms": 4000}})
    check("ue_configure", not is_error)
    status, is_error, ue2 = rpc.call("ue_status")
    check("runtime config applied", not is_error and ue2.get("game_thread", {}).get("timeout_ms") == 4000, ue2.get("game_thread"))
    rpc.call("ue_configure", {"game_thread": {"timeout_ms": 5000}})

    status, is_error, inp = rpc.call("input_window")
    check("input_window handled", is_error or inp.get("window"), inp)

    dll_rva = export_rva(args.dll, "FmcpAbiVersion")
    status, is_error, full_modules = rpc.call("memory_modules", {})
    dll_base = next((m for m in full_modules.get("modules", []) if "fortnitemcp.dll" in m["name"].lower()), None)
    check("find DLL module", dll_base is not None and dll_rva is not None, (dll_base, dll_rva))
    if dll_base and dll_rva is not None:
        target = int(dll_base["base"], 16) + dll_rva
        status, is_error, called = rpc.call("call_address", {
            "address": hex(target),
            "args": [],
            "return_type": "u32",
            "allow_direct": True,
        })
        check("call_address", not is_error and called.get("value") == 1, called)

        mix_rva = export_rva(args.dll, "FmcpAbiTest")
        check("find mixed-ABI export", mix_rva is not None)
        if mix_rva is not None:
            mix_target = int(dll_base["base"], 16) + mix_rva
            status, is_error, mixed = rpc.call("call_address", {
                "address": hex(mix_target),
                "args": [
                    {"type": "int", "value": 1},
                    {"type": "double", "value": 2.0},
                    {"type": "int", "value": 3},
                    {"type": "double", "value": 4.0},
                    {"type": "int", "value": 5},
                    {"type": "int", "value": 6},
                    {"type": "double", "value": 7.0},
                ],
                "return_type": "u64",
                "allow_direct": True,
            })
            check("call_address mixed ABI", not is_error and mixed.get("value") == 15013,
                  mixed)

    status, is_error, loaded = rpc.call("load_dll", {"path": "C:\\Windows\\System32\\version.dll", "label": "smoke"})
    if is_error:
        check("load_dll (skipped/failed)", False, loaded)
    else:
        check("load_dll", loaded.get("loaded") is True, loaded.get("base"))
        status, is_error, listed = rpc.call("dll_list")
        check("dll_list", not is_error and any(d.get("label") == "smoke" for d in listed.get("dlls", [])), listed)
        status, is_error, unloaded = rpc.call("unload_dll", {"module": "version.dll", "confirm": True})
        check("unload_dll", not is_error and unloaded.get("unloaded") == "version.dll", unloaded)

    host_exe = str(Path(args.dll).with_name("FortniteMCPTestHost.exe"))
    fake_name_rva = export_rva(host_exe, "FmcpFakeNameToString")
    fake_engine_slot_rva = export_rva(host_exe, "g_fmcpFakeEngineSlot")
    fake_world_rva = export_rva(host_exe, "g_fmcpFakeWorld")
    check("test fixtures exported", fake_name_rva is not None and fake_engine_slot_rva is not None and
          fake_world_rva is not None, (fake_name_rva, fake_engine_slot_rva, fake_world_rva))
    if fake_name_rva is not None and fake_engine_slot_rva is not None and fake_world_rva is not None:
        status, is_error, configured = rpc.call("ue_configure", {"ue": {
            "names": {"style": "function", "resolve": "offset", "offset": hex(fake_name_rva),
                      "abi": "fstring_ref", "fname_size": 4, "max_chars": 64},
            "gengine": {"resolve": "offset", "offset": hex(fake_engine_slot_rva), "decode": ""},
            "gworld": {"resolve": "chain", "from": "gengine", "chain": [0xB70, 0x78], "decode": ""},
        }})
        check("fake UE configure", not is_error, configured)
        status, is_error, fake_ue = rpc.call("ue_status")
        world_name = fake_ue.get("globals", {}).get("gworld", {}).get("name", "")
        check("FNameToString backend", not is_error and fake_ue.get("flags", {}).get("names") is True and
              fake_ue.get("names", {}).get("style") == "function" and
              "FakeName_" in world_name, world_name)
        status, is_error, fname = rpc.call("resolve_fname", {"index": 7})
        check("resolve_fname", not is_error and fname.get("faulted") is False and
              fname.get("name") == "FakeName_7", fname)
        chain = fake_ue.get("globals", {}).get("gworld", {}).get("chain", [])
        viewport_value = next((h.get("value") for h in chain if h.get("hop") == 1), None)
        if viewport_value:
            status, is_error, found = rpc.call("find_pointer_field", {
                "owner": viewport_value, "class": "FakeName_7", "max_offset": 256,
            })
            check("find_pointer_field", not is_error and
                  any(m.get("offset") == 0x78 for m in found.get("matches", [])), found)
        status, is_error, globals_out = rpc.call("get_globals")
        world_entry = next((g for g in globals_out.get("globals", []) if g.get("name") == "gworld"), None)
        expected_world = int(main_base, 16) + fake_world_rva
        check("GEngine->GameViewport->World chain", not is_error and world_entry is not None and
              int(world_entry.get("value", "0"), 16) == expected_world,
              (world_entry, hex(expected_world)))
        rpc.call("ue_configure", {"ue": {
            "names": {"style": "off", "resolve": "off"},
            "gengine": {"resolve": "off"},
            "gworld": {"resolve": "off"},
        }})

    status, is_error, logdata = rpc.call("get_log", {"lines": 10})
    check("get_log", not is_error and len(logdata.get("text", "")) > 0)

    status, is_error, selftest = rpc.call("self_test")
    check("self_test", not is_error and selftest.get("ok") is True, [t["name"] for t in selftest.get("tests", []) if not t["ok"]])

    print()
    if FAILS:
        print("FAILED:", ", ".join(FAILS))
        return 1
    print("ALL SMOKE TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

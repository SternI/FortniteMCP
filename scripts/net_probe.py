import json
import os
import pathlib
import struct
import time
import http.client

TOKEN_PATH = pathlib.Path(os.path.expandvars(r"%LOCALAPPDATA%\FortniteMCP\token.txt"))


def call(name, args=None, timeout=90):
    token = TOKEN_PATH.read_text().strip()
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": name, "arguments": args or {}}})
    conn = http.client.HTTPConnection("127.0.0.1", 26064, timeout=timeout)
    conn.request("POST", "/mcp", body,
                 {"Content-Type": "application/json", "Authorization": "Bearer " + token})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    reply = json.loads(data)
    if "error" in reply:
        raise RuntimeError(reply["error"])
    result = reply["result"]
    text = result["content"][0]["text"]
    if result.get("isError"):
        raise RuntimeError(text)
    return json.loads(text)


def read(addr, size):
    r = call("memory_read_safe", {"address": hex(addr), "size": size})
    if not r.get("ok"):
        raise RuntimeError(r.get("error", "unreadable") + " @" + hex(addr))
    return bytes.fromhex(r["hex"])


def qword(addr):
    b = read(addr, 8)
    return struct.unpack("<Q", b)[0] if len(b) == 8 else 0


def name_of(addr):
    if not addr or addr < 0x10000:
        return None
    try:
        b = read(addr + 0x20, 8)
        index, number = struct.unpack("<II", b)
        r = call("resolve_fname", {"index": index, "number": number})
        return None if r.get("faulted") else r.get("name")
    except Exception:
        return None


def class_of(addr):
    if not addr or addr < 0x10000:
        return None
    try:
        return name_of(qword(addr + 0x10))
    except Exception:
        return None


def describe(addr):
    try:
        return {"address": hex(addr), "name": name_of(addr), "class": class_of(addr)}
    except Exception as exc:
        return {"address": hex(addr), "error": str(exc)}


def find_manager_in(owner, label, max_offset=0x2000):
    found = []
    try:
        data = read(owner, max_offset)
    except Exception as exc:
        return found
    for off in range(0, len(data) - 8, 8):
        ptr = struct.unpack_from("<Q", data, off)[0]
        if ptr < 0x10000 or ptr > 0x7FFFFFFEFFFF:
            continue
        try:
            block = read(ptr, 0x170)
        except Exception:
            continue
        if len(block) < 0x168:
            continue
        cap = struct.unpack_from("<i", block, 0x38)[0]
        cap_min = struct.unpack_from("<i", block, 0x3C)[0]
        cap_max = struct.unpack_from("<i", block, 0x40)[0]
        padding = struct.unpack_from("<i", block, 0x44)[0]
        loss = struct.unpack_from("<f", block, 0x4C)[0]
        ping = struct.unpack_from("<f", block, 0x50)[0]
        jitter = struct.unpack_from("<f", block, 0x54)[0]
        poll = struct.unpack_from("<f", block, 0x160)[0]
        if not (0 <= loss <= 100 and 0 <= ping <= 5000 and 0 <= jitter <= 5000):
            continue
        if not (1 <= cap <= 10000000 and 0 <= cap_min <= 10000000 and
                0 <= cap_max <= 10000000 and 0 <= padding <= 10000000):
            continue
        if not (0.0001 <= poll <= 120):
            continue
        found.append({"owner": label, "field": hex(off), "manager": hex(ptr),
                      "cap_kbps": cap, "cap_min": cap_min, "cap_max": cap_max,
                      "padding_kbps": padding, "loss_pct": round(loss, 3),
                      "baseline_ping_ms": round(ping, 3), "ping_variance_ms": round(jitter, 3),
                      "poll_s": round(poll, 4)})
    return found


def delta_scan(conn_addr, seconds=1.0):
    size = 0x19D0
    first = read(conn_addr, size)
    time.sleep(seconds)
    second = read(conn_addr, size)
    hits = []
    for off in range(0, size - 4, 4):
        a = struct.unpack_from("<I", first, off)[0]
        b = struct.unpack_from("<I", second, off)[0]
        d = (b - a) & 0xFFFFFFFF
        if 5 <= d <= 5000:
            hits.append({"offset": hex(off), "delta": d, "value": b, "class": "packets?"})
        elif 2000 <= d <= 50000000:
            hits.append({"offset": hex(off), "delta": d, "value": b, "class": "bytes?"})
    floats = []
    for off in range(0, size - 4, 4):
        v = struct.unpack_from("<f", second, off)[0]
        if 0.0005 <= v <= 2.0:
            floats.append({"offset": hex(off), "value": round(v, 5)})
    return hits, floats


def main():
    status = call("ue_status")
    world = int(status["globals"]["gworld"]["value"], 16)
    engine = int(status["globals"]["gengine"]["value"], 16)
    print("world", hex(world), status["globals"]["gworld"].get("name"))
    print("engine", hex(engine), status["globals"]["gengine"].get("name"))

    net_driver = qword(world + 0x48)
    print("netdriver@world+0x48", describe(net_driver) if net_driver else None)

    connection = 0
    if net_driver:
        for off in [0x118, 0x120, 0x110, 0x128]:
            cand = qword(net_driver + off)
            if cand and "onnection" in (class_of(cand) or ""):
                connection = cand
                print("connection@netdriver+0x%X" % off, describe(cand))
                break
        if not connection:
            for off in range(0x100, 0x180, 8):
                cand = qword(net_driver + off)
                if cand and "onnection" in (class_of(cand) or ""):
                    connection = cand
                    print("connection@netdriver+0x%X" % off, describe(cand))
                    break
    print("connection", describe(connection) if connection else None)

    owners = [("world", world), ("engine", engine), ("netdriver", net_driver)]
    viewport = qword(engine + 0xB70) if engine else 0
    if viewport:
        owners.append(("gameviewport", viewport))
    game_instance = qword(world + 0x250) if world else 0
    if game_instance:
        owners.append(("gameinstance", game_instance))

    managers = []
    for label, owner in owners:
        if owner:
            managers.extend(find_manager_in(owner, label))
    print("manager_candidates", json.dumps(managers, indent=1))

    if connection:
        packets, floats = delta_scan(connection)
        print("connection_deltas", json.dumps(packets[:40], indent=1))
        print("connection_floats", json.dumps(floats[:40], indent=1))


if __name__ == "__main__":
    main()

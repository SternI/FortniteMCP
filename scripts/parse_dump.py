import struct
import sys
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

if len(sys.argv) < 2:
    print("usage: python scripts/parse_dump.py <path-to-minidump.dmp>")
    raise SystemExit(2)
DUMP = Path(sys.argv[1])
data = DUMP.read_bytes()

sig, ver, nstreams, dirrva, checksum, timestamp, flags = struct.unpack_from("<IIIIIIQ", data, 0)
streams = {}
for i in range(nstreams):
    stype, size, rva = struct.unpack_from("<III", data, dirrva + i * 12)
    streams[stype] = (size, rva)

modules = []
if 4 in streams:
    size, rva = streams[4]
    count = struct.unpack_from("<I", data, rva)[0]
    off = rva + 4
    for _ in range(count):
        base, msize, checksum, tds, nameRva = struct.unpack_from("<QIIII", data, off)
        nameOff = rva + nameRva
        # MINIDUMP_STRING: length u32 in bytes, then UTF-16
        slen = struct.unpack_from("<I", data, nameOff)[0]
        name = data[nameOff + 4:nameOff + 4 + slen].decode("utf-16-le", errors="replace")
        modules.append((base, msize, name.encode("ascii", "replace").decode("ascii")))
        off += 108

def module_for(addr):
    for base, size, name in modules:
        if base <= addr < base + size:
            return f"{Path(name).name}+0x{addr-base:X}"
    return None

# Exception stream 6
ctx_rva = None
exc_tid = None
exc_addr = None
exc_code = None
if 6 in streams:
    size, rva = streams[6]
    exc_tid = struct.unpack_from("<I", data, rva)[0]
    e = rva + 8
    exc_code, exc_flags = struct.unpack_from("<II", data, e)
    exc_record = struct.unpack_from("<Q", data, e + 8)[0]
    exc_addr = struct.unpack_from("<Q", data, e + 16)[0]
    nparams = struct.unpack_from("<I", data, e + 24)[0]
    info = struct.unpack_from("<15Q", data, e + 32)
    ctx_size, ctx_rva = struct.unpack_from("<II", data, e + 152)

# Thread list for contexts
threads = []
if 3 in streams:
    size, rva = streams[3]
    count = struct.unpack_from("<I", data, rva)[0]
    off = rva + 4
    for _ in range(count):
        tid, suspend, pclass, prio, teb = struct.unpack_from("<IIIIQ", data, off)
        stack_start, stack_size, stack_rva = struct.unpack_from("<QII", data, off + 24)
        ctx_size2, ctx_rva2 = struct.unpack_from("<II", data, off + 40)
        threads.append((tid, stack_start, stack_size, stack_rva, ctx_rva2, teb))
        off += 48
        # MINIDUMP_THREAD size is 48 on x64

ctx = None
ctx_thread = None
for t in threads:
    if t[0] == exc_tid:
        ctx_thread = t
        if ctx_rva is None:
            ctx_rva = t[4]
        break
if ctx_rva is None and ctx_thread:
    ctx_rva = ctx_thread[4]

regs = {}
if ctx_rva:
    base = ctx_rva
    names = ["Rax","Rcx","Rdx","Rbx","Rsp","Rbp","Rsi","Rdi","R8","R9","R10","R11","R12","R13","R14","R15","Rip"]
    for i, name in enumerate(names):
        regs[name] = struct.unpack_from("<Q", data, base + 0x78 + i * 8)[0]

# Memory segments: MemoryList (5) and Memory64List (9)
memranges = []
if 5 in streams:
    size, rva = streams[5]
    count = struct.unpack_from("<I", data, rva)[0]
    off = rva + 4
    for _ in range(count):
        start, msize, mrva = struct.unpack_from("<QII", data, off)
        memranges.append((start, msize, mrva))
        off += 16
if 9 in streams:
    size, rva = streams[9]
    count, baseRva = struct.unpack_from("<QQ", data, rva)
    off = rva + 16
    fileoff = baseRva
    for _ in range(count):
        start, msize = struct.unpack_from("<QQ", data, off)
        memranges.append((start, msize, fileoff))
        off += 16
        fileoff += msize

def read_virtual(addr, size):
    for start, msize, mrva in memranges:
        if start <= addr and addr + size <= start + msize:
            off = mrva + (addr - start)
            return data[off:off + size]
    return None

print("streams", sorted(streams))
print("modules", len(modules))
print("exception tid", hex(exc_tid) if exc_tid else None, "code", hex(exc_code) if exc_code else None,
      "addr", hex(exc_addr) if exc_addr else None, "read", hex(info[1]) if nparams > 1 else None)
print("regs", {k: hex(v) for k, v in regs.items()})
print("memranges", len(memranges))
print("stack module", module_for(regs.get("Rsp", 0)))

if "Rsp" in regs:
    rsp = regs["Rsp"]
    raw = read_virtual(rsp, 0x600)
    if raw:
        for i in range(0, min(len(raw), 0x400), 8):
            val = struct.unpack_from("<Q", raw, i)[0]
            loc = module_for(val)
            if loc is None and 0x180000000 <= val < 0x180200000:
                loc = f"MCP+0x{val-0x180000000:X}"
            if loc:
                print(f"stack+{i:03X} {rsp+i:016X} {val:016X} {loc}")
    else:
        print("no stack memory for Rsp", hex(rsp))

# Search stack for object-looking pointers near MCP/game module, and name indices maybe
if "Rsp" in regs:
    rsp = regs["Rsp"]
    raw = read_virtual(rsp - 0x400, 0x1000)
    if raw:
        print("stack around rsp written to dump_stack.bin")
        Path("build/dump_stack.bin").write_bytes(raw)

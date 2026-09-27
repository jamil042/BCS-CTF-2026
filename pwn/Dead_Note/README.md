# Dead Note

| | |
|---|---|
| **CTF** | BCS CTF 2026 |
| **Category** | Pwn |
| **Difficulty** | Hard |
| **Points** | 483 (12 solves) |
| **Author** | 0xblackfox |
| **File** | `deadnote` (+ `libc.so.6`, `ld-linux-x86-64.so.2`) |
| **Flag** | `bcsctf{st4ck_0rw_1n_c0ld_st0r4g3_n0_sh3ll_4ll0w3d}` |

## Challenge

> Cold storage for the dead internet. Every memo is frozen read only, and the viewer spawns
> a fresh worker to thaw each page a torn page only ever costs a worker, never the vault.
> That is just how cold storage works. Nothing can go wrong.
>
> Server: `nc 172.16.38.22 6657`

## TL;DR

A memo service (Full RELRO, canary, NX, PIE, seccomp, glibc 2.35) where reading a memo
`fwrite`s a **256-byte stack buffer that's only ever filled with as many bytes as the memo's
stored size** - so a short memo leaks whatever was on the stack from earlier calls: a stale
copy of the **canary** and a **libc return address**, both at fixed offsets, in a single
read. The same read path also has a stack **buffer overflow** (up to 640 bytes into a
264-byte buffer). Seccomp blocks `execve`/`execveat` and neuters `open()`, but leaves
**`openat()`** untouched, so the payload is a plain libc ROP chain doing
`read`→`openat`→`read`→`write` to cat `flag.txt` straight to the socket - no shell needed,
and the "torn page only costs a worker" flavor text turns out to be literally true: the
whole exploit runs inside the forked child that dies right after.

## Binary analysis

```
$ checksec deadnote
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

`main()` calls `setup()` → `gate()` (a PoW/verification gate) → `lockdown()` (installs a
seccomp filter) → `build_menu()` (shuffles the menu option numbers) → a loop over `menu()`.

Global state:

```c
void   *notes[8];   // @ 0x4040
size_t  sizes[8];   // @ 0x4080
int     count;      // @ 0x40c0
```

- **Write** (`write_memo`): reject if `count >= 8`; read a size `0 < size <= 0x280`;
  `malloc(size)`; read exactly `size` bytes into it via `read_raw` (a `read()`-until-full
  loop, no NUL tricks here).
- **Read** (`read_memo`, the interesting one, `0x1b8c`):

  ```c
  int idx = read_int();
  if (idx < 0 || idx >= count) { puts("no such memo"); return; }
  char buf[0x108];                 // rbp-0x110, canary at rbp-0x8
  for (size_t i = 0; i < sizes[idx]; i++)
      buf[i] = notes[idx][i];      // copies sizes[idx] bytes - NOT clamped to sizeof(buf)!
  fwrite(buf, 1, 0x100, stdout);   // always writes 256 bytes, regardless of sizes[idx]
  putchar('\n');
  ```

  Two bugs live here:
  1. The copy loop trusts `sizes[idx]` completely - writing a memo of size up to `0x280`
     (640) overflows `buf` (only 264 bytes to the saved RBP, and the canary sits right after
     at `rbp-8`) straight into the saved return address.
  2. The `fwrite` always sends **256 bytes of `buf`**, even when the note itself was much
     shorter - so anything past the note's own data is *uninitialized stack from a previous
     stack frame*, and it gets leaked to us for free.
- **Remove** simply swaps the entry out and `free()`s it (no null-out - a UAF exists too,
  but it isn't needed for this solve).
- Every memo operation is dispatched from inside a **`fork()`ed child** in `main()`'s loop;
  the parent `waitpid()`s and prints `"[+] page served"` if the child exited normally or
  `"[-] the page resisted"` if it died to a signal. That's the "a torn page only ever costs
  a worker" line: crashing the child (e.g. a bad canary) doesn't crash the vault, and also
  hands you a free **crash oracle** if you ever need to brute-force something byte-by-byte.
  We didn't need it here - see below.

## The gate: free PIE leak + a solvable PoW

Before the menu, `gate()` prints:

```
[*] Diagnostics: system() @ 0x<addr>
[*] Prove you are human.
[*] Token: <64 hex chars>
```

The "diagnostics" address is not `system()` - it's `rogue_filter()` (`pie_base + 0x12b9`),
an unused function that just prints a message and exits. So **`pie_base = leaked - 0x12b9`**,
handed to us before we've sent a single byte.

The token is 32 bytes read straight from `/dev/urandom`. `gate()`'s check (reversed from the
disassembly) is:

```c
ok = 1;
for (i = 0; i < 32; i++)
    if (((13*i) ^ input[i] ^ 0xA5) != token[i]) ok = 0;
```

so the correct response is simply:

```python
resp[i] = token[i] ^ 0xA5 ^ ((13 * i) & 0xff)
```

Send that back and the real menu unlocks. The menu itself is **shuffled per connection**
(seeded off the same token via a small Fisher-Yates in `build_menu()`), so the exploit has
to parse `"<n>) Write a memo"` etc. out of the banner every time rather than hard-coding
option numbers.

## Seccomp: `openat` survives, `execve`/`open` don't

`lockdown()` installs (via libseccomp) a default-**allow** filter that:

- kills `execve` (59) and `execveat` (322) with a signal - no shell, ever, even via ROP,
- forces `open` (2) to return `-EACCES` regardless of arguments.

It never touches `openat` (257), `read`, or `write`. That's the whole point of "no shell
allowed" in the flag: this has to be solved as **stack ORW** (open/read/write flag.txt and
print it), not `system("/bin/sh")`.

## Leak: canary and libc from one short memo

`read_memo`'s `fwrite` always dumps 256 bytes of the stack buffer, no matter how small the
requested memo is. Write a 32-byte throwaway memo, read it back, and the extra 224 bytes are
leftover stack from the previous stack frame(s) in this exact same child process (same
binary, same libc, same call sequence every time - so the layout is stable run to run).
Two offsets turned out to be gold, confirmed against a locally rebuilt copy of the exact
same Docker image (see *Pitfalls*):

```
leak[0xe8:0xf0]  ==  saved stack canary            (all frames share fs:[0x28])
leak[0xb8:0xc0]  ==  a libc return address, libc_base + 0x43654
```

```python
canary    = u64(leak[0xe8:0xf0])
libc_base = u64(leak[0xb8:0xc0]) - 0x43654
```

No brute force, no fork-crash oracle needed - both values, plus the PIE base from the
banner, come out of a single `write` + `read` round trip.

## The overflow: ROP chain in the forked worker

`read_memo` copies up to `sizes[idx]` bytes (max `0x280`) into a 264-byte buffer, so a
600-byte memo overflows straight past the canary and the saved return address, into ROP
gadgets, entirely inside the write's own stack frame in the forked child. Layout:

```
[ 264 bytes filler ]
[ canary            ]  (leaked value - keeps __stack_chk_fail from firing)
[ saved rbp         ]  (junk pivot, unused)
[ ROP chain...      ]
```

The ROP chain (four `read`/`openat`/`read`/`write` syscalls via `pop rdi`/`pop
rsi`/`pop rdx,rbx`/`pop rax`/`syscall ; ret` gadgets, all libc-base-relative):

1. `read(0, scratch, 16)` - the exploit script sends `"flag.txt\0"` right after triggering
   the read, landing in a writable BSS scratch page inside the PIE image.
2. `openat(AT_FDCWD, scratch, O_RDONLY)` → fd 3 (no `open` needed, so the seccomp filter
   never even notices).
3. `read(3, flagbuf, 0x100)`.
4. `write(1, flagbuf, 0x100)` - the flag goes straight out over the socket.

The forked child then falls off the end of the chain and dies (segfault/exit) - exactly
"a torn page only ever costs a worker" - but by then the flag has already been written to
the client.

## Solution

[`solve.py`](solve.py) automates the whole thing (needs `pwntools`):

```
$ python3 solve.py remote
[*] PIE base = 0x57b9f6b57000
[+] canary    = 0x348f7802af660100
[+] libc base = 0x736523b97000
[+] FLAG: bcsctf{st4ck_0rw_1n_c0ld_st0r4g3_n0_sh3ll_4ll0w3d}
```

## Pitfalls

- **Don't trust a leak offset until it's cross-checked against ground truth.** The
  `0xe8`/`0xb8` offsets weren't guessed - the shipped `Dockerfile` was rebuilt locally
  (`docker build .` against the exact same `ubuntu:22.04` base) so the target's real
  `libc.so.6` (`2.35-0ubuntu3.14`) and `ld-linux-x86-64.so.2` could be extracted and used to
  run the unmodified challenge binary locally via
  `./ld-linux-x86-64.so.2 --library-path . ./deadnote`. That let every offset (canary
  position, libc-leak offset, ROP gadget addresses) be verified against `/proc/<pid>/maps`
  across several runs *before* ever touching the real server, instead of guessing from a
  single remote round trip and hoping the stack layout matched.
- **`libseccomp2` in the `Dockerfile` is a tell, not decoration.** Seeing it in the package
  list before even disassembling meant checking exactly which syscalls survive
  (`seccomp_rule_add` calls in `lockdown()`) was the very next step - it's what ruled out
  `execve`/`system("/bin/sh")` early and pointed straight at ORW via the untouched `openat`.
- **A stack leak that "just happens" to be there is still a leak worth reverse-engineering
  precisely.** It would have been easy to dismiss the extra 224 bytes `fwrite` sends as
  noise; instead, diffing the same offsets across three separate local runs showed they
  were perfectly stable (same call chain -> same stale stack contents), which is what made
  skipping any brute force possible.

## Takeaways

- A function that always emits a fixed-size buffer, even when it only ever *fills* a
  variable, smaller amount of that buffer, is an automatic uninitialized-stack leak -
  worth checking on every "read back what I wrote" style feature.
- `fork()`-per-request isn't just isolation flavor text: it also means the previous
  frame's stack garbage is perfectly reproducible between the leak call and the exploit
  call, since both run through the identical call sequence inside a fresh child image every
  time.
- Seccomp filters that leave `openat` open while blocking `open` are a strong, specific
  signal to go looking for a stack/heap ORW chain rather than a one-shot `system()` call -
  read the syscall numbers being filtered, not just the function names in the source.

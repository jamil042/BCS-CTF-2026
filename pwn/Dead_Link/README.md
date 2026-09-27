# Dead Link

| | |
|---|---|
| **CTF** | BCS CTF 2026 |
| **Category** | Pwn |
| **Difficulty** | Hard |
| **Points** | 500 (0 solves) |
| **Author** | 0xblackfox |
| **File** | `deadlink` (+ `libc.so.6`, `ld-linux-x86-64.so.2`) |
| **Flag** | `bcsctf{nU11_byt3_31nh3rj4r_1n_th3_d34d_l1nk_n0de}` |

## Challenge

> A collector for the dead internet. Recently patched and declared stable. The auditors found nothing left to fix.
>
> Server: `nc 172.16.38.22 6656`

## TL;DR

A heap-note service (Full RELRO, PIE, NX, glibc 2.35) with a single-NUL off-by-one in its
input reader. The "auditors" missed that the challenge itself leaks a PIE pointer and hands
out a `binview` command that dumps freed-chunk `fd`/`size` fields on request - free a big
chunk for a **libc leak**, a small one for a **heap leak**. From there, a **House of
Einherjar** off-by-null merge overlaps a live node's data with a freshly carved node's
header, turning `change()` into an **arbitrary-address write**. Land that on
`_IO_2_1_stdout_`, forge a **House of Apple 2** FSOP FILE, and the next `printf` runs
`system("  /bin/sh")`.

## Binary analysis

```
$ file deadlink
deadlink: ELF 64-bit LSB pie executable, x86-64, ... dynamically linked, not stripped
$ readelf -d deadlink | grep -E 'FLAGS|BIND_NOW'
 (FLAGS)     BIND_NOW
 (FLAGS_1)   Flags: NOW PIE
```

Full RELRO + PIE + NX, glibc 2.35 (Ubuntu 22.04). GOT overwrites are out; this has to be a
heap-metadata / FSOP exploit.

The menu (`add` / `delete` / `change` / `print` / `view` / `exit`) manages a singly-linked
list of nodes:

```
node[0] = next          (8 bytes)
node[1] = stored size   (8 bytes)
node+0x10 = data...     (up to `size` bytes)
```

`add`/`change` both call a helper, `read_with_null()`:

```c
n = read(0, buf, size);
if (buf[n-1] == '\n') buf[n-1] = 0;   // trim the newline in-place
else                  buf[n]   = 0;   // otherwise NUL-terminate one past what we sent
```

Send **exactly** `size` bytes with no trailing newline and it writes a NUL at `buf[size]`
- one byte past the buffer, landing on the next chunk's size field. Classic
**poison-null-byte**.

## The gate

Before the menu even appears, the binary opens `/dev/urandom`, reads a 32-byte token, and
prints it back along with this line:

```
[*] Diagnostics: system() @ %p
```

It's not `system()` - the address printed is `dead_filter`'s (`pie_base + 0x1369`), an
unused "you got caught" function. Free **PIE leak**, no bug required.

The "human verification" is just XOR-based: reversing `gate()`'s check gives

```
resp[i] = token[i] ^ (7*i) ^ 0xC3
```

Send that back and the menu unlocks.

## The other free leak: `binview`

`delete` unlinks a node and pushes the raw pointer into a `bin[]` array *before* calling
`free()`. The `view` menu option then prints, straight from the freed chunk:

```
Bin(i): next=%p size=%lu data=%s
```

`next` is chunk-header-adjacent memory read straight through the freed pointer:

- Free a **large** chunk (request `0x4e8`, real chunk size `0x500`) → it lands in the
  **unsorted bin**, so its `fd` is `main_arena + 96` → **libc base**.
- Free a **small** chunk (request `0x28`) → it lands in **tcache 0x30**, so its mangled
  `fd` is `chunk_addr >> 12` (glibc 2.35 has no safe-linking on `fd`'s top bits here, just
  the pointer-mangle-by-shift used for `next`) → shift left 12 → **heap base**.

Both were confirmed against a live process with `/proc/<pid>/mem` before trusting them
blind on the real target - see *Pitfalls*.

## House of Einherjar: forging an overlap

With libc/heap leaks in hand, the single-NUL bug becomes a full **House of Einherjar**:

1. Allocate `C` (request `0x88` → chunk `0xa0`) immediately followed by `V` (request
   `0x4e8` → chunk `0x500`), plus a guard after `V` so it never merges with the top chunk.
2. `change(C)` with **exactly** `0x88` bytes, containing:
   - a forged chunk header `P` at the start of `C`'s own data (`size = 0x80`,
     `fd = bk = P` so glibc's unlink check `P->fd->bk == P && P->bk->fd == P` trivially
     passes),
   - `prev_size(V) = 0x80` at the very end of the buffer,
   - and, by omitting the trailing byte, the off-by-one NUL lands exactly on `V`'s size
     field, clearing its `PREV_INUSE` bit.
3. `delete(V)`. Because `PREV_INUSE(V)` is now 0, `free()` believes the chunk before `V`
   is free and backward-consolidates it - unlinking our forged `P` (trivial, since it's
   its own `fd`/`bk`) and merging it with `V` into one large **unsorted chunk that starts
   inside `C`'s live data** and overlaps `C` itself.

```
[ C node (0xa0) ][ V node (0x500) ][ guard ]
   ^--- P forged here, size=0x80
after free(V): merged unsorted chunk = P .. end-of-V, overlapping C's data
```

## Arbitrary write: node injection

4. `add(0x88, ...)` carves a new node `X` straight out of the merged chunk, i.e. at `P`'s
   old address. `X`'s header (`next` at `+0x10`, `size` at `+0x18`) now sits *inside `C`'s
   data* at offsets `0x10`/`0x18`.
5. `change(C)` again → we now directly control `X.next`. Since every list operation reads
   `next`/`size`/`data` straight from whatever address is stored there, pointing `X.next`
   at **any address minus `0x10`** turns that address into a fully-controlled fake node:
   `change(X)` reads its "size" from `*(target+8)` and writes attacker data starting at
   `target` for that many bytes.

We aim it at `_IO_2_1_stdout_ - 0x10`. The 8 bytes at `stdout - 8` happen to be a large
libc pointer, so the "size" the program reads there is enormous - more than enough to
write a full fake `FILE`.

## House of Apple 2: `printf` → `system("  /bin/sh")`

With arbitrary-length writes landing at `_IO_2_1_stdout_`, forge a minimal
[House of Apple 2](https://bbs.kanxue.com/thread-276618.htm) FSOP FILE:

```
fake[0x00:0x09] = "  /bin/sh\0"   # doubles as system()'s argument
fake[0x20:0x28] = 0               # _IO_write_base
fake[0x28:0x30] = 1               # _IO_write_ptr  (> write_base -> triggers overflow)
fake[0x88:0x90] = H               # _lock -> writable scratch
fake[0xa0:0xa8] = H               # _wide_data -> fake wide_data (also at H)
fake[0xc0:0xc8] = 0               # _mode = 0 (not yet wide-oriented)
fake[0xd8:0xe0] = _IO_wfile_jumps # vtable
```

`H` (a separately-allocated "cfg" node) doubles as the fake `_IO_wide_data`, with its own
`_wide_vtable` pointing at **itself**, and slot `0x68` (`__doallocate`) overwritten with
`system`.

The moment this write lands, the very next `printf` (the challenge's own
`"Success : Change %dth entry\n"`) touches `stdout`, glibc walks into
`_IO_wfile_overflow` → wide-orientation setup → `_IO_WDOALLOCATE(fp)` →
`fp->_wide_data->_wide_vtable->__doallocate(fp)` = `system(fp)`. Since `fp`'s first bytes
are the string `"  /bin/sh"`, that's `system("  /bin/sh")` - a shell, as the `error` user
inside the container, with `/script/flag.txt` sitting right there.

## Solution

[`solve.py`](solve.py) automates the whole chain (needs `pwntools`):

```
$ python3 solve.py remote
[+] PIE base: 0x5ac5bf79e000
[+] libc base: 0x78093dd63000
[+] heap base: 0x5ac5f58ea000
[+] system   : 0x78093ddb3d70
[*] overwriting stdout -> FSOP -> system('  /bin/sh')
$ cat /script/flag.txt
bcsctf{nU11_byt3_31nh3rj4r_1n_th3_d34d_l1nk_n0de}
```

## Pitfalls

- **Trusting a working local exploit against a socket without testing it as a socket
  first.** The exploit was 5/5 reliable run locally under `process()` (a pipe), then
  appeared to silently break over the real `nc` connection - no crash message, just a
  lone `\n` and a closed connection. It turned out FSOP had actually succeeded and the
  shell was alive and waiting; the *test harness* was the bug (`Popen.communicate(input=…)`
  closes stdin/EOFs after writing, and `pwntools`' `interactive()` tears the whole
  connection down on local EOF before remote output has a chance to arrive). Stood up a
  throwaway local TCP server for the same binary, watched raw bytes with patient,
  explicit `recv()`s instead of `interactive()`, and confirmed the payload itself was
  fine all along. **When remote behaves differently from local, suspect your own I/O
  harness before the exploit.**
- **`binview`'s `size=` field is not a real chunk size** - it's whatever the *node*
  struct's stored-size field happens to read as, which is meaningless once a chunk has
  been merged/overlapped. Verify heap-shape claims (e.g. "the einherjar merge actually
  happened") against real process memory (`/proc/<pid>/mem`, ptrace-scope permitting)
  during development, not against this cosmetic field.
- **Deterministic heap offsets are load-bearing.** Because every allocation size and
  order in the exploit is fixed, node addresses are a constant offset from the leaked
  heap base every run (`CFG` at `heap_base+0x820`, `C` at `heap_base+0x930`, ...) - no
  need to leak or brute-force them individually, but any change to the allocation
  sequence must recompute these by hand (or re-derive with a debug build).

## Takeaways

- A leak doesn't have to be a real bug - read every diagnostic string the binary prints
  you. `"system() @ %p"` printing something else entirely was the whole PIE leak.
- A "debug" feature like `binview` that echoes internal pointers from a free-list is a
  gift: it turns heap-metadata manipulation from blind to fully observed, which is
  normally the hard part of unsorted-bin/tcache leaks.
- Off-by-one NULs are still very exploitable in 2.35 via House of Einherjar - you don't
  need a full off-by-N overwrite, just enough to clear one `PREV_INUSE` bit on a chunk
  you control the `prev_size` of.
- FSOP (`_IO_FILE` vtable hijacking) remains the standard finale once you have an
  arbitrary write and no direct code-pointer target - House of Apple 2 needs only two
  structures (`FILE` + `_IO_wide_data`) and one write each.

# WireTap

| | |
|---|---|
| **CTF** | BCS CTF 2026 |
| **Category** | Network |
| **Difficulty** | Medium |
| **Points** | 454 (4 solves) |
| **Author** | otolk1 |
| **File** | `capture.pcap` |
| **Flag** | `bcsctf{1cmp_c0v3rt_ch4nn3l_dh_k3y_xch4ng3_7a3f2b}` |

## Challenge

> We intercepted network traffic from a compromised machine on our internal network. Our analysts reviewed it and say it's nothing but routine ICMP monitoring - just pings, nothing suspicious.
> But the incident-response team isn't convinced. Something was exfiltrated. Can you find out what?

## TL;DR

One pair of hosts runs a custom protocol inside ICMP echo payloads. It opens with a **Diffie–Hellman** key exchange over a **40-bit prime** (`p = 2^40 + 15`, `g = 5`). Solve the discrete log with baby-step giant-step, which takes under a second. Derive the key as `SHA256(shared_secret)`, XOR it over the real data chunks, and gunzip the result to get the exfiltrated note.

## Finding the covert stream

The capture holds 254 ICMP packets and nothing else. Nearly all of them are echo requests between random `10.x`, `172.16.x` and `192.168.x` hosts with 56 random bytes of payload and no replies. That traffic is noise.

One conversation stands out: **`10.13.37.1 ↔ 10.13.37.2`**, ICMP id `0xa0f0`, with seq numbers 0–26.

- Every payload starts with the magic bytes **`DE AD`**.
- The "echo replies" do **not** echo the request payload, as real ping replies would.
- The requests go in both directions, so this is a two-way conversation.

```
seq0  .1 -> .2  dead 01 00 0000 18 abcd 0000010000000f 0000000000000005 000000fb185e132d ...
seq1  .2 -> .1  dead 02 00 0100 08 2eab 0000008a33d0088b ...
seq2  .1 -> .2  dead 03 00 0200 18 77d6 4f355be4549fd562eda09320948fccf8d9bae15bdc28040d ...
```

## Reversing the protocol

Every covert payload follows the same layout:

```
DE AD | type (1) | 00 | index (u16 LE) | len (1) | crc16 (2, BE) | data[len] | random padding
```

The 2-byte field before the data is **CRC-16/CCITT-FALSE** (`binascii.crc_hqx(data, 0xFFFF)`) computed over `data[len]`. It matches on every chunk, which confirms the framing. It also turned out to be essential for reading the handshake values correctly (see *Pitfalls*).

| Type | Index | Meaning |
|---|---|---|
| 1 | 0 | Handshake from `.1`: `p`, `g`, `A` (u64 big-endian ×3) |
| 2 | 1 | Handshake reply from `.2`: `B` (u64 big-endian) |
| 3 | 2–13 | **Real data**: fixed 24-byte chunks (last one 17), sent in order |
| 4 | 14–25 | **Chaff**: random lengths, shuffled order, valid CRCs, random content |
| 5 | 26 | End of transfer (len 0) |

Decoded handshake values:

```
p = 0x0000010000000f  = 1099511627791 = 2^40 + 15   (prime)
g = 5
A = 0x000000fb185e132d
B = 0x0000008a33d0088b
```

## Breaking the key exchange

A 40-bit Diffie–Hellman group gives no real protection. Baby-step giant-step needs about √p ≈ 2^20 steps:

```python
m = isqrt(p) + 1
table = {pow(g, j, p): j for j in range(m)}          # baby steps
step, y = pow(g, -m, p), A
for i in range(m):                                     # giant steps
    if y in table: a = i * m + table[y]; break
    y = y * step % p
s = pow(B, a, p)
```

```
a = 457190135943
s = B^a mod p = 795831131244  (0xb94b3b5c6c)
```

## Decrypting the exfil

To find the key derivation, I tried the common options (raw, MD5, SHA-1, SHA-256 of different encodings of `s`) with XOR, RC4 and AES-CTR. None of the outputs were printable. That's because the plaintext is **compressed**. After adding a check for file magic bytes, one combination produced a gzip header (`1f 8b 08 00`):

- **key** = `SHA256(s.to_bytes(8, "big"))`
- **cipher** = repeating-key XOR over the concatenated type-3 chunk data, in index order
- **plaintext** = gzip

```
CLASSIFIED - TOP SECRET
========================
Operation: WIRETAP
Date: 2026-09-14
Status: EXFILTRATION COMPLETE

Target network credentials recovered.
Primary access code:
bcsctf{1cmp_c0v3rt_ch4nn3l_dh_k3y_xch4ng3_7a3f2b}

Secondary assets staged for retrieval.
All tracks covered — ICMP tunnel active.

--- END OF TRANSMISSION ---
```

The type-4 chunks don't decrypt to anything with this key. They're decoys meant to break naive "concatenate everything" approaches.

## Solution

[`solve.py`](solve.py) needs only the Python standard library: no scapy and no tshark. It parses the pcap by hand, checks every chunk's CRC, recovers `a`, derives the key, and prints the note:

```
$ python solve.py ../../../network/capture.pcap
p = 1099511627791 (2^40+15), g = 5
A = 0xfb185e132d, B = 0x8a33d0088b
a = 457190135943
shared secret s = 795831131244 (0xb94b3b5c6c)
...
bcsctf{1cmp_c0v3rt_ch4nn3l_dh_k3y_xch4ng3_7a3f2b}
```

## Pitfalls

- **Reading the fields at the wrong offset.** At first I treated the CRC bytes (`abcd`, `2eab`) as part of the data. That reads `p` wrong. Once I skipped the 2-byte CRC, `p` became `2^40 + 15`, a prime, which confirmed the layout.
- **Copying a hex byte wrong.** I dropped one byte of `B` when copying it by hand, so the shared secret was wrong and nothing decrypted. Scanning every packet for a matching `[crc16][data]` gave the exact bytes. Parse values in code instead of copying them by eye.
- **A successful discrete log doesn't prove the parse is right.** If `g` generates the whole group, any value has a discrete log, so solving for `a` says nothing about whether you read `A` correctly. The CRC is the real check.
- **Only checking for printable output.** The plaintext is gzip-compressed, so a correct decryption doesn't look like text. Check for file magic bytes or attempt decompression when brute-forcing key derivations.

## Takeaways

- "Just pings" with echo replies that don't echo the request means a covert channel. Look for a constant magic value at the start of the payload.
- Custom tunnels usually have a checksum. Finding it tells you the framing and confirms every value you extract.
- Diffie–Hellman is only as strong as its group. Primes under about 64 bits fall to BSGS or Pohlig–Hellman in seconds.
- Chaff packets with valid framing are a common trick. Separate the streams by their `type` field before decrypting.

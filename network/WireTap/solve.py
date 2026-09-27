#!/usr/bin/env python3
# WireTap (BCS CTF 26, Network) - ICMP covert channel with a weak Diffie-Hellman key exchange
# Pure stdlib: parses the pcap by hand, breaks the 40-bit DH, decrypts the gzip'd exfil.
import sys, struct, hashlib, binascii, zlib
from math import isqrt

SRC = sys.argv[1] if len(sys.argv) > 1 else "../../../network/capture.pcap"

# --- 1. Parse pcap (little-endian, Ethernet) and pull out covert ICMP payloads ---
d = open(SRC, "rb").read()
off, msgs = 24, {}
while off < len(d):
    _, _, caplen, _ = struct.unpack("<IIII", d[off:off + 16]); off += 16
    frame = d[off:off + caplen]; off += caplen
    ip = frame[14:]
    icmp = ip[(ip[0] & 15) * 4:]
    pl = icmp[8:]
    if icmp[0] != 8 or pl[:2] != b"\xde\xad":        # echo request with DEAD magic
        continue
    # DEAD | type | 00 | index (u16 LE) | len | crc16 (BE) | data[len] | padding
    typ, idx, ln = pl[2], struct.unpack("<H", pl[4:6])[0], pl[6]
    crc, data = pl[7:9], pl[9:9 + ln]
    assert ln == 0 or binascii.crc_hqx(data, 0xFFFF) == int.from_bytes(crc, "big")
    msgs[idx] = (typ, data)

# --- 2. Handshake: p, g, A from type 1; B from type 2 (all u64 big-endian) ---
hs = next(v for t, v in msgs.values() if t == 1)
p, g, A = struct.unpack(">QQQ", hs)
B = struct.unpack(">Q", next(v for t, v in msgs.values() if t == 2))[0]
print(f"p = {p} (2^40+{p - 2**40}), g = {g}\nA = {A:#x}, B = {B:#x}")

# --- 3. Baby-step giant-step: recover a from A = g^a mod p (40-bit -> instant) ---
m = isqrt(p) + 1
table, e = {}, 1
for j in range(m):
    table.setdefault(e, j); e = e * g % p
step, y = pow(g, -m, p), A
for i in range(m):
    if y in table:
        a = i * m + table[y]; break
    y = y * step % p
assert pow(g, a, p) == A
s = pow(B, a, p)
print(f"a = {a}\nshared secret s = {s} ({s:#x})")

# --- 4. Decrypt: type-3 chunks in index order, XOR with SHA256(s as 8-byte BE), gunzip ---
key = hashlib.sha256(s.to_bytes(8, "big")).digest()
ct = b"".join(v for i, (t, v) in sorted(msgs.items()) if t == 3)
pt = bytes(c ^ key[i % len(key)] for i, c in enumerate(ct))
print("\n" + zlib.decompress(pt, 31).decode(errors="replace"))

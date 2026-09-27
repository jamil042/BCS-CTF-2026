#!/usr/bin/env python3

import json
import hashlib
import hmac

from fpylll import IntegerMatrix, LLL, BKZ


# ============================================================
# Load challenge data
# ============================================================

data = json.load(open("ciphertext.json"))

Q = 914567134764605290855390575400195937376361098871

P = (
    16916709010350403556045430803815227052174405750535080879403537258739
    40808753356513972919806277977063096694321746922069549137421634576026
    18067077765296366656417983202906431280176980780631304418597500365488
    59582938807863969513855473791264526821109831626696369597842763472363
    2619984296822042980853080477906461973
)

G = (
    43665013998153712144866901859652944177111926994088190392110016664049
    49371277046174820139753625009731389918435086129481960410134239416511
    54178653294066747053562756831973107596496014255391295853002573029702
    81154030575483841609429766612775445716425286098508694625258471568371
    806282838750362654108351925505086404
)

BOTTOM_BITS = 128

transcript = data["transcript"]
n = len(transcript)


# ============================================================
# Build HNP parameters
# ============================================================

ts = []
us = []
msgs = []
counters = []
rs = []
ss = []

for entry in transcript:

    m = entry["message"].encode()

    r = int(entry["r"], 16)
    s = int(entry["s"], 16)
    counter = int(entry["counter"], 16)

    z = int.from_bytes(
        hashlib.sha256(m).digest(),
        "big"
    ) % Q

    sinv = pow(s, -1, Q)

    t = (sinv * r) % Q

    u = (
        sinv * z
        - (counter << BOTTOM_BITS)
    ) % Q

    ts.append(t)
    us.append(u)

    msgs.append(m)
    counters.append(counter)
    rs.append(r)
    ss.append(s)


# ============================================================
# Step 1: Construct lattice
# ============================================================

M0 = IntegerMatrix(n + 1, n)

for i in range(n):
    M0[i, i] = Q

for j in range(n):
    M0[n, j] = ts[j]

LLL.reduction(M0)

B = [
    [M0[i, j] for j in range(n)]
    for i in range(n + 1)
    if any(M0[i, j] != 0 for j in range(n))
]

assert len(B) == n


# ============================================================
# Step 2: Kannan embedding
# ============================================================

K = 1 << BOTTOM_BITS

M1 = IntegerMatrix(n + 1, n + 1)

for i in range(n):
    for j in range(n):
        M1[i, j] = B[i][j]

for j in range(n):

    val = us[j]

    if val > Q // 2:
        val -= Q

    M1[n, j] = -val

M1[n, n] = K


# LLL + BKZ
LLL.reduction(M1)
BKZ.reduction(
    M1,
    BKZ.Param(block_size=20)
)


# ============================================================
# Recover leaked nonce low bits
# ============================================================

row = next(
    r for r in range(n + 1)
    if M1[r, n] == K
)

a = [
    -M1[row, j]
    for j in range(n)
]

assert all(
    0 <= v < (1 << BOTTOM_BITS)
    for v in a
)


# ============================================================
# Step 3: Recover DSA private key
# ============================================================

ks = [
    (counters[i] << BOTTOM_BITS) + a[i]
    for i in range(n)
]

zs = [
    int.from_bytes(
        hashlib.sha256(msgs[i]).digest(),
        "big"
    ) % Q
    for i in range(n)
]

xs = [
    (
        (ss[i] * ks[i] - zs[i])
        * pow(rs[i], -1, Q)
    ) % Q
    for i in range(n)
]

x = max(
    set(xs),
    key=xs.count
)

print(f"[+] Private key x = {x}")


# ============================================================
# Verify public key
# ============================================================

assert pow(G, x, P) == int(
    data["public"],
    16
)

print("[+] Public key match: True")


# ============================================================
# Decrypt flag
# ============================================================

DOMAIN = b"BCSCTF-2026/nonce-vault/v1"

key = hashlib.sha256(
    DOMAIN + x.to_bytes(20, "big")
).digest()

salt = bytes.fromhex(data["salt"])
sealed = bytes.fromhex(data["sealed"])
tag = bytes.fromhex(data["tag"])


# Verify HMAC
assert hmac.new(
    key,
    salt + sealed,
    hashlib.sha256
).digest() == tag

print("[+] HMAC tag match: True")


# Generate keystream
pad = hashlib.shake_256(
    key + salt
).digest(len(sealed))


# XOR decrypt
flag = bytes(
    a ^ b
    for a, b in zip(sealed, pad)
)

print(f"[+] FLAG: {flag.decode()}")

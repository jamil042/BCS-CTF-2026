# Spotted Image — Recovering the Hidden Message from `frame_014.png`

**Flag:** `bcsctf{r3c0v3r_th3_p1x3l_p1p3l1n3}`

## Challenge Summary

We’re given two files:

* `frame_014.png` — a 256×256 image that looks like pure noise
* `recorder.sqlite` — a database of “run” records and a “journal” describing pipeline steps, spanning multiple unrelated runs/cases

The task is to reverse a multi-stage embed pipeline:

**bit-embedding → row shift → XOR mask**

The hidden message is recovered using a session key derived from a Diffie-Hellman-style XOR of two secret shares.

## Step 1 — Identify the Right Case

`recorder.sqlite` has two tables:

```sql
CREATE TABLE runs (
    case_id TEXT PRIMARY KEY,
    frame_file TEXT,
    share_a_hex TEXT,
    state TEXT
);

CREATE TABLE journal (
    case_id TEXT,
    seq INTEGER,
    stage TEXT,
    detail TEXT,
    PRIMARY KEY (case_id, seq)
);
```

The `runs` table contained three rows:

| case_id  | frame_file      | state                   |
| -------- | --------------- | ----------------------- |
| `...980` | `frame_013.png` | superseded              |
| `...981` | `frame_014.png` | crashed after PNG write |
| `...982` | `frame_015.png` | pending                 |

The relevant case is:

```text
IC-CGU67042.2025.11337981
```

Its journal entries laid out the exact embed pipeline:

1. **Packet format**

   `BCS1` + payload length (`uint16 BE`) + payload (ASCII) + CRC32(payload) (`uint32 BE`)

2. **Embed**

   Packet bits are deposited into the RED channel's bit 0 using:

   ```text
   index = (base + n*stride) mod (W*H)
   ```

   with:

   ```text
   x = index mod W
   y = index div W
   ```

3. **Row shift**

   Each row `y` is circularly rolled right by:

   ```text
   (7*y + 11) mod width
   ```

4. **Key derivation**

   ```text
   session_key = SHA256(shareA XOR shareB || case_id_ascii)
   ```

5. **Mask**

   Every RGB byte is XORed with a keystream generated from:

   ```text
   SHA256(session_key || ":" || frame_filename || ":" || counter_uint32_BE)
   ```

6. **Store**

   A crash-ring fragment is appended after the PNG `IEND` marker.

## Step 2 — Recover the Crash-Ring Footer

Scanning the raw PNG bytes after `IEND` for:

```text
00 ff 52 49 4e 47 00
```

revealed a zlib-compressed JSON object:

```json
{
  "bit_order": "most-significant bit first",
  "bit_walk_base": 137,
  "bit_walk_stride": 4099,
  "case": "IC-CGU67042.2025.11337981",
  "footer_type": "recovered crash-ring fragment",
  "share_b_hex": "9279c398d6a4f11b737ed90a58ed2f644943af865bea215dcc576da734b1e02d"
}
```

Therefore:

```text
base   = 137
stride = 4099
order  = MSB-first
```

and we also recover `share B`.

## Step 3 — Derive the Session Key

```python
share_a = bytes.fromhex(runs.share_a_hex)
share_b = bytes.fromhex(footer.share_b_hex)

xor_bytes = bytes(a ^ b for a, b in zip(share_a, share_b))

session_key = SHA256(
    xor_bytes + b"IC-CGU67042.2025.11337981"
)
```

## Step 4 — Reverse the Pipeline

### 1. Un-mask

Regenerate the keystream using:

```text
SHA256(
    session_key || ":" ||
    "frame_014.png" || ":" ||
    counter_BE
)
```

for counters:

```text
0, 1, 2, ...
```

until `H*W*3` bytes are generated.

XOR the keystream against the image's row-major RGB bytes.

Since XOR is self-inverse, this recovers the row-shifted RGB data.

### 2. Un-shift

For every row `y`, roll the RGB pixels **left** by:

```text
(7*y + 11) mod width
```

This reverses the original rightward shift.

### 3. Extract Bits

Walk through pixel indices using:

```text
idx = (137 + n*4099) mod 65536
```

For every selected pixel:

* Read the RED channel
* Extract its LSB
* Pack the bits MSB-first into bytes

## Step 5 — Parse the Packet

The first six bytes give:

```text
magic  = BCS1
length = 34
```

Total packet size:

```text
4 + 2 + 34 + 4 = 44 bytes
```

Recovered payload:

```text
bcsctf{r3c0v3r_th3_p1x3l_p1p3l1n3}
```

CRC verification:

```text
crc_stored = 0x6582f49c
crc_calc   = 0x6582f49c
```

The CRC matches.

## Result

```text
bcsctf{r3c0v3r_th3_p1x3l_p1p3l1n3}
```

### Recovery Chain

```text
Case Selection
      ↓
Crash-Ring Recovery
      ↓
Session-Key Derivation
      ↓
XOR Keystream Unmasking
      ↓
Row Unshift
      ↓
MSB-First LSB Extraction
      ↓
Packet Parsing
      ↓
CRC32 Verification
      ↓
FLAG
```

## Appendix — PNG Metadata

The PNG also contains plain metadata that corroborates the case:

| Key     | Value                                                              |
| ------- | ------------------------------------------------------------------ |
| Case-ID | `IC-CGU67042.2025.11337981`                                        |
| Frame   | `frame_014.png`                                                    |
| Receipt | `640044af3d5844e6c0d8f11ab45b3028c3d97372714840aec744c3f0364b6a18` |

These metadata values are not required for recovery because the packet's CRC already confirms correctness.

## Tools / Approach

Tools used:

```text
Python
sqlite3
zlib
hashlib
numpy
PIL
struct
```

The original analysis was performed read-only against the provided files, with no network access or external services required.

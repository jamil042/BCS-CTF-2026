# 3 Word 2.0

| | |
|---|---|
| **CTF** | BCS CTF 2026 |
| **Category** | Steganography |
| **File** | `secret.png` |
| **Prerequisite** | Password `circus.topmost.winds` from the challenge *3 Words* |
| **Flag** | `bcsctf{r3m3mb3r_7h3_n1gh7??}` |

## Challenge

> The photograph from 3 Words led you to a location. It has another story about rijz to tell.
>
> Follow the trail beyond the image, find the right way to examine it, and recover the hidden secret.
>
> flag format: `bcsctf{...}`

## TL;DR

The RGB LSBs, read pixel by pixel, start with an `STG1` header. **rijz** points to the GitHub user [Rijzzz](https://github.com/Rijzzz), whose tool [StegoCrypt](https://github.com/Rijzzz/StegoCrypt) writes exactly that header. StegoCrypt derives the key with PBKDF2 using a hard-coded salt. Running its extractor with the *3 Words* password decrypts the flag.

## Reading the clues

| Clue | Meaning |
|---|---|
| *The photograph from 3 Words led you to a location* | The image and the password `circus.topmost.winds` (a what3words address) come from the previous challenge. The location itself is a red herring for this one. |
| *another story about rijz* | `rijz` is a handle. It leads to the GitHub user **Rijzzz**. |
| *Follow the trail beyond the image* | The answer isn't only in the pixels. You need something from outside the file: the tool's source code. |
| *find the right way to examine it* | Extract with the tool's exact format and key derivation. Generic LSB tools or guessed crypto won't work. |

## Analysis

### File triage

`secret.png` is a 393×297 8-bit RGBA PNG. It has only `IHDR`, `IDAT` and `IEND` chunks, no metadata and nothing after `IEND`. The decompressed `IDAT` is exactly `297 × (393·4 + 1)` bytes, so no rows are hidden beyond the declared height. Alpha is 255 everywhere.

### Finding the payload

Read the least significant bit of R, G and B **pixel by pixel** (R0 G0 B0 R1 G1 B1 …, MSB first) and pack the bits into bytes:

```
53 54 47 31 40 11 1d 93 21 38 bc 74 e6 45 19 76  STG1@...!8.t.E.v
84 2b 3e 98 4f 14 87 ff 97 84 8d 87 0d 68 bc 17  .+>.O........h..
00 00 00 1c 9d be 21 ee fd dd 3f f9 9a 98 8b 57  ......!...?....W
3e 42 ed 21 5f b0 ea b7 94 48 5c 28 ba 7a 1e a1  >B.!_....H\(.z..
```

The `STG1` magic is a clear sign of a structured container. If you read the channels plane by plane instead (all R bits, then all G, then all B), the header never shows up.

### The trap: guessing the layout

Without the tool, the obvious guess is `magic | salt(16) | nonce(12) | len(4) | ciphertext`. That makes the 28 ciphertext bytes look like 12 bytes of plaintext plus a 16-byte GCM tag, which is too short for a flag. Brute-forcing PBKDF2, scrypt and Argon2 with AES-GCM, ChaCha20-Poly1305, CTR and similar modes on that layout gets nowhere, because the layout and the salt are both wrong.

### Following the trail: rijz → StegoCrypt

Searching GitHub for users named `rijz` turns up **Rijzzz**, who has a repo called **StegoCrypt**. It was created on 2026-09-26, the day before the CTF. Its `stego.py` uses the same magic:

```python
MAGIC = b"STG1"
HEADER_LEN = 36  # [4B magic] [12B nonce] [16B tag] [4B ct_len]
SALT = b"stego_fixed_salt_v1"

def derive_key(passphrase):
    # PBKDF2-HMAC-SHA256, 100,000 iterations, 32-byte key
    ...

raw = AESGCM(key).encrypt(nonce, data, MAGIC)   # MAGIC is the associated data
ct, tag = raw[:-16], raw[-16:]
hdr = struct.pack(">4s12s16sI", MAGIC, nonce, tag, len(ct))
```

So the real layout is:

| Bytes | Field | Value |
|---:|---|---|
| 4 | magic | `STG1` |
| 12 | AES-GCM nonce | `40111d932138bc74e6451976` |
| 16 | AES-GCM tag | `842b3e984f1487ff97848d870d68bc17` |
| 4 | ciphertext length | `0x1c` = 28 |
| 28 | ciphertext | 28-byte flag |

What I had taken for a random salt is actually `nonce + tag`. The real salt isn't in the image at all. It's the constant `stego_fixed_salt_v1` in the tool's source, which is why you have to follow the trail beyond the image.

## Solution

Use StegoCrypt directly:

```
git clone https://github.com/Rijzzz/StegoCrypt
python StegoCrypt/stego.py extract --image secret.png --password "circus.topmost.winds"
```

```
Extracted secret: bcsctf{r3m3mb3r_7h3_n1gh7??}
```

Or reimplement it without the repo:

```python
import hashlib, struct
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

rgb = np.array(Image.open("secret.png").convert("RGB"))
stream = np.packbits(rgb.reshape(-1) & 1).tobytes()

magic, nonce, tag, n = struct.unpack(">4s12s16sI", stream[:36])
ct = stream[36:36 + n]

key = hashlib.pbkdf2_hmac("sha256", b"circus.topmost.winds", b"stego_fixed_salt_v1", 100_000, 32)
print(AESGCM(key).decrypt(nonce, ct + tag, magic).decode())
```

The full script is [`solve.py`](solve.py):

```
$ python solve.py
magic=b'STG1' nonce=40111d932138bc74e6451976 tag=842b3e984f1487ff97848d870d68bc17 ct_len=28
bcsctf{r3m3mb3r_7h3_n1gh7??}
```

## Flag

```
bcsctf{r3m3mb3r_7h3_n1gh7??}
```

## Takeaways

- A readable magic like `STG1` at the start of an LSB stream means a specific tool made it. Find the tool before guessing the crypto.
- Try both bit orders: interleaved per pixel (RGBRGB…) and planar (all R, then G, then B). Only one of them showed the header here.
- With authenticated encryption, a wrong guess about the layout, salt or associated data looks exactly like a wrong password. If the decryption fails no matter which KDF you try, question your parsing of the header.
- Hard-coded salts and other constants in public source code are part of the key. The tool is the missing piece of the challenge.
- Handles in the challenge text (`rijz`) are worth searching on GitHub. Look for recently created repos that match the challenge's theme.

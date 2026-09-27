#!/usr/bin/env python3
# 3 Word 2.0 (BCS CTF 26, Steg) - decrypt the StegoCrypt "STG1" packet hidden in RGB LSBs
import hashlib
import struct
import sys

import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SRC = sys.argv[1] if len(sys.argv) > 1 else "../../../steg/secret/secret.png"
PASSWORD = sys.argv[2] if len(sys.argv) > 2 else "circus.topmost.winds"  # from "3 Words"

# StegoCrypt constants (github.com/Rijzzz/StegoCrypt, stego.py)
MAGIC = b"STG1"
SALT = b"stego_fixed_salt_v1"
ITERATIONS = 100_000

# 1 bit per R, G, B channel, pixel by pixel, MSB first; alpha is skipped
rgb = np.array(Image.open(SRC).convert("RGB"))
stream = np.packbits(rgb.reshape(-1) & 1).tobytes()

# header: [4B magic] [12B nonce] [16B tag] [4B ct_len], then ciphertext
magic, nonce, tag, ct_len = struct.unpack(">4s12s16sI", stream[:36])
assert magic == MAGIC, "no STG1 header"
ct = stream[36:36 + ct_len]
print(f"magic={magic} nonce={nonce.hex()} tag={tag.hex()} ct_len={ct_len}")

key = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), SALT, ITERATIONS, 32)
print(AESGCM(key).decrypt(nonce, ct + tag, MAGIC).decode())

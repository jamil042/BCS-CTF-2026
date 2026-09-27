#!/usr/bin/env python3
"""
solve.py -- Recover the hidden message from frame_014.png + recorder.sqlite

Usage:
    python3 solve.py [path/to/frame_014.png] [path/to/recorder.sqlite]

Defaults to ./frame_014.png and ./recorder.sqlite if no args are given.

Pipeline (reverse of the recorder's embed process):
  1. Look up the case matching the target frame in the `runs` table.
  2. Pull the crash-ring JSON footer appended after IEND in the PNG
     (marker: 00 ff 52 49 4e 47 00 + uint32 BE zlib length + zlib JSON).
  3. Derive session_key = SHA256(share_a XOR share_b || case_id).
  4. Undo the XOR mask: XOR pixel bytes with a keystream built from
     SHA256(session_key || ":" || frame_filename || ":" || counter_BE).
  5. Undo the row shift: roll each row left by (7*y + 11) mod width.
  6. Walk pixel indices idx = (base + n*stride) mod (W*H), read the RED
     channel's LSB, pack bits MSB-first to rebuild the packet.
  7. Parse packet: "BCS1" magic + uint16 BE length + payload + uint32 BE CRC32.
"""

import sys
import struct
import sqlite3
import zlib
import hashlib

import numpy as np
from PIL import Image

RING_MARKER = bytes.fromhex("00ff52494e4700")


def find_case(db_path, frame_filename):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        "SELECT case_id, share_a_hex, state FROM runs WHERE frame_file=?",
        (frame_filename,),
    )
    row = cur.fetchone()
    if row is None:
        raise ValueError(f"No run found for frame {frame_filename!r}")
    case_id, share_a_hex, state = row
    conn.close()
    return case_id, share_a_hex, state


def extract_crash_ring(png_path):
    data = open(png_path, "rb").read()
    idx = data.find(RING_MARKER)
    if idx == -1:
        raise ValueError("No crash-ring footer found after IEND")
    off = idx + len(RING_MARKER)
    length = struct.unpack(">I", data[off:off + 4])[0]
    comp = data[off + 4:off + 4 + length]
    raw = zlib.decompress(comp)
    import json
    return json.loads(raw.decode("utf-8"))


def derive_session_key(share_a_hex, share_b_hex, case_id):
    a = bytes.fromhex(share_a_hex)
    b = bytes.fromhex(share_b_hex)
    xor_bytes = bytes(x ^ y for x, y in zip(a, b))
    return hashlib.sha256(xor_bytes + case_id.encode("ascii")).digest()


def build_keystream(session_key, frame_filename, nbytes):
    blocks = []
    counter = 0
    total = 0
    while total < nbytes:
        msg = session_key + b":" + frame_filename.encode("ascii") + b":" + struct.pack(">I", counter)
        d = hashlib.sha256(msg).digest()
        blocks.append(d)
        total += len(d)
        counter += 1
    return b"".join(blocks)[:nbytes]


def unmask(arr, session_key, frame_filename):
    H, W, _ = arr.shape
    flat = arr.reshape(-1).astype(np.uint8)
    ks = np.frombuffer(build_keystream(session_key, frame_filename, flat.size), dtype=np.uint8)
    return np.bitwise_xor(flat, ks).reshape(H, W, 3)


def unshift_rows(arr):
    H, W, _ = arr.shape
    out = np.zeros_like(arr)
    for y in range(H):
        shift = (7 * y + 11) % W
        out[y] = np.roll(arr[y], -shift, axis=0)  # invert the recorder's rightward roll
    return out


def extract_packet(arr, base, stride):
    H, W, _ = arr.shape
    N = W * H

    def get_bit(n):
        idx = (base + n * stride) % N
        x, y = idx % W, idx // W
        return int(arr[y, x, 0]) & 1

    def bits_to_bytes(bits):
        out = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            out.append(byte)
        return bytes(out)

    header_bits = [get_bit(n) for n in range(48)]  # 4 (magic) + 2 (length) bytes
    header = bits_to_bytes(header_bits)
    magic, length = header[0:4], struct.unpack(">H", header[4:6])[0]
    if magic != b"BCS1":
        raise ValueError(f"Bad magic: {magic!r}")

    total_bits = (4 + 2 + length + 4) * 8
    bits = [get_bit(n) for n in range(total_bits)]
    packet = bits_to_bytes(bits)

    payload = packet[6:6 + length]
    crc_stored = struct.unpack(">I", packet[6 + length:6 + length + 4])[0]
    crc_calc = zlib.crc32(payload) & 0xFFFFFFFF
    if crc_stored != crc_calc:
        raise ValueError(f"CRC mismatch: stored {crc_stored:#x} != calc {crc_calc:#x}")

    return payload


def main():
    png_path = sys.argv[1] if len(sys.argv) > 1 else "frame_014.png"
    db_path = sys.argv[2] if len(sys.argv) > 2 else "recorder.sqlite"
    frame_filename = png_path.split("/")[-1]

    case_id, share_a_hex, state = find_case(db_path, frame_filename)
    print(f"[+] Case: {case_id} (state: {state})")

    footer = extract_crash_ring(png_path)
    print(f"[+] Crash-ring footer: {footer}")

    session_key = derive_session_key(share_a_hex, footer["share_b_hex"], case_id)
    print(f"[+] Session key: {session_key.hex()}")

    arr = np.array(Image.open(png_path).convert("RGB"))
    arr = unmask(arr, session_key, frame_filename)
    arr = unshift_rows(arr)

    payload = extract_packet(arr, footer["bit_walk_base"], footer["bit_walk_stride"])
    print(f"[+] Recovered payload: {payload.decode('ascii')}")


if __name__ == "__main__":
    main()

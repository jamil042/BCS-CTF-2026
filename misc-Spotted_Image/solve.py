#!/usr/bin/env python3

import hashlib
import sqlite3
import struct
import zlib

from PIL import Image


PNG_FILE = "frame_014.png"
DB_FILE = "recorder.sqlite"

CASE_ID = "IC-CGU67042.2025.11337981"

RING_MARKER = b"\x00\xffRING\x00"


def recover_footer(filename):
    """Recover the crash-ring JSON appended after the PNG IEND chunk."""
    with open(filename, "rb") as f:
        data = f.read()

    pos = data.find(RING_MARKER)

    if pos == -1:
        raise RuntimeError("Crash-ring marker not found")

    offset = pos + len(RING_MARKER)

    compressed_len = struct.unpack(
        ">I",
        data[offset:offset + 4]
    )[0]

    offset += 4

    compressed = data[offset:offset + compressed_len]

    footer = zlib.decompress(compressed)

    import json
    return json.loads(footer)


def get_share_a():
    """Get share A from recorder.sqlite."""
    conn = sqlite3.connect(DB_FILE)

    row = conn.execute(
        """
        SELECT share_a_hex
        FROM runs
        WHERE case_id = ?
          AND frame_file = ?
        """,
        (CASE_ID, PNG_FILE)
    ).fetchone()

    conn.close()

    if row is None:
        raise RuntimeError("Case not found in database")

    return bytes.fromhex(row[0])


def derive_session_key(share_a, share_b):
    """Derive session key from XOR of both shares and case ID."""
    xor_bytes = bytes(
        a ^ b
        for a, b in zip(share_a, share_b)
    )

    return hashlib.sha256(
        xor_bytes + CASE_ID.encode()
    ).digest()


def generate_keystream(session_key, filename, length):
    """Generate SHA256 counter-mode keystream."""
    stream = bytearray()

    counter = 0

    while len(stream) < length:
        block = hashlib.sha256(
            session_key
            + b":"
            + filename.encode()
            + b":"
            + struct.pack(">I", counter)
        ).digest()

        stream.extend(block)
        counter += 1

    return bytes(stream[:length])


def unmask(image, session_key):
    """Undo the XOR mask."""
    width, height = image.size

    rgb = bytearray(image.convert("RGB").tobytes())

    keystream = generate_keystream(
        session_key,
        PNG_FILE,
        len(rgb)
    )

    for i in range(len(rgb)):
        rgb[i] ^= keystream[i]

    return width, height, rgb


def unshift_rows(width, height, rgb):
    """Undo the per-row circular right shift."""
    result = bytearray(len(rgb))

    row_bytes = width * 3

    for y in range(height):
        shift_pixels = (7 * y + 11) % width
        shift_bytes = shift_pixels * 3

        start = y * row_bytes
        row = rgb[start:start + row_bytes]

        # Inverse of right rotation = left rotation
        restored = row[shift_bytes:] + row[:shift_bytes]

        result[start:start + row_bytes] = restored

    return result


def extract_packet(width, height, rgb):
    """Extract RED-channel LSBs using the embedded walk."""
    total_pixels = width * height

    base = 137
    stride = 4099

    bits = []

    # Need enough bits for the maximum packet.
    # A 256x256 image contains 65536 pixels,
    # so there are 65536 available RED-channel LSBs.
    for n in range(total_pixels):
        idx = (base + n * stride) % total_pixels

        red_offset = idx * 3

        bit = rgb[red_offset] & 1

        bits.append(bit)

    # Pack MSB-first
    output = bytearray()

    for i in range(0, len(bits), 8):
        byte = 0

        chunk = bits[i:i + 8]

        if len(chunk) < 8:
            break

        for bit in chunk:
            byte = (byte << 1) | bit

        output.append(byte)

    return bytes(output)


def parse_packet(data):
    """Parse BCS1 packet and verify CRC32."""
    if data[:4] != b"BCS1":
        raise RuntimeError(
            f"Invalid magic: {data[:4]!r}"
        )

    payload_length = struct.unpack(
        ">H",
        data[4:6]
    )[0]

    packet_length = 4 + 2 + payload_length + 4

    if len(data) < packet_length:
        raise RuntimeError("Incomplete packet")

    payload_start = 6
    payload_end = payload_start + payload_length

    payload = data[payload_start:payload_end]

    stored_crc = struct.unpack(
        ">I",
        data[payload_end:payload_end + 4]
    )[0]

    calculated_crc = zlib.crc32(payload) & 0xffffffff

    print(f"[+] Magic       : {data[:4].decode()}")
    print(f"[+] Length      : {payload_length}")
    print(f"[+] Stored CRC  : 0x{stored_crc:08x}")
    print(f"[+] Calculated  : 0x{calculated_crc:08x}")

    if stored_crc != calculated_crc:
        raise RuntimeError("CRC32 verification failed")

    return payload.decode("ascii")


def main():
    print("[*] Recovering crash-ring footer...")

    footer = recover_footer(PNG_FILE)

    print(f"[+] Case        : {footer['case']}")
    print(f"[+] Bit order   : {footer['bit_order']}")
    print(f"[+] Base        : {footer['bit_walk_base']}")
    print(f"[+] Stride      : {footer['bit_walk_stride']}")

    share_b = bytes.fromhex(
        footer["share_b_hex"]
    )

    print("[*] Reading share A from database...")

    share_a = get_share_a()

    print("[*] Deriving session key...")

    session_key = derive_session_key(
        share_a,
        share_b
    )

    print(
        f"[+] Session key : {session_key.hex()}"
    )

    print("[*] Loading image...")

    image = Image.open(PNG_FILE).convert("RGB")

    print(
        f"[+] Image size  : {image.width}x{image.height}"
    )

    print("[*] Removing XOR mask...")

    width, height, unmasked = unmask(
        image,
        session_key
    )

    print("[*] Undoing row shifts...")

    restored = unshift_rows(
        width,
        height,
        unmasked
    )

    print("[*] Extracting embedded bits...")

    packet_data = extract_packet(
        width,
        height,
        restored
    )

    print("[*] Parsing packet...")

    flag = parse_packet(packet_data)

    print()
    print("=" * 60)
    print(f"FLAG: {flag}")
    print("=" * 60)


if __name__ == "__main__":
    main()

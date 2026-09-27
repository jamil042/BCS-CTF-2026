#!/usr/bin/env python3
"""
After the Beep - CTF Solve Script
Category: Misc

Recovers the flag from an old multi-tap phone transcript encrypted
with a repeating-key (Vigenere-style) cipher, key = "MODEM", A = 0.
"""

# T9 / multi-tap keypad mapping: digit -> letters in press order
KEYPAD = {
    "2": "ABC",
    "3": "DEF",
    "4": "GHI",
    "5": "JKL",
    "6": "MNO",
    "7": "PQRS",
    "8": "TUV",
    "9": "WXYZ",
}

TRANSCRIPT = "22|666|5|444|3 / 9|7777|22|9 / 33|333|9|666|7 / 444|2|333|66"
KEY = "MODEM"


def multitap_decode(group: str) -> str:
    """Decode a run-of-same-digit group like '666' -> 'O'."""
    digit = group[0]
    presses = len(group)
    letters = KEYPAD[digit]
    return letters[(presses - 1) % len(letters)]


def decode_transcript(transcript: str):
    """Split into words -> letter-groups -> multi-tap-decoded letters."""
    words = transcript.split(" / ")
    decoded_words = []
    for word in words:
        groups = word.split("|")
        letters = "".join(multitap_decode(g) for g in groups)
        decoded_words.append(letters)
    return decoded_words


def vigenere_decrypt(letters: str, key: str, key_pos: int):
    """Subtract repeating key from letters (mod 26), continuing key_pos
    across word boundaries. Returns (plaintext, new_key_pos)."""
    plain = []
    for ch in letters:
        k = key[key_pos % len(key)]
        p = (ord(ch) - ord("A") - (ord(k) - ord("A"))) % 26
        plain.append(chr(p + ord("A")))
        key_pos += 1
    return "".join(plain), key_pos


def main():
    cipher_words = decode_transcript(TRANSCRIPT)
    print("Multi-tap decoded (raw cipher letters):", " / ".join(cipher_words))

    key_pos = 0
    plain_words = []
    for word in cipher_words:
        plain, key_pos = vigenere_decrypt(word, KEY, key_pos)
        plain_words.append(plain)

    print("Vigenere decrypted (plaintext):        ", " / ".join(plain_words))

    flag_body = "_".join(w.lower() for w in plain_words)
    flag = f"bcsctf{{{flag_body}}}"
    print("\nFLAG:", flag)


if __name__ == "__main__":
    main()

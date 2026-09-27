# After the Beep

**Category:** Misc
**Flag:** `bcsctf{pager_keys_still_work}`

---

## Challenge

A 1997 BBS operator recovers a garbled transcript from an old phone.

The handset has a strip of tape reading **MODEM**, and a note scratched under the battery cover:

> A = 0. Move forward to hide; move backward to read. The tape repeats. Only letters turn the wheel.

The transcript:

```text
22|666|5|444|3 / 9|7777|22|9 / 33|333|9|666|7 / 444|2|333|66
```

---

## Step 1 — Multi-Tap Decoding

The digit groups use classic **T9 / multi-tap phone input**.

The mappings are:

```text
2 = ABC
3 = DEF
4 = GHI
5 = JKL
6 = MNO
7 = PQRS
8 = TUV
9 = WXYZ
```

Each digit group represents the number of times a key was pressed.

For example:

```text
22   → B
666  → O
5    → J
444  → I
3    → D
```

Decoding the complete transcript gives:

```text
BOJID / WSBW / EFWOP / IAFN
```

So this is not yet the final plaintext.

---

## Step 2 — Identify the Encryption Key

The tape says:

```text
MODEM
```

This is the repeating key.

The note also says:

> A = 0. Move forward to hide; move backward to read.

This indicates a **Vigenère-style cipher**.

Encryption:

```text
Plaintext + Key = Ciphertext
```

Therefore, to decrypt:

```text
Ciphertext - Key = Plaintext
```

with calculations performed modulo 26.

The key `MODEM` repeats continuously:

```text
MODEMMODEMMODEMMODE
```

Importantly, the note says:

> Only letters turn the wheel.

Therefore, the key advances **one position for every decoded letter**, continuously across the entire message. It does not restart at each word.

---

## Step 3 — Vigenère Decryption

Using:

```text
A = 0
B = 1
...
Z = 25
```

and subtracting the repeating `MODEM` key:

| Cipher | Key | Calculation       | Plain |
| ------ | --- | ----------------- | ----- |
| B      | M   | 1 - 12 = -11 → 15 | P     |
| O      | O   | 14 - 14 = 0       | A     |
| J      | D   | 9 - 3 = 6         | G     |
| I      | E   | 8 - 4 = 4         | E     |
| D      | M   | 3 - 12 = -9 → 17  | R     |
| W      | M   | 22 - 12 = 10      | K     |
| S      | O   | 18 - 14 = 4       | E     |
| B      | D   | 1 - 3 = -2 → 24   | Y     |
| W      | E   | 22 - 4 = 18       | S     |
| E      | M   | 4 - 12 = -8 → 18  | S     |
| F      | M   | 5 - 12 = -7 → 19  | T     |
| W      | O   | 22 - 14 = 8       | I     |
| O      | D   | 14 - 3 = 11       | L     |
| P      | E   | 15 - 4 = 11       | L     |
| I      | M   | 8 - 12 = -4 → 22  | W     |
| A      | M   | 0 - 12 = -12 → 14 | O     |
| F      | O   | 5 - 14 = -9 → 17  | R     |
| N      | D   | 13 - 3 = 10       | K     |

The decrypted message is:

```text
PAGER / KEYS / STILL / WORK
```

Therefore:

```text
PAGER KEYS STILL WORK
```

---

## Final Flag

```text
bcsctf{pager_keys_still_work}
```

### Flag

🏁 **`bcsctf{pager_keys_still_work}`**

---

## Key Takeaways

* Recognize **multi-tap/T9 encoding** from repeated phone digits.
* `MODEM` acts as a repeating **Vigenère key**.
* `A = 0` defines the numerical alphabet mapping.
* "Move forward to hide" means encryption uses addition.
* "Move backward to read" means decryption uses subtraction.
* "Only letters turn the wheel" means the key advances per letter, not per digit group or word.

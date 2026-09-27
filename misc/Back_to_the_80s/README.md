# Back to the 80s

**Category:** Misc  
**Flag:** `bcsctf{EASYTOFINDOUTTHESECIPHER}`

---

## Challenge

> The world is back in the 80's.
>
> Find out the code and enclose it with `bcsctf{}` before submitting.

The supplied PNG shows an old CRT television displaying apparently random
colored blocks.

---

## Approach

### Step 1 — Inspect the Television Screen

Most of the screen looks noisy, but its middle section contains a sharply
structured rectangular band. It uses six colors:

```text
Red, Green, Blue, Yellow, Cyan, Magenta
```

The band is 24 colored cells wide and 6 cells high. White dividers appear
after every two columns, indicating that the individual cells must be grouped
to form symbols.

### Step 2 — Determine the Symbol Dimensions

The grid dimensions factor naturally as:

```text
24 columns / 2 = 12 symbols per line
 6 rows    / 3 =  2 lines
```

Each character is therefore a 2-by-3 colored tile:

```text
+---+---+
| 1 | 2 |
+---+---+
| 3 | 4 |
+---+---+
| 5 | 6 |
+---+---+
```

The full band contains 24 encoded characters.

### Step 3 — Identify the Cipher

A 2-by-3 tile made from permutations of six colors is characteristic of the
**Hexahue alphabet**. Hexahue uses the following color symbols:

```text
R = Red       G = Green     B = Blue
Y = Yellow    C = Cyan      M = Magenta
```

Each tile is flattened in row-major order. For example, the first tile is:

```text
R G
Y B
M C
```

This becomes `RGYBMC`, which is the Hexahue representation of `E`.

The second tile is:

```text
M R
G Y
B C
```

This becomes `MRGYBC`, which represents `A`. The message therefore starts
with `EA`.

### Step 4 — Transcribe the Color Grid

Representing every color by its initial produces these six rows:

```text
RGMRBCCMBCYBRGGYYBRGYBBC
YBGYMYRGMRCMYBBRCGYMCMMR
MCBCRGBYYGGRCMCMMRBCGRGY
BCBCGYRGBCRGRGGYYBGYRGBC
MRMRRBYBMYYBMYBRCMRBYBYM
YGYGCMMCRGMCBCCMRGCMMCRG
```

The first three rows form the first twelve glyphs, while the final three rows
form the remaining twelve.

### Step 5 — Decode the Tiles

The upper twelve tiles decode to:

```text
EASYTOFINDOU
```

The lower twelve tiles decode to:

```text
TTHESECIPHER
```

Combining them gives the exact plaintext embedded in the image:

```text
EASYTOFINDOUTTHESECIPHER
```

---

## Automated Solution

The accompanying [`solve.py`](solve.py) groups the transcribed cells into
2-by-3 tiles and looks each tile up in the Hexahue alphabet.

```console
$ python solve.py
Decoded message: EASYTOFINDOUTTHESECIPHER
Flag: bcsctf{EASYTOFINDOUTTHESECIPHER}
```

---

## Final Flag

```text
bcsctf{EASYTOFINDOUTTHESECIPHER}
```

### Key Takeaways

* Focus on the structured central band instead of the surrounding visual noise.
* Use the white separators and grid dimensions to identify 2-by-3 glyphs.
* Six-color 2-by-3 permutations are the signature of the Hexahue alphabet.
* Read the upper glyph line first, followed by the lower glyph line.

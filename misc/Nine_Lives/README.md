# Nine Lives

| | |
|---|---|
| **CTF** | BCS CTF 2026 |
| **Category** | Misc |
| **Difficulty** | Medium |
| **Points** | 500 |
| **Author** | HxN0n3 |
| **File** | `shattered_qr.png` |
| **Flag** | `bcsctf{5m45h3dQR_c4n_b3_r3bu1l7_4g41n}` |

## Challenge

> During an investigation into a compromised identity-management server, the incident response team recovered a QR-based emergency access token from an incomplete print-spool artifact.
>
> The image is structurally intact, but no standard QR reader can recognize it. Forensic analysis confirms that the file was not encrypted, compressed, cropped, or damaged. The number of black and white cells remains unchanged, suggesting that the attacker rearranged the original square matrix instead of modifying its contents.
>
> EDR telemetry shows that an unknown image-processing utility accessed the token immediately before deletion. The executable could not be recovered, but one fragmented log entry survived:
>
> ```
> job=FELIS-09
> mode=spatial_permutation
> passes=9
> boundary=wrap
> result=success
> ```
>
> A junior analyst believes FELIS-09 is the attacker's malware family. The senior analyst disagrees and claims the name is probably a joke—or a clue.
>
> Reconstruct the original QR code and recover the emergency access token.

## TL;DR

*Felis* is the Latin genus for cats, so the image was scrambled with **Arnold's Cat Map**, applied **9** times. Undo the map 9 times on the 45×45 module grid and the QR decodes.

## Reading the clues

| Log field | Meaning |
|---|---|
| `job=FELIS-09` | *Felis* = cat → **Arnold's Cat Map**; `09` = 9 passes |
| `mode=spatial_permutation` | Cells were moved, not changed, so the black/white counts stay the same |
| `passes=9` | The map was applied 9 times |
| `boundary=wrap` | Coordinates wrap around the edges (arithmetic mod N), like a torus |

Arnold's Cat Map is a well-known pixel-scrambling transform on an N×N grid:

```
(x, y) → ((x + y) mod N, (x + 2y) mod N)
```

Its matrix `[[1,1],[1,2]]` has determinant 1, so the map is a bijection (a pure permutation of cells) and can be undone exactly.

## Analysis

The image is a 540×540, 1-bit (0/255) grayscale PNG with only `IHDR`, `IDAT`, and `IEND` chunks and no trailing data, so nothing is hidden in the file itself.

Measuring run lengths along a row shows every run is a multiple of **12 px**:

```
[24, 12, 36, 12, 84, 36, 12, 12, 24, 12, 36, 12, ...]
```

That gives a module size of 12 px and a grid of 540 / 12 = **45×45** modules, which is exactly the size of a **QR version 7** symbol. The scramble covered the whole grid, and there is no quiet zone. Sampling the center of each 12×12 block reproduces the image exactly (0 mismatched pixels), so the grid extraction is lossless.

## Solution

1. Sample the 45×45 module grid from the center of each 12 px block.
2. Undo the cat map 9 times, with `x` = column and `y` = row. The scrambler did `new[f(p)] = old[p]`, so each inverse pass is `old[p] = new[f(p)]`.
3. Upscale, add a white quiet zone, and decode.

```python
import numpy as np
from PIL import Image
from pyzbar.pyzbar import decode

a = np.array(Image.open("shattered_qr.png").convert("L"))
g = a[6::12, 6::12]                       # 45x45 module grid
N = g.shape[0]

Y, X = np.indices((N, N))                 # x = column, y = row
fx, fy = (X + Y) % N, (X + 2 * Y) % N     # Arnold's Cat Map
for _ in range(9):                        # 9 inverse passes
    g = g[fy, fx]

img = np.pad(np.kron(g, np.ones((10, 10), dtype=np.uint8)), 40, constant_values=255)
print(decode(Image.fromarray(img))[0].data.decode())
```

The full script is in [`solve.py`](solve.py), and it writes [`recovered_qr.png`](recovered_qr.png).

Output:

```
pctf{5m45h3dQR_c4n_b3_r3bu1l7_4g41n}
```

### Sanity check: the map's period

The cat map is periodic: after enough passes every cell returns to its starting position. For N = 45 the period is **60**. As expected, applying the forward map **51** more times (9 + 51 = 60) also gives the original QR.

## Flag

The QR payload uses a `pctf{` prefix. The flag accepted in the event's `bcsctf{...}` format is:

```
bcsctf{5m45h3dQR_c4n_b3_r3bu1l7_4g41n}
```

## Takeaways

- Cat-themed names in scrambling challenges often point to Arnold's Cat Map.
- "Same number of black/white cells" plus "wrap boundary" means a toroidal permutation, not corruption.
- Work on the **module grid**, not raw pixels. Find the cell size from run lengths first.
- Coordinate convention matters: treating `x` as the row instead of the column gives a different permutation. If one orientation doesn't decode, try the transpose.

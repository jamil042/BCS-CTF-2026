#!/usr/bin/env python3
# Nine Lives (BCS CTF 26, Misc) - undo 9 passes of Arnold's Cat Map on a 45x45 QR
import sys
import numpy as np
from PIL import Image
from pyzbar.pyzbar import decode

SRC = sys.argv[1] if len(sys.argv) > 1 else "../../../misc/shattered_qr.png"
CELL, PASSES = 12, 9

a = np.array(Image.open(SRC).convert("L"))
g = (a[CELL // 2::CELL, CELL // 2::CELL] > 128).astype(np.uint8) * 255  # 45x45
N = g.shape[0]

# x = column, y = row.  Cat map: (x, y) -> ((x + y) mod N, (x + 2y) mod N)
# Scrambling did new[f(p)] = old[p], so undoing it is old[p] = new[f(p)].
Y, X = np.indices((N, N))
fx, fy = (X + Y) % N, (X + 2 * Y) % N
for _ in range(PASSES):
    g = g[fy, fx]

img = np.pad(np.kron(g, np.ones((10, 10), dtype=np.uint8)), 40, constant_values=255)
Image.fromarray(img).save("recovered_qr.png")
for r in decode(Image.fromarray(img)):
    print(r.data.decode())

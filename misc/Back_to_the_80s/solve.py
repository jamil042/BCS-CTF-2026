#!/usr/bin/env python3
"""Decode the Hexahue message displayed in the challenge image."""

ROWS = [
    "RGMRBCCMBCYBRGGYYBRGYBBC",
    "YBGYMYRGMRCMYBBRCGYMCMMR",
    "MCBCRGBYYGGRCMCMMRBCGRGY",
    "BCBCGYRGBCRGRGGYYBGYRGBC",
    "MRMRRBYBMYYBMYBRCMRBYBYM",
    "YGYGCMMCRGMCBCCMRGCMMCRG",
]

HEXAHUE_PATTERNS = [
    "MRGYBC",  # A
    "RMGYBC",  # B
    "RGMYBC",  # C
    "RGYMBC",  # D
    "RGYBMC",  # E
    "RGYBCM",  # F
    "GRYBCM",  # G
    "GYRBCM",  # H
    "GYBRCM",  # I
    "GYBCRM",  # J
    "GYBCMR",  # K
    "YGBCMR",  # L
    "YBGCMR",  # M
    "YBCGMR",  # N
    "YBCMGR",  # O
    "YBCMRG",  # P
    "BYCMRG",  # Q
    "BCYMRG",  # R
    "BCMYRG",  # S
    "BCMRYG",  # T
    "BCMRGY",  # U
    "CBMRGY",  # V
    "CMBRGY",  # W
    "CMRBGY",  # X
    "CMRGBY",  # Y
    "CMRGYB",  # Z
]

HEXAHUE = dict(zip(HEXAHUE_PATTERNS, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))


def decode_grid(rows: list[str]) -> str:
    """Decode two lines of 2-by-3 Hexahue tiles from six color rows."""
    if len(rows) != 6 or any(len(row) != 24 for row in rows):
        raise ValueError("Expected a 24-by-6 color grid")

    plaintext = []

    for row_start in (0, 3):
        for column_start in range(0, 24, 2):
            tile = "".join(
                rows[row][column_start : column_start + 2]
                for row in range(row_start, row_start + 3)
            )

            try:
                plaintext.append(HEXAHUE[tile])
            except KeyError as error:
                raise ValueError(f"Unknown Hexahue tile: {tile}") from error

    return "".join(plaintext)


def main() -> None:
    message = decode_grid(ROWS)
    print(f"Decoded message: {message}")
    print(f"Flag: bcsctf{{{message}}}")


if __name__ == "__main__":
    main()

# Quantum Oracle

| | |
|---|---|
| **CTF** | BCS CTF |
| **Category** | Crypto |
| **Points** | 250 |
| **Difficulty** | Easy |
| **Author** | jatisshor0081 |
| **Flag** | `BCSCTF{lwe_no1se_15_t00_pr3d1ct@bl3_f0r_lll}` |

## Challenge

> The terminal's glow lit the silent server room as the analyst stared at a rogue
> infrastructure node dubbed the **Quantum Oracle**. Intelligence indicated a rogue
> developer had sandboxed a highly classified post-quantum cryptography challenge
> inside a simulated command-line dungeon. To extract the data, the analyst had to
> interact with a live API serving primitives based on the **Learning With Errors
> (LWE)** mathematical problem.

Connection:

```
nc 172.16.38.21 5001
nc 172.16.38.22 5001
```

On connect the service prints a 20×20 matrix `A` over `Z_127` and a menu:

```
=== QUANTUM LWE ORACLE TESTING INTERFACE ===
Matrix A (dimensions 20x20, Modulus 127):
[[63, 21, 122, ...], ...]

Options: [1] Get Ciphertext Sample [2] Submit Secret Key [3] Exit
```

## Recon

Mapping the interface (on both hosts, identical behaviour):

| Input | Behaviour |
|-------|-----------|
| `1` Get Ciphertext Sample | Prints only text: `Sample Error Bound Leak Active. Fixed Matrix verification token issued.` — **no numbers, ever** (verified with an 8s drain and with follow-up arguments). |
| `2` Submit Secret Key | Prompts for a comma-separated vector, then returns an identical `Incorrect secret key matrix configuration.` for everything. No partial-match oracle, no length/format leak, no traceback on malformed input. |
| `3` Exit | Does **not** exit — it **regenerates a fresh matrix `A`**. (Handlers are mis-wired.) |

Key observations:

- `A` is a **fresh, random, full-rank** 20×20 matrix mod 127 on every connection.
- The **ciphertext `b = A·s + e` is never transmitted**, so classic LWE recovery
  (`s = round(A⁻¹·b)`) is impossible from the wire alone — given only `A`, the secret
  is information-theoretically hidden.
- The secret is **not** a function of `A` either — ruled out: constants, rows/cols,
  diagonal, row/col sums, `A⁻¹·(constant sweep)`, the trivial kernel (A always
  full-rank), the augmented `[A|b]` reading (never consistent), and matrix answers
  (`A⁻¹`, `A`, `I`, all orderings).

The "LWE" story is a **red herring**.

## The Vulnerability — predictable PRNG seed

Every matrix entry lies in `0..126`, i.e. exactly `random.randint(0, 126)`. The server
generates the public matrix `A` **and** the secret `s` from the **same Python `random`
stream**, seeded with a small integer:

```python
random.seed(SEED)                                                 # small int seed
A = [[random.randint(0,126) for _ in range(20)] for _ in range(20)]  # 400 draws
s =  [random.randint(0,126) for _ in range(20)]                      # next 20 draws
```

Because the 400 values of `A` are consecutive outputs of the RNG, they fully pin down
the stream. Recover the seed from `A`, then simply **replay the RNG** to read off the
next 20 draws — that is the secret `s`. No ciphertext needed.

## Exploit

1. Read the 400 values of `A` from the banner.
2. Brute-force the seed: match `A[:8]` first (cheap filter), then verify all 400.
3. Replay: the **next 20 draws after `A`** are the secret `s`.
4. Submit `s` via option `2`.

Hit at **`SEED = 793`** (a small integer, not time-based — a wide time-window search
missed it; a small-integer sweep landed it).

```
> Submit Secret Key
82,107,109,41,52,25,65,7,48,11,38,107,121,1,6,75,31,23,55,111
Success! Flag: BCSCTF{lwe_no1se_15_t00_pr3d1ct@bl3_f0r_lll}
```

See [`solve.py`](solve.py).

## Flag

```
BCSCTF{lwe_no1se_15_t00_pr3d1ct@bl3_f0r_lll}
```

The flag itself confirms the intended solve: *"lwe noise is too predictable for lll"* —
the secret/noise was PRNG-predictable rather than requiring lattice reduction (LLL).

## Takeaways

- **Never seed a CSPRNG-critical value with a small/predictable integer.** Use
  `secrets` / `os.urandom` for key material.
- Generating the public value and the secret from the **same** ordinary `random`
  stream leaks the secret: any consecutive outputs reconstruct the state, and Mersenne
  Twister is fully invertible.
- Elaborate crypto framing (post-quantum, LWE, lattices) can hide a mundane
  implementation bug — always fingerprint the actual primitive (here: value range
  `0..126` ⇒ `random.randint(0,126)`).

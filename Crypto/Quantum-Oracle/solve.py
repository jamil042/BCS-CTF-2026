#!/usr/bin/env python3
"""
BCS CTF - Quantum Oracle (Crypto, 250) solver.

The "LWE" service leaks its public matrix A (20x20 mod 127) as 400 consecutive
outputs of Python's random.randint(0,126). The secret s is drawn from the SAME
stream right after A. So: recover the small integer seed from A, replay the RNG,
and the next 20 draws are s. Submit s -> flag.

    python solve.py [host]
"""
import socket, time, re, random, sys

HOST = (sys.argv[1] if len(sys.argv) > 1 else "172.16.38.22", 5001)

def grab():
    s = socket.create_connection(HOST, timeout=10); s.settimeout(2.5)
    d = b""
    try:
        while True:
            c = s.recv(65536)
            if not c: break
            d += c
    except Exception:
        pass
    d = d.decode(errors="replace")
    after = d.split("Modulus")[1]
    nums = list(map(int, re.findall(r"\d+", after)))
    if nums and nums[0] == 127:
        nums = nums[1:]
    return s, nums[:400]

def check(seed, A, head):
    r = random.Random(seed)
    v = [r.randint(0, 126) for _ in range(28)]
    if v[:8] == head:
        r2 = random.Random(seed); full = [r2.randint(0, 126) for _ in range(420)]
        if full[:400] == A:
            return ("Afirst", full[400:420])
    if v[20:28] == head:
        r2 = random.Random(seed); full = [r2.randint(0, 126) for _ in range(420)]
        if full[20:420] == A:
            return ("sfirst", full[:20])
    return None

def ru(sock, markers, t=8):
    d = ""; end = time.time() + t
    while time.time() < end:
        try:
            c = sock.recv(65536)
            if not c: break
            d += c.decode(errors="replace")
            if any(m in d for m in markers):
                end = min(end, time.time() + 0.8)
        except Exception:
            pass
    return d

def main():
    sock, A = grab()
    print("A[:8] =", A[:8])
    head = A[:8]
    t0 = int(time.time())
    found = None
    # small integer seeds first (this is where the real seed lived: 793),
    # then a wide time window in case a deployment uses int(time.time()).
    for rg in (range(0, 3_000_000), range(t0 - 90000, t0 + 90000)):
        for seed in rg:
            res = check(seed, A, head)
            if res:
                found = (seed,) + res
                break
        if found:
            break
    if not found:
        print("[-] seed not found (space may be larger / non-integer seed)")
        sock.close(); return
    seed, order, s = found
    print(f"[+] seed={seed} order={order}")
    print("[+] secret s =", s)
    sock.sendall(b"2\n"); ru(sock, ["separated):"], 4)
    sock.sendall((",".join(map(str, s))).encode() + b"\n")
    resp = ru(sock, ["Flag", "FLAG", "flag", "{", "Success", "Incorrect"], 8)
    print(resp.strip())
    sock.close()

if __name__ == "__main__":
    main()

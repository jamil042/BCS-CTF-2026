# BCS CTF 2026 — Security Talent

| Field | Details |
| --- | --- |
| **Author** | M Ariful Islam |
| **Difficulty** | Hard |
| **Category** | Web (with a Misc/Stego twist at the final stage) |
| **Flag format** | `bcsctf{...}` |

## Challenge Description

A cybersecurity organization is searching for its next security talent. Instead of relying on resumes and interviews, they have decided to put candidates to the test.

To identify professionals with real-world bug-hunting and vulnerability research experience, the organization has launched an open cybersecurity challenge. Anyone can participate, investigate the provided targets, uncover hidden vulnerabilities, and demonstrate their technical skills.

Your mission is simple: solve the challenges and prove that you have what it takes to become the organization's next security expert.

## Challenge Information

**Targets:**

- `http://172.16.38.21:16000`
- `http://172.16.38.22:16000`

## 1. Reconnaissance

Nmap scans of both targets showed identical setups:

```bash
nmap -sV -sC -p 16000 172.16.38.21
nmap -sV -sC -p 16000 172.16.38.22
```

Result:

```text
16000/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: CTF
```

Running `curl -v` against `/` revealed:

- `X-Powered-By: PHP/8.0.30`
- A form (`#challange`) posting to `challange_actions.php` through jQuery AJAX
- A `payload` input referenced by JavaScript but not actually present in the HTML—a red herring or broken form
- The following hint on the page:

> Flag: `$DOCUMENT_ROOT/flag.php` Hint: Flag contains only alphanumeric characters.

The file `assets/generate.js` revealed a second endpoint:

```js
function genToken(value){
  $.ajax({
    type: "GET",
    url: 'lib/generateToken.php',
    data: {value: value},
    ...
  });
}
```

## 2. Finding the Token Mechanism

A request to `GET /flag.php` returned a static response header:

```text
Token: kl1sdfsdafj3eeWc0k
```

The response body was:

```text
Parameter <b>getflag</b> requires valid token to get content. Try Again!
```

Requests to `GET /lib/generateToken.php?value=...` always returned `Try Again!`, regardless of the supplied value. Although the JavaScript used `GET`, switching the request method to `POST` was the key:

```bash
curl -s -X POST http://172.16.38.21:16000/lib/generateToken.php \
  -d "value=kl1sdfsdafj3eeWc0k"
```

This returned the derived token:

```text
e38089p0jsd2f9d
```

The request worked only when `value` exactly matched the original token from the `flag.php` response header. Every other input returned `Try Again!`. This indicated a hardcoded or keyed transformation rather than a general encoder. The process was also not chainable: submitting the derived token failed.

## 3. Getting the Hidden File Path

Numerous parameter combinations were tried against `flag.php`, including `token=`, a `Token` header, and cookies. All failed with the same error until the parameter names and expected values were effectively swapped:

```http
GET /flag.php?getflag=<derived_token>&token=<original_token>
```

The successful request was:

```http
GET /flag.php?getflag=e38089p0jsd2f9d&token=kl1sdfsdafj3eeWc0k
```

The server returned:

```text
File location: $DOCUMENT_ROOT/0x923131LBH39SDwwQqhfqcxvDwqd/23df98102kajdiouopnaxS8s/flag.zip
```

## 4. Retrieving and Unlocking the Archive

The archive was downloaded from the disclosed path:

```bash
curl -O "http://172.16.38.21:16000/0x923131LBH39SDwwQqhfqcxvDwqd/23df98102kajdiouopnaxS8s/flag.zip"
```

It contained:

```text
flag/flag.txt                          (2,067,040 bytes)
flag/use token to open this zip.txt    (15 bytes)
```

The second filename hinted that a token was the archive password. The ZIP used AES encryption, which the older `unzip` utility could not handle and reported as `need PK compat. v5.1`. Using `p7zip` instead:

```bash
7z x flag.zip -p'e38089p0jsd2f9d'
```

The derived token, `e38089p0jsd2f9d`, was the correct password—not the original static token.

## 5. JSFuck and Steganography Analysis

The extracted `flag.txt` was an approximately 2 MB, single-line JSFuck-encoded blob. JSFuck normally expresses JavaScript using only these six characters:

```text
[ ] ( ) ! +
```

Running the blob directly produced syntax errors. Closer inspection revealed exactly 30 characters outside the valid JSFuck character set. These ordinary alphanumeric characters were scattered throughout the file at fixed positions:

| Position | Character |
| ---: | :---: |
| 11 | `J` |
| 1,532 | `6` |
| 3,993 | `K` |
| 4,850 | `A` |
| 5,588 | `4` |
| 6,669 | `Q` |
| 8,424 | `0` |
| 10,781 | `X` |
| 11,805 | `N` |
| 39,729 | `r` |
| 237,284 | `d` |
| 318,080 | `I` |
| 403,230 | `w` |
| 405,755 | `F` |
| 411,280 | `E` |
| 417,758 | `R` |
| 426,089 | `L` |
| 431,729 | `g` |
| 439,758 | `P` |
| 716,802 | `4` |
| 726,141 | `6` |
| 923,394 | `N` |
| 1,148,146 | `w` |
| 1,216,672 | `H` |
| 1,428,744 | `7` |
| 1,597,653 | `Q` |
| 1,610,918 | `5` |
| 1,626,845 | `C` |
| 1,827,211 | `3` |
| 2,065,910 | `2` |

Several attempts were made to repair the JSFuck around these positions:

- Character substitution followed by `node --check`
- Positional brute forcing with the `acorn` parser
- Deleting all 30 anomalous characters

None produced valid, runnable JavaScript. This was the crucial signal: the JSFuck blob was not intended to execute. It was camouflage and carrier data, while the injected anomalies formed the real payload—a steganography-style technique that hides meaningful data inside apparent noise.

Reading the 30 anomalous characters in ascending order of position produced:

```text
J6KA4Q0XNrdIwFERLgP46NwH7Q5C32
```

The result is 30 characters long and entirely alphanumeric, matching the hint on the challenge page.

## 6. Flag

```text
bcsctf{J6KA4Q0XNrdIwFERLgP46NwH7Q5C32}
```

---

## Key Takeaways

1. **HTTP methods matter.** An endpoint can silently reject `GET` while accepting only `POST`.
2. **Try unexpected parameter mappings.** The application required the derived value in `getflag` and the original value in `token`, the reverse of the obvious assumption.
3. **Response headers can contain application logic.** The original token appeared in a custom `Token` response header rather than the body.
4. **Test every plausible secret systematically.** When multiple token-like values exist, the most obvious one may not be the archive password.
5. **Not every obfuscated blob is meant to run.** If repeated repairs fail, the obfuscation may be a carrier and its anomalies may be the real data.
6. **Bash history expansion can corrupt JSFuck commands.** The `!` character inside double-quoted heredocs or `-e` strings may be expanded. Use `set +H`, single quotes, or files when handling JSFuck payloads in Bash.

---

*Writeup prepared from the live solve session against `172.16.38.21` and `172.16.38.22` on port `16000`.*

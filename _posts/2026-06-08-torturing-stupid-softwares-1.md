---
title: "Torturing Stupid Softwares — Part 1: PacketRaft.ir"
date: 2026-06-09
author: b00tkitism
tags: [reverse-engineering, rust, reqwest, rustls, wireguard, tls, ida]
---

# Torturing Stupid Softwares — Part 1: PacketRaft.ir

Welcome to a new series where I take a piece of software that thinks it's clever,
turn it inside out, and document every soft spot. First victim: **PacketRaft** —
an Iranian "anti‑sanction gaming tunnel" (a fancy WireGuard wrapper) whose desktop
client is `PacketRaft.exe`. (It's not stupid though)

Everything below was recovered with **Reverse Engineering**, a MITM proxy, and a
bit of patience. No server‑side access, no insider info just the binary and the
traffic it produces.

> Don't be a jerk with it.

---

## 0. Recon — what are we dealing with?

`PacketRaft.exe` is a **Rust** binary (GTK4 GUI) that bundles a privileged
WireGuard service and a custom UDP "forwarder". The networking stack is the giveaway
the binary is stuffed with `.cargo` source paths:

The backend lives at three hosts:

| Host | Purpose |
|------|---------|
| `https://packetraft.ir/api` | the app API (auth, config, telemetry) |
| `https://captcha.packetraft.ir` | a CAP.js proof‑of‑work captcha |
| `https://packetraft.ir/auth/app` | the in‑browser login → localhost callback |


---

## 1. TLS — defeating certificate verification

### 1.1 Bypassing the Certificate verification

`reqwest`'s `ClientBuilder::build` picks the rustls certificate verifier from a
**single boolean in its config struct**. Decompiled, the decision looks like:

```c
if ( BYTE9(config[53]) == 1 )          // certs_verification flag
    verifier = WebPkiServerVerifier;   // real verification
else
    verifier = NoVerifier;             // accept ANY certificate
```

`NoVerifier::verify_server_cert` is a two‑instruction stub that ignores its
arguments and returns `Ok(...)` — i.e. **trust everything**. It's the same thing
`reqwest`'s `danger_accept_invalid_certs(true)` installs, and the type is literally
called `NoVerifier` (with a sibling `IgnoreHostname`) right there in the strings.

The flag is initialised in the default‑config constructor with a classic compiler
trick — **eight `bool` fields packed into one 64‑bit store**:

```asm
mov  rax, 0101010100010101h   ; 8 flags, little-endian
mov  [config+358h], rax       ; byte at +359h = certs_verification = 0x01
```

Each `01` is a separate flag (`certs_verification`, `hostname_verification`,
`auto_sys_proxy`, gzip, brotli, …). Flip the byte at `+359h` from `01` to `00`
(or patch the `0x01` in that immediate) and **every TLS connection the client makes
silently accepts forged certificates.**

### 1.2 Automating the patch — `reqwest-unverify-ida`

Hand‑patching is fine once. To do it on *any* reqwest+rustls binary, I wrote an
IDA tool that locates the verifier‑selection flag and disables verification
automatically:

**→ https://github.com/b00tkitism/reqwest-unverify-ida**

Point it at a Rust/reqwest target and it neuters certificate validation for you.

### 1.3 Putting it together for a working MITM

1. Run a **real forward proxy** — mitmproxy / Burp / Fiddler on, say, `:8080`.
2. Launch the client with the env proxy set:
   ```bat
   set HTTPS_PROXY=http://127.0.0.1:8080
   set ALL_PROXY=http://127.0.0.1:8080
   ```
3. Make the client accept the proxy's MITM cert

Now every `https://packetraft.ir/api/*` call is in plaintext in front of you, and
the rest of this post writes itself.

---

## 2. Authentication — captchas, plaintext tokens, and a free privilege upgrade

### 2.1 The CAP.js proof‑of‑work captcha

Login is gated by a [CAP.js](https://capjs.js.org) proof‑of‑work:

```
POST https://captcha.packetraft.ir/<site>/challenge
  -> { "challenge": { "c": 80, "s": 32, "d": 4 }, "token": "9f7f…" }
```

`c` sub‑puzzles, salt length `s`, difficulty `d`. The client derives the puzzles
**deterministically from the token** and brute‑forces a nonce per puzzle. The
algorithm is just FNV‑1a → xorshift32 → SHA‑256, fully reproducible:

```python
import hashlib

def _fnv1a(s):
    h = 0x811c9dc5
    for ch in s:
        h ^= ord(ch); h = (h * 0x01000193) & 0xFFFFFFFF
    return h

def _prng(seed, length):           # xorshift32, 8-hex-char words
    st, out = _fnv1a(seed), []
    while sum(len(x) for x in out) < length:
        st ^= (st << 13) & 0xFFFFFFFF
        st ^= st >> 17
        st ^= (st << 5)  & 0xFFFFFFFF; st &= 0xFFFFFFFF
        out.append(f"{st:08x}")
    return "".join(out)[:length]

def solve_one(salt, target):
    n = 0
    while not hashlib.sha256(f"{salt}{n}".encode()).hexdigest().startswith(target):
        n += 1
    return n

def solve(token, c, s, d):
    return [solve_one(_prng(f"{token}{i}", s), _prng(f"{token}{i}d", d))
            for i in range(1, c + 1)]
```

```
POST /<site>/redeem  { "token": "...", "solutions": [75893, 101704, ...] }
  -> { "success": true, "token": "<captcha-token>" }
```

I verified this against a captured challenge, it reproduces the exact 80 nonces
the official client sent. So the gate is solvable in a few seconds of pure Python.

### 2.2 The login

```
POST https://packetraft.ir/api/auth/login
  header  captcha: <captcha-token>
  body    { "username": null, "phone_number": "09xxxxxxxxx", "password": "<redacted>" }
  -> { "access_token": "...", "refresh_token": "..." }
```

### 2.3 The token format — claims in plaintext

This is my favourite part. The token is:

```
base64( 32-byte MAC ) "=" <plaintext JSON claims>
```

A real captured token (values redacted), prettified:

```
oQ7…Y=                      {"user_id":XXXXX,"username":"b00tkitism","expires_in":17808XXXXX,"kind":"web"}
└── 32-byte signature ──┘  └──────────────────── readable claims ────────────────┘
```

The 32 bytes before the `=` are a MAC (HMAC‑SHA256‑shaped). Everything after it,
your `user_id`, `username`, expiry, and the all‑important `kind` is **plaintext
JSON you can read**. The only thing standing between you and forging
`{"user_id": someone_else}` is that 32‑byte MAC.

### 2.4 `web` vs `app` — and the free upgrade

The app endpoints (`/app/*`) reject `kind: "web"` tokens with
`400 unexpected_session_kind`. The native client never password‑logs‑in directly
it opens a browser to `/auth/app` and gets an `app` token via a localhost callback.

But you don't need the browser dance. The website performs a trivial **token
exchange** that anyone holding a web token can replay:

```
POST https://packetraft.ir/api/auth/app
  header  Authorization: Bearer <WEB token>
  (empty body)
  -> { "access_token": <kind:"app">, "refresh_token": "..." }
```

So the full path is: **solve captcha → `/auth/login` (web token) → `/auth/app`
(app token)**. No browser, no OAuth ceremony. A `web` session upgrades itself to
an `app` session with one authenticated POST.

### 2.5 Refresh — the bare‑string body

When the app token expires you'll get `401`, or sometimes a `400 invalid_session`.
Refresh is quirky — the body is a **bare JSON string**, not an object:

```
POST https://packetraft.ir/api/auth/refresh
  body  "<refresh_token>"          ← yes, just a quoted string
  -> { "access_token": "...", "refresh_token": "..." }
```

(In the binary this is literally `'"' + json_escape(token) + '"'`.)

---

## 3. The app API surface

Base `https://packetraft.ir/api`, `User-Agent: packetraft-app`,
`Authorization: Bearer <kind:app token>`.

| Method + path | Body | Returns |
|---|---|---|
| `GET  /app/status` | — | full catalog (games, servers, regions, chains, versions, **signed** installer links) |
| `POST /app/generate_config` | `{game_name, server_name, service_name}` (lowercased) | a WireGuard config |
| `POST /app/stat` | `{type, data:{game_name, advanced:{server_name, chain_name, ping_stat, anti_sanction_mode}, ...}}` | telemetry sink |
| `POST /app/server_pings` | per‑server ping/loss | — |
| `GET/POST /app/lan` | LAN‑lobby info | — |

`generate_config`'s request struct (`GenerateConfigArgs`) is **exactly three
fields** — no `kind`, no chain, no auth in the body. The `kind` that matters is the
one baked into the bearer token.

### 3.1 The catalog

`/app/status` is a ~34 KB JSON catalog:

- **`games[]`** (123 of them) — each has `game_servers` per region
  (`me` / `eu` / `ru`) that reference providers either by `#tag` or literal name,
  plus a `programs[]` list of `.exe` names and an `is_program` flag. Entries with
  `is_program:true` (Discord, Spotify, Steam, …) are **apps**, not games; `LAN` /
  `LanRoom` are their own thing.
- **`servers[]`** — providers like `GCore`, `DataForest`, `RETN`, `Programs`,
  `NoServer`, each with `tags`, `services`, `is_cheap`, `no_chain`.
- **`chains[]`** — Iranian ISP relays with real IPs: `AsiaTech`, `Respina`,
  `ParsOnline`, …
- **`regions[]`**, client version, and **download links with signatures**.

This one endpoint hands you the entire topology of their network.

---

## 4. The data path — WireGuard, the XOR "forwarder", and the chain trick

`generate_config` returns a WireGuard config whose `endpoint` is an enum:

```
endpoint = Normal "host:port"                  // connect WireGuard directly
         | Forwarder ["ip:port", "udp"]         // go through their relay
```

### 4.1 The "forwarder" — encryption is XOR with a hardcoded key

When the endpoint is `Forwarder`, the GUI spawns itself as a child
(`PacketRaft.exe --forwarder …`) and points WireGuard at `127.0.0.1:<localport>`.
That local process is a UDP reverse proxy that "encrypts" every datagram before
sending it on… by **XOR‑ing it with a hardcoded 8‑byte key**:

```asm
mov rax, 70697468736F686Bh     ; "khoshtip"  (little-endian)
```

That's the whole cipher. Repeating‑key XOR with `khoshtip`, applied to the entire
UDP payload, symmetric, no framing. Reimplemented in one line:

```python
KEY = b"khoshtip"
def deobfuscate(p): return bytes(b ^ KEY[i % 8] for i, b in enumerate(p))
```

So anyone capturing the "obfuscated" tunnel traffic can XOR it back to raw
WireGuard with a key that ships in the binary. Calling this encryption is generous.

### 4.2 The chain — domestic relays and `port − 1000`

A **chain** is an Iranian ISP relay used as a domestic first hop (to dodge the
international throttling). When you pick a chain, the client connects WireGuard
**directly to the chain IP**, on a port derived by simple arithmetic:

```
chain endpoint = chain_ip : (forwarder_port − 1000)
```

i.e. if the server forwarder is on `:2015`, the chain entry is on `:1015`; another
server's `:2018` → `:1018`. The client requires the endpoint to be `Normal` in
this mode (it'll literally panic `expected Endpoint::Normal` otherwise). Apps and
LAN don't use chains; the `Programs` server is flagged `no_chain`.

---

## 5. Result — a from‑scratch client

With all of the above I rebuilt a clean client that speaks the exact protocol:
solve captcha → login → `/auth/app` upgrade → `/app/status` → `/app/generate_config`,
plus a faithful re‑implementation of the `khoshtip` XOR forwarder and the
`port − 1000` chain logic, with reactive token refresh on `401` / `invalid_session`.

It needed **zero** of PacketRaft's binary, just the protocol notes above. Which is
the whole point: none of this was protected by anything more than obscurity and one
flippable byte.

---

## Toolbox

- **IDA Pro + Hex‑Rays** — the heavy lifting (find `ClientBuilder::build`, the
  verifier vtables, the config‑byte store, the `khoshtip` immediate, the chain math).
- **[`reqwest-unverify-ida`](https://github.com/b00tkitism/reqwest-unverify-ida)** —
  my IDAPython tool to locate and kill reqwest/rustls certificate verification
  automatically. Use it on any reqwest target.
- **mitmproxy / Burp** + `HTTPS_PROXY` env var the only MITM setup that works
  against an in‑process rustls client.
- A tiny reqwest‑0.12.23 + rustls‑0.23.31 test binary same stack as the target,
  built to study the TLS code in isolation before touching the real thing.

---

Part 2 will torture something else (ElitePing maybe?). If you want the cert‑unverify tool, it's here:
**https://github.com/b00tkitism/reqwest-unverify-ida**

*— b00tkitism*
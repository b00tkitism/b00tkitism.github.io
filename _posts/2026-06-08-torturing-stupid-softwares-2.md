---
title: "Torturing Stupid Softwares — Part 2: ElitePing"
date: 2026-06-09
author: b00tkitism
tags: [reverse-engineering, golang, grpc, openvpn, split-tunnel, wiresock, electron, ida, goresym]
---

# Torturing Stupid Softwares — Part 2: ElitePing

Welcome back. Part 1 took a Rust application apart with a one‑byte patch.
Today's victim is heavier: **ElitePing** another Iranian "gaming ping reducer / VPN"
(`eliteping.net`, panel on `eliteping.ir`) shipped as an **Electron** app.

Spoiler, because the highlights deserve it:
- The pretty React frontend is theatre. All the privileged work lives in a **Go
  DLL** that opens an **unauthenticated, plaintext gRPC server on
  `127.0.0.1:18458`**
- The "anti‑sanction" magic is just **OpenVPN** (`bin\open.exe`) plus **L2TP/PPTP**,
  with credentials written to disk in a temp `auth.txt`.
- Split tunneling is a **kernel packet‑filter driver** (`bin\wiresock.sys`) driven
  by IVPN's `SplitTun_*` API, "complemented" by four `route.exe` lines that beat
  the VPN's default route.
- Your account password rides around in **plaintext URL query strings**, in
  **`elite://` deep links**, and through the **clipboard**.

The Electron half was recovered by unpacking `app.asar`. The interesting half
`elitecore.dll` was recovered with **IDA Pro**, with Go symbols
restored by **GoReSym** (more on why that matters in §3). No server access, no
insider info just the two binaries that ship in the installer.

> Don't be a jerk with it.

---

## 0. Recon — two binaries, one of them is a decoy

ElitePing installs to `…\AppData\Local\Programs\eliteping\`. Two pieces matter:

| Piece | What it is |
|---|---|
| `resources\app.asar` | the Electron app: **React** renderer + **preload** bridge + a Node **main** process |
| `bin\elitecore.dll` | the actual engine — a **Go** `c-shared` DLL that does everything privileged |

The asar is the part everyone looks at, so it's the part with nothing worth
hiding behind. Unpack it (`npx asar extract app.asar out`) and you get readable
if minified JS. The main process is a thin client it shells out to the DLL over
gRPC for anything that touches the network stack. So this post spends one section
on the shell, then moves into the DLL where the real comedy is.

Hosts involved:

| Host | Purpose |
|---|---|
| `https://eliteping.net/api` | the app API (login, games, servers, app details) |
| `https://eliteping.net/panel/ovpn` | hands back a raw `.ovpn` config as text |
| `https://eliteping.net/updates/next/` | electron‑updater generic feed |
| `https://eliteping.ir/panel/quicklogin` | "quick login" → `elite://` callback |
| third‑party IP/geo (`api64.ipify.org`, `api.seeip.org`) | "where am I now?" lookups |

---

## 1. The Electron shell — secrets you don't even have to MITM for

Part 1 was a whole TLS adventure because `rustls` hid the traffic. ElitePing saves
you the trouble: the interesting secrets are **sitting in the asar** and the
credentials are **in the URLs**. You barely need a proxy.

### 1.1 A hardcoded API key and a cosplay User‑Agent

The preload bridge builds API URLs with a key baked in and a User‑Agent that was
clearly typed by a human mashing a keyboard (LOL):

```js
// preload/index.js
`${BASE}/GetGameList/?key=F45ER62437J32673547341TGBER56324&platform=next`
userAgent: "Mozilla/1.0.5.2.7 (Windows NT 10.0; …) Chrome/112.5.4.1 Safari/537.36"
```

`Mozilla/1.0.5.2.7`. `Chrome/112.5.4.1`. Versions that have never existed. The key
`F45ER62437J32673547341TGBER56324` ships in every install.

### 1.2 Credentials in the query string

Login isn't a POST with a body. It's a **GET with your password in the URL**:

```
GET /api/GetUserDetailsByCredentials/?username=<u>&password=<p>&raw&platform=next
  -> { error:false, details:{ uniqueID:"…", password:"…" } }
```

After that, the app authenticates with `uniqueID` + a *service password*, also
passed in the query string:

```
GET /api/GetUserDetails/?raw&u=<uniqueID>&d=<service_password>&platform=next
```

There is no token, no session cookie, no expiry you can't read. The renderer just
stashes the whole thing in `localStorage["user-storage"]` and replays it. Whatever
logs sit between the client and `eliteping.net` have everyone's passwords in the
URL line.

### 1.3 The `elite://` deep link — and the clipboard grab

"Quick login" opens `eliteping.ir/panel/quicklogin` in the browser, which calls
back into the app via a custom protocol (easy to steal users' accounts):

```
elite://auth-<uniqueID>-<password>
```

The main process parses that, forwards `{uniqueID, password}` to the renderer…
and, for good measure, it also **reads your clipboard on launch**; if the clipboard
text starts with `elite://` it consumes it as credentials and then **clears the
clipboard**. Credentials as plaintext deep links, harvested from the clipboard.
Bold.

### 1.4 WTF?

> Bonus stupidity, no charge: `Settings-CA-owJ4f.js` is **24 MB**. Not data, not
> wasm — about **30,000 inline SVG country‑flag icons** statically imported into
> one chunk. The settings page logic is ~65 strings.

---

## 2. The backend API surface

Base `https://eliteping.net/api`, key in the query, garbage UA.

| Method + path | Notable params | Returns |
|---|---|---|
| `GET /GetUserDetailsByCredentials/` | `username`, `password` (plaintext) | `uniqueID` + service password |
| `GET /GetUserDetails/` | `u=<uniqueID>`, `d=<password>` | account / subscription details |
| `GET /GetGameList/` | `key=…` | game catalog (+ split‑tunnel hints) |
| `GET /GetServerListNew/` | `platform=next` | servers grouped direct / route / intl |
| `GET /GetAppDetails/` | `platform=next` | version gate + notifications |
| `POST /RequestGame/?raw` | form incl. **`u`,`p`** | "add my game" request |
| `GET /panel/ovpn` | `server_ip`, `port`, `protocol`, `text=true` | a raw `.ovpn` config as text |

The `/panel/ovpn` endpoint is the one to remember: the client downloads the OpenVPN
config as **plaintext over HTTPS** and hands it, as a string, to the DLL. Nothing is
generated locally. Hold that thought for §4.

---

## 3. The real engine an unauthenticated gRPC server running as you, elevated

Here's the whole trick. `app.asar`'s main process loads the native core with
**koffi** and only ever binds two functions:

```js
const e = Cs.load("./elitecore.dll");   // koffi, CWD-relative path
Run  = e.func("Run",  "string", []);
Stop = e.func("Stop", "void",   []);
```

`elitecore.dll` is a **Go `c-shared` library**. IDA out of the box names *nothing*
in it Go stores symbol names in `pclntab`, not the COFF symbol table so the
first move is to run **GoReSym** and import the recovered names. Suddenly the 21k
functions have labels like `main.(*server).ConnectOvpn`, and the whole thing reads
like source.

Decompiling the export → `main.Run` → its goroutine `main.Run.func1`:

```c
// main.Run.func1, cleaned up
net.Listen("tcp", "127.0.0.1:18458");
s = grpc.NewServer();                 // <-- no ServerOption. no creds. no interceptor.
grpc_dll.RegisterVpnServiceServer(s, &main.server);
grpc.(*Server).Serve(s, listener);
```

That's it. A **plaintext gRPC server, on loopback, with zero authentication**,
exposing a service called `grpc.VpnService`. The Electron client dials it with
`grpc.credentials.createInsecure()` — and so can **anything else on the machine**.

Why does that matter? Because the DLL is the thing that runs **elevated** and does
all the privileged work. The handlers never check a token, a caller PID, or a
shared secret. Any local process any sandboxed app, any other user session that
can reach loopback can call `RunNetworkReset`, install drivers, rewrite your
proxy, or stand up a VPN, **and** sniff the cleartext credentials going by. The
"VPN client" is a SYSTEM‑level RPC with the auth ripped out.

### 3.1 The service, reconstructed

The proto is fully recoverable from the wire encoders on the JS side and the
handlers in the DLL. Reconstructed:

```proto
service VpnService {
  rpc ConnectOvpn(ConnectOvpnRequest) returns (Response);
  rpc ConnectL2TP(ConnectRasRequest) returns (Response);
  rpc ConnectPPTP(ConnectRasRequest) returns (Response);
  rpc DisconnectOvpn(Empty) returns (Response);
  rpc DisconnectL2TP(Empty) returns (Response);
  rpc DisconnectPPTP(Empty) returns (Response);
  rpc GetConnectionStatus(StatusRequest) returns (Response);
  rpc GetGeoInfo(Empty) returns (GeoResponse);
  rpc FlushDns(Empty) returns (Response);
  rpc RunNetworkReset(Empty) returns (Response);
  rpc RepairWANMiniport(Empty) returns (Response);
  rpc EnableRASServices(Empty) returns (Response);
  rpc RepairOpenVPNInterface(Empty) returns (Response);
  rpc RepairL2TPInterface(Empty) returns (Response);
  rpc RepairPPTPInterface(Empty) returns (Response);
  rpc DisableSystemProxy(Empty) returns (Response);
  rpc DisableConnectionProxy(ProxyRequest) returns (Response);
  rpc ClearAppsCache(Empty) returns (Response);
}

message Auth { string username=1; string password=2; string uniqueId=3; string token=4; }
message App  { string name=1; repeated string processNames=2; repeated string dirNames=3; }

message ConnectOvpnRequest {
  Auth auth=1; string ovpnConfig=2; string mode=3;
  string connectionAdapter=4; string directAdapter=5;
  repeated App apps=6; repeated string appsCustom=7;
}
message ConnectRasRequest {   // L2TP / PPTP
  Auth auth=1; string serverAddr=2; string mode=3;
  string connectionAdapter=4; string directAdapter=5;
  repeated App apps=6; repeated string appsCustom=7;
}
message StatusRequest { string type=1; }   // "ovpn" | "l2tp" | "pptp"
message Response { bool status=1; string message=2; string appNotFound=3; string pathNotFound=4; }
```

You don't need ElitePing's UI to drive any of this. `grpcurl -plaintext
127.0.0.1:18458 list` and you're talking to the elevated core directly.

---

## 4. How a connection actually works

The "VPN" is OpenVPN, or Windows RAS (L2TP/PPTP). The DLL ships its own copy of the
tools in `bin\`:

| File | Role |
|---|---|
| `bin\open.exe` | OpenVPN, renamed |
| `bin\RAS.exe` | L2TP/PPTP dial helper |
| `bin\OemVista.inf` (+ `tap0901`) | the OpenVPN **TAP** driver; adapter installed as `ElitePing TAP` |
| `bin\wiresock.dll` / `bin\wiresock.sys` | the split‑tunnel **kernel driver** (see §5) |
| `bin\wanminiport-repair.ps1` | a PowerShell repair script |

`ConnectOvpn` (`main.(*server).ConnectOvpn`, ~16 KB of Go) does, in order:

1. `shell.RunningElevated()` — refuse unless admin; install the `ElitePing TAP`
   adapter if missing.
2. Resolve the split‑tunnel app list (see §5) and bring up the WireSock driver.
3. **`adapter.CreateTempOpenVPNConfig`** — this is the part to note. It:
   - `os.MkdirTemp(...)`,
   - writes your username/password to **`auth.txt`** with mode **`0600`**,
   - rewrites the server‑supplied config to inject
     `dev-node "ElitePing TAP"` and `auth-user-pass "auth.txt"`,
   - writes the final `config.ovpn`.
4. **`adapter.RunEliteOpenVpn`** — spawns `bin\open.exe` and watches its **stdout**
   for the literal string `Initialization Sequence Completed` to decide it's up.

So the credential handling is: cleartext over loopback gRPC → written to a temp
file on disk → handed to OpenVPN. At least they `chmod 600`'d it. The success
detector is grepping OpenVPN's console output for a magic string — which is exactly
as robust as it sounds.

The `Auth{username,password,uniqueId,token}` message is, again, sent in cleartext —
the gRPC channel has no TLS, because it's loopback, because "it's only local." See §3
for why "only local" isn't the comfort they think it is.

---

## 5. Split tunneling a kernel driver and the `/2` routing trick

This is the technically interesting bit, so it gets the detail.

Split tunneling is **not** done with routes alone. It's a **kernel packet‑filter
driver** — `bin\wiresock.sys` with the user‑mode `bin\wiresock.dll` exposing the
`SplitTun_*` API. That API (and the Go wrapper around it) is **IVPN's open‑source
Windows split‑tunnel driver**: per‑process socket redirection by image path, in
the kernel. ElitePing reuses it almost verbatim (`internal/splittun`).

### 5.1 Loading the driver

`splittun.initialize` finds `bin\wiresock.dll` **relative to the process CWD**,
`LoadLibrary`s it, and binds these exports as lazy procs:

```
SplitTun_Connect      SplitTun_Disconnect       SplitTun_StopAndClean
SplitTun_SplitStart   SplitTun_SplitStop        SplitTun_ProcMonInitRunningApps
SplitTun_ConfigSetAddresses                     SplitTun_ConfigSetSplitAppRaw
```

then calls `SplitTun_Connect` in a retry loop (≤10×, 1 s apart) until the driver
session is ready. CWD‑relative `LoadLibrary` of a **kernel driver loader** is its
own little planting hazard, but let's continue.

### 5.2 Choosing the apps

`ConnectOvpn` turns the request's `apps[]` (`App{name, processNames, dirNames}`)
and `appsCustom[]` into concrete `.exe` full paths via `pkg/appfinder`, which
**enumerates installed executables across every drive and the registry** (then
caches the result). That's a broad host‑inventory capability sitting inside a
"ping reducer."

### 5.3 The wire format — `makeRawBuffAppsConfig`

The exe paths are serialized into one packed, little‑endian blob
(`syscall.UTF16FromString` + `encoding/binary.Write`):

```
[uint32 totalSize][uint32 appCount]
  section A (headers): for each app -> [uint32 utf16Len][utf16le path]
  section B (strings):  all utf16le paths, concatenated
```

### 5.4 Pushing config to the driver, `setConfig`

Two driver calls:

```c
SplitTun_ConfigSetAddresses(pubIPv4, pubIPv6, tunIPv4, tunIPv6);  // 4 source IPs
SplitTun_ConfigSetSplitAppRaw(buf, len);                          // the blob from 5.3
```

`ConfigSetAddresses` tells the driver the **physical adapter's public IPs** and the
**VPN adapter's tunnel IPs** (IPv4‑mapped IPv6 gets normalized to 4 bytes first).
Then `SplitTun_SplitStart` arms it, and the kernel rebinds the selected processes'
sockets to the tunnel IP — only those processes traverse the VPN.

### 5.5 The routing trick — `doApplyInverseRoutes`

For "only my game uses the VPN" mode, the driver isn't enough: OpenVPN pushes
`redirect-gateway` (`0.0.0.0/0`) and wants everything. So the client reads the real
default gateway and runs **`route.exe`** to add four routes back to the **physical**
gateway:

```
0.0.0.0/2     ->  real gateway
64.0.0.0/2    ->  real gateway
128.0.0.0/2   ->  real gateway
192.0.0.0/2   ->  real gateway
```

Four `/2`s blanket the entire IPv4 space **more specifically** than `0.0.0.0/0`, so
ordinary traffic stays on the real link and the driver alone pulls the selected
games into the tunnel. Longest‑prefix‑match as a policy engine. It works; it's also
"winning an argument by being one bit louder."

### 5.6 The three modes

| UI mode (fa) | Meaning | Mechanism |
|---|---|---|
| معمولی (normal) | whole device via VPN | no split; OpenVPN's default route carries everything |
| معکوس (inverse) | only selected apps via VPN | driver redirects selected exes **in** + the four `/2` routes keep the rest direct |
| جداساز (separator) | selected apps excluded | driver splits selected exes **out**; default route goes through the VPN |

Teardown is the mirror image: `SplitTun_SplitStop` → `SplitTun_StopAndClean` →
`SplitTun_Disconnect`, and the `/2` routes get removed.

---

## 6. The "repair" toolbox one click, no auth, full system

The Settings page has a troubleshooting panel. Every button is an unauthenticated
RPC into the elevated core, and each one is a real OS mutation. Reconstructed from
the argv handed to the `shell.Exec` helper (and the registry / service‑manager
calls):

| RPC | What runs |
|---|---|
| `RunNetworkReset` | `netsh winsock reset` **and** `netsh int ip reset` (argv `["winsock","reset"]`, `["int","ip","reset"]`) |
| `FlushDns` | `ipconfig /flushdns` (argv `["/flushdns"]`) |
| `RepairWANMiniport` | `RasHangUp` every active L2TP/PPTP handle, then `powershell -ExecutionPolicy Bypass -File …\bin\wanminiport-repair.ps1` |
| `EnableRASServices` | Service Manager: set start type + start **RasMan** ("Remote Access Connection Manager") |
| `DisableSystemProxy` | registry: `HKCU\…\Internet Settings` → `ProxyEnable=0`, `ProxyServer=""` |
| `DisableConnectionProxy` | registry: clears the per‑connection `DefaultConnectionSettings` |
| `RepairOpenVPNInterface` / `RepairL2TPInterface` / `RepairPPTPInterface` | reset the respective adapter / RAS miniport |

`netsh int ip reset` and a WAN‑miniport reinstall need a reboot and can wipe a
machine's network config. They're reachable, with no authentication, from any local
caller that can open a TCP socket to `127.0.0.1:18458`.

---

## 7. `GetGeoInfo` phones a friend (or three)

`GetGeoInfo` doesn't ask the eliteping backend where you are. It opens HTTP requests
**bound to the Elite adapter** to third‑party services — `api64.ipify.org` to get
the public IP, then a geolocation lookup (`api.seeip.org`, among others) — and JSON‑
decodes the result. So "your location" is computed by leaking your post‑connect IP
to a couple of free SaaS endpoints the user never agreed to. Minor, but telling:
even the geolocation is outsourced.

---

## 8. Result — you already have the client

Part 1 ended with a from‑scratch client because the protocol was the only thing
worth stealing. ElitePing is funnier: you don't rebuild anything, because **the
privileged engine is sitting on a known port with no lock on it.**

- The account side is `GET` requests with the password in the URL and a key that
  ships in the asar (§1–2).
- The system side is `grpc.VpnService` on `127.0.0.1:18458`, plaintext, no auth.
  `grpcurl -plaintext 127.0.0.1:18458 list`, feed it the proto from §3.1, and you
  can stand up a tunnel, rewrite the proxy, or `netsh int ip reset` the box — as a
  *non‑elevated* caller, because the DLL is the one holding the privileges.

There is no certificate to patch (Part 1), no XOR key to undo. The door was already
open. The only "security" here is that the port is on loopback and nobody looked.

---

## Toolbox

- **IDA Pro + Hex‑Rays** — the heavy lifting on `elitecore.dll`.
- **[GoReSym](https://github.com/mandiant/GoReSym)** — restores Go function names
  from `pclntab` so a stripped Go `c-shared` DLL stops being 21k `sub_…` and starts
  being source. Mandatory first step on any Go target.
- **`asar extract`** — the Electron half is right there; no MITM required.
- **`grpcurl`** — talk to the core directly once you have the proto.
- A reconstructed `vpn.proto` (§3.1) — the whole privileged API in one file.

---

## Assets

[Download the proto file](/assets/files/eliteping.proto)

Part 3 will torture something else.

*— b00tkitism*
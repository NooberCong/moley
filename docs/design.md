# Moley — Design

Status: phases 1 and 2 implemented (2026-11-26); see §17 and §18 for where the code settled details. Supersedes the extension-only draft.

Moley is a desktop VPN router. You import connections from any provider in any common
format, then route traffic with ordered rules: by domain, IP, app, or (in the browser) by
tab and site. One engine handles both system-wide (TUN) traffic and browser traffic, and
a browser extension acts as the per-site remote control.

## 1. Goals and non-goals

**Goals**
- Run many exits at once from different providers and formats, and route between them per
  connection.
- Fast and light: one process on the data path, in-process control, and no polling.
- Per-domain routing in the browser that works without TUN and without admin rights.
- Fail closed: a rule that says "via JP" never silently goes direct.
- Windows and Linux, each with a tray UI and a full CLI that scripts and AI agents can
  drive. macOS later, on the same code.

**Non-goals (v1)**
- Writing our own protocol implementations. The core does the protocols, and Moley does
  the model, compile, control and UX.
- Mobile. The core is portable there later (libbox), but it is out of scope now.
- Safari, which has no proxy API for extensions.
- Multiple cores (mihomo or xray side by side).

## 2. Key decisions

| Decision | Choice | Why |
|---|---|---|
| Proxy core | **sing-box 1.14.x**, embedded as a Go library and pinned to an exact version | Covers every format we need: WireGuard, **OpenVPN (native since 1.14)**, SS, VLESS/Reality, Trojan, Hysteria2, TUIC, SOCKS/HTTP. It has userspace endpoints (no adapters, no admin), local rule-sets that hot-reload, process rules, FakeIP and TUN. mihomo is the runner-up: it has AmneziaWG and a real fallback group, but its TUN and endpoint model is weaker. Rust cores (clash-rs, leaf, shoes) aren't complete enough for Windows. |
| OpenVPN | sing-box `openvpn-client` endpoint, `system: false` | Runs in userspace inside the core, needs no adapter or route-table changes, and several sessions can run at once. This replaces the old plan of one Docker container per profile. |
| Process model | **One Go daemon** (`moley`) that owns the core, plus a thin UI | No sidecar, no REST hop, and no app/core version skew. Most bugs in other clients sit in that seam. |
| Daemon ↔ clients | Length-prefixed JSON-RPC over a named pipe (Windows) or Unix socket | Other processes and web pages can't reach it, unlike localhost HTTP. The framing matches native messaging exactly, so the extension host is a literal byte relay (§6). |
| UI | **Wails v3** tray app on Windows and Linux, unprivileged | Same language as the daemon, so it shares types. It has an updater and signing built in. v3 is young, so pin it and keep the UI thin enough to replace. |
| CLI | **The CLI is a full peer of the UI**, built for scripts and AI agents | The UI and the CLI call the same RPC methods, so anything the UI can do, the CLI can do. Every command has `--json` output and never prompts (§7). |
| Browser ↔ engine | The extension points the browser at the daemon's local SOCKS inbound. **The daemon makes every routing decision.** | One rule brain. No PAC generator, and no copy of rule matching in JS. |
| License | GPL-3.0 | sing-box is GPL-3.0-or-later. Its extra term means we can't use the "sing-box" name or imply association with it. |

## 3. Architecture

```
                         ┌──────────────────── moley (daemon, Go) ─────────────────────┐
 Moley UI (Wails, tray)  │  rpc ── model ── compile ──► sing-box instance (in-process)│
   │ JSON-RPC            │   │       │                    inbounds:                    │
   ├──── named pipe ─────┤   │    moley.json              tun          (system mode)  │
 moley nmh (relay)       │   │                            mixed :P     (browser, CLI) │
   │ stdin/stdout        │   ├─ health checker ──►       endpoints/outbounds:          │
 Browser extension       │   │  (switches selectors)      wg-*, ovpn-*, ss-*, …        │
   │ proxy → 127.0.0.1:P ┼───┼──────────────────────►    selectors (groups), direct   │
   └─────────────────────┘   └─ kill switch (WFP)         rule-sets: geo *.srs, user   │
                         └──────────────────────────────────────────────────────────────┘
```

**Binaries**
- `moley.exe` (Go) is one binary with subcommands:
  - `moley service`: the daemon.
  - `moley nmh`: the native messaging relay.
  - `moley <cli>`: status, import, rules and so on.
- `moley-ui(.exe)` (Wails) is the tray and window app for Windows and Linux. (Not
  `Moley.exe`: Windows file names ignore case, so it would overwrite `moley.exe`.)
  When its window is closed it holds no WebView, only the tray icon.
  - On Linux the window uses WebKitGTK and the tray uses StatusNotifierItem. Stock GNOME
    needs the AppIndicator extension for the tray; without it the app falls back to a
    plain window plus the CLI.
  - The tray is optional. The daemon never depends on the UI running, so a headless box
    or an agent-only setup is just the daemon plus the CLI.

**Privileges**
- **Proxy-only mode** (browser routing, no TUN) needs no admin. The daemon can run as a
  per-user process. This is phase 1: the pipe admits only the user and SYSTEM, and
  clients check the pipe's server runs as one of those before sending anything.
- **The local proxy ports have no auth** (Chromium can't send SOCKS credentials), so
  another local user could use the daemon's exits. The pipe, and so all control, stays
  per-user.
- **System mode** (TUN plus kill switch) runs the daemon as a Windows service under
  LocalSystem, with SCM restart-on-failure. The pipe ACL allows SYSTEM, Administrators
  and the installing user's SID.

## 4. Data model

The user's state is one file, `moley.json` (in `%ProgramData%\Moley` for the service, or
`%LocalAppData%` per user), written atomically. Secrets in it (keys, passwords) are
encrypted with DPAPI on Windows. (Phase 1 on Unix: a 0600 file; keychain/libsecret
sealing later.)

```jsonc
{
  "profiles": [                       // one imported connection = one sing-box outbound/endpoint
    { "id": "proton-jp-3", "kind": "wireguard", "source": "file:proton-jp-3.conf", "config": { … } },
    { "id": "sq1",         "kind": "openvpn",   "source": "file:work.ovpn",        "config": { … },
      "auto_rule": true },            // routes + DNS the server pushes become a rule to this profile (§5)
    { "id": "hk-reality",  "kind": "vless",     "source": "sub:mysub",             "config": { … },
      "via": "proton-jp-3" }          // optional chain: dial this profile through another (sing-box `detour`)
  ],
  "subscriptions": [ { "id": "mysub", "url": "https://…", "refresh": "12h" } ],

  "exits": [                          // groups; every profile is also an exit under its own id
    { "id": "asia",   "group": "fallback", "members": ["proton-jp-3", "hk-reality"] },  // first healthy, in order (phase 3)
    { "id": "fast",   "group": "fastest",  "members": ["…"] },                          // sing-box urltest
    { "id": "pick",   "group": "manual",   "members": ["…"] }                           // sing-box selector
  ],                                  // built-ins: "direct", "block"

  "rules": [                          // ordered; first match wins
    { "id": "r1", "exit": "proton-jp-3", "match": { "domain_suffix": ["netflix.com"], "rule_set": ["geosite-netflix"] } },
    { "id": "r2", "exit": "direct", "match": { "domain_suffix": ["vcb.com.vn"], "ip_cidr": ["192.168.0.0/16"] } },
    { "id": "r3", "exit": "asia",   "match": { "process_name": ["Telegram.exe"] } },
    { "id": "r4", "exit": "proton-jp-3", "match": { "site": ["crunchyroll.com"] }, "scope": "browser" }
  ],
  "quick": { "crunchyroll.com": "proton-jp-3" },  // one-click picks: host and subdomains → exit
  "default_exit": "direct",

  "settings": { "proxy_port": 7890 },                              // hint inbound is proxy_port+1
  "mode": { "tun": false, "kill_switch": "off" }   // off | on | persistent; needs the service
}
```

**Rule matchers**
- These compile straight to sing-box: `domain`, `domain_suffix`, `domain_keyword`,
  `domain_regex`, `ip_cidr`, `rule_set` (remote `.srs`, e.g. geosite or geoip lists),
  `process_name`, `process_path`, `port`. Fields within one match are OR-ed.
- `scope: browser | system | any` limits a rule to one inbound.
- `site` (the top-level site of the tab) is browser-only. See §8.

**There is no per-rule "if down, go direct" flag.** By default an exit that is down fails
closed. If you want a fallback, you say so explicitly with a group: `{"group": "fallback",
"members": ["jp", "direct"]}`. That leaves one concept instead of two.

## 5. Engine: compile, reload, health

**Compile.** `internal/compile` is a pure function from the Moley model to sing-box
options. It is the only code that imports sing-box option types, so a sing-box version
bump touches one package, and golden tests guard it.
- Each profile becomes an outbound or endpoint (WireGuard and OpenVPN are endpoints with
  `system: false`).
- Each exit becomes either a direct reference to its profile or a `selector`/`urltest`.
- Each rule becomes a route rule whose action is `route` to the exit's tag.

**DNS.** Names should resolve where the traffic exits, so you get no leaks and
region-correct CDNs.
- *Browser path:* the browser sends the hostname to SOCKS, and we pass it through
  unresolved. Proxy protocols resolve it on the server. WireGuard and OpenVPN endpoints
  resolve it through the tunnel's own DNS (from the `.conf`, or pushed by the OpenVPN
  server) via `domain_resolver`.
- *TUN path:* `dns_mode: hijack`. A/AAAA queries get **FakeIP** answers, except domains
  routed direct and a small exclude list (LAN, NTP, STUN, captive portals), which go to
  the system resolver. The real name is then recovered at connect time, so routing works
  the same as the browser path. Optimistic cache is on.

**Reload without dropping connections.** A full sing-box rebuild drops every connection,
so we keep rebuilds off the hot path.
- **Each rule's domain and IP lists are written to a local rule-set file**
  (`rules/<id>.json`), and the route rule references it. sing-box watches local rule-set
  files, so adding or removing domains in an existing rule is a file write with no
  restart.
- **Quick picks**, the most frequent action ("route this site via X" from the
  extension), are a pre-created rule per exit, ordered first, each with its own rule-set
  file. Quick picks never trigger a rebuild.
- **Switching a group** (manual pick, or a fallback failing over) is an in-process
  `selector.SelectOutbound` call, which also doesn't rebuild.
- **Structural edits** do rebuild: adding or removing a profile, exit or rule, reordering,
  or toggling TUN. The daemon validates the new options first and keeps the old instance
  if they're invalid. It then stops the old instance and starts the new one, which takes
  ~100 ms. In system mode the WFP filters stay in place across the gap, so nothing leaks.
- Applies are serialized. Whether an edit is hot or structural isn't classified by hand:
  the engine compares the compiled sing-box config, and rebuilds only if it changed.

**Server-pushed routes and DNS (corporate VPNs).** A work VPN usually tells the client
what belongs to it: internal IP ranges (`route`), a DNS server (`dhcp-option DNS`) and
internal domains (`dhcp-option DOMAIN` / `DOMAIN-SEARCH`). It often also pushes
`redirect-gateway`, meaning "send everything here".

Moley ignores `redirect-gateway`, because rules decide what uses the tunnel. For a
profile with `auto_rule: true` (the importer turns it on for OpenVPN profiles), it uses
the rest:
- **Live match:** sing-box 1.14's `preferred_by` route rule matches whatever the
  endpoint's current push claims (routes, DNS domains, search domains). The rule is
  pinned right after quick picks and routes to the profile. A reconnect or a changed push
  takes effect with no rebuild.
- **Learned list, for failing closed:** the push is only visible while the tunnel is up.
  So each host the live rule matches is remembered (the shortest pushed suffix, or the
  IP) in the rule-set file `rules/auto-<profile>.json`, matched right after the live
  rule. When the tunnel is down, those hosts still route to the profile and fail instead
  of going direct.
- **DNS:** a DNS rule sends queries for pushed domains to the pushed resolver through the
  tunnel (sing-box's `openvpn` DNS server type, which follows the endpoint). Everything
  else keeps its normal DNS path, so internal names resolve and nothing else leaks to the
  work resolver.
- **Full tunnel is still one setting:** set `default_exit` to the profile and everything
  goes through it, as with `redirect-gateway`.
- **The auto rule is visible but read-only.** `moley rules show auto-sq1` shows whether
  it is live, the pushed resolver and what it has learned. sing-box doesn't expose the
  pushed route list itself. Add your own rule above it to override any part.
- **Known limit:** an internal host whose name isn't under a pushed domain, and that only
  resolves on the internal DNS, needs a manual domain rule. Matching it by IP would mean
  resolving every name locally first, which leaks.
- `redirect-gateway` is dropped with a `pull_filters` ignore entry the importer adds, so
  the live rule never claims 0.0.0.0/1 and 128.0.0.0/1.

**Health and fallback.** sing-box has no ordered fallback group, so the daemon provides
one, which is about 100 lines.
- A `fallback` exit compiles to a `selector`.
- The checker probes the members **only while an exit is in use** (it has had
  connections in the last 5 min). It sends an HTTP 204 probe through each member every
  60 s, then retries quickly after a failure.
- It selects the first healthy member in list order, and fails back once the preferred
  member has been healthy for 2 checks in a row.
- `fastest` uses sing-box's own `urltest`.
- The same probe powers `profiles.test`, which reports latency and exit IP/country.

**Observability.** The daemon reads sing-box's connection tracker in process. It exposes
live connections (host, inbound, matched rule, exit chain, bytes) and per-exit throughput.
It streams these only while a client is subscribed, so an idle daemon does no
stats work.

## 6. Control plane

There is one RPC surface, used by the UI, the CLI and the extension. Messages are JSON
objects with a 4-byte little-endian length prefix, over `\\.\pipe\moley` or
`$XDG_RUNTIME_DIR/moley.sock`.

| Area | Methods |
|---|---|
| State | `status`, `events.subscribe` (pushes state, health and conns while subscribed) |
| Profiles | `profiles.import` (file, text, link or subscription URL), `profiles.list`, `profiles.update {id, name?, auto_rule?}`, `profiles.remove`, `profiles.test` |
| Routing | `exits.put/remove/select`, `rules.list/put/remove/reorder`, `quick.set {host, exit\|null}` |
| Mode | `mode.set {browser, tun, kill_switch}` |
| Config | `config.export`, `config.apply {doc, dry_run}` → diff, `history.list` (audit log) |
| Diagnose | `probe {url, exit?}` → rule, exit, exit IP, resolver, latency; `logs {since, level}` |
| Clients | `client.hello` → `{proxy_port, hint_port, secret, exits}`, `conns.list {host?}` (what a host is actually using) |

**Audit log.** Every mutating call is recorded with the time, the method, a diff summary
and the caller. The caller is found from the pipe peer: `GetNamedPipeClientProcessId` on
Windows, `SO_PEERCRED` on Linux, and is recorded as parent → process, e.g.
`claude.exe → moley.exe` for an agent's CLI call or `chrome.exe → moley.exe` for the
extension (shell wrappers like `cmd.exe` are skipped). When an agent changes routing, you can see what changed and who
did it.

**Native messaging.** Chrome's native messaging framing is also a 4-byte length plus
JSON, so the native host (`moley.exe` started with the extension's origin as its first
argument) forwards frames unchanged in both directions. It checks the origin, and lets
the browser call only `client.hello` (without the hint secret), `status`, `exits.list`,
`rules.list`, `quick.set` and `conns.list` for one host.
- `moley browser install` registers the host manifest for the user under
  `HKCU\Software\Google\Chrome\…`, `…\Microsoft\Edge\…`, `…\BraveSoftware\…` and
  `…\Chromium\…`. `allowed_origins` lists every extension ID.
- `connectNative` also keeps the MV3 service worker alive while connected.

## 7. CLI and agents

The CLI is a first-class client, built so a script or an AI agent can run Moley end to
end with no UI. This covers two things: **controlling** Moley, and **routing** the
traffic of command-line programs.

### 7.1 Controlling Moley

- **Same power as the UI.** Each CLI command is a thin wrapper over one RPC method, and
  the UI uses the same methods, so the CLI can't fall behind. `moley rpc <method> '<json>'`
  is the escape hatch for anything that doesn't have a command yet.
- **Machine-readable.**
  - Every command takes `--json`, and `MOLEY_OUTPUT=json` sets it globally.
  - JSON output has a stable, versioned schema (`"v": 1`). Errors are JSON on stderr:
    `{"error": {"code": "exit_unhealthy", "message": "…", "hint": "…"}}`.
  - Event streams (`moley events`, `moley logs --follow`) are NDJSON, one object per line.
- **Never interactive.** No prompts, pagers or spinners, ever.
  - Destructive commands (`remove`, `apply` that deletes, `mode --kill-switch
    persistent`) need `--yes`. Without it they exit 2 and say what would happen.
  - Secrets are never printed unless you pass `--reveal`.
- **Exit codes:**

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | Error |
| 2 | Usage, or confirmation needed |
| 3 | Daemon unreachable |
| 4 | Check failed (unhealthy, timed out, probe mismatch) |

- **Agent-friendly verbs.** These answer "did it work?" directly, so agents don't have to
  parse status or retry on their own.
  - `moley probe <url> [--exit X] [--expect-exit X]` makes a real request through the
    engine. It reports the matched rule, the exit used, the exit IP and country, which
    resolver answered, and latency. With `--expect-exit` it fails with code 4 on a
    mismatch, which makes it the routing assertion for tests. Because it goes through the
    real engine and connection tracker, it is never a prediction.
  - `moley wait --healthy <exit> | --connected <profile> [--timeout 30s]` blocks until the
    condition holds.
  - `moley apply -f moley.json [--dry-run]` is declarative and idempotent: it prints the
    diff, then applies it in one rebuild. `moley export` is the inverse. An agent can
    keep Moley's config in a repo and converge on it.
  - `moley quick <host> <exit|none>` is the extension's one-click pick, from the shell.
- **Self-describing.**
  - `moley help --json` dumps every command, flag and RPC schema, so an agent can learn
    the CLI in one call.
  - Text `--help` stays short, with examples.
- **Access.** Anything running as the same user can reach the pipe, which is the same
  trust boundary as the UI. There is no separate token. The audit log (§6) shows what an
  agent changed, and `config.apply --dry-run` lets it ask before it acts.

```console
$ moley import work.ovpn --id sq1 --json
{"v":1,"profile":{"id":"sq1","kind":"openvpn","auto_rule":true},"warnings":[]}
$ moley wait --connected sq1 --timeout 20s && moley probe https://wiki.internal.example --expect-exit sq1 --json
{"v":1,"rule":"auto-sq1","exit":"sq1","resolver":"pushed:sq1","ms":41}
```

### 7.2 Routing command-line programs

CLI programs (curl, git, package managers, an agent's own HTTP calls) are routed by one
of three mechanisms:

1. **Same rules, nothing to do.** In system mode (TUN), all their traffic follows the
   normal rules. `process_name` / `process_path` rules can single out one program, e.g.
   `node.exe` via `jp`.
2. **Per command, no admin:** `moley exec --exit jp -- <cmd …>` runs a command with
   `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` (`socks5h://`) pointed at the daemon's
   local **mixed (SOCKS + HTTP) inbound**. With `--exit` they point at the hint inbound
   and the proxy username names the exit (the `auth_user` mechanism the Firefox build
   uses, §8). Without `--exit` the normal rules apply.
   - This works in proxy-only mode, for any tool that respects proxy env vars.
   - It's the quickest way for an agent to run one request through one exit.
3. **Shell session:** `moley env --exit jp` prints the same variables in shell syntax
   (`--shell pwsh|bash|cmd`), so you can set them for a whole terminal session.

Tools that ignore proxy env vars need system mode (1).

## 8. Browser extension

The extension has one TypeScript codebase with two builds (Chromium and Firefox). It
holds no rules of its own: it is a proxy switch and a remote control.

**Shared**
- On connect it calls `client.hello` and points the browser at `socks5 127.0.0.1:P` (the mixed inbound). It
  sets `webRTCIPHandlingPolicy = disable_non_proxied_udp`, so UDP can't bypass the proxy.
- **Popup:**
  - The current site and the exit its connections are actually using (from
    `conns.list`: live data, not a prediction).
  - A one-click "route this site via…" control (`quick.set`).
  - Exit health.
- **Fail closed:** if the daemon goes away, the proxy setting stays. Requests fail, and
  the popup shows "Moley isn't running" with a "Turn off for this browser" button. The
  service auto-restarts, so this is rare.
- It watches `levelOfControl` and warns when another proxy extension or a policy takes
  over.

**Chromium (Chrome, Edge, Brave)**
- Uses `chrome.proxy` with `fixed_servers` pointing at the daemon, and bypasses nothing.
  Every routing decision, including "direct", happens in the daemon by hostname.
- Chromium can't make per-request decisions, so `site` rules are approximated by
  **companion learning** (opt-in). The extension watches `webRequest` (non-blocking) on
  tabs whose top-level site has a `site` rule. It then adds the third-party hosts it sees
  to that rule's rule-set file via RPC, which hot-reloads the rule.
  - The first load of a new CDN host can go out the wrong way, which the UI says plainly.
  - Seed lists (geosite rule-sets) cover the big sites from the start.
- Trade-off: Chromium turns off HTTP/3 for proxied requests, which is all requests here.
  We accept this to keep one rule brain.

**Firefox**
- Uses `proxy.onRequest`, answering synchronously from an in-memory map. It knows
  `tabId`, `documentUrl` and `cookieStoreId`, so it gives **true per-tab, per-container
  routing**: everything a tab on `crunchyroll.com` loads goes via its exit, and you can
  assign a container to an exit.
- It sends the routing hint as the proxy username on the daemon's **hint inbound**
  (port P+1): username = exit id, password = per-install secret from `client.hello`. The
  daemon matches it with sing-box `auth_user` rules, which sit above all other rules.
  It's a second inbound because sing-box can't make auth optional on one port, and
  Chromium can't send SOCKS credentials. (No `exit:` prefix: HTTP Basic auth can't carry
  a `:` in the username.)
- It returns `proxyDNS: true` and ends the proxy list with `null`, so it never falls back
  to direct.

## 9. Importers

`internal/importer` turns any input into Moley profiles. It owns its own parsers, because
the existing Go converters are partial and CLI-first.

| Input | Notes |
|---|---|
| WireGuard `.conf` | Maps directly onto the endpoint |
| OpenVPN `.ovpn` | Maps directives to `openvpn-client`, with inline `<ca>`/`<cert>`/`<key>`/`<tls-crypt>`. Unknown directives are reported, not silently dropped. Redirect-gateway is ignored, because Moley does the routing. |
| Share links | `ss://`, `vless://`, `vmess://`, `trojan://`, `hysteria2://`, `tuic://`, `socks://`, `http(s)://` |
| Subscriptions | base64 link lists, Clash/mihomo YAML (the `proxies:` section only), sing-box JSON (outbounds only). On refresh, profiles are diffed by stable ID so that exits and rules keep pointing at the right ones. |

Every parser has table tests plus Go fuzz tests, because the link formats are informal.

## 10. System mode and kill switch

**Windows**

- **TUN:** sing-box `tun` with `auto_route`, `strict_route`, `auto_detect_interface` and
  the default stack (stock `mixed` on 1.14, then sing-box's own stack once 1.15 is pinned).
- **Kill switch:** `strict_route` only blocks off-tunnel DNS, so the daemon adds its own
  **WFP** filters, ported from wireguard-windows `tunnel/firewall`. They permit the TUN
  adapter, the daemon process (whose sockets carry the tunnels), loopback, DHCP and
  optionally the LAN, and block everything else.
  - `on` uses a dynamic WFP session, so the filters disappear if the daemon dies.
  - `persistent` keeps blocking until Moley reconnects, including across reboots.

**Linux**
- The daemon is a systemd unit running as a dedicated user with
  `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE`. Its socket is
  `/run/moley/moley.sock`, group `moley`. Proxy-only mode can also run as a systemd
  `--user` unit with no capabilities.
- TUN uses the same sing-box `auto_route` and `strict_route` (policy routing via
  nftables). The kill switch is one nftables table owned by the daemon, with the same
  permit list as on Windows. `on` deletes the table when the daemon exits; `persistent`
  is a boot-time unit that loads a block-all table.

## 11. Performance

- **No extra hops:** the core is in-process and controlled by direct calls. There is no
  REST polling and no sidecar process.
- **Userspace WireGuard and OpenVPN:** no adapters to create or route around. sing-box
  1.14 forwards TUN to WireGuard at L3, without converting to streams and back. If one
  exit ever needs maximum throughput, WireGuard `system: true` is available per profile.
- **Browser path:** the hostname arrives in the SOCKS request, so there is no local DNS
  lookup and no sniffing delay. Loopback overhead for direct sites is negligible.
- **Rule matching:** binary `.srs` rule-sets, and only referenced ones are loaded. Remote
  rule-sets are cached in sing-box's `cache_file`, so there are no downloads at startup.
- **Idle cost:** health checks only run for exits in use. Stats stream only to
  subscribers. The UI frees its WebView when the window closes.
- **Budgets, checked in CI on a reference box:**
  - daemon idle RSS < 60 MB with 10 profiles and 5 geosite sets;
  - < 1 ms added latency on the browser path;
  - ≥ 80 % of the raw link speed through a single WireGuard exit;
  - structural rebuild < 200 ms.

## 12. Code layout

```
cmd/moley/            daemon, nmh relay, CLI (one binary)
internal/cli/         commands as thin RPC wrappers, --json/exit codes, exec/env
cmd/moley-ui/         Wails v3 tray app
internal/model/       config types, validation, atomic store, secret sealing
internal/importer/    wg, ovpn, links, clash, singbox-json → model.Profile
internal/compile/     model → sing-box options (the only sing-box option import)
internal/engine/      box lifecycle, rebuild, rule-set file writer, selectors, health, conns
internal/rpc/         framing, methods, event fan-out
internal/platform/    service install, pipe ACL, WFP, NMH registration (per-OS files)
extension/            TS; build targets chromium/ and firefox/
```

## 13. Phases

1. **Browser and CLI routing, no admin.**
   - Daemon as a user process.
   - WireGuard, OpenVPN (with `auto_rule`) and link importers; exits and rules.
   - The local mixed (SOCKS + HTTP) inbound and quick picks.
   - **The full agent-ready CLI** (§7: `--json`, `probe`, `wait`, `apply`, `exec`/`env`)
     and the audit log.
   - The Chromium extension.
   - No TUN and no UI app yet. Passes the acceptance test below.
2. **System mode on Windows and Linux.**
   - Windows service and systemd unit, TUN with FakeIP DNS, and the kill switch (WFP or
     nftables).
   - The Wails tray UI on both platforms, with installer and updater (NSIS on Windows;
     `.deb`/`.rpm` and AppImage on Linux).
3. **Flexibility.** Subscriptions, fallback groups with the health checker, chains,
   the Firefox build with per-tab and container routing, and companion learning on
   Chromium.
4. **macOS.** An `SMAppService` daemon first, then a Network Extension.

**Phase 1 acceptance test (real work VPN).** It uses the existing OpenVPN Connect
profile: a cert plus tls-crypt profile from an OpenVPN Access Server that pushes
`redirect-gateway def1`. Disconnect OpenVPN Connect first, because two full tunnels
fight over routes. Then run the steps below, all from the CLI so an agent can run them.
1. `moley import work.ovpn --id sq1 --json` gives no warnings and sets `auto_rule: true`.
2. `moley wait --connected sq1 --timeout 30s` exits 0.
3. `moley rules show auto-sq1 --json` lists the pushed internal ranges and domains, and
   the pushed DNS server shows as the resolver for those domains.
4. `moley probe https://<intranet-host> --expect-exit sq1` passes, and the resolver is
   `pushed:sq1`.
5. `moley probe https://ifconfig.co --expect-exit direct` passes, and the exit IP is the
   home IP. This shows it is a split tunnel, not a full tunnel.
6. `moley exec --exit sq1 -- curl -s https://ifconfig.co` prints the office exit IP.
7. In Chrome with the extension, an intranet site loads, and the popup shows `sq1` as the
   exit actually used.
8. Fail closed: block the VPN server (e.g. a firewall rule on its IP). Step 4 now fails
   with exit code 4, intranet hosts don't go out direct, and the
   non-intranet probe (step 5) is unaffected.
9. Reconnect: `auto-sq1` is refreshed without a rebuild (open connections in other exits
   survive), and the audit log shows each change with its caller.

## 14. Testing

- **Golden tests** for `compile`: model fixtures compiled to sing-box JSON, which must
  pass `box.New` checks.
- **Importer fuzzing,** plus a corpus of real configs from Proton, Mullvad, VPNGate,
  Surfshark and others, with secrets stripped.
- **Integration:** local WireGuard, OpenVPN and SS servers in containers. Assert the exit
  IP per rule, that a downed exit fails closed, that fallback fails over, and that a
  quick-pick edit doesn't drop open connections.
- **CLI contract tests:** golden `--json` output per command, exit codes, no prompts
  when stdin isn't a TTY, and `help --json` matching the RPC table.
- **Leak suite** (manual, then scripted): DNS, WebRTC and IPv6 leak checks per mode,
  plus a kill switch test that kills the daemon mid-download.

## 15. Risks

| Risk | Mitigation |
|---|---|
| sing-box internal APIs change between versions | Pin the exact version. Only `compile` and `engine` touch it. Bump deliberately, with golden tests. |
| The OpenVPN endpoint is new (Aug 2026) | Test interop against the corpus early in phase 1. Escape hatch: stock OpenVPN 2.7 plus `bind_interface`, which needs a high-metric default route on the adapter. |
| No AmneziaWG upstream | Moley registers its own `amneziawg` outbound (amneziawg-go + gVisor netstack, AWG 2.0) in the core's registry: no fork. It can't be chained with `via` yet, and peer hostnames resolve once, at start. |
| Wails v3 is only weeks old | Pin it. The UI is a thin RPC client, so it can be swapped. |
| Chromium can't route per tab | Daemon-side hostname rules, plus companion learning and seed lists. True per-tab routing is advertised as Firefox-only. |
| Agents change routing in ways you don't expect | `apply --dry-run` diffs; destructive commands need `--yes`; every change is in the audit log with its caller. |
| Linux tray support varies by desktop | The tray is optional. GNOME without AppIndicator gets a normal window plus the CLI. |
| Rebuilds drop connections | Hot paths (domain edits, quick picks, group switches) never rebuild. |

## 16. Open questions

1. Should the Firefox build ship in phase 1? It is the only browser that can do true
   per-tab routing. (GPL-3.0 is accepted; AmneziaWG is in v1.)

## 17. Implementation notes (phase 1)

Where the code settled details the design left open, or changed them:

- **Toolchain:** Go is pinned to 1.27.4 in `go.mod`. Go 1.26.0 fails every WireGuard
  send on Windows (`WSASendMsg` with an empty control buffer returns WSAEFAULT).
- **Build tags:** `with_gvisor,with_quic,with_wireguard,with_openvpn,with_utls`
  (see the Makefile).
- **Encrypted client keys** (`ENCRYPTED PRIVATE KEY`, legacy `Proc-Type: 4,ENCRYPTED`)
  are decrypted at import (`moley import --key-password-stdin`); only the decrypted key
  is stored, sealed with DPAPI. sing-box has no key-password option.
- **Every profile is an exit** under its own id; explicit exits are only groups
  (`manual`, `fastest`). `fallback` groups and the health checker remain phase 3.
- **Each rule is one rule-set file** holding its whole match (domains, IPs, process,
  port), so any match edit is hot; adding, removing, reordering or retargeting a rule
  rebuilds.
- **Probe** goes through the local SOCKS5 inbound (like the browser), so a failing exit
  is a connect error rather than a proxy 502 page, then reads the result from the
  connection tracker.
- **Connection history:** sing-box drops its closed-connection list on every GC, so the
  engine keeps its own last 512 closed connections for `conns` and the popup.
- **Not yet:** `site` and
  `scope` rule fields (Firefox and TUN); Clash/sing-box subscriptions (phase 3).
- **Testing:** `internal/teststack` runs real OpenVPN (pushing a route, DNS, a search
  domain and `redirect-gateway`), WireGuard, AmneziaWG 2.0 and Shadowsocks servers on
  loopback. Each exits from its own 127.0.0.x source address, so tests assert by the exit
  IP the echo server sees.

## 18. Implementation notes (phase 2)

- **Service.** `moley service install` registers `moley service --system --allow <SID>`
  (Windows: LocalSystem, automatic, restart on failure, an unrestricted service SID that
  the WFP filters match; the allowed user may start and stop it) or the systemd units
  (`internal/platform/systemd/`, user `moley` with ambient `CAP_NET_ADMIN` and friends,
  socket `/run/moley/moley.sock` for the `moley` group). It stops a per-user daemon and
  moves its config over, resealing secrets with machine DPAPI in `%ProgramData%\Moley`
  (SYSTEM and Administrators only). Clients verify the pipe by its owner (this user,
  SYSTEM or Administrators): a user can't open a SYSTEM process's token.
- **System mode** (`mode.set {tun}`) adds a `tun` inbound (`moley`, `auto_route`,
  `strict_route`), a sniff and a `hijack-dns` rule first, and FakeIP for A/AAAA except
  local names and names routed direct (198.18.0.0/15 and 2001:2::/48, both public space so
  the LAN rule never claims a placeholder). `find_process` is on when a rule names
  programs. A per-user daemon refuses system mode with `needs_service`.
- **LAN rule.** Private destinations go direct unless an earlier rule claims them
  (`lan`, just before the default). It holds in proxy-only mode too.
- **Kill switch.** Windows: wireguard-windows' WFP filters (vendored in
  `internal/platform/wfp`) plus a LAN permit, and a persistent layer with fixed keys that
  survives the daemon and reboots; when Moley runs, its dynamic permits go into that
  layer's sublayer. A new session is installed before the old one closes, and the filters
  are reapplied after every rebuild (the adapter is recreated). Linux: one nftables table
  (`inet moley`), output only, permitting loopback, the LAN, DHCP, NDP, the TUN interface
  and the daemon's uid; `persistent` leaves the block in place on exit and
  `moley-killswitch.service` restores it at boot. Lifting goes before the engine change,
  setting after, with rollback on failure.
- **Events.** `events.subscribe` streams `status` and `traffic` (and `conns` when asked)
  when they change, checked each second and right after a config change; nothing is
  computed without a subscriber. Event frames carry the request's id. `moley events`.
- **Tray app** (`cmd/moley-ui`, its own Go module so the daemon never links Wails): one
  bound service passes RPC calls through on short-lived connections, plus start daemon,
  install service (UAC or pkexec), start at login and updates. The window is destroyed on
  close. The tray icon is drawn at run time; its colour is the status (tunnel, direct,
  problem, not running).
- **Updates.** The Wails updater against a manifest (`cmd/moley-release`); every release
  is Ed25519-signed over its SHA-256 and the public key is built in. Windows runs the
  downloaded installer (`/S /launch`), which also updates the service; AppImages swap
  themselves; `.deb`/`.rpm` update through the package manager.
- **Testing.** `test/linux/run.sh` (36 checks: install, migration, TUN, FakeIP, the kill
  switch on and persistent, uninstall) and `test/linux/package.sh` (the .deb and the tray
  on a virtual display) run in a systemd container; `test/windows/system.ps1` checks TUN,
  FakeIP and the WFP kill switch elevated on Windows.

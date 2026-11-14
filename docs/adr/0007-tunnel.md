# ADR-0007: Tunnel role, quick share and tunnel-token mode

**Status:** Proposed
**Date:** 14 Nov 2026
**Deciders:** Owner

## Context

Phase 3 builds the tunnel role (plan section 9): cloudflared embedded in `soireehost.exe` and unpacked by setup, the hash check before every launch, quick share with its hostname check, tunnel-token mode, health and reconnect, the offline switch, and the firewall block rules. The requirements are S-02, S-03, S-04 (cloudflared part), S-06 (quick share), S-10 (R-06), S-21 (cloudflared part), S-23, S-40 (R-21), S-50 and S-51. ADR-0002 fixed the packaging and ADR-0006 the pipes, so this record covers what runs and how it is checked.

Four items from the Phase 1–2 review backlog (`docs/reviews/2026-11-12-skills-review.md`) land here:

- **SE-21.** One worker message type serves both workers, and `Validate` ignores the role.
- **GO-6.** The tunnel token is delivered from an unordered goroutine outside the change lock.
- **R-06.** S-10 must also refuse quick-share and cloudflared ports.
- **R-21.** No cloudflared text may carry the token into a failure reason or a log.

Owner decisions taken on 14 Nov 2026:

- **No domain.** Buying one is ruled out by the budget rule. Tunnel-token mode is built and tested against a stand-in for cloudflared, and the check "works with a tunnel token and a real hostname" is marked not yet verified in the release notes.
- **Installed-system checks run on a CI runner only.** Nothing elevated runs on the owner's PC. For the phone check, a manually started CI run keeps a quick share up for a few minutes and prints its link, and the owner opens it on a phone over mobile data.
- **No second machine for the port scan.** CI substitutes a full TCP connect scan of the runner's own non-loopback addresses together with a listener table of every SoiréeHost and cloudflared process. The true second-machine scan stays open for a release check.

Facts checked on 14 Nov 2026 against the cloudflared source at tag 2026.11.0 and the Cloudflare run-parameter documentation:

- **Newer release.** cloudflared 2026.11.0 (12 Nov 2026) supersedes the pinned 2026.10.7. It carries one security fix (VULN-170057, matrix parameters bypassing Access) and a Go bump. `cloudflared-windows-amd64.exe` has SHA-256 `d5c1d82031da6253dcdcff64c944cd0fe063016edeb2e4fd088075fc9bd52d0a` and is 55,397,592 bytes.
- **Metrics server.** It cannot be turned off: `CreateMetricsListener` either binds the given `--metrics` address or tries `localhost:20241-20245` and then a random port, and cloudflared exits if no bind succeeds. Its `/ready`, `/quicktunnel` and `/metrics` routes answer anyone who can reach that address. Since 2026.10.4 the debug routes are behind an allow list.
- **Management diagnostics.** `--management-diagnostics` defaults to true, which offers `/debug/pprof` and `/metrics` through Cloudflare's remote management service.
- **Logs.** `--output json` (2025.6.1 or later) writes one JSON object per log line to stderr.
  - A quick tunnel's address is printed as a table row: `"message": "|  https://NAME.trycloudflare.com  |"`.
  - Connections log `Registered tunnel connection` and `Unregistered tunnel connection`, each with `connIndex`.
  - A remotely managed tunnel logs every configuration it receives from Cloudflare as `Updated to new configuration`, with its ingress rules in `config`.
- **Token.** A tunnel token is standard base64 of `{"a": account tag, "t": tunnel UUID, "s": base64 secret, "e": optional endpoint}`. cloudflared reads it from `TUNNEL_TOKEN`.
- **Protocols.** `--protocol http2` uses only outbound TCP. The default, `auto`, prefers QUIC, which binds a UDP socket on all addresses.

## Decision

### 1. Packaging and the launch check (S-23, S-71)

- `build/cloudflared.lock` moves to 2026.11.0. `internal/tunnel` holds the same version and SHA-256 as constants, and a test fails if they ever differ from the lock file, so the file stays the one source.
- `build/fetch-cloudflared.ps1` downloads the asset from the official GitHub release URL into `internal/tunnel/embed/cloudflared.exe` (ignored by git), checks its SHA-256 against the lock and deletes it on a mismatch.
- Builds with the `cloudflared` build tag embed it with `go:embed`. Builds without the tag carry no copy, so ordinary tests, linters and the owner's local builds need neither the 55 MB file nor a download.
- `build.ps1 -Cloudflared` fetches and tags. The CI build and isolation jobs always do.
- **Setup install and repair.**
  - The embedded bytes are hashed in memory and must match the pin before anything is written.
  - They are written to `%ProgramFiles%\SoireeHost\cloudflared.exe` as a new file, which inherits the program folder's permissions (administrators write, everyone else reads and executes).
  - The written file is read back and hashed again.
  - A build without an embedded copy installs without it, and the tunnel then reports Repair needed. Release builds (Phase 6) are always built with the tag.
- **Before every launch, the tunnel launcher:**
  1. opens `cloudflared.exe` from its own install folder, with read sharing only, so nobody can write, rename or delete it while the handle is open;
  2. hashes it through that handle and compares with the compiled-in pin;
  3. starts that same path while still holding the handle.

  Between the check and the start the file cannot change. A missing file or a mismatch means no cloudflared runs: the launcher reports the problem code `binary_missing` or `binary_mismatch`, and `status.get` reports `repair_needed` with the sentence "The tunnel program is missing or was changed. Run Repair to restore it." The control panel's Repair button is Phase 5 UI work. Until then, Repair is `soireehost.exe setup install` run again, which the CI isolation job already exercises.

### 2. How cloudflared runs (S-04, S-21, S-23, S-01)

The tunnel launcher starts every cloudflared itself, with `CreateProcess`:

- **Creation.** The process is created suspended. It goes into a job object of its own, nested inside the launcher's, with kill-on-close, one active process (cloudflared can start nothing) and a 256 MB memory cap, and only then is it resumed. The UI restrictions come from the launcher's own job, whose limits cover every job nested inside it: Windows refuses to add a process to a nested job that sets UI restrictions of its own ("The request is not supported", found by the CI isolation job on pull request 7).
- **Child-process policy.** It is also applied at creation through `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY` (`PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`). If Windows refuses it, cloudflared is not started (fail closed). The child gets no console at all (`DETACHED_PROCESS`): with `CREATE_NO_WINDOW` Windows still starts a hidden conhost.exe for it, which the policy refuses, and the child then dies in DLL start-up (0xC0000142, found while building, 14 Nov 2026).
- **Token.** cloudflared inherits the launcher's token, which already holds only `SeChangeNotifyPrivilege`.
- **Handles.** Only the stdout and stderr pipe handles are inherited.
- **Environment.** It is built from scratch, never inherited: `SystemRoot`, `windir`, `SystemDrive`, `TEMP`, `TMP`, `USERPROFILE`, `LOCALAPPDATA` (all the service profile's), plus `TUNNEL_TOKEN` in token mode. The token never appears on the command line, so it never shows in a process list (S-23).
- **Fixed arguments.** None comes from the user:

  | Argument | Why |
  | --- | --- |
  | `tunnel` | subcommand |
  | `--no-autoupdate` | S-23 |
  | `--protocol http2` | outbound TCP only, so cloudflared binds no UDP socket on any address (S-01 for cloudflared) |
  | `--metrics 127.0.0.1:<port>` | the metrics server cannot be off, so it is pinned to loopback on a port SoiréeHost owns (S-04, R-06) |
  | `--management-diagnostics=false` | no profiling or metrics through the management service (S-04) |
  | `--output json` | machine-readable lines |
  | `--loglevel info` | debug level would log request headers |
  | `run` (token mode) or `--url http://127.0.0.1:<share port>` (quick share) | |

- **Listener check.** After start, and every 30 seconds, the launcher reads the TCP listener and UDP tables for each cloudflared process ID. Any TCP listener that is not on `127.0.0.1` or `::1`, and any UDP socket, kills that process and reports `unexpected_listener` (S-01). The table code moves from `internal/worker` into `internal/winsec` so the worker and the launcher share it.
- **What is never trusted.** The launcher never reads the metrics server: any local process could take that port first and answer with false data. Everything it learns comes from the stderr of the process it started.
- **Restarts.** A cloudflared process that exits is restarted with backoff (1, 2, 4 … 60 s; the delay resets after it has been connected for a minute). The tunnel launcher's own job allows 1 + 1 + 4 processes: itself, the token tunnel and at most four quick shares.

### 3. Reading cloudflared's output (R-21, S-40)

Each line of stderr is read with a 64 KB cap and decoded as JSON. Lines that do not decode are kept only as length-capped text.

- **Scrubbing.** Before any line goes anywhere, every occurrence of the token, of its `s` secret (both the base64 text and the base64 of the decoded bytes), and of the account tag is replaced with `[redacted]`.
- **Where lines go.** Lines go only to `logs\tunnel\cloudflared.log`, which the launcher writes and rotates (10 MB, 3 kept). They never reach the supervisor. What the supervisor gets is a closed set of problem codes and counts, never cloudflared's words, so a failure reason cannot echo the token (R-21).
- **Second scrub.** The supervisor also checks every worker reason it receives against the token it holds and replaces the whole reason if it contains it.
- **Connection health.** It is derived from `Registered` and `Unregistered tunnel connection` per `connIndex`. Each tunnel is `starting`, `connected` (with the number of edge connections), `reconnecting` (it was connected and has none now), `down` (cloudflared exited; restart pending) or `refused` (binary missing or changed, or an unexpected listener).
- **Quick share address.** It is the first message of that process that matches `^\|\s+https://([a-z0-9-]{1,63})\.trycloudflare\.com\s+\|$` and is logged before the first registered connection. Later matches are ignored, so no text that reaches cloudflared later, such as a request path in an error, can change it. The supervisor validates the hostname again with the same pattern and `config.ValidateHostname`.
- **Remote ingress (tunnel-token mode).** When cloudflared logs `Updated to new configuration`, the launcher parses the ingress list in `config`. Every rule whose service is not `http://127.0.0.1:<listen port>`, `http://localhost:<listen port>` or an `http_status:` response, and a `warp-routing` block that is enabled, raise the code `ingress_outside`. Status then warns: "Your Cloudflare dashboard sends some traffic to a service other than SoiréeHost, so SoiréeHost's protections do not cover it." SoiréeHost cannot stop the Cloudflare dashboard from routing elsewhere (it is the owner's own account), so this is reported, not enforced. S-10 for the dashboard is a documented limit.

### 4. Quick share (S-06, S-51, R-06)

- **Config.** A site may carry `"quick_share": {"port": P, "metrics_port": M}`. Its presence means the site is shared. New control methods `quickshare.start {site_id}` and `quickshare.stop {site_id}` change it through the normal change path (validated, versioned, audited). `start` picks the lowest free ports in 8788–8887 and 20301–20400. At most 4 sites may be shared at once.
- **Web worker.** It gets one extra Caddy server per shared site, listening on `127.0.0.1:P`. Its only site route matches the hostname cloudflared assigned and runs that site's normal handler chain. Everything else, including every request before a hostname is known, gets the same 404 as the main listener. The main listener never serves the quick-share hostname.
- **The assigned hostname** lives only in the supervisor's memory: a new process gets a new hostname, so saving it would be wrong after any restart. The supervisor passes it to `worker.BuildCaddyJSON` as runtime input, reloads the web worker, and reports the link in `status.get` with `temporary: true` and the label "Temporary link for testing. It changes whenever the tunnel restarts." (S-51).
- **After a restart.** A shared site stays shared across a supervisor restart and gets a new link. This is stated in the label.

### 5. Tunnel-token mode (S-50, S-03)

- **Token check.** `secret.set` for `tunnel_token` checks the format before storing. The value must be standard base64 of JSON with exactly the keys `a` (32 hex characters), `t` (a UUID), `s` (base64 of 32 to 256 bytes) and optionally `e` (a short lower-case label), no other keys and no trailing data. Anything else is refused with "This is not a Cloudflare Tunnel token. Copy the token from the tunnel's install command in the Cloudflare dashboard. An API key or API token cannot be used." That covers a Global API Key, an API token, a certificate and arbitrary text (S-50).
- **Running it.** cloudflared runs with that token whenever one is set and the switch is not offline.
- **Ingress.** It points at the main listener (`127.0.0.1:8787` by default), where Caddy routes by Host header. The control panel shows the hostname and the exact service URL to enter in the dashboard (Phase 5). `status.get` carries the service URL now.
- **No port forwarding.** There is still no setting of any kind for it (S-03). A test asserts that no config field, control method or listen address can bind beyond loopback.

### 6. The offline switch

`"tunnel": {"offline": true}` in config, set with the new control method `tunnel.set_offline {offline}`, stops every cloudflared process. Nothing is reachable from the internet while it is on. The web worker keeps serving loopback, so going back online is instant. The switch survives restarts. Both directions write an audit entry. Going offline needs no confirmation. Going back online re-exposes only what was exposed before, which is not one of the S-32 weakening actions, but it is audited.

### 7. Ports SoiréeHost owns (R-06, S-10)

`config.Validate` collects the app's own ports:

- the listen port;
- `tunnel.metrics_port` (default 20300, the token tunnel's metrics; clear of 20241–20245, which a cloudflared the user runs on their own takes by default);
- every quick share's `port` and `metrics_port`.

They must all differ and be 1024 or higher, and no proxy target on a loopback address may use any of them. A LAN target is not checked, because these ports listen on loopback only. `ParseTarget`'s single own-port argument becomes a set. Quick-share and metrics addresses are always `127.0.0.1`, built by code and never read from config.

### 8. Typed worker messages per role (SE-21)

`WorkerConn` knows its role, and `DecodeWorkerMsg(data, role)` validates for that role. The message set:

| Type | Direction | Web | Tunnel |
| --- | --- | --- | --- |
| `hello` | worker → supervisor | `role: web` | `role: tunnel` |
| `load` | supervisor → worker | `caddy`: a non-empty JSON object; nothing else | `tunnel`: a `TunnelPlan` (`offline`, `token`, `metrics_port`, `listen_port`, `shares[] {site_id, port, metrics_port}`), validated; nothing else |
| `loaded`, `failed` | worker → supervisor | as today | as today (failure reasons are fixed launcher sentences) |
| `status` | worker → supervisor | refused | `report`: a `TunnelReport` (one entry per tunnel: kind, site, state, connections, quick hostname, problem codes from a closed set, since) |
| `stop` | supervisor → worker | | |

- **Refused combinations.** A Caddy load on the tunnel pipe, a tunnel plan or status on the web pipe, an empty payload, and a hello naming the other role are all refused at decoding.
- **Redaction.** `TunnelPlan` implements `String` and `GoString` that print no token.
- **Test identities.** Supervisor tests run the two workers under separate pipes and check that each pipe's decoder refuses the other role's messages. Tests that need distinct caller SIDs use the e2e job, where each worker runs under its own account.

### 9. Token delivery (GO-6)

All tunnel state changes go through one lock (`tunnelMu`) and one function, `pushTunnel`:

1. it reads the current config, the stored token and the quick-share assignments;
2. it builds the whole `TunnelPlan`;
3. it sends it synchronously and returns the launcher's answer.

`secret.set` holds `tunnelMu` from the "is one already set?" check through storing and pushing, so two first sets in a row are serialised and the second needs confirmation. A delivery error comes back as a warning in the result ("Saved. The tunnel did not take the new token: …"), not hidden. Because the plan is the whole desired state, the last push always wins, whatever order earlier ones finished in. The tunnel connecting, a config change touching quick shares or the offline switch, and a new quick-share hostname all call `pushTunnel` or the web reload under the same locks, in a fixed order (`changeMu` before `tunnelMu`), so they cannot deadlock.

### 10. Firewall block rules (S-02)

- **Install and repair.** Setup runs `%SystemRoot%\System32\netsh.exe advfirewall firewall` with fixed arguments: it deletes and re-adds two rules, `SoireeHost: block inbound soireehost.exe` and `SoireeHost: block inbound cloudflared.exe`, each `dir=in action=block enable=yes profile=any` with `program=` set to the installed path.
- **Precedence.** In Windows Firewall a block rule overrides any allow rule, so a later "allow" prompt answered by mistake changes nothing.
- **No allow rule.** Setup creates no inbound allow rule.
- **Uninstall** deletes both rules.
- **Why netsh.** It is preferred to the COM firewall API because it needs no new dependency (the COM route needs `go-ole` or hand-written vtable calls) and runs only inside elevated setup, with an absolute System32 path and no user input in its arguments.

### 11. Control API additions

| Method | Does | Notes |
| --- | --- | --- |
| `quickshare.start {site_id}` | Shares an enabled site through a temporary link | Audited; refused for a disabled or unknown site and beyond 4 shares |
| `quickshare.stop {site_id}` | Ends the share | Audited |
| `tunnel.set_offline {offline}` | The offline switch | Audited |
| `status.get` | Gains `tunnel`: `offline`, `token_set`, `service_url`, `repair_needed`, one entry per tunnel (kind, site, state, connections, `temporary` link, warnings as sentences) | No secret, ever |

## Options considered

### Hostname source for quick share: cloudflared's stderr (chosen) or its `/quicktunnel` metrics route

| Dimension | stderr of our own child | `/quicktunnel` on the metrics port |
| --- | --- | --- |
| Complexity | Line parser | HTTP client and polling |
| Spoofing | Only cloudflared can write it | Any local process that binds the port first can answer |
| Fit with the plan | What section 4 describes | Needs a loopback client in the launcher |

stderr wins: it cannot be spoofed from outside the process tree.

### Transport: HTTP/2 (chosen) or QUIC

QUIC is cloudflared's default and is somewhat faster on lossy links. It binds a UDP socket on all addresses, which would show in `netstat` as a non-loopback endpoint and weaken the S-01 property the acceptance check tests. HTTP/2 over TCP is fully supported for both quick and token tunnels. Revisit if users report performance problems. The trade is a small speed loss for an exposure property that can be tested.

### Firewall rules: netsh (chosen), the COM API, or PowerShell `New-NetFirewallRule`

- **COM.** Needs a new dependency or several hundred lines of unsafe vtable code.
- **PowerShell.** Starts a heavier interpreter whose behaviour depends on execution policy and modules.
- **netsh.** One System32 program with fixed arguments, run only inside elevated setup.

### Quick-share state: in config (chosen) or only in memory

Keeping shares in config makes the ports static, so S-10 and R-06 are pure validation that can be fuzzed. Every share is versioned and audited like any other change, and a share survives a supervisor restart. Keeping shares only in memory would need dynamic port checks against config changes, with a race between them. The assigned hostname stays in memory because it is not stable.

## Trade-offs and limits

- **Size.** The binary grows by about 55 MB. That was accepted in ADR-0002.
- **Dashboard ingress.** SoiréeHost cannot stop the Cloudflare dashboard from sending a hostname to another service. It warns (section 3) and documents it.
- **Unchecked metrics port.** A local program that takes a metrics port before cloudflared starts makes that cloudflared fail to start (reported as `down`, retried). It cannot feed the launcher anything, because the launcher never reads the metrics server.
- **Unverified checks.** Tunnel-token mode is checked live only once the owner has a domain, which is not yet verified (owner decision). The port scan from a second machine is replaced by the CI scan until a release check (owner decision).

## Consequences

- **Easier.** One `TunnelPlan` makes tunnel state declarative: reconnecting, restarting and racing changes all converge on the last plan.
- **Harder.** The launcher now manages several child processes and parses an external program's log format, which can change between releases. The parser is fuzzed, its patterns are pinned by tests against recorded 2026.11.0 lines, and the upstream watcher (S-65) brings each new release through CI, where the isolation job runs a real quick share.
- **Revisit.**
  - QUIC, once a UDP-aware exposure check exists.
  - Protected quick tunnels (`--allowed-mail`, new in 2026), as a later option for private sharing.
  - The Phase 5 Repair button and link display.

## Action items

1. [ ] Owner: accept or amend this record.
2. [ ] Lock and pin at 2026.11.0, fetch script, `cloudflared` build tag, embed, setup unpack, uninstall removal.
3. [ ] Launcher: launch check, process start with nested job and mitigation, listener check, output parser and scrubber, restarts, health, quick-share hostname, ingress warning, log rotation.
4. [ ] Typed per-role worker messages (SE-21); `pushTunnel` and the serialised `secret.set` (GO-6); token format check (S-50); scrubbing of reasons (R-21).
5. [ ] Config: `tunnel` block and `quick_share`, the own-port set in validation (R-06), fuzz targets updated.
6. [ ] Web worker: quick-share servers with the hostname gate (S-06).
7. [ ] Control methods and status fields; audit entries.
8. [ ] Setup: firewall block rules on install and repair, removed on uninstall (S-02).
9. [ ] Tests: unit and fuzz (parser, token check, plan validation, ports), an in-process launcher test with a stand-in cloudflared (the test binary run again), worker tests for the quick-share 404, and e2e on CI: a real quick share fetched over the internet, the listener table and own-address port scan, a canary token swept from process command lines, logs and config, a tampered `cloudflared.exe` refused with `repair_needed`, and the firewall rules present with no allow rule.
10. [ ] CI: fetch and embed in the build and isolation jobs; a `workflow_dispatch` input that holds a quick share open for the phone check.

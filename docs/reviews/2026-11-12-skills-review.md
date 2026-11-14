# Skills review of Phases 0 to 2

**Date:** 12 Nov 2026
**Scope:** everything on `main` at `d1c4181` (Phases 0, 1 and 2)
**Why:** plan rule 9 requires the section 8 skills at every phase. The Trail of Bits and Go skill sets were not installed while Phases 1 and 2 were built, so those phases were reviewed only by the built-in code review, the end-of-phase security review, and CI's static analysis. This review applies the listed skills after the fact. Plan section 10's "Semgrep with the project rules" was also missing from CI since Phase 0.

Each stage below names the skill used, what it covered, and its findings. Findings are numbered `R-NN` and tracked to a fix or a recorded decision in the last section.

## Stage 1: supply chain (`supply-chain-risk-auditor`, S-75)

The collector ran on `go.mod` (5 direct modules, 152 further modules checked for advisories) and on `frontend/package-lock.json` (12 direct packages, 188 further packages), authenticated to GitHub. Reports are reproducible with the commands in the plugin's `SKILL.md`; the figures below are quoted from them.

- No known advisory affects any of the 17 direct dependencies.
- **R-01** `github.com/go-jose/go-jose/v3` v3.0.5 (Go, transitive: Caddy's `caddytls` → smallstep `certificates` → `go.step.sm/crypto/jose`) carries GHSA-4w3g-jfj2-cw2q, GHSA-mgcc-cww5-fp2q and GHSA-vvm8-gf78-28g4: panics and a denial of service when parsing hostile JOSE objects or JWKs. v3.0.5 is the newest v3 release and the advisories list it as last affected, so no v3 fix exists; the fixes are in v4 (4.1.5, 4.1.6). `govulncheck` reports none of them reachable from SoiréeHost's code: the affected parsing runs only in Caddy's internal CA and ACME server, which the generated config never enables.
- **R-02** `github.com/go-jose/go-jose/v4` is at v4.1.6, which contains the fixes, but v4.1.9 is the newest release (plan rule 4 prefers the newest stable).
- `deepmerge` 4.3.1 (npm, build-time only) carries GHSA-gcqx-w48m-w2h4, already accepted in `docs/DEPENDENCIES.md`.
- OpenSSF Scorecard, informational: `wails/v3` and `@wailsio/runtime` score 0/10 on Dangerous-Workflow and 5/10 on Binary-Artifacts; `vite` scores 1/10 on Binary-Artifacts. These describe the upstream repositories' CI, not code SoiréeHost runs, and have no action here beyond watching Wails releases (ADR-0003 already pins it).
- Not assessable for Go by design: publisher concentration, download volume, publish provenance, module deprecation.

## Stage 2: spec-to-code compliance (`spec-to-code-compliance`)

Each requirement owned by Phases 0 to 2 was checked by its own `spec-compliance-checker` agent against `docs/PLAN.md` and ADRs 0005 and 0006. Verdicts so far:

| Requirement | Verdict | Finding |
| --- | --- | --- |
| S-01 | partial | R-05 |
| S-03 | implemented (Phase 2 scope) | — |
| S-04 | implemented | R-14 (note) |
| S-05 | partial | R-11 |
| S-06 | partial | R-13 |
| S-10 | implemented | R-06 (Phase 3 note) |
| S-11 | partial | R-09 |
| S-12 | stronger than spec | R-12 |
| S-13 | partial | R-10 |
| S-15 | partial | R-15 |
| S-16 | partial | R-16 |
| S-18 | partial | R-19 |
| S-20 | implemented | R-17 (note) |
| S-21 | implemented | R-18 (test) |
| S-22 | partial | R-03 |
| S-24 | partial | R-20 |
| S-30 | implemented | — |
| S-31 | implemented | R-07, R-08 |
| S-32 | partial | R-04 |
| S-35 | implemented (control API) | — |
| S-36 | implemented | — |
| S-40 | implemented | R-21 (Phase 3 note) |
| S-41 | partial | R-22 |
| S-70 | implemented | R-23 (note) |
| S-72 | implemented (Phase 0 part) | — |
| ADR-0006 lifecycle | partial | R-24 |
| ADR-0006 and plan folder tables | partial | R-25 |

- **R-03 (S-22)** The start-time check covers only the `config` and `secrets` folder objects, and only their writers and owner. Plan section 4 lists six folders and says the ACLs "match the table … checked at every start". The logs, updates and data-root folders are not checked at start, no worker checks its own folder, and the worker log folders get modify where section 4 says append. ADR-0006 reads the requirement as config and secrets only; the plan does not say so.
- **R-04 (S-32)** Adding a LAN target is gated on the main `site.put` path only. A LAN target can be added without confirmation in three ways: `site.put` on a site whose `allow_lan` flag is already set, a user's `config.rollback` to a revision that has one (rollback takes no confirmation), and the supervisor's own restore to the last good config. The audit half is met while the audit log is writable; a failed audit write lets the change stand (fail-open, a recorded design choice). Whether other weakening actions (directory listing, removing security headers, raising limits) need confirmation is not settled by any document.
- **R-05 (S-01)** In the release service, a failed listener self-check makes `worker.LoadJSON` stop Caddy and return an error, but `ipc.RunAgent` only reports `MsgFailed` and waits for the next message: the process does not exit, as S-01 requires, and the supervisor reloads the previous config into the same process. The once-a-minute re-check that ADR-0005 describes runs only in the dev `worker -config` path (`worker.Run`), not in the release worker.
- **R-06 (S-10, note for Phase 3)** S-10 holds today. `config.ParseTarget` refuses a single "own port", the listen port, which is the app's only TCP port now. Phase 3 adds quick-share loopback ports and a cloudflared metrics port; the check has to take all of them. Also, a site with `allow_lan` already set can be pointed at a different LAN device without confirmation (part of R-04).
- **R-07 (from S-31)** `site.put` skips the web worker read-access check when reading the folder's access list fails (`err == nil && !ok` in `supervisor/control.go`), so that check fails open. It should refuse the site.
- **R-08 (from S-31)** `config.rollback` and `site.set_enabled` bring back a stored static root without re-running `sitecheck.CheckRoot` in the supervisor; only the worker's `OpenRoot` repeats the folder checks. A folder that became a link or changed owner since it was added is caught by the worker, not by the supervisor, so the error reaches the user as a failed load instead of a refused request.
- **R-09 (S-11)** A user-profile root is refused only when it sits directly in the Users folder (`FOLDERID_UserProfiles`). A profile stored elsewhere (for example `D:\Profiles\bob`, set through the ProfileList registry key) is accepted as a static root, and its `AppData` subtree is then served, because `AppData` is refused only as a component of the root path, not of a request path. Fix: refuse every profile folder listed under `HKLM\...\ProfileList` and its parents, and refuse `AppData` as a request path component. Open question for the owner: whether `Windows` and `Program Files` mean only this system's folders or any folder with that name on any drive.
- **R-10 (S-13)** Static sites reject every trick S-13 lists. Proxy sites reject short names, backslashes and single-level encoded traversal, but pass `:`, trailing dots and spaces, reserved device names (`/CON`) and double-encoded traversal (`%252e%252e`) to the app, unless the Windows-normalised name is on the never-serve list. ADR-0005 records this as deliberate (a proxied app is not a Windows file system) and the owner accepted it, but `docs/PLAN.md` S-13 and `docs/SECURITY_CHECKLIST.md` still state the requirement with no proxy exception. The documents need to agree; double-encoded traversal on proxy sites is worth refusing regardless.
- **R-11 (S-05)** The client address comes only from `CF-Connecting-IP` on every path, and the log filter drops forged headers from every log line. But `worker.StripForwarded` deletes a fixed list of 16 header names (and their underscore spellings), so other forwarding headers such as `Forwarded-For` or `X-Forwarded` reach proxied apps unchanged. Request trailers are not stripped either. Fix: strip every header whose name contains `forwarded` or ends in `-ip`/`-client-ip`, plus trailers on proxy routes. Note: any local process can connect to the loopback listener and set `CF-Connecting-IP`; this falls under the plan's "another program on the same PC" threat row, which accepts it.
- **R-12 (S-12)** No way was found to serve a blocked name through a static or proxied URL path; the code blocks more than the plan lists (SSH key names, `.p12`, `.ppk`, `.kdbx`, folder segments), and the plan should list those extras so a later change cannot drop them unnoticed. Two open paths need tests: (a) NTFS case folding of characters such as U+017F or U+0131, which Go's `ToLower` leaves alone, could make `/deſktop.ini` open `desktop.ini`; (b) `os.Root` follows a link that stays inside the site folder, so a link or junction with an allowed name pointing at `.git` or `.env` serves that content on a direct request (listings drop links). Fix for (b): refuse any request whose resolved path differs from the requested one by a link.
- **R-13 (S-06)** A request with an absolute-form target naming a configured site and a Host header naming an unknown one (`GET http://blog.example.com/ HTTP/1.1` with `Host: evil.example`) is served the site's content: Go takes the host from the request line, and the guard accepts absolute-form targets. S-06 says the Host header decides. Browsers never send absolute-form targets, so DNS rebinding is not affected, and whether cloudflared can forward one is not established. Fix: refuse (400) an absolute-form target whose host differs from the Host header, and test that direction (the checklist says "absolute-form target" is tested, but only the opposite direction is). A missing or malformed Host gets 400 rather than 404; no content is served, so only the wording of S-06 needs to allow it.
- **R-14 (S-04, hardening note)** The admin API is off on every path and no debug, profiling or metrics endpoint is served in release builds. Two hardening notes: Caddy's imports register pprof and expvar handlers on `http.DefaultServeMux`, which nothing serves today (a Semgrep rule should keep it that way); and the GUI does not clear the `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` environment variable, through which another program could turn on WebView2 remote debugging for the control panel. The GUI should clear that variable (and the related `WEBVIEW2_*` overrides) before creating the window.
- **R-15 (S-15)** Body size and rate limit are per site with the plan's defaults. Header size, read timeout and idle timeout are one value for the shared listener, because Go's `http.Server` has no per-host setting; ADR-0005 records this and the owner accepted it, but `docs/PLAN.md` S-15 still says "per site". Further points: the limiter allows a burst of 300 then one request every 200 ms, so a new client can make up to 599 requests in its first minute (the plan does not say which reading it means); counters reset on every config reload; requests for an unknown hostname get the 404 fallback with no rate limit; no test covers the read or idle timeout. Fix: rate-limit the fallback route, add the two timeout tests, and bring the plan's wording in line with ADR-0005.
- **R-16 (S-16)** Every response that reaches Caddy carries the four default headers and no `Server` header, including 413, 429, 502, redirects and listings. Responses that Go's `net/http` writes itself before any handler (400 for a malformed request or missing Host, 431 for oversized headers, 501 for an unknown Transfer-Encoding) carry none of the four headers; `Server` is absent there too. These bodies are short fixed `text/plain` messages, so the risk is low and no Caddy setting can change it; ADR-0005 should record it. The missing `Server` header cannot be changed per site (stricter than the plan's "each can be changed"); ADR-0005 records that, the plan does not. Tests cover the headers on static, guard, proxy, unknown-host and 429 responses, not on 502, redirects or listings.
- **R-17 (S-20, notes)** Three own-process services, each a virtual account with a restricted SID, privileges trimmed to `SeChangeNotifyPrivilege`, and worker descriptors giving the supervisor `LCRPWPLO` only. Notes: on a fresh install the binary path is quoted only when it contains a space (x/sys behaviour; the default path has one), so setup should always quote it; no test checks the supervisor's exact rights on the worker services, so a later change that widens them would pass; between `CreateService` and `SetSecurityInfo`, and after a failed `configureService`, a worker service keeps the service manager's default descriptor.
- **R-18 (S-21, test gap)** Confinement holds: privileges dropped, kill-on-close job with process, memory and UI limits, no-child mitigation for the web worker, all before the pipe or network opens; the tunnel launcher's exception is recorded in ADR-0006. `TestConfineStopsChildProcesses` cannot show the no-child mitigation works, because its helper also sets `ActiveProcesses: 1`, which alone stops `cmd.exe`. The test needs a helper with a process limit above 1 and the mitigation on. The job's `DIE_ON_UNHANDLED_EXCEPTION` limit is undocumented; ADR-0006 should list it.
- **R-19 (S-18)** Both Caddy logs use the filter encoder; headers are an allow-list (no `Authorization`, `Cookie` or `Set-Cookie`), rotation is capped at 10 MB, 5 files, 30 days, and SoiréeHost's own logs carry no secrets. Gap: Go parses the request target with `url.ParseRequestURI`, which does not split off `#`, so in `/p?a=1#&token=S` the parameter `token=S` is real to Go and to the proxied app, but `RedactURI` treats everything after `#` as a fragment and logs it unmasked (`TestRedactURI` expects this). Browsers never send a raw `#`; whether Cloudflare's edge forwards one is not established. Fix: the guard refuses a raw `#` in the request target (400), and `RedactURI` masks the whole query without splitting on `#`.
- **R-20 (S-24)** `RestrictDLLSearch` runs first thing in `main`, before every role, and the project's own DLL loads all use `NewLazySystemDLL`; build flags and the PE check hold. Gap: every role imports `internal/gui`, so Wails' package `init` functions run before `main` in every process, including the services and the elevated setup, and `wails/v3/pkg/w32/theme.go` loads `uxtheme.dll` by bare name with plain `LoadLibraryW` before the restriction exists. The program folder is writable only by administrators, which limits the risk, but S-24's guarantee does not hold before `main`. Fix: apply the restriction from the `init` of a small package with no dependencies beyond the standard library that sorts and initialises before Wails (Go 1.21+ initialises packages in import-path order once their dependencies are done), and test that `uxtheme.dll` is not loaded from outside System32. Also: the CI `isolation` job's binary, the one installed as the services, gets no PE check.
- **R-21 (S-40, note for Phase 3)** Secrets are DPAPI-protected under the supervisor's service account (no machine scope) with fixed entropy, and no path puts a value in config, logs, the event log, audit entries or error text; the IPC types redact themselves when printed. Phase 3 note: once the tunnel worker's `Load` can fail, its error text becomes a `MsgFailed` reason; if cloudflared echoes the token, that reason must stay discarded or be scrubbed.
- **R-22 (S-41)** The store validates on read and write, writes atomically and keeps versions. The supervisor restores the last good config when the web worker explicitly replies `failed` and the last-good revision can be read. It does not restore, and at reconnect does not report, when: (1) the worker dies while loading a new revision (`errWorkerDown` is treated as "applies when it starts", so the bad revision is re-sent on every restart); (2) the worker does not answer within the load timeout; (3) the rollback target is missing or unreadable (no fallback to the previous revision). Fix: treat a crash or timeout on a new revision as a refusal, fall back to the previous revision when the last-good one cannot be read, and report every outcome at reconnect.
- **R-23 (S-70, note)** `go.sum` pins everything and is verified in CI, `-mod=readonly` is set for every project build, the checksum database is never disabled, and both npm installs use `npm ci --ignore-scripts`. Small gaps: `build.ps1` runs `wails3 generate bindings` before it sets `GOFLAGS`, and `fuzz.ps1` never sets it; two CI steps clear `GOFLAGS` to install pinned tools without a comment saying why. `go mod verify` and a read-only build pass on this branch after the go-jose update.
- **R-24 (ADR-0006 lifecycle)** Start types, recovery, start order, backoff arithmetic, pre-shutdown and the 10-second worker stop hold, and workers end when their pipe closes. Four clauses fail: (1) worker restarts are counted only in memory and never written to the worker log as the ADR says; (2) the `stop` message is never sent, because `stop()` runs only after `serve` has already closed the pipe (the pipe close does the job, so the ADR or the code must change); (3) the backoff resets to 1 s as soon as a worker says hello, so a worker that connects and then dies restarts every second for ever; (4) the supervisor's exit waits for open control connections, each of which blocks on a read with a 5-minute idle timeout and ignores cancellation (no production client exists yet, but the control panel will be one). Also: the connect and hello waits are 30 s each, so the worst case is 60 s, not 30.
- **R-25 (folder tables)** The code matches the ADR-0006 folder table exactly, including owners and atomic creation. Against plan section 4: worker log folders get modify where the plan says append (R-03); the program folder gets no explicit descriptor and no owner or link check, only what `Program Files` passes down; both workers get list and traverse on the data root (they can see the names `config`, `secrets`, `logs`, `updates`), which neither document records and which the tunnel launcher does not need; `GrantSiteAccess` grants read and execute (`0x1200a9`) where the ADR says read and list, keeps every existing entry, and has no production caller yet (the control panel arrives in Phase 5). The plan's "only" rows omit SYSTEM, which the ADR and code include.

Stage 2 result: 27 requirements and design records checked; 13 hold (S-12 stronger than the plan), 14 are partial, none is contradicted or absent. Every partial verdict goes through `fp-check` before it is fixed.

## Stage 3a: insecure defaults (`insecure-defaults`)

The plugin's audit runs through Claude Code's Workflow tool, which this session does not have (the desktop app did not provide it even with "Dynamic workflows" on). The pipeline in the plugin's `workflows/audit.js` was followed by hand: the recon profile written from Stages 1 and 2, three sweep agents covering the six categories with the plugin's seed patterns and reference corpus, then one refuting verifier per category using the pipeline's own five-step verify prompt.

| Category | Files scanned | Candidates | Confirmed |
| --- | --- | --- | --- |
| Fallback secrets | 98 | 0 | — |
| Default credentials | 98 | 0 | — |
| Fail-open security | 62 | 8 | 0 |
| Weak crypto | 62 | 3 | 0 |
| Permissive access | 60 | 9 | 0 |
| Debug features | 60 | 7 | 0 |

No insecure default was confirmed. The two empty categories are a real result of the sweeps, not proof of absence. Refutations worth keeping in view: `supervisor.Options.CheckACLs` and `WorkerCanRead` default to off or nil and are safe only because the one production caller sets them (a sharp edge for future callers, carried to Stage 3b); `winsec.GrantSiteAccess` has no production caller yet and must be re-audited when Phase 5 wires it in; the audit chain is unkeyed SHA-256, which is enough for the stated design because the folder ACL makes the log append-only for the supervisor. Verdicts with their reasons are in the session scratchpad (`insecure-defaults/verify-*.json`).

## Stage 3b: sharp edges (`sharp-edges`)

Two `sharp-edges-analyzer` agents probed the internal APIs for misuse by future contributors (Phases 3 to 6) and by the owner through the control API: zero values, swappable parameters, ignorable returns, call-order rules and silent failures. Severity follows the skill's table (High: easy misconfiguration breaks security; Medium: unusual but possible; Low: needs deliberate misuse). No current caller misuses any of these unless the row says so.

### Windows security helpers, secrets, atomic writes, audit

| ID | Location | Severity | Sharp edge | Fix |
| --- | --- | --- | --- | --- |
| SE-01 | `winsec/acl_windows.go` `EnablePrivileges` | Medium | Returns nil for a privilege the token does not hold: x/sys treats `ERROR_NOT_ALL_ASSIGNED` as success. | Check `GetLastError` after the call and return an error. |
| SE-02 | `winsec/confine_windows.go` `DropPrivileges` | Medium | Keeps the privileges it is given and drops the rest, the opposite of its name. | Rename to `KeepOnlyPrivileges`, or unexport. |
| SE-03 | `winsec/acl_windows.go` `SetFolderSDDL` | High | Exported from production code and the obvious helper, but creates the folder with inherited permissions first, follows junctions, and propagates down the tree; in setup (with SeRestore) that is a privileged re-permission primitive. Used only by tests today. | Move to a test-only package; offer one safe `EnsureFolderSDDL`. |
| SE-04 | `winsec/acl_windows.go` descriptor appliers | Medium | `CreateFolderSDDL`, `SetFolderSDDL` and `ForceSDDL` read the same SDDL differently: missing `D:`, missing `P`, NULL DACL, `S:` and `G:` are handled inconsistently. | One shared parser requiring a present, non-NULL, protected DACL. |
| SE-05 | `winsec/sddl.go` builders; `supervisor.readControlUsers` | Medium | SIDs are pasted into SDDL unchecked; the only check on `control-users.json` is an `S-1-` prefix, which accepts `S-1-5-18)(A;;GA;;;WD)` (Everyone full control on the control pipe, so any process could add a rogue pipe instance) and Everyone itself. Writing that file needs administrator, SYSTEM or supervisor rights. | Parse every SID with `StringToSid` and re-render it; refuse well-known groups in control users. |
| SE-06 | `GrantSiteAccess`, `WorkerLogFolderSDDL`, supervisor `Identity` | Medium | Role SIDs are same-typed strings; a swapped call compiles and grants the supervisor read on every site file. | Compute SIDs inside the function, or role types. |
| SE-07 | `winsec/acl_windows.go` `GrantSiteAccess` | Medium | No path checks of its own, follows links, propagates to the whole tree, appends duplicate entries; safe only if `CheckRoot` ran on the same path just before (Phase 5 caller). | Open the folder without following links, run `CheckRoot` on the handle's path inside, apply on the handle. |
| SE-08 | `winsec/acl_windows.go` `ForceSDDLUnlessLinked` | Medium | "Skipped" is a bool that is easy to discard; link count and apply use two opens (race). | Sentinel error; one handle for both. |
| SE-09 | `winsec/acl_windows.go` `CheckWriters` | Medium | Checks only the final object and follows reparse points; says nothing about replacement through the parent. | Refuse reparse points; add a parent-chain check. |
| SE-10 | `winsec/acl_windows.go` `WorkerGroups` | Low | Returns Everyone, Users, Authenticated Users, SERVICE; fits `CheckWriters(allowed...)` and would accept world-writable folders there. | Unexport behind a role-specific wrapper. |
| SE-11 | `winsec/confine_windows.go` `Limits` | Low | Zero value allows child processes; no upper bounds. | `AllowChildProcesses` instead; bound the limits. |
| SE-12 | `winsec/confine_windows.go` `Confine` | Low | Call-order rules (first, workers only, never close the job) are unenforced; no check afterwards that it took effect. | Verify after applying; `sync.Once`; refuse outside worker SIDs. |
| SE-13 | `audit/audit.go` chain | Medium | Unkeyed chain from a fixed genesis: truncating the tail, deleting the file, or rehashing everything verifies as OK; `Open` returns success on a broken chain. ADR-0006's "a removal is reported" overstates it. Only actors who can write the file can do this. | Anchor the last sequence and hash outside the file (event log on every append); typed error from `Open` when broken. |
| SE-14 | `audit/audit.go` `List` | Low | Never checks `sc.Err()`, so a 64 KiB line silently ends the listing; skips unparseable lines. | Return the scan error; report skipped lines. |
| SE-15 | `audit/audit.go` `Append` | Medium | "No secrets in Detail" is only a comment on a free-form map; actor and action are swappable strings. | Typed actor and action; refuse secret-like detail keys; test. |
| SE-16 | `secrets/secrets_windows.go` `Open` | Low | Accepts any folder, follows links, no ACL check of its own; zero-value `Store` writes to the working directory and panics. | Check writers and refuse reparse points in `Open`. |
| SE-17 | `secrets/secrets_windows.go` | Low | Same entropy for every secret, so blobs are interchangeable across names; `Status` reports an undecryptable blob as set. | Entropy includes the name (with migration); report "unreadable". |
| SE-18 | `fsutil/atomic_windows.go` `WriteAtomic` | Low | Replaces a file's own DACL with the folder's inherited one; follows links in the parent. | Document "protected folders only" or refuse parent reparse points. |
| SE-19 | `audit/audit.go` `Verify` | Low | Hashes the decoded entry, not the raw line; duplicate or differently-cased keys verify. | Compare canonical re-encoding to the raw bytes. |

Probed and sound: zero `Limits`, empty allowed lists, empty SID lists and bad SIDs all fail closed; `ForceSDDL` refuses NULL DACLs and does not follow links; `PipeCaller` before a read fails; secret names are pattern-checked.

### IPC, config, path rules, supervisor, web worker

| ID | Location | Severity | Sharp edge | Fix |
| --- | --- | --- | --- | --- |
| SE-20 | `worker/worker.go` `LoadJSON` | High | Loads any Caddy JSON. An empty, `null` or `{}` payload, or any config without `admin.disabled`, starts Caddy's unauthenticated admin API on `localhost:2019` (traced in Caddy v2.11.9, not run), which the loopback-only self-check accepts; any local process could then load a config without the guard. Needs a supervisor-side bug today. | Refuse empty payloads and any config without `admin.disabled: true` and `persist: false`; compare listening ports with exactly the configured one; clear `CADDY_ADMIN`; test. |
| SE-21 | `ipc/worker.go` `WorkerMsg` | Medium | One message type for both workers; `Validate` ignores the role, so a token sent to the web worker or a Caddy load sent to the tunnel is accepted (the tunnel would store an empty token and reply `loaded`). Tests use one SID for all three identities. | Typed messages per role; role-aware `Validate`; refuse empty payloads; distinct test SIDs. |
| SE-22 | `supervisor/supervisor.go` `Options.CheckACLs` | High | Zero value turns S-22 off with no log, status or audit trace; the production caller sets it. | Invert to a test-only skip; refuse a relative `Paths.Root`; record when off. |
| SE-23 | `supervisor/supervisor.go` `New` | Low | Validates no option: nil `WorkerCanRead` skips the check, nil `CheckRoot` panics the supervisor on the first static `site.put`, negative timeouts accepted. | `New` returns an error for nil hooks, relative root, negative timeouts. |
| SE-24 | `sitecheck/root_windows.go` `Locations` | Medium | A zero `Locations{}` or any empty field silently turns that S-11 rule off. Production uses `DefaultLocations`. | `CheckRoot` and `OpenRoot` build the locations themselves, or refuse empty fields. |
| SE-25 | `sitecheck/path.go` `Static`, `Proxy` | Medium | `(decoded, raw string)` can be swapped; swapped, encoded dotfiles and `..` pass, and on proxy sites the guard is the only check. | One typed request-path value built from the request. |
| SE-26 | `sitecheck/path.go` `Verdict`; `worker/guard.go` | Low | The zero `Verdict` is `Allow`, and any mode other than `static` gets the proxy rules. | Zero value refuses; explicit switch with a deny default. |
| SE-27 | `ipc/control.go`, `supervisor/control.go` confirmation | Medium | S-32 confirmation is a client-set `confirm: true`; a control panel that always sends it never asks the user, and the flag is not tied to the change shown. | Server-issued single-use nonce bound to the exact change and caller. |
| SE-28 | `config/fields.go` `response_headers` | Medium | An empty value silently removes a security header (and weaker values such as `frame-ancestors *` pass) with no warning; directory listing and `allow_well_known` raise no warning either. | Explicit removal list, refuse `""`, warnings for every weakened header and opt-in. |
| SE-29 | `ipc/pipe_windows.go`, `supervisor/control.go` | Medium | Access is checked once per connection and every method then runs with the supervisor's rights; "the only path is a site folder" is a comment, so a Phase 5 or 6 method taking a path becomes a confused deputy. | Per-method policy table checked before the handler, with a test that every method has one. |
| SE-30 | `ipc/pipe_windows.go` `Client.Call` | Low | After a timeout or I/O error the connection is out of step; an error reply is returned before its ID is checked, so a stale error can answer a later call; context cancellation ignored without a deadline. | Close on any error; check the ID first; honour cancellation. |
| SE-31 | `supervisor/workers.go` load result | Low | Any reply other than `failed` with the pending revision counts as loaded (and is marked good). | Require `loaded`; anything else is a protocol error. |
| SE-32 | `worker/logfilter.go` query masking | Medium | Masks a deny-list of parameter names; `code` (OAuth and reset codes), `sig`, `jwt`, `otp`, `ticket`, `SAMLResponse`, `assertion` are logged in clear for 30 days. Affects production logs today. | Mask every query value by default, or allow-list harmless names; tests. |
| SE-33 | `config/fields.go` `ParseTarget` | Low | `ownPort` 0 skips the own-port check and `allowLAN` is a bare positional bool; `Warnings` calls `(t, true, 0)`, an easy call to copy. | Policy struct with `OwnPorts` (empty is an error); separate classifier for warnings. |
| SE-34 | `config/store.go` `LastGood` | Low | Returns 0 for missing, unreadable and corrupt alike; `prune` can then delete the real last-good revision; a failed rename of a damaged config is ignored before it is overwritten. | `LastGood() (uint64, error)`; skip pruning when unreadable; stop on a failed rename. |
| SE-35 | `ipc/pipe_windows.go` `Listen` | Low | An empty SDDL falls back to the Windows default pipe ACL (Everyone and Anonymous read). Same family as SE-05. | `Listen` refuses an empty SDDL. |

Probed and sound: config numbers (0 means the default, every limit has a minimum and maximum), the rate limit cannot be turned off, `Rules{}` is the strict set, empty control parameters fail closed, `Dial` with an empty owner refuses, `BuildCaddyJSON` validates and needs an absolute log folder.

## Stage 4: differential review (`differential-review`)

Range `cb99b4b..d1c4181`: 71 files, 12,096 lines added, 58 removed. No security code was removed (the deletions are the old "role not built yet" stub, its test, and document edits), so the history phases have little to compare: the skill itself notes that greenfield code has no baseline. Stages 2 and 3 already read every changed file. The review therefore ran its Phase 5, adversarial modelling, with two `adversarial-modeler` agents on the highest-risk new code: the elevated setup role, and the pipes, caller identity, worker management and web-worker load path.

### Pipes, identity, worker management, load path

| ID | Location | Exploitability | Attacker | Finding | Fix |
| --- | --- | --- | --- | --- | --- |
| DR-1 | `ipc/pipe_windows.go` `Listen`; fixed names in `ipc/control.go`, `ipc/worker.go` | Medium | Standard local user | Pipe names are fixed and public; a user who creates them while the supervisor is not running (before install, during a restart or update, after a crash) keeps it from starting, and service recovery fails each time. Denial of service only: clients check the pipe owner, so spoofing is blocked. | Random pipe names per start, passed to workers as start arguments and to the control panel through a supervisor-only file; name the squatting process in the event log. |
| DR-2 | `config/fields.go` `validHeaderValue`; `worker/caddyconfig.go` header handlers | Easy | Any control-pipe caller (a process in the installing user's session) | Response-header values may contain `{` and `}`, and Caddy expands placeholders in header values on every response, so a value such as `{file.C:/ProgramData/SoireeHost/logs/web/access.log}` sends any file the web worker can read to every visitor, and `{env.*}` sends its environment. This bypasses S-11 and S-12. The `site.put` audit entry does not record header values. (Traced in Caddy v2.11.9, not run.) | Refuse `{` and `}` in header values (or escape them); test that generated JSON carries only fixed placeholders; record header changes in the audit entry. |
| DR-3 | `ipc/pipe_windows.go` serve loop; `ipc/frame.go` | Easy | Any control-pipe caller | No limit on control connections, and each frame header makes the supervisor allocate up to 1 MiB before the payload arrives and before the caller is identified, held for the 5-minute idle timeout; thousands of connections exhaust memory in a supervisor that has no job limit. Other users cannot connect at all. | Limit open connections; read payloads in steps; small first-frame limit until identified; shorter frame deadline. |
| DR-4 | `svcrun/svcrun_windows.go` `Start`, `Stop`; `supervisor/workers.go` `await` | Hard (needs code execution in the web worker) | Compromised web worker | A worker that ignores pipe close and the stop request survives: `Stop` returns after 10 s whether or not it stopped, a new supervisor's `Start` counts "already running" as success, and `await` accepts the old process (role and account match, version ignored). Only a reboot removes it. Contradicts ADR-0001's "a dead supervisor takes its workers with it". | Treat a running worker at supervisor start as stale; tie each connection to the process the service manager started; require the supervisor's version in hello. |
| DR-5 | `supervisor/control.go` `workerConnected`; `supervisor/workers.go` backoff; `config/store.go` | Hard | Compromised web worker | Answering `failed` then reconnecting makes the supervisor save a new "restored" revision and audit entry each cycle (about 86,000 a day with the 1 s backoff reset), and `prune` deletes the owner's own history. | Restore at most once per revision per run; no new revision when nothing changes; mark the worker suspect after a known-good revision is refused; reset backoff only after a minimum connected time. |
| DR-6 | `ipc/worker.go` reason; `supervisor/control.go` replies and status | Hard | Compromised web worker | A worker's failure reason (up to 2048 bytes, any printable text including bidirectional controls) is shown verbatim in control-panel replies and status; plain text (S-34), but attacker-written instructions inside the trusted panel once Phase 5 exists. | Closed set of reason codes plus a short cleaned detail labelled as coming from the web server. |

Blocked vectors confirmed: rogue control-pipe instances from allowed clients (no create-instance right), supervisor impersonation (owner check plus `O:` in the descriptor), the web worker posing as the tunnel or reaching the token (pipe ACL, account and role checks, secrets ACL), Identification-level identity spoofing, frames from unauthorised accounts, worker messages reaching a path or a log, and internet visitors or a proxied app reaching any pipe.

### Elevated setup

| ID | Location | Exploitability | Attacker | Finding | Fix |
| --- | --- | --- | --- | --- | --- |
| DR-7 | `setup/setup_windows.go` `takeBack` (`filepath.WalkDir` with path-based `ForceSDDLUnlessLinked`); `stopAndWait` | Medium (worker); Hard (standard user, only on a root that user pre-created) | Compromised web or tunnel worker | `uninstall --purge` re-permissions by path while walking top-down, and only the last path component is opened without following links. A worker that ignores stop (setup gives up after 20 s and continues) pads its log folder, then turns an already-listed empty subfolder into a mount point to `C:\Users\` (or `C:\`) during the walk; with SeRestore on, every folder and single-link file under it gets owner Administrators and an Administrators-only DACL, unrecoverably. Contradicts ADR-0006's "handles that do not follow junctions". (Traced, not run.) | Walk relative to open handles (`NtCreateFile` with `FILE_OPEN_REPARSE_POINT`, refuse reparse points, apply on the same handle); turn on redirection trust in the setup role; terminate and confirm services gone before purging, or refuse. |
| DR-8 | `setup/setup_windows.go` `checkDataRoot`, `makeFolders`; `config/store.go` | Hard (microsecond race, visible on failure) | Standard local user | Between `checkDataRoot` seeing no folder and `makeFolders` running, a user can create `%ProgramData%\SoireeHost` with planted contents; `ForceSDDL` fixes only the folder objects, so a planted `config\history` (Everyone full control, inherited by every revision) or `logs\audit\audit.log` survives, and the S-22 start check (folder objects only) passes. Contradicts ADR-0006's promise to refuse a planted folder. | Create the root with `CreateFolderSDDL` first and treat "already exists" as the only existing path; for an existing root check owner and DACL on every entry, or re-permission with the handle-relative walk. |
| DR-9 | `setup/setup_windows.go` `copyBinary` | Hard (setup run from a folder other users can rename in) | Standard local user | Setup copies itself by path after waiting up to 60 s for services to stop; a user who can rename in that folder swaps the file, and the swapped binary is installed as all three services. | Refuse to install from a folder non-admins can write; open the executable once, compare its file ID with the running image, copy from that handle. |

Blocked vectors confirmed: a pre-created root that is a link or user-owned (refused); junctions at subfolders on reinstall (refused, `ForceSDDL` does not follow the last component); the create-then-secure gap (closed by `CreateFolderSDDL`); service and event-log registration (admin-only); purge through a junction at the root or a log folder (Go 1.27 `RemoveAll` is handle-relative and `WalkDir` does not descend mount points); planted hard links (skipped, SE-08 race aside); install while a worker refuses to stop (aborts before folder work).

## Stage 5: Go skills (`cc-skills-golang`)

Two agents applied ten skills. This group (testing, lint, CI, dependency management, project layout) also ran golangci-lint v2.15.0 locally with extra linters and `go mod tidy -diff`. Nothing to report for dependency management (tidy, no replace directives, `GOTOOLCHAIN=local`, every dependency documented) or layout (thin `cmd`, everything under `internal`).

### Testing, lint, CI

| ID | Where | Severity | Gap | Fix |
| --- | --- | --- | --- | --- |
| GOE-1 | `ci.yml`, `.golangci.yml` | Medium | vet, golangci-lint, staticcheck, gosec and govulncheck run on default tags only: the `e2e` tests and the `production` build files are never vetted, linted or scanned in CI. | Lint with `e2e`; vet with `e2e` and `production`; scan with `production`. |
| GOE-2 | `ci.yml` build job | Medium | govulncheck scans source with dev tags, not the shipped binary. | `govulncheck -mode=binary bin/soireehost.exe`. |
| GOE-3 | `.github/` | Medium | No `dependabot.yml`: pinned action SHAs and modules go stale silently. | Weekly grouped updates for gomod, github-actions and npm with a cooldown; no auto-merge. |
| GOE-4 | `ci.yml` | Low | No tidiness check. | `go mod tidy -diff`. |
| GOE-5 | `ci.yml`, `TEST_PLAN.md` | Medium | The plan's 85% coverage target for five packages is never measured in CI. | Coverage profile on the race run and a threshold check (no paid service). |
| GOE-6 | `ci.yml` | Low | No `-shuffle=on` or `-timeout`; order dependence would go unnoticed. | `-shuffle=on -count=1 -timeout 15m`. |
| GOE-7 | `ci.yml` concurrency | Medium | `cancel-in-progress` cancels the nightly run (fuzz and isolation) when `main` is pushed; no job has `timeout-minutes`. | Cancel only pull-request runs; timeouts on every job. |
| GOE-8 | `ci.yml` fuzz, `fuzz.ps1` | Low | A fuzz crasher is lost with the runner. | Upload `testdata/fuzz` on failure; commit minimised crashers. |
| GOE-9 | `winsec/acl_windows.go` (`Owner()` errors discarded in two appliers); `config/store.go` | Medium | `errcheck` `check-blank` finds discarded errors: if the owner cannot be read, it is silently not applied. | Enable `check-blank`; handle the `Owner()` error; explain intentional discards. |
| GOE-10 | `.golangci.yml` | Low | Useful linters off: `forcetypeassert` (unchecked assertions in the control dispatcher), `nilerr`, `thelper`, `govet shadow` (about 25 `err` shadows, some in security paths), `usetesting`, `unparam`. | Enable them and fix the hits. |
| GOE-11 | `ci.yml` | Low | Standalone staticcheck and gosec duplicate the golangci-lint linters. | Drop or justify in a comment. |
| GOE-12 | `supervisor_test.go`, `secrets_test.go`, `e2e_test.go` canary sweeps | Medium | The S-40 secret sweeps ignore read and walk errors and never assert that anything was visited, so they can pass checking nothing. | Fail on errors other than not-exist; assert a visited count. |
| GOE-13 | `ipc/frame.go` | Medium | The pre-authentication frame parser has no fuzz target. | `FuzzReadFrame`, `FuzzDecodeResponse`. |
| GOE-14 | `worker/logfilter.go` | Medium | S-18 redaction tested only with fixed cases. | Fuzz with a canary that must never appear in output. |
| GOE-15 | `worker/guard.go` | Low | Header stripping and host handling tested only through integration tests. | Table and fuzz tests. |
| GOE-16 | `audit/audit.go` | Low | Audit parsers read a file an attacker may shape; no fuzz. | `FuzzVerify`. |
| GOE-17 | `setup/setup_windows.go` | Medium | The elevated role has no unit tests; its folder logic (`checkDataRoot`, `makeFolders`, `copyBinary`, `takeBack`) is testable without admin rights and covers DR-7 to DR-9. | `setup_windows_test.go` with junction and pre-created-root cases. |
| GOE-18 | `fsutil/atomic_windows.go` | Low | `WriteAtomic` has no direct tests. | Replace, failed write, locked target. |
| GOE-19 | `supervisor/workers.go` | Low | Backoff schedule untested; 12 `time.Sleep` polls in tests. | Extract and table-test the backoff; wait-until helper or `testing/synctest`. |
| GOE-20 | supervisor, ipc, worker, svcrun tests | Medium | No goroutine-leak check; R-24's stalled shutdown would pass every test. | Dependency-free leak check at the end of shutdown tests. |
| GOE-21 | several table tests | Low | Table cases without `t.Run`. | Named subtests. |
| GOE-22 | `worker/unit_test.go` | Low | Tests do not map to source files. | Split by source file. |
| GOE-23 | `tunnel/service_windows.go` | Low | No tests (logic arrives in Phase 3). | Add with Phase 3. |

### Security, safety, concurrency, context, error handling

Nothing new at Medium or above: unsafe and syscall pointer use, integer conversions, nil maps and the rate limiter's locking were all checked and found sound. All the new items are Low.

| ID | Where | Gap | Fix |
| --- | --- | --- | --- |
| GO-1 | `ipc/agent_windows.go` reason cut | The 2048-byte cut can split a multi-byte character; JSON then grows it past the limit, the supervisor refuses the `failed` message as invalid, treats the worker as down and restores nothing, so a long non-ASCII error loops. | Cut on a character boundary; test with multi-byte text. |
| GO-2 | `supervisor/workers.go` accept loop; `ipc/pipe_windows.go` | One non-close `Accept` error stops worker accepts for good (status stuck at "starting") or ends the supervisor through `ServeControl`. | Treat as temporary: record, back off, retry; set Down with a reason. |
| GO-3 | `supervisor/control.go` `workerConnected` | Recording an error resets state to running after `serve` set Down. | Separate `setLastErr`. |
| GO-4 | `supervisor/control.go` restore | The result of reloading the restored config is discarded; the user is told it was restored even when it was not loaded. | Check and report it. |
| GO-5 | `supervisor/control.go` `applyWeb` | A `MarkGood` failure after a successful load is reported as "could not be applied". | Distinct error: applied but not recorded. |
| GO-6 | `supervisor/control.go` `secretSet` | Runs outside the change lock and hands the token over with an unordered goroutine: two quick sets can leave the tunnel on the older token; both concurrent first sets skip confirmation; delivery errors hidden. | Serialise; send synchronously or through one goroutine reading the latest value; report errors. |
| GO-7 | `supervisor/workers.go`, `control.go` | Fire-and-forget goroutines can write a rollback or audit entry after stop, or be killed mid-append (a torn line is later reported as a chain break). | Track in `Run`'s wait group. |
| GO-8 | `audit/audit.go` `Append` | If the write succeeds but sync or close fails, the sequence is not advanced and the next entry reuses it, so `Verify` reports tampering the program caused. | Advance after a completed write; return the sync error separately. |
| GO-9 | `supervisor/control.go` `status`; `config/store.go` `History` | A damaged current config shows as revision 0 with no note; `History` hides unreadable entries. | Report read errors. |
| GO-10 | `supervisor/control.go` error codes | Disk failures reported as `invalid` or `not found`. | Classify with `errors.As`; otherwise `internal`. |
| GO-11 | `svcrun/svcrun_windows.go` stop | Stop waits for the role with no deadline and never advances the checkpoint, so a slow stop (R-24's 5-minute control wait) is killed mid-write at shutdown. | Advance the checkpoint on a ticker; hard deadline. |
| GO-12 | `ipc/agent_windows.go` | A goroutine waiting on the context leaks when `RunAgent` returns first. | `context.AfterFunc` with a deferred stop. |
| GO-13 | `winsec/pipeid_windows.go` | On the `RevertToSelf` panic path the thread is unlocked first, so a still-impersonating thread could run other goroutines before the process dies; the comment about Identification level holds only for SoiréeHost's own client. | Unlock only after a successful revert; correct the comment. |
| GO-14 | `worker/rootfs.go` | `sync.OnceValues` caches a failed known-folder lookup for the life of the worker, so every later static load fails. | Cache only success, or look up at start and exit on failure. |
| GO-15 | `ipc/pipe_windows.go` per-connection goroutine; `supervisor/control.go` dispatcher | No `recover` and bare type assertions: any handler panic ends the supervisor and both workers. | Comma-ok assertions; recover at the connection boundary (except `PipeCaller`'s deliberate panic). |

## Stage 6: Semgrep project rules (`semgrep-rule-creator`)

Plan section 10 requires Semgrep with the project's rules in CI; it had been missing since Phase 0. Five rules were written test-first in `.semgrep/`, one rule per file with its own test file, all passing `semgrep --test` (Semgrep 1.185.0, LGPL-2.1-or-later, run with `--metrics=off`, no account):

| Rule | Guards |
| --- | --- |
| `go-no-public-listener` | S-01: no Go listener on an empty, wildcard or non-loopback host |
| `go-no-insecure-skip-verify` | CLAUDE.md rule 6 |
| `go-no-default-servemux` | R-14: nothing serves `http.DefaultServeMux`, where Caddy's imports register pprof and expvar |
| `go-no-secret-in-log` | S-40: taint from the secret store, `SecretSetParams.Value` and `WorkerMsg.Token` to fmt, log, slog, logger methods, the audit log and errors |
| `ts-no-inner-html` | S-34 for TypeScript; Svelte `{@html}` is already refused by ESLint (`svelte/no-at-html-tags`, `--max-warnings 0`) |

The full scan finds nothing in the code. Its one first-run hit (`supervisor/control.go`, the error from `secrets.Store.Set` placed in a reply) was judged a false positive, since `Set` never puts the value in its errors (confirmed under S-40), and the store's `Set` result is a sanitizer in the rule. A new CI job `semgrep` (Ubuntu runner, Semgrep installed with the image's `pipx` at the pinned version, so no action outside the repository's allow list) runs the rule tests and the scan. DR-2 is caught by a Go test with its fix rather than a rule; GO-15's bare assertions by golangci-lint's `forcetypeassert` (GOE-10).

## Owner decisions (13 Nov 2026)

1. **Scope.** Put the security items that are reachable today through `fp-check` and fix them now, with the cheap CI fixes (GOE-1, 2, 4, 6, 7). Items that belong to Phase 3 or Phase 5 code, and the remaining test-quality items, go into a tracked backlog and are fixed when those phases touch the code.
2. **Rollback (R-04).** `config.rollback` asks for confirmation when the target revision has a LAN target the current one lacks. The supervisor's own automatic restore to the last good config stays exempt, because it only restores what was already running, and it is audited.
3. **Plan wording (R-10, R-15, R-16, R-12).** Amend `docs/PLAN.md` and `docs/SECURITY_CHECKLIST.md` so S-13, S-15 and S-16 state the exceptions ADR-0005 recorded, and S-12 lists the extra never-serve names.
4. **Folder check (R-03, R-25).** The supervisor checks every folder in the table at start (owner, writers, no links). Worker log folders keep modify rights because log rotation deletes old files; the plan's table is corrected to say so.

## Stage 7: verification (`fp-check`)

Each security item in the owner's scope went through `fp-check`: restatement, data flow, exploitability, impact, proof of concept with a negative case, the 13 devil's-advocate questions, and the six gates. Proofs that need no administrator rights are Go tests named `fpcheck_<id>_test.go`, which fail before the fix and become its regression test; proofs that need administrator rights are written for the CI isolation job. Full analyses are in the session scratchpad (`fp-check/batch-A.md` to `batch-D.md`).

### Batch B: web-worker request path

| ID | Verdict | Severity | Notes |
| --- | --- | --- | --- |
| DR-2 | True positive | Medium (High once a lower-trust config source such as backup import exists) | Proof served a file outside the site folder and a worker environment variable in 200, 404 and guard-404 responses. |
| R-11 | True positive | Low | Seven forged forwarding names and two trailers reach the app; harmful only for an app that trusts one of them. |
| SE-32 | True positive | Low; Medium chained with DR-2 | `code`, `sig`, `jwt`, `otp`, `ticket`, `SAMLResponse`, `assertion` in clear in the access log, including `Referer`. |
| R-09 | True positive | Medium (high impact, low likelihood) | A profile-like folder outside `C:\Users` is accepted and its `AppData` served. |
| R-13 | False positive (gates 2, 3, 6) | Informational | RFC 9112 requires the target's host; only loopback clients can send absolute-form, and they can set Host anyway. Wording of S-06 to change; the guard may still refuse a mismatch. |
| R-19 | False positive (gates 2, 3) | Informational | Only the secret's own holder can send a raw `#`. Cheap hardening kept. |
| R-12b | False positive (gates 2, 3, 4) | Informational | `os.Root` never follows junctions (absolute targets); a relative symlink needs admin or Developer Mode and the owner's own act. ADR-0005's "hides links" holds for listings only. |

Exploit chain: DR-2 with SE-32 publishes the access log, and the codes SE-32 leaves in clear, to every visitor (Medium).

### Batch A: elevated setup and permission helpers

| ID | Verdict | Severity | Notes |
| --- | --- | --- | --- |
| DR-7 | True positive | Medium | The real walk, with a junction swapped in after the listing, re-permissioned a file outside the tree (proof without SeRestore; the elevated run is a CI sketch). |
| DR-9 | True positive | Medium | The test renamed its own running binary and the real `copyBinary` installed the swapped file. Needs setup run from a folder others can rename in (folders made under `C:\` qualify by default). |
| DR-8 | True positive | Low | Microsecond, single-attempt race; the S-22 gap it relies on (planted children survive, folder-object check only) is shown by a failing proof. |
| SE-05 | False positive (gates 2, 4) | Informational | The injection works, but only SYSTEM, Administrators or the supervisor can write `control-users.json`, and `authorize` still needs an exact SID. ("Everyone itself" was wrong: `S-1-1-0` is refused by the length check.) Hardening kept. |
| SE-35 | False positive (gates 2, 3, 4) | Informational | Every caller passes a non-empty descriptor. Hardening kept. |
| GOE-9 | False positive (gates 2 to 5) | Informational | `Owner()` cannot fail after a successful parse; S-22 would catch a missing owner. Handle it anyway for the linter. |
| R-07 | False positive (gates 3, 4, 6) | Low (robustness) | The read check is advisory; Windows enforces what the worker can read, and a failed load restores (S-41). Fix kept for a clear error. |

Exploit chain: DR-8 then DR-7 lets a standard user, without compromising a worker, drive the privileged permission rewrite at a later purge (bounded by the DR-8 race; fixing either breaks it).

### Batch D: pipes and supervisor

| ID | Verdict | Severity | Notes |
| --- | --- | --- | --- |
| DR-1 | True positive | Low (availability only) | A non-elevated squatter holding any of the three names made the supervisor fail to start; spoofing is blocked by the owner check. The window must come from a restart, update or crash. |
| DR-3 | False positive (gates 2, 3, 6) | Low hardening | 24 header-only connections held 24 MiB; but the pipe ACL admits exactly the principals the identity check admits, all already trusted. |
| GO-6 | False positive as a vulnerability (gates 2, 3); confirmed Low correctness bug | Low | Two concurrent first sets both skipped confirmation in 18 of 20 runs; the tunnel ended on the older token in 1 to 8 of 40 pairs; two sets failed with access denied while delivery held the blob. Callers are already trusted. |
| GO-15 | False positive (gates 2, 3, 4) | Low hardening | A panicking handler does end the process, but every assertion matches the decoder; 37 hostile calls over all 10 methods did not panic. |
| GOE-12 | False positive as a vulnerability; confirmed Medium test-assurance gap | Medium (assurance) | The sweeps pass blind on unreadable files and folders. The CI e2e sweep runs as an administrator, and the secrets folder grants Administrators nothing, so it never sees `secrets`. |

No chain raises severity: the crash triggers that would open the DR-1 window need a trusted control caller, while the squatter is an untrusted account.

### Batch C: worker lifecycle and load path

The gate rule counts a bug as a true positive only when it gives code execution, privilege escalation or information disclosure; availability and compliance defects are recorded as confirmed defects.

| ID | Verdict | Severity | Notes |
| --- | --- | --- | --- |
| R-22 | False positive as a vulnerability; confirmed S-41 defect | Medium (reliability) | No restore on worker crash, timeout or unreadable rollback target. |
| R-24 | False positive as a vulnerability; confirmed defect on all four clauses | Medium for the stop stall and restart storm, Low otherwise | Backoff reset, restarts unlogged, `stop` never sent, exit stalls on idle control connections. |
| R-05 | False positive as a vulnerability; confirmed S-01 and ADR-0005 defect | Low to Medium (defence in depth) | The release worker keeps running after a failed self-check; no periodic re-check. |
| GO-1 | False positive as a vulnerability; confirmed reliability defect | Low to Medium | Reachable with real errors through a junctioned folder. |
| SE-20 | False positive as exploitable today; confirmed hardening gap | Low (down from High) | No attacker path reaches `LoadJSON` with a hand-made config. |
| R-20 | False positive as exploitable on a default desktop; confirmed S-24 gap | Low | The restriction is not in force before `main`; a residual case (themes off, setup run from Downloads) is left for the CI isolation job. |

### Verification result

8 true positives: DR-2, R-09 (Medium); DR-7, DR-9 (Medium); R-11, SE-32, DR-8, DR-1 (Low). 23 false positives as vulnerabilities, of which 13 are confirmed defects or gaps that are still fixed in this round (R-22, R-24, R-05, GO-1, SE-20, R-20, GO-6, GOE-12, DR-3, GO-15, R-07, SE-05, SE-35) and the rest are hardening or wording (R-13, R-19, R-12b, GOE-9).

## Fixes in this round (true positives, 13 to 14 Nov 2026)

| ID | Fix | Regression tests |
| --- | --- | --- |
| R-02 | `go-jose/v4` raised to v4.1.9. | `govulncheck`, `go mod verify` |
| R-01 | go-jose v3 advisories accepted and recorded in `docs/DEPENDENCIES.md`. | — |
| DR-2 | `config` refuses `{` and `}` in response-header values, so no Caddy placeholder can be set. | `TestHeaderValueRefusesPlaceholders` |
| SE-32, R-19 | `RedactURI` masks every query value, keeps names, and treats everything after `?` (including a raw `#`) as query. | `TestRedactURI`, `TestRedactURIRawHash`, `TestRedactURIMasksEveryName`, `TestLogMasksAfterRawHash`, `TestLogMasksCredentialParams`, `TestLogRedaction` |
| R-11 | `StripForwarded` drops headers by shape (name contains "forwarded", ends in "-ip", "client-ip", "remote-addr", with `_` read as `-`), keeping only the exact `Cf-Connecting-Ip` and a valid `X-Forwarded-Proto`; request trailers lose every forwarding name, again once the body ends. | `TestStripForwarded`, `TestStripsOtherForwardedSpellings`, `TestStripsForwardedTrailers`, `TestForwardedHeaders` |
| R-09 | `DefaultLocations` lists every profile from the `ProfileList` registry key; a profile anywhere, or a folder containing one, is refused; `appdata` and `ntuser.dat` join the never-serve names. | `TestDefaultLocationsListsProfiles`, `TestCheckRootRefusesProfileOutsideUsers`, `TestStaticRefusesAppData`, `TestAppDataNeverServed` |
| DR-7 | New `winsec.WalkTree` opens every entry relative to its parent's handle without following reparse points; `takeBack` sets descriptors on those handles. Uninstall keeps the data folder unless every service process has exited. | `TestTakeBackWalkIgnoresSwappedJunction`, `TestTakeBackWalkStaysInsideRoot`, `TestTakeBackWalkIgnoresExistingJunction`; the elevated purge runs in the CI isolation job |
| DR-8 | Creating the data root decides whether it existed; an existing root is walked and refused if any entry is a link, a hard-linked file, or owned by anyone but Administrators, SYSTEM or a SoiréeHost service. | `TestCheckContents*` (4) |
| DR-9 | Setup refuses a folder that anyone but the person running it, Administrators, SYSTEM or TrustedInstaller can change, holds the program open without write or delete sharing from the start, and copies from that handle. The CI isolation job runs setup from a folder only SYSTEM and Administrators can change. | `TestOpenSelfHoldsTheProgram`, `TestOpenSelfRefusesFolderOthersCanChange` |
| DR-1 | The supervisor names its three pipes with 128 random bits at every start and writes each name to a pipe-name file that it owns, in a folder of its own under `config` that setup creates so that only the pipe's clients (plus SYSTEM and Administrators) may read it; workers and the control panel read the file, check its owner and dial that exact name. | `TestNewPipeNameIsRandom`, `TestDialFileConnects`, `TestReadPipeNameRefuses`; the supervisor tests publish under the installed descriptors; `TestSecondUserLockedOut` (a second user cannot read the files); the e2e tests and workers use the files in CI |

Also: gosec now skips `.semgrep` (the rule fixtures are deliberately bad code), in CI, `CLAUDE.md` and the testing reference.

## Backlog for the next round

Tracked here until fixed. The fp-check proof tests for these items are kept outside the repository (they fail by design) and come back as regression tests with their fixes.

- **Confirmed defects (fp-check):** R-22, R-24, R-05, GO-1, SE-20, R-20, GO-6, GOE-12, DR-3, GO-15, R-07, SE-05, SE-35.
- **Hardening and wording:** R-13 (S-06 wording; guard may refuse a host mismatch), R-19 guard refusal of a raw `#`, R-12b (refuse reparse points in `RootFS`), GOE-9 (handle `Owner()` errors).
- **Owner decisions of 13 Nov 2026 still to apply:** rollback confirmation (R-04), plan and checklist wording for S-12, S-13, S-15, S-16, and the folder check at start for every folder (R-03, R-25).
- **Lower-priority review items:** remaining R-, SE-, DR-, GO- and GOE- items not listed above, in their tables.
- **Phase-bound:** Phase 3 (R-06, R-21, SE-21), Phase 5 (SE-07, SE-27 to SE-30, DR-6, GrantSiteAccess re-audit).

## Pre-merge review of the fixes (14 Nov 2026)

One focused review agent read the whole diff for correctness and security (in place of a multi-agent review, to stay within the week's usage). No High findings. Its findings and what was done:

| Severity | Finding | Done |
| --- | --- | --- |
| Medium | The first DR-1 fix found pipes by listing the namespace; pipe listings are sorted, so 64 decoys named to sort first (`soireehost-web-.0`...) kept workers from ever reaching the supervisor, at any time. | Replaced: names are published in owner-checked pipe-name files; nothing lists pipes any more. |
| Medium | `control-users.json` took the elevated token's default owner (the user's own account on a full administrator token), so a reinstall would be refused by the new contents check, with advice to delete the data root. | The file is written with an explicit owner (Administrators) and descriptor; the administrator running setup is also an accepted owner; the refusal names the file instead of advising deletion. |
| Low | Uninstall could see a worker as stopped with no process id after the supervisor stopped it. | Every service's process id is recorded before anything is stopped, and each is waited on. |
| Low | An existing data root was walked before it was locked. | The root's descriptor is set first, then the contents are checked. |
| Low | A query item without `=` (`/verify?<token>`) was logged in clear. | Masked. |
| Low | The forwarding-name rule missed `X-Azure-ClientIP`, `X-Azure-SocketIP`, `Cf-Connecting-Ipv6`, `Cf-Pseudo-Ipv4`, `X-Envoy-External-Address`. | Matched; added to the test list. |
| Low | An agent with no pipe and no pipe-name file would match every pipe. | It now returns an error. |
| Low | `openSelf` checks the folder by path, not on the opened handle; with over-the-shoulder elevation the standard user's Downloads folder is refused. | Kept for the backlog: the writer check blocks any untrusted renamer, so the path check is safe in practice. |
| Docs | ADR-0006 still showed a fixed pipe name; the checklist credited new tests to the 12 Nov CI run. | Fixed. `docs/PLAN.md` still names fixed pipes and the old S-18 masking; changing the plan is the owner's call and is in the backlog. |

Checked and found sound by the review: the directory-listing parser, `WalkTree` handle use, service-owned files passing the contents check, the web worker reading `ProfileList` (Users may read the key), DR-2, the removed pipe constants.

After the fixes: `go vet` (default, `production`, `e2e`), `go test ./...`, golangci-lint (with `e2e`), staticcheck, gosec, govulncheck, gitleaks and the project Semgrep rules are clean; `FuzzCheckStatic`, `FuzzCheckProxy` and `FuzzDecode` ran 10 minutes each with no failure. The elevated paths (install, reinstall, purge, pipe-name files read by the real service accounts) are exercised only by the CI isolation job.

## CI and merge (14 Nov 2026)

The CI isolation job, the first run of the elevated paths, found two faults, fixed on the pull request before the merge:

| Fault | Fix |
| --- | --- |
| `TestCheckContentsRefusesOtherOwner` passed nothing to refuse on the elevated runner, where new entries are owned by Administrators. | The test sets the planted entry's owner to the test account explicitly. |
| The supervisor service could not start: creating a pipe-name file with its own descriptor was refused in `config`. The folder's OWNER RIGHTS entry, which keeps a file's creator from granting itself more, also refuses any descriptor passed at creation, whether or not the token is restricted. | Setup creates one folder per pipe-name file (`config\pipe-control`, `config\pipe-web`, `config\pipe-tunnel`) with the pipe's clients as inheritable readers; the supervisor writes plain files that take those permissions. The supervisor tests now build these folders with their installed descriptors and fail on the old write path. Recorded as rule 13 of the conventions skill. |

Every CI job then passed, the isolation job included (run 43571470671), and pull request 3 was merged into `main` on 14 Nov 2026.

## Cleanup round before Phase 3 (14 Nov 2026)

The owner chose to clear the Phase 1 and 2 backlog before Phase 3. Fixed, each with regression tests (the fp-check proof tests restored where they existed):

| ID | Fix | Regression tests |
| --- | --- | --- |
| SE-20 | `worker.LoadJSON` refuses any config that does not disable the admin API and config persistence, and any other `admin` or `admin.config` key (Caddy starts `admin.remote` even when the admin API is disabled), checking every duplicate the decoder would merge. | `TestLoadJSONRefusesAdminAPI`, `TestCheckAdminOffAcceptsBuiltConfig` |
| SE-05 | Control users must be one user account's SID in canonical form (`winsec.UserSID`). | `TestReadControlUsers` |
| SE-35 | `ipc.Listen` refuses an empty descriptor. | `TestListenRefusesEmptySDDL` |
| DR-3 | The control pipe identifies its caller after the frame header, before any payload is read; payloads are read as they arrive; at most 16 connections are served at once. | `TestRefusedCallerHoldsNoMemory`, `TestReadFramePayloadGrowsWithData`, `TestControlConnectionLimit` |
| GO-15 | A handler panic fails only its call; the dispatcher's type assertions are checked. | `TestHandlerPanicIsContained` |
| GO-1 | Failure reasons are made valid UTF-8 and cut on a character boundary. | `TestCutReason`, `TestFailedReasonReachesSupervisor`, `FuzzCutReason` |
| R-22 | A load the worker dies on or does not answer counts as refused and the change is undone; if the last good revision cannot be read, the settings in force before the change are restored; at reconnect only an explicit refusal rolls back, and a failed restore is reported and audited. Rollback now restores the current settings, not the defaults, if it is refused. | `TestRefusedChangeIsUndone`, `TestWorkerCrashOnChangeIsUndone`, `TestWorkerTimeoutOnChangeIsUndone`, `TestRefusedChangeRestoresWhenLastGoodUnreadable` |
| R-24 | The restart delay resets only after a minute connected; restarts are audited (`worker.restart`, hourly once at the cap); `stop` is sent; control connections close when the supervisor stops. ADR-0006 updated. | `TestRestartBackoffSurvivesHello`, `TestWorkerRestartIsRecorded`, `TestStopIsSentToWorkers`, `TestIdleControlConnectionDoesNotStallExit` |
| R-05 | The release worker exits after a failed self-check and repeats the check every minute. | `TestAgentExitsAfterFatalLoad`, `TestWatchListenersEndsWithContext`, `TestWatchListenersStopsOnPublicSocket` (CI) |
| R-20 | `internal/dllsearch` restricts DLL search from a package init that runs before Wails' init. | `TestPlantedDLLNotLoadedBeforeMain` (fails with the init disabled) |
| R-07 | A failed web-worker read check refuses the site. | covered by the `site.put` tests |
| GOE-9 | `Owner()` errors are handled; the store refuses to save when a damaged current file cannot be set aside. | existing store and ACL tests |
| GOE-12 | Canary sweeps fail on anything they cannot read and must read the secrets, config and audit files; the e2e sweep reads with backup semantics. | the sweeps in `TestTunnelTokenWriteOnly`, `TestSetGetEncrypted`, `TestTunnelTokenCanary` |
| R-04 | Rolling back to a revision with a LAN target the current settings lack, or pointing a site at a new LAN device, needs confirmation and is audited (owner decision 2). | `TestRollbackToLANNeedsConfirmation`, `TestWeakeningNeedsConfirmation` |
| R-03, R-25 | The supervisor checks every folder of one shared table at start (exists, not a link, owner, writers); setup builds the folders from the same table (owner decision 4). | `TestFolderCheck*` (4), `TestNewRefusesWritableFolders` |
| R-10, R-15, R-16, R-12 | `docs/PLAN.md` and `docs/SECURITY_CHECKLIST.md` wording for S-12, S-13, S-15, S-16 and S-22, and the plan's log folder row (owner decisions 3 and 4); ADR-0005 records the net/http responses. | — |

Reviews: the pre-merge code review (`code-review` at high) found seven issues in this round's own changes; six were fixed before commit (the admin guard's `remote`/`identity` gap and duplicate merging, a 10-second first-frame timeout that would have broken early-dialling clients, LAN retargeting of an existing site, reconnect rollback on a slow first load, unbounded restart auditing, duplicated privilege code). The seventh is accepted: the folder tests leave folders the non-elevated test account cannot delete under `%TEMP%`. The security review (a security-focused subagent, which also covered the earlier unreviewed pipe-name folder commits `0c81582` and `2d09803`) found nothing at its reporting bar. `FuzzCutReason`, `FuzzDecodeRequest` and `FuzzDecodeWorkerMsg` ran 10 minutes each with no failure.

Still open: SE-21, GO-6, R-06 and R-21 belong to Phase 3 code; `docs/PLAN.md` still names fixed pipe names and the old S-18 masking (the owner's call); the remaining lower-priority items stay in their tables.

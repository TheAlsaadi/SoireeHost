# Security checklist

Every S-ID from docs/PLAN.md with the test that proves it and its latest result. A requirement with no passing test or recorded manual check is **not met**. Test types are defined in docs/TEST_PLAN.md.

Status values: **Not started**, **Partial** (some of it tested), **Pass**, **Fail**, **Manual** (recorded manual check, with date).

Last updated: 12 Nov 2026, end of Phase 0.

## 5.1 Network exposure

| ID | Requirement (short) | Phase | Test | Status |
| --- | --- | --- | --- | --- |
| S-01 | No non-loopback listener; config rejects it; worker self-check exits | 1 | Config validation table test; worker start test with forced bad listener | Not started |
| S-02 | No inbound allow rule; block rules for both executables | 3 | Setup test on CI admin runner reads firewall rules | Not started |
| S-03 | Tunnel-only, no port-forward setting | 3 | Config schema test: no such field; exposure check | Not started |
| S-04 | Caddy admin API off; no debug/metrics endpoints; cloudflared metrics loopback or off | 1 | Generated Caddy JSON has `admin.disabled`; listener enumeration | Not started |
| S-05 | Trust only `CF-Connecting-IP`; drop other forwarded headers | 1 | Integration: spoofed `X-Forwarded-For` ignored | Not started |
| S-06 | Unknown Host gets 404 (including quick share) | 1, 3 | Integration: unknown host; quick share assigned-host test | Not started |

## 5.2 Web worker

| ID | Requirement (short) | Phase | Test | Status |
| --- | --- | --- | --- | --- |
| S-10 | Proxy targets loopback only; LAN opt-in; link-local and own ports refused | 1 | Config validation table test + fuzz | Not started |
| S-11 | Static roots canonicalised; blocked folders; no escaping links | 1 | `sitecheck` table tests; junction/symlink integration test | Not started |
| S-12 | Never serve dotfiles and secret file types; no listings by default | 1 | Path traversal suite | Not started |
| S-13 | Reject 8.3 names, ADS, trailing dots/spaces, device names, backslashes, encoded traversal | 1 | Path traversal suite + `sitecheck` fuzz | Not started |
| S-14 | Coraza + CRS blocking at PL1 by default; per-site modes; warning when off | 4 | Firewall attack/normal sets | Not started |
| S-15 | Body, header, timeout and rate limits | 1 | Integration: limits and 429 | Not started |
| S-16 | Default security headers, no `Server` | 1 | Integration: response headers | Not started |
| S-17 | Private sites require valid Access JWT, fail closed | After 1.0 | JWT tests | Not started (after 1.0) |
| S-18 | Logs drop credentials and mask secret-like query params; rotation cap | 1 | Log redaction integration test | Not started |

## 5.3 Process isolation

| ID | Requirement (short) | Phase | Test | Status |
| --- | --- | --- | --- | --- |
| S-20 | Separate services, virtual accounts, restricted SID, trimmed privileges, quoted path, service security descriptors | 2 | CI admin runner: `sc qsidtype`, `sc sdshow`, privilege list; ordinary user cannot start/stop workers | Not started |
| S-21 | Job object, no child processes, memory cap, UI restrictions for workers and cloudflared | 2, 3 | Worker test build tries `cmd.exe` and fails | Not started |
| S-22 | Folder ACLs checked at start; refuse if writable by users | 2 | ACL drift test | Not started |
| S-23 | cloudflared unpacked only by setup, runs from install folder, hash checked every launch, `--no-autoupdate`, token never on command line | 3 | Modified binary refused; command-line canary check | Not started |
| S-24 | DLL search restricted to System32 (WebView2 exception recorded if needed); `-trimpath`, CGO off; ASLR, DEP, high-entropy VA | 0, 2 | `build/pecheck` in CI checks the PE flags; build script uses `-trimpath` and `CGO_ENABLED=0`. DLL restriction from Phase 2 | Partial: binary flags Pass locally 12 Nov 2026 |

## 5.4 Control plane and control panel

| ID | Requirement (short) | Phase | Test | Status |
| --- | --- | --- | --- | --- |
| S-30 | Pipe ACL; remote clients rejected; caller SID checked | 2 | Second local user in VM; remote-flag test | Not started |
| S-31 | Small typed API; no command or arbitrary path parameters | 2 | API decode fuzz; review of message types | Not started |
| S-32 | Weakening actions need confirmation and audit entry | 2 | Supervisor tests per weakening action | Not started |
| S-33 | Bundled content only, strict CSP, navigation locked, no dev tools in release | 5 | Release build check; CSP test | Partial: CSP meta tag in `frontend/index.html`; release builds use the `production` tag, which turns dev tools off and ignores `FRONTEND_DEVSERVER_URL` |
| S-34 | Outside data rendered as text only; lint fails the build | 5 | `frontend/src/lint-rules.test.ts`; UI injection tests | Partial: lint rules Pass 12 Nov 2026 |
| S-35 | Secrets write-only from the control panel | 2, 5 | API has no read method for secrets | Not started |
| S-36 | Append-only, hash-chained audit log | 2 | Tamper detection test | Not started |

## 5.5 Secrets, config and privacy

| ID | Requirement (short) | Phase | Test | Status |
| --- | --- | --- | --- | --- |
| S-40 | DPAPI under service account; never in config, logs, crash output, backups | 2 | Canary sweep | Not started |
| S-41 | Schema-validated, atomic, versioned config with rollback | 2 | Crash-during-write test; bad config rollback test | Not started |
| S-42 | No telemetry; only tunnel and update check outbound | 6 | Traffic capture in VM | Not started |

## 5.6 Cloudflare credentials

| ID | Requirement (short) | Phase | Test | Status |
| --- | --- | --- | --- | --- |
| S-50 | Tunnel token by default; API mode refuses Global API Key | 3 | Validation test | Not started |
| S-51 | Quick share labelled temporary | 3 | UI copy check | Not started |

## 11. Updates and supply chain

| ID | Requirement (short) | Phase | Test | Status |
| --- | --- | --- | --- | --- |
| S-60 | Pinned Ed25519 key; manifest and artifact must verify | 6 | Wrong key, missing signature, bad signature | Not started |
| S-61 | Authenticode check once signed; never signed to unsigned | 6+ | Unsigned candidate refused when running signed | Not started |
| S-62 | No downgrades or same version | 6 | Older and equal version refused | Not started |
| S-63 | Supervisor-only download folder; verify twice; keep previous; auto rollback | 6 | Truncated download; kill during swap; failed start rollback | Not started |
| S-64 | One-click install through the Windows prompt via `setup apply-update` | 6 | Manual check in VM | Not started |
| S-65 | Upstream security fixes released within 7 days; watcher opens PRs with a GitHub App token | 6 | Watcher workflow dry run | Not started |
| S-70 | `go.sum`, `-mod=readonly`, checksum DB on; npm lockfile and `npm ci --ignore-scripts` | 0 | CI sets `GOFLAGS=-mod=readonly`, runs `go mod verify`; CI and build script use `npm ci --ignore-scripts` | Partial: config in place; Pass once CI runs on GitHub |
| S-71 | cloudflared SHA-256 checked against committed value before embedding | 3 | Build fails on mismatch | Partial: value committed in `build/cloudflared.lock` |
| S-72 | Actions pinned by SHA; least-privilege tokens; no secrets in PR builds; signing only on tagged main | 0, 6 | Workflow review | Partial: all actions SHA-pinned, `contents: read`, `persist-credentials: false`; no secrets used yet |
| S-73 | SBOM and provenance per release | 6 | Release workflow output | Not started |
| S-74 | Reproducible builds | 6 | Build twice, compare hashes | Not started |
| S-75 | Written reason and supply-chain review for each new dependency | 0 | docs/DEPENDENCIES.md; `supply-chain-risk-auditor` pass | Partial: reasons and licences recorded; auditor pass waits for plugin install |

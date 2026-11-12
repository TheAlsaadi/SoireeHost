# Test plan

Turns plan section 10 into concrete tests per layer and phase. Rule: every security requirement is proven by a test that tries to break it. `docs/SECURITY_CHECKLIST.md` maps each S-ID to its test and latest result.

## Where tests run

| Environment | What runs there | Why |
| --- | --- | --- |
| Every commit, CI (`windows-2025`) | Go unit and table tests with `-race`, frontend tests, lint, static analysis, `govulncheck`, `npm audit`, secret scan, CodeQL, binary flag check, path traversal suite | Fast; no admin rights needed |
| Nightly, CI | Every Go fuzz target for 10 minutes (`build/fuzz.ps1`), dependency scans again | Catches what new advisories and longer fuzzing find |
| CI with admin (from Phase 2) | Service install, ACLs, pipe ACL, job objects, uninstall. GitHub-hosted runners have admin rights and are thrown away after each job | Keeps admin-level tests off the owner's PC (machine rule) |
| Windows 11 VM (from Phase 2) | Second local user, reboot survival, full install-to-live-site, traffic capture, port scan from a second machine | Needs a real Windows 11 desktop and a second machine |
| Before release | 8-hour fuzz per target, 72-hour soak, canary-token sweep, manual checks | Plan section 10 |

**VM note:** this PC runs Windows 11 Home, which has no Hyper-V or Windows Sandbox. The free route is VirtualBox (base package, GPLv2; skip the Extension Pack, whose licence is not free for every use) with Microsoft's free Windows 11 Enterprise evaluation image (90 days, renewable by reinstalling). Installing VirtualBox needs admin rights, so it waits for the owner's go-ahead before Phase 2.

## Layers

### Unit and table tests (Go, Vitest)

Every package. Pure functions get table tests with hostile inputs as well as normal ones: config validation, path rules, hostname rules, header filtering, log redaction, version parsing, manifest verification. Coverage target: 85% of statements in `internal/config`, `internal/sitecheck`, `internal/secrets`, `internal/update`, `internal/ipc`, `internal/audit`; no fixed target elsewhere.

### Fuzzing (Go native)

One target per parser or validator that sees outside data:

| Target | Package | From phase |
| --- | --- | --- |
| Version string | `internal/version` | 0 (exists: `FuzzValid`) |
| Config JSON decode and validate | `internal/config` | 1 |
| Static root and request path rules | `internal/sitecheck` | 1 |
| Hostname validation | `internal/config` | 1 |
| Control-API message decoding | `internal/ipc` | 2 |
| Update manifest parse and verify | `internal/update` | 6 |

Each fuzz finding becomes a seed in `testdata/fuzz/` and a regression test.

### Integration (in-process)

The web worker started in-process on a random loopback port with a test config, driven by `net/http` clients:

- **Path traversal suite** (Phase 1, every commit). Each must return 400 or 404 and never file content: `/../win.ini`, `/..%2fwin.ini`, `/..%5cwin.ini`, `/%252e%252e/`, `/SECRET~1.TXT`, `/index.html::$DATA`, `/index.html.`, `/index.html%20`, `/CON`, `/nul.txt`, `/COM1`, `/.git/config`, `/.ENV`, `/.Env`, `/key.PEM`, a junction pointing outside the root, a symlink pointing outside the root.
- **Headers and limits** (Phase 1): default security headers present, no `Server` header, body over 10 MB refused, rate limit returns 429 after 300 requests a minute from one `CF-Connecting-IP`, spoofed `X-Forwarded-For` ignored.
- **Host check** (Phase 1, Phase 3): unknown `Host` gets 404; quick share port answers only its assigned hostname.
- **Firewall** (Phase 4): fixed attack set (SQL injection, XSS, traversal, scanner user agents) gets 403 and a firewall log entry; fixed normal set (static site, a typical JSON API, form posts, file upload under the limit) passes at paranoia level 1.
- **Log redaction** (Phase 1): requests carrying `Authorization`, `Cookie`, `?token=`, `?password=` produce log lines without those values.

### Isolation (CI with admin, then VM)

From Phase 2. Each attempt must fail:

- Web worker test build starts `cmd.exe`.
- Web worker reads `%ProgramData%\SoireeHost\secrets\`.
- Web worker writes outside its log folder.
- An ordinary user opens `\\.\pipe\soireehost-control` (VM, second user).
- An ordinary user starts or stops a worker service.
- Config or secrets folder made writable by Users: supervisor refuses to start.
- Supervisor killed: both workers exit within 5 seconds.

### UI (Vitest, then manual)

- Lint rules for S-34 are themselves tested (`frontend/src/lint-rules.test.ts`, exists).
- Phase 5: component tests render hostile strings (`<script>`, `<img onerror>`, RTL override characters, 10 KB lines) from paths, hostnames, user agents and site names, and assert they appear as text.
- Phase 5: accessibility review at WCAG 2.1 AA, full keyboard pass, Windows high-contrast and 200% text size, manually and with the `design:accessibility-review` skill.

### Exposure (from Phase 3)

- `Get-NetTCPConnection` and `Get-NetUDPEndpoint` for every SoiréeHost process: only `127.0.0.1` or `::1`.
- Port scan of the PC from a second machine on the LAN: no open port belonging to SoiréeHost.
- Traffic capture (Phase 6): only Cloudflare tunnel endpoints and the GitHub update URL.

### Updates (Phase 6)

Tampered binary, manifest signed with a wrong key, truncated download, older version, same version, signature missing, interrupted install (kill during swap), supervisor fails to start after swap (rollback).

### Secrets (each release)

Plant canary tokens as the tunnel token and in site config, run the app through a session, then search logs, config, backups, crash dumps and process command lines (`Get-CimInstance Win32_Process`).

### Soak (before release)

72 hours serving a static site and a proxied app under steady load, with tunnel drops and service restarts injected every few hours. Pass: no crash, memory and handle counts flat after warm-up, every request served or cleanly failed.

## Current coverage (Phase 2 in progress)

| Area | Tests |
| --- | --- |
| Role dispatch | `cmd/soireehost/main_test.go`: valid roles, unknown roles, unbuilt roles exit 2 |
| Version | `internal/version`: table tests, malformed link-time value, `FuzzValid` |
| UI version binding | `internal/gui/gui_test.go` |
| Version label in UI | `frontend/src/lib/version.test.ts`, including HTML payloads |
| S-34 lint rules | `frontend/src/lint-rules.test.ts` |
| S-24 binary flags (ASLR, DEP, high-entropy VA) | `build/pecheck` in CI; unit tests in `build/pecheck/main_test.go` |
| Config schema and validation (S-01, S-03, S-06, S-10) | `internal/config`: table tests with hostile values, strict decoding, fuzz targets `FuzzDecode`, `FuzzHostname`, `FuzzTarget`, `FuzzRootSyntax`. Coverage 94.8% |
| Path rules and static roots (S-11, S-12, S-13) | `internal/sitecheck`: path tables, `FuzzCheckStatic`, `FuzzCheckProxy`, root checks against fake and real system folders, junctions. Coverage 85.2% |
| Web worker (S-01, S-04, S-05, S-06, S-12, S-15, S-16, S-18) | `internal/worker`: in-process worker on a random loopback port with a static site, a proxy site and a listing site, driven by raw TCP requests (path traversal suite, headers, limits, forwarding, host check, log redaction, listener self-check); unit tests for the limiter, filters, file system and config builder. Coverage 86.0% |
| Worker role CLI | `cmd/soireehost/main_test.go`: `worker` needs `-config` in development builds; release builds refuse the role until Phase 2 |
| Windows security helpers (S-20 to S-24, S-30) | `internal/winsec`: service SIDs against Windows' own, descriptor parsing, the S-22 writer check, confinement in a re-run copy of the test binary (no `cmd.exe`, one privilege, System32-only DLLs) |
| Stores (S-36, S-40, S-41) | `internal/audit` (chain and tamper cases), `internal/secrets` (DPAPI round trip, nothing in clear on disk, tampered blob refused), `internal/config` store (history, rollback, damaged file) |
| Control API and pipes (S-30, S-31, S-35) | `internal/ipc`: strict decoding tables, `FuzzDecodeRequest`, `FuzzDecodeWorkerMsg`, real pipes for caller identity, owner check against squatting, exclusive creation |
| Supervisor (S-22, S-32, S-40, S-41) | `internal/supervisor`: the real supervisor in-process with real pipes and real Caddy (web worker) and a stand-in tunnel worker: control flow, blocked folders, confirmation, rollback of a refused config, token canary, worker restart, workers ending with the supervisor, folder refusal |
| Installed system (CI admin runner only) | `internal/e2e` (build tag `e2e`), run by the `isolation` CI job between `setup install` and `setup uninstall --purge`: service configuration, serving through the installed services, a second local user locked out, workers in job objects, token canary in files and command lines, killing and stopping the supervisor ends both workers, ACL drift refused, and nothing left after uninstall |

Gap: the GUI window itself is checked by hand (it opens, shows the version, owns no TCP or UDP endpoint). Automating that waits for Phase 5.

Two kinds of test run only on CI runners, which have admin rights and no desktop:

- `TestSelfCheckStopsPublicListener` binds `0.0.0.0`, which on a desktop makes Windows Firewall ask to allow the test binary (machine rule). It skips unless `CI` is set.
- The symbolic-link cases in `TestPathTraversalSuite` (`/link.txt`, `/rellink.txt`) need Developer Mode or admin to create the links. Without them the test logs that the links were not created; the junction cases run everywhere.

Test fixtures that must be publishable live in `testsite-*` folders created in the package directory (`testutil.SiteDir`), because `t.TempDir()` is under `AppData`, which S-11 refuses.

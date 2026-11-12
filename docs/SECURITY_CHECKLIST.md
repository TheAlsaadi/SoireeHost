# Security checklist

Every S-ID from docs/PLAN.md with the test that proves it and its latest result. A requirement with no passing test or recorded manual check is **not met**. Test types are defined in docs/TEST_PLAN.md.

Status values: **Not started**, **Partial** (some of it tested), **Pass**, **Fail**, **Manual** (recorded manual check, with date).

Last updated: 12 Nov 2026, Phase 2 in progress (local runs; the CI isolation job has not run yet). `FuzzDecodeRequest` and `FuzzDecodeWorkerMsg` each ran 10 minutes locally without a crash. End of Phase 1: Phase 1 was merged through pull request 1, with CI green on the pull request (run 43232776044) and on `main` after the merge (run 43236752556). Phase 0's first green CI run: 43191377974. The symbolic-link cases in `TestPathTraversalSuite` only log, rather than fail, if the runner cannot create links; the job log needs a GitHub sign-in and was not read, so whether they ran is not confirmed. Test names refer to `internal/config`, `internal/sitecheck` and `internal/worker` unless a path is given. Fuzz targets `FuzzDecode`, `FuzzHostname`, `FuzzTarget`, `FuzzRootSyntax`, `FuzzCheckStatic` and `FuzzCheckProxy` each ran 10 minutes locally on 12 Nov 2026 without a crash. The end-of-phase security review found one gap (Windows name aliases of never-serve files on proxy sites), now fixed and tested.

## 5.1 Network exposure

| ID | Requirement (short) | Phase | Test | Status |
| --- | --- | --- | --- | --- |
| S-01 | No non-loopback listener; config rejects it; worker self-check exits | 1 | `TestParseListen`, `TestSiteValidation`, `FuzzDecode`; worker: `TestCheckEndpoints`, `TestOwnEndpointsSeesLoopbackListener`, `TestNoAdminAndOnlyLoopback`, `TestBuildCaddyJSON`. `TestSelfCheckStopsPublicListener` (worker loads a 0.0.0.0 config and must stop) runs in CI only, because binding a public address makes Windows Firewall prompt on a desktop | Pass in CI 12 Nov 2026 (PR 1 run 43232776044; main 43236752556), including the CI-only test |
| S-02 | No inbound allow rule; block rules for both executables | 3 | Setup test on CI admin runner reads firewall rules | Not started |
| S-03 | Tunnel-only, no port-forward setting | 3 | `TestSchemaHasNoExposureSetting`, `TestDecodeStrict` (unknown fields refused); exposure check in Phase 3 | Partial: schema tests Pass in CI 12 Nov 2026 (PR 1 run 43232776044; main 43236752556) |
| S-04 | Caddy admin API off; no debug/metrics endpoints; cloudflared metrics loopback or off | 1 | `TestBuildCaddyJSON` (admin disabled, no autosave, no metrics, HTTP/1 only); `TestNoAdminAndOnlyLoopback` (only the configured socket is open, nothing on 2019, no autosave or data-folder writes). cloudflared part in Phase 3 | Partial: Caddy part Pass in CI 12 Nov 2026 (PR 1 run 43232776044; main 43236752556); cloudflared in Phase 3 |
| S-05 | Trust only `CF-Connecting-IP`; drop other forwarded headers | 1 | `TestForwardedHeaders` (forged `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `True-Client-IP` never reach the app; app sees the `CF-Connecting-IP` address), `TestStripForwarded`, `TestRateLimit` (forged `X-Forwarded-For` does not reset the count) | Pass in CI 12 Nov 2026 (PR 1 run 43232776044; main 43236752556) |
| S-06 | Unknown Host gets 404 (including quick share) | 1, 3 | `TestUnknownHost` (other names, IP, `localhost`, disabled site, suffix tricks, absolute-form target); quick share in Phase 3 | Partial: tunnel-token listener Pass in CI 12 Nov 2026 (PR 1 run 43232776044; main 43236752556); quick share in Phase 3 |

## 5.2 Web worker

| ID | Requirement (short) | Phase | Test | Status |
| --- | --- | --- | --- | --- |
| S-10 | Proxy targets loopback only; LAN opt-in; link-local and own ports refused | 1 | `TestParseTarget`, `TestNormalizeTarget`, `TestLANWarning`, `FuzzTarget`, `FuzzDecode`. The confirmation and audit entry for the LAN opt-in are S-32 (Phase 2) | Pass in CI 12 Nov 2026 (PR 1 run 43232776044; main 43236752556) |
| S-11 | Static roots canonicalised; blocked folders (all of ProgramData and drive-root system folders too, ADR-0005); no escaping links | 1 | `TestValidateRootSyntax`, `FuzzRootSyntax`, `TestCheckRootAccepts`, `TestCheckRootRefuses`, `TestCheckRootRealSystem`, `TestCheckRootJunction`, `TestOpenRoot`, `TestRootFSRefusesBlockedFolder`, `TestRootFSOpenAndStat`, junction and symlink cases in `TestPathTraversalSuite`. Symbolic links need Developer Mode or admin to create, so those two cases run in CI; junctions run everywhere | Pass in CI 12 Nov 2026 (PR 1 run 43232776044; main 43236752556) |
| S-12 | Never serve dotfiles and secret file types; no listings by default; `/.well-known/` only on sites that opt in | 1 | `TestPathTraversalSuite`, `TestCheckStatic`, `TestCheckProxy`, `TestDirectoryListing`, `TestRootFSListingFiltered`, `TestWellKnownOptIn` (sitecheck and worker: served only with the opt-in, nothing hidden or blocked inside it, other spellings refused) | Pass in CI 12 Nov 2026 (PR 1 run 43232776044; main 43236752556) |
| S-13 | Reject 8.3 names, ADS, trailing dots/spaces, device names, backslashes, encoded traversal | 1 | `TestPathTraversalSuite`, `TestCheckStatic`, `TestReservedAndShortNames`, `FuzzCheckStatic`, `FuzzCheckProxy` | Pass in CI 12 Nov 2026 (PR 1 run 43232776044; main 43236752556) |
| S-14 | Coraza + CRS blocking at PL1 by default; per-site modes; warning when off | 4 | Firewall attack/normal sets | Not started |
| S-15 | Body, header, timeout and rate limits | 1 | `TestBodyLimit` (10 MB, with and without Content-Length), `TestHeaderLimitAndTimeout`, `TestRateLimit` (429 after 300 a minute, other client unaffected), `TestLimiterBurstThenRate`, `TestLimiterBoundedAndFailsClosed`, `TestClientKey` | Pass in CI 12 Nov 2026 (PR 1 run 43232776044; main 43236752556) |
| S-16 | Default security headers, no `Server` | 1 | `TestSecurityHeaders` (static, proxy, 400, 404, 429 and unknown-host responses; app's own CSP kept; per-site override), `TestEffectiveHeaders` | Pass in CI 12 Nov 2026 (PR 1 run 43232776044; main 43236752556) |
| S-17 | Private sites require valid Access JWT, fail closed | After 1.0 | JWT tests | Not started (after 1.0) |
| S-18 | Logs drop credentials and mask secret-like query params; rotation cap | 1 | `TestLogRedaction` (planted secrets in `Authorization`, `Cookie`, `X-Api-Key`, `Cf-Access-Jwt-Assertion`, `Set-Cookie`, query and `Referer` never appear in either log), `TestRedactURI`, `TestFilterHeaders`, `TestFiltersDropUnexpectedTypes`; rotation settings in `TestBuildCaddyJSON` | Pass in CI 12 Nov 2026 (PR 1 run 43232776044; main 43236752556) |

## 5.3 Process isolation

| ID | Requirement (short) | Phase | Test | Status |
| --- | --- | --- | --- | --- |
| S-20 | Separate services, virtual accounts, restricted SID, trimmed privileges, quoted path, service security descriptors | 2 | `internal/e2e` `TestServiceConfiguration` on the CI admin runner after `setup install` (account, restricted SID type, quoted path, required privileges = SeChangeNotifyPrivilege only, worker descriptors: interactive users query only); `TestSecondUserLockedOut` (a second local user cannot start or stop the worker services); `winsec` `TestSDDLParses` | Partial: descriptors Pass locally 12 Nov 2026; CI isolation job written, not yet run |
| S-21 | Job object, no child processes, memory cap, UI restrictions for workers and cloudflared | 2, 3 | `winsec` `TestConfineStopsChildProcesses` (a confined copy of the test binary cannot start `cmd.exe` and keeps one privilege), `TestConfineAllowsOneChildForTunnel`; `internal/e2e` `TestWorkersAreConfined` (both service processes are in a job). cloudflared's own job in Phase 3 | Partial: confinement Pass locally 12 Nov 2026; CI isolation job written, not yet run; cloudflared in Phase 3 |
| S-22 | Folder ACLs checked at start; refuse if writable by users | 2 | `winsec` `TestCheckWriters`; `supervisor` `TestRefusesWritableFolders`; `internal/e2e` `TestACLDriftRefused` (secrets made writable by Users on the installed system: the supervisor does not run; fixed: it runs) | Partial: Pass locally 12 Nov 2026; CI isolation job written, not yet run |
| S-23 | cloudflared unpacked only by setup, runs from install folder, hash checked every launch, `--no-autoupdate`, token never on command line | 3 | Modified binary refused; command-line canary check | Not started |
| S-24 | DLL search restricted to System32 (WebView2 exception recorded if needed); `-trimpath`, CGO off; ASLR, DEP, high-entropy VA | 0, 2 | `build/pecheck` in CI checks the PE flags; build script uses `-trimpath` and `CGO_ENABLED=0`. DLL restriction from Phase 2 | Partial: binary flags Pass in CI 12 Nov 2026 (run 43191377974). DLL search restricted to System32 in every role from Phase 2 (`winsec.RestrictDLLSearch` first thing in `main`; `TestConfineStopsChildProcesses` checks it); the control panel's WebView2 loads under it with no exception (checked by hand 12 Nov 2026), so none is recorded |

## 5.4 Control plane and control panel

| ID | Requirement (short) | Phase | Test | Status |
| --- | --- | --- | --- | --- |
| S-30 | Pipe ACL; remote clients rejected; caller SID checked | 2 | `ipc` `TestControlForbidden`, `TestDialRefusesWrongOwner` (pipe squatting), `TestListenExclusive`; `supervisor` `TestAuthorize`; `internal/e2e` `TestSecondUserLockedOut` (a second local user cannot open the control or worker pipes). Remote clients: go-winio sets `PIPE_REJECT_REMOTE_CLIENTS` on every instance and the descriptor denies NETWORK | Partial: Pass locally 12 Nov 2026; CI isolation job written, not yet run |
| S-31 | Small typed API; no command or arbitrary path parameters | 2 | `ipc` `TestDecodeRequest` (unknown methods, fields and types refused), `FuzzDecodeRequest`, `FuzzDecodeWorkerMsg`, `TestWorkerMsgValidate`; method list in ADR-0006 | Pass locally 12 Nov 2026 |
| S-32 | Weakening actions need confirmation and audit entry | 2 | `supervisor` `TestWeakeningNeedsConfirmation` (LAN target), `TestTunnelTokenWriteOnly` (replacing the tunnel token); every change writes an audit entry (`TestControlFlowServesSites`). Turning the firewall off and importing a backup arrive with those features (Phases 4, 6) | Partial: LAN target and tunnel change Pass locally 12 Nov 2026 |
| S-33 | Bundled content only, strict CSP, navigation locked, no dev tools in release | 5 | Release build check; CSP test | Partial: CSP meta tag in `frontend/index.html`; release builds use the `production` tag, which turns dev tools off and ignores `FRONTEND_DEVSERVER_URL` |
| S-34 | Outside data rendered as text only; lint fails the build | 5 | `frontend/src/lint-rules.test.ts`; UI injection tests | Partial: lint rules Pass 12 Nov 2026 |
| S-35 | Secrets write-only from the control panel | 2, 5 | No control method returns a secret (ADR-0006 method list); `secrets` `TestStatusHasNoValue`; `ipc` `TestSecretsNotPrinted`; `supervisor` `TestTunnelTokenWriteOnly` | Partial: API Pass locally 12 Nov 2026; control panel in Phase 5 |
| S-36 | Append-only, hash-chained audit log | 2 | `audit` `TestChainVerifies`, `TestTamperingDetected` (edit, removal, reorder, duplicate, garbage, unknown field), `TestPartialLineThenAppend`; append-only file mode and folder ACL (`AuditFolderSDDL`) | Pass locally 12 Nov 2026 |

## 5.5 Secrets, config and privacy

| ID | Requirement (short) | Phase | Test | Status |
| --- | --- | --- | --- | --- |
| S-40 | DPAPI under service account; never in config, logs, crash output, backups | 2 | `secrets` `TestSetGetEncrypted`, `TestTamperedBlobRefused`; canary sweeps in `supervisor` `TestTunnelTokenWriteOnly` and `internal/e2e` `TestTunnelTokenCanary` (files and process command lines). Backups arrive later | Partial: Pass locally 12 Nov 2026; CI isolation job written, not yet run |
| S-41 | Schema-validated, atomic, versioned config with rollback | 2 | `config` `TestStoreSaveAndHistory`, `TestStoreRefusesInvalid`, `TestStoreRollbackAndGood`, `TestStoreKeepsTenAndGood`, `TestStoreDamagedCurrent`; `supervisor` `TestRefusedConfigIsRolledBack` (a config the web worker refuses is replaced by the last good one and the site keeps serving) | Pass locally 12 Nov 2026 |
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
| S-70 | `go.sum`, `-mod=readonly`, checksum DB on; npm lockfile and `npm ci --ignore-scripts` | 0 | CI sets `GOFLAGS=-mod=readonly`, runs `go mod verify`; CI and build script use `npm ci --ignore-scripts` | Pass in CI 12 Nov 2026 (run 43191377974) |
| S-71 | cloudflared SHA-256 checked against committed value before embedding | 3 | Build fails on mismatch | Partial: value committed in `build/cloudflared.lock` |
| S-72 | Actions pinned by SHA; least-privilege tokens; no secrets in PR builds; signing only on tagged main | 0, 6 | Workflow review | Partial: all actions SHA-pinned, `contents: read`, `persist-credentials: false`; no secrets used yet |
| S-73 | SBOM and provenance per release | 6 | Release workflow output | Not started |
| S-74 | Reproducible builds | 6 | Build twice, compare hashes | Not started |
| S-75 | Written reason and supply-chain review for each new dependency | 0 | docs/DEPENDENCIES.md; `supply-chain-risk-auditor` pass | Partial: reasons and licences recorded, including Caddy and its 150 linked modules (Phase 1); auditor pass waits for the plugin to load in a session |

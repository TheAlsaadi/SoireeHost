# Quality and maintainability review after Phase 5

16 Nov 2026, branch `quality-review`, from `main` at `de88164` (pull request 16 merged). Phases 0 to 5 were reviewed for structure, Go and frontend code quality, tests, build and CI, dependencies and records. The prompt is in `docs/prompts/post-phase5-quality-review.md`.

**Overall.** The codebase was already in good shape:

- every package has a doc comment;
- golangci-lint, staticcheck, gosec and govulncheck were clean;
- every one of the 223 tests the records named existed;
- the frontend had no `any`, no inline styles and no hard-coded user-facing strings.

Most findings are small. Each finding is marked **fixed** (commit and test), **proposed** (waiting on the owner) or **kept** (decided, with the reason).

## Baseline and result

Baseline taken on `main` at `de88164` with the commands in `CLAUDE.md`. "After" figures are from the end of this review.

| Check | Baseline | After |
| --- | --- | --- |
| Full build (`build.ps1`) | pass, 82 s | pass |
| `go vet` | pass | pass |
| `go test ./...` | pass; with `-cover`, two `winsec` tests failed (QR-05) | pass, with and without `-cover` |
| Go test and fuzz functions | 304 tests, 18 fuzz targets | 310 tests, 18 fuzz targets |
| Frontend (`check`, `lint`, `test`) | pass; 117 tests | pass; 118 tests |
| golangci-lint, staticcheck, gosec, govulncheck | clean | clean |
| Fuzz smoke (`fuzz.ps1 -Duration 10s`) | 17 of 18 targets passed; `FuzzStripForwarded` stopped once with "fuzzing process terminated without fuzzing: EOF" (QR-17) | see QR-17 |
| `pecheck`, gitleaks, `check-crs.ps1` | pass | pass |
| Binary size | 64,367,104 bytes | about the same |

Coverage per package, baseline → after: `logread` 0% → 86.5%, `fsutil` 0% → 65.0%. Every other package is the same as before, within a rounding: `config` 94.0, `sitecheck` 87.7, `audit` 86.0, `worker` 84.9, `fwevent` 84.7, `accesslog` 84.5, `waf` 83.8, `supervisor` 83.7, `secrets` 83.3, `ipc` 80.4, `tunnel` 77.2, `cmd/soireehost` 56.0, `winsec` 42.5, `gui` 41.1, `setup` 10.9, `svcrun` 5.3. The low ones (`setup`, `svcrun`, `gui`, `winsec`) are code that installs services, runs as a service or opens a window. The CI `isolation` job (`internal/e2e`) tests it, but that job does not count towards this coverage.

## Findings

### Structure and architecture

| # | Severity | Finding | Outcome |
| --- | --- | --- | --- |
| QR-01 | Medium | There was no developer guide. Two package maps existed: plan section 4 (missing 11 of the 22 packages) and the conventions skill (missing 10). A newcomer could not find the build or the layout from the README | **Fixed**: `docs/DEVELOPMENT.md` covers the tools, build, checks, full package map and the records to keep. The README links to it; plan section 4 points to it; the skill's table lists every package |
| QR-02 | Low | `internal/ipc` imports `accesslog`, `audit` and `fwevent` for their entry types. The protocol package therefore depends on the log readers, and the control panel links that code | **Kept**: the types belong to the packages that produce and validate them. `ipc` only assembles the contract, and moving the types would split each validator from its type. No cycle, and nothing outside the supervisor calls the readers |
| QR-03 | Low | `internal/supervisor` imports `internal/worker` | **Kept**: it uses only `BuildCaddyJSON` and `Scan` (config building), never Caddy at run time; tests use the rest |
| QR-04 | Low | ADR-0001 and ADR-0003 still say "Proposed", although Phases 1 to 5 are built on them | **Fixed** (owner, 16 Nov 2026): both accepted. ADR-0004 (updates) stays Proposed until Phase 6 |
| QR-15 | Low | Two leftover worktrees in `.claude/worktrees/` (`fix-firewall-memory-flake`, `deps-otel-1.47`) and several local branches, all for merged pull requests | **Fixed** (owner, 16 Nov 2026): both worktrees and the 16 local branches merged into `main` removed. Two empty folders remain under `.claude/worktrees/` while another process holds them open |

### Go code

The lint probe enabled 26 extra linters for one run, without changing `.golangci.yml`: `revive`, `gocognit`, `funlen`, `dupl`, `unparam`, `modernize`, `intrange`, `thelper` and others. It found 121 repeated strings (`goconst`, almost all Caddy JSON keys and test data) and 112 other findings.

| # | Severity | Finding | Outcome |
| --- | --- | --- | --- |
| QR-05 | Low | `TestStartConfinedChild` and `TestStartConfinedFromConfinedLauncher` failed under `go test -cover`. The confined child has an explicit environment with no `TEMP`, so its coverage set-up tried the Windows folder and the child exited with status 2 | **Fixed**: `childTemp(t)` gives the child a `TEMP`; conventions skill rule 24 |
| QR-06 | Low | `ipc.RunAgent` starts a goroutine that closes the pipe when the context ends. If the caller's context never ended, that goroutine outlived `RunAgent` | **Fixed**: `RunAgent` cancels its own derived context on return. No other change in behaviour |
| QR-07 | Low | The worker guard compared site types with the literals `"static"` and `"proxy"` instead of `config.TypeStatic` and `config.TypeProxy`. The S-05 client-address header `Cf-Connecting-Ip` was spelled out three times | **Fixed**: the guard uses the config constants, and the header is the single constant `clientIPHeader` |
| QR-08 | Low | `checkFolders` took a `controlUsers` parameter that every caller passed as nil; it checks owners and writers, never readers | **Fixed**: parameter removed, and its comment now says so |
| QR-09 | Low | 27 places could use current Go idioms (`errors.AsType`, `slices.Contains`, `slices.Backward`, `strings.SplitSeq`, `maps.Copy`, `WaitGroup.Go`, range over integers) | **Fixed**. Each loop rewrite in a validator or parser was checked by hand: none changes its index inside the body. The string-builder rewrite of the SDDL builders was left out, because the plain `+=` form is easier to check against the access lists |
| QR-10 | Low | Doc comments of four exported SDDL builders and `ErrAgentExit` did not start with the name. Two local variables shadowed the built-ins `real` and `min`, and a test helper had an unused parameter | **Fixed** |
| QR-11 | Low | High cognitive complexity in: `WorkerMsg.ValidateFor` (58), `RunAgent` (47), `Event.Validate` (35), `Site.validate` (33), `configImport` (37), `Firewall.process` (31), `sitePut` (27), `Uninstall` (29). `StartConfined` has 78 statements | **Kept**: each was read. The validators are flat lists of checks, one per case, which read top to bottom; splitting them adds indirection without making a rule easier to find. The rest are sequential steps with early returns. Revisit any of them when it next changes |
| QR-12 | Low | Mixed pointer and value receivers on `config.Config`, `config.Firewall`, `waf.Firewall`, `worker.Guard`, `RateLimit` and `RootFS` | **Kept**: the Caddy modules need value `CaddyModule` and pointer `Provision`, and the config types use value methods for reading and pointer methods for defaults |
| QR-13 | Low | `procGetExtendedTcpTable` and `procGetExtendedUdpTable` do not follow Go's initialism style | **Kept**: they mirror the Windows API names, which helps anyone checking them against Microsoft's documentation |
| QR-14 | Low | `os.MkdirTemp` in `testutil.SiteDir` and one sitecheck test, where `t.TempDir` would be usual | **Kept**: deliberate. `t.TempDir` is under `AppData`, which S-11 refuses to publish (conventions skill rule 11) |

**Linters to keep these rules from now on.** Enabled in `.golangci.yml` on the owner's word (16 Nov 2026), with the test findings below fixed and modernize's `stringsbuilder` check off for the SDDL builders (QR-09). They were proposed, all free and already inside golangci-lint v2.15.0:

- `modernize` and `intrange`: no findings left.
- `revive` with `exported`, `package-comments` and `redefines-builtin-id`: no findings left except QR-13, which would take one `//nolint` with its reason.
- `errname` and `unparam`: four findings left, all in tests.

This is **proposed**: enabling them changes the lint gate, so the owner decides. `gocognit`, `funlen`, `goconst` and `thelper` are not recommended. Their findings here were noise (QR-11) or style choices in tests.

### Frontend

| # | Severity | Finding | Outcome |
| --- | --- | --- | --- |
| QR-16 | Low | When the service did not answer, a failed action showed "Something went wrong" instead of the catalogue's purpose-written "SoiréeHost's service is not answering…" sentence. `toApiError` falls back to code `unavailable` with no message, and the callers used only the generic fallback. The sentence was in the catalogue, unused | **Fixed**: `errorText` in `lib/errors.ts`, used by the toasts, the first run and the site form, with a test |
| QR-18 | Low | Six message keys nothing used (`common.save`, `common.copy`, `common.loading`, `common.tryAgain`, `common.warnings`, `site.permanent.hostnames`) | **Fixed**: removed |
| QR-19 | Low | Three keys for an exposure-check section (`site.exposureTitle`, `site.exposureNone`, `site.exposureBlocked`) are unused. The supervisor returns the exposure report in every `site.put` and `site.set_enabled` result (ADR-0008), but the control panel shows only the warnings that come with it | **Fixed** (owner, 16 Nov 2026): the three keys are removed. Showing the report, with its list of never-served files, can come in a later phase |
| QR-20 | Low | Four selection and blocked-row bars used a literal `3px`, and the dialog backdrop a literal colour | **Fixed**: `--marker-width` and `--scrim` tokens. The other pixel values are 1–2 px optical adjustments and the QR code's fixed black on white |

### Tests

| # | Severity | Finding | Outcome |
| --- | --- | --- | --- |
| QR-21 | Low | `internal/logread` and `internal/fsutil` had no tests of their own; other packages' tests reached them only partly | **Fixed**: `TestFilesOrderAndFilter`, `TestFilesMissingFolder`, `TestNextLine`, `TestWriteAtomic`, `TestWriteAtomicMissingFolder` |
| QR-22 | Medium | Nothing checked that the tests named in the security checklist still exist. All 223 names did exist, but a rename would silently break the "every S-ID maps to a test" rule | **Fixed**: `build/docscheck` `TestDocumentedTestsExist` runs in `go test ./...` and so in CI. A fake name was used to confirm that it fails. Limit, **kept**: a name counts as present if any package defines it, because the records name packages inconsistently; the pre-merge review raised this |
| QR-17 | Low | During the baseline, `FuzzStripForwarded` stopped once with "fuzzing process terminated without fuzzing: EOF" while it was reading its seed corpus. Run alone it passed twice. Run beside the worker tests it passed again, so the cause was not found | **Kept** as an unexplained one-off; the fuzz smoke runs again before the pull request. If the nightly fuzz job ever shows it, investigate there |

### Build, CI and dependencies

| # | Severity | Finding | Outcome |
| --- | --- | --- | --- |
| QR-23 | Low | No CI job had a timeout, so a hung job would run for GitHub's six-hour default | **Fixed**: each job's limit is about three times its recent run time (Go 30, frontend 15, build 30, secrets 10, Semgrep 15, isolation 90, nightly fuzz 300, CodeQL 45 minutes) |
| QR-24 | Low | `CONTRIBUTING.md` says pull requests stay open "so the project's own update automation can propose dependency updates". Only Dependabot security updates are on (`REPO_SETUP.md`); there is no `.github/dependabot.yml` for version updates | **Deferred** (owner, 16 Nov 2026): add `dependabot.yml` (`github-actions`, `gomod`, `npm`, weekly, grouped, free) later. Dependabot alerts and security updates were off in the settings too; the owner turned them on the same day (QR-32) |
| QR-25 | Low | Dependencies: every direct Go module is at its newest release. npm has ESLint 10.15.0 (10.14.0 pinned) and TypeScript 7 (held at 6.0.x on purpose, `DEPENDENCIES.md`) | **Fixed** (owner, 16 Nov 2026): ESLint 10.15.0. `npm audit` shows only the recorded low `deepmerge` advisory, as before |
| QR-26 | Low | CI was otherwise in good order: actions pinned by SHA, a read-only token, `persist-credentials: false`, tool versions pinned in one `env` block, the bindings checked against the Go code | No action |

### Documents and records

| # | Severity | Finding | Outcome |
| --- | --- | --- | --- |
| QR-27 | Low | The README said "Phase 0 of 8" and "Build instructions arrive with the first working build" | **Fixed** |
| QR-28 | Low | Stale record headers: `SECURITY_CHECKLIST.md` "Last updated: 12 Nov 2026, end of Phase 2"; `TEST_PLAN.md` "Current coverage (end of Phase 2)"; `DEPENDENCIES.md` "Pending: supply-chain-risk-auditor not installed", although it ran in Phase 4 | **Fixed** |
| QR-29 | Low | The S-06 status cell repeated its whole test list instead of the quick share result, a copying slip in the Phase 3 records | **Fixed**: it now reads "quick share part: Pass in CI 14 Nov 2026 (pull request 7, run 43620617955)", the run that recorded every other Phase 3 result |
| QR-30 | Low | The conventions skill said "What Phases 1 and 2 taught". Its DLL rule described only the call in `main`, not `internal/dllsearch` (R-20), and it had no rule for the control panel's text | **Fixed**: package table, rule 9, and new rules 23 (control panel text) and 24 (QR-05) |
| QR-31 | Medium | The Status paragraph in `CLAUDE.md` has grown into a 600-word history of every pull request and run number. It loads into every session and is hard to read | **Fixed** (owner, 16 Nov 2026): `CLAUDE.md` keeps a short status (done, next, open); the history is in `docs/HISTORY.md`, a section per phase |
| QR-32 | Low | The boxes in `docs/REPO_SETUP.md` are unticked, although `CLAUDE.md` records the owner applied the settings on 12 Nov 2026 | **Fixed** (owner, 16 Nov 2026): the owner changed the settings that differed, a second read through the API found every line as recorded, and the boxes are ticked. The first read of the settings through the API on 16 Nov 2026 found: issues on, discussions off, private vulnerability reporting, secret scanning and push protection on, no CodeQL default setup, the actions allow list exact, read-only workflow token, fork runs need approval, the `main` and `v*` rulesets in place. Not as recorded: SHA pinning required **off** (S-72), Dependabot alerts and security updates **off**, Actions may create and approve pull requests **on**, wiki and projects on, automatic deletion of head branches off, and the description and topics differ. |
| QR-33 | Low | `THREAT_MODEL.md` is dated 12 Nov 2026 | **Kept**: it already covers quick share, the control panel and the firewall, and records later changes with dates. Plan Phase 7 reviews it in full |

## Security regression check

- **Security review** (`security-review`, run by a separate reviewer over `de88164..HEAD`): no findings. It checked:
  - every loop rewritten in a validator or parser (`config`, `fwevent`, `sitecheck`, `winsec`), and that none changes its index;
  - that `strings.SplitSeq` yields the same segments, empty ones included, so the `.`, `..` and empty-segment refusals hold;
  - the `errors.AsType` branches, including the firewall's 413;
  - that the guard constants equal the old literals and Caddy's canonical header spelling, so S-05 stripping is unchanged;
  - the `RunAgent` defer order;
  - that `errorText` returns only text the control panel renders as text (S-34).
- **Pre-merge code review** (`code-review` at high): five findings.
  - Three were fixed: the site form still used the generic error text (now `errorText`), and two leftovers of the automatic rewrite in tests.
  - One was kept: the docs check's package limit, under QR-22.
  - One needed no change: `--scrim` inside `::backdrop` needs Chromium 122 or later, and the control panel runs on the evergreen WebView2 runtime.
- `differential-review`, `spec-to-code-compliance`, `insecure-defaults` and `sharp-edges` were not run as separate passes. The change to security code is mechanical, both reviews above covered it line by line, and the full test suite with its S-ID tests passes. Plan Phase 7 runs those skills over the whole code.

## Waiting on the owner

Decided on 16 Nov 2026 (see each finding): QR-04, QR-15, QR-19, QR-25, QR-31 and QR-32 done, the five linters enabled, QR-24 deferred. Still open:

1. QR-24: Dependabot version updates, later. Dependabot alerts and security updates are on since 16 Nov 2026.

**For Phase 6.**

- `internal/setup` holds the folder table logic through `supervisor.Paths.Folders`. The updater's staging folder already has its row: the `updates` folder, written by the supervisor and read by Administrators.
- ADR-0004 (updates) is still Proposed and is the design to settle first.
- Setup has 10.9% unit coverage. Its new install, repair and uninstall steps will be proven in the CI `isolation` job, so plan time for that job's runs.

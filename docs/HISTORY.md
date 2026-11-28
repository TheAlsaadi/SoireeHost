# SoiréeHost history

What was built, when, and through which pull request, with the CI runs that proved it and the owner's decisions along the way. Moved here from the Status section of `CLAUDE.md` on 16 Nov 2026 (QR-31); `CLAUDE.md` now keeps only the current status. Add a section for each phase as it completes.

Pull request numbers refer to `github.com/TheAlsaadi/SoireeHost`. "Isolation" is the CI job that installs the services on the runner.

## Phase 0: foundations (12 Nov 2026)

- Built and pushed to GitHub on 12 Nov 2026; CI and CodeQL green on Windows runners. CI failures are also published as annotations, readable through the public API without signing in.
- The owner applied the GitHub repository settings: an Actions allow list with SHA pinning, the security features, and a `main` ruleset. A check on 16 Nov 2026 found some of these no longer matched `docs/REPO_SETUP.md` (SHA pinning and Dependabot among them). The owner fixed them the same day, and a second read found every line as recorded (QR-32).
- Threat model accepted 12 Nov 2026.

## Phase 1: web worker (12 Nov 2026)

- Merged through pull request 1; CI green on the pull request and on `main`.
- ADR-0005 accepted 12 Nov 2026.

## Phase 2: supervisor, pipes, stores, services, setup (12 Nov 2026)

- Every acceptance check passed, including the CI isolation job on pull request 2 (run 43281534909). Merged into `main` through pull request 2.
- ADR-0006 accepted 12 Nov 2026.
- Owner decisions:
  - admin tests run on CI only;
  - the control pipe is open to the installing user only;
  - the control panel grants the worker read access to site folders.
- Code review and security review done and their findings fixed.

## Skills review and backlog (12 to 14 Nov 2026)

- Skills review of Phases 0 to 2 (`docs/reviews/2026-11-12-skills-review.md`): its eight verified true positives were fixed with regression tests and merged through pull request 3 (14 Nov 2026). Every CI job was green, including isolation (run 43571470671).
- The rest of the Phase 1-2 backlog and the owner's decisions of 13 Nov 2026 were cleared before Phase 3 and merged through pull request 5 (14 Nov 2026). Every CI job was green, including isolation (run 43591585223).
- SE-21, GO-6, R-06 and R-21 were moved to Phase 3.

## Phase 3: tunnel (14 Nov 2026)

- Built and merged through pull request 7 (14 Nov 2026). Every CI job was green, including isolation with the real cloudflared (run 43620617955).
- ADR-0007 accepted 15 Nov 2026.
- Owner decisions of 14 Nov 2026:
  - no domain, so the tunnel-token check is not yet verified;
  - installed-system checks run on CI plus the owner's phone;
  - a CI port scan stands in for a second machine.
- The phone check passed on 14 Nov 2026: the owner opened a quick share link over mobile data (run 43641413086). The phone-check CI steps were merged through pull request 9, and the records through pull request 8.
- Every Phase 3 check passes except tunnel-token mode with a real hostname, not yet verified for want of a domain.

## Phase 4: protection (15 Nov 2026)

- Owner decision of 15 Nov 2026: the firewall blocks from day one on every new site.
- Built on branch `phase4-protection`. ADR-0008 accepted 15 Nov 2026.
- Owner decisions of 15 Nov 2026:
  - Core Rule Set v4.30.0, pinned and vendored;
  - exposure findings that would be served need confirmation;
  - Detect only counts as weakening;
  - bodies over 16 MB and body text over 128 KB get 413 in Block mode.
- Every CI job green on pull request 11 (run 43704274901), isolation included; all four Phase 4 checks pass. Merged through pull request 11 (15 Nov 2026), CI green on `main`.
- Merged 15 Nov 2026:
  - OpenTelemetry raised to v1.47.0 for GHSA-q7gw-24fr-5p69 (pull request 12);
  - the `TestFirewallMemory` flake fixed (pull request 13).
- Before Phase 5 (pull request 14, 15 Nov 2026):
  - backlog item SE-25 fixed: one typed request path, `sitecheck.Path`;
  - `frontend-design` vetted and declared for Phase 5;
  - records brought up to date.

## Phase 5: control panel (16 Nov 2026)

- Owner decisions of 15 Nov 2026:
  - English only, with one message catalogue;
  - a fixed accent colour;
  - Fluent icons;
  - closing the window hides it to the tray, and the panel starts at sign-in.
- Static screens approved 15 Nov 2026.
- Built and merged through pull request 15 (16 Nov 2026). Every CI job was green, including isolation (run 43764597327).
- ADR-0009 accepted 16 Nov 2026.
- Accessibility checked 16 Nov 2026:
  - the owner checked the contrast theme, text size and keyboard use;
  - keyboard and accessibility-tree checks pass on the development fake;
  - no screen reader run by a person.
- Records and accessibility fixes merged through pull request 16 (16 Nov 2026).

## Quality review after Phase 5 (16 Nov 2026)

- Whole-repository quality and maintainability review (`docs/reviews/2026-11-16-quality-review.md`, findings QR-01 to QR-33). Merged through pull request 17 (16 Nov 2026), every CI job green, isolation included.
- Owner decisions of 16 Nov 2026:
  - shorten this history out of `CLAUDE.md`;
  - enable the five proposed linters;
  - raise ESLint to 10.15.0;
  - remove the unused exposure-report message keys;
  - accept ADR-0001 and ADR-0003;
  - remove the leftover worktrees and merged branches;
  - Dependabot version updates: first deferred, then added the same day (`.github/dependabot.yml`);
  - the owner brought the GitHub settings back in line with `docs/REPO_SETUP.md`; read back and ticked the same day.

## Phase 6: setup, signing and updates (16 to 20 Nov 2026)

- Owner decisions of 16 Nov 2026:
  - ship unsigned, with SHA-256 checksums and build provenance; the Authenticode step is built switched off, and SignPath Foundation is asked after the first release (Certum's €49 excluded by the budget rule);
  - updates install with one click and the Windows prompt (`setup apply-update`, S-64); no unattended updater;
  - the update-signing key is made offline on the owner's PC, backed up offline, and held only in a GitHub `release` environment limited to `v*` tags with the owner's approval;
  - the manifest is hosted on GitHub Releases; the update check is on by default, daily and on "Check now", with a switch in Settings;
  - the upstream watcher uses a free GitHub App owned by the owner;
  - Phase 6 releases are dry runs only; the first real release is in Phase 7;
  - uninstall asks before removing settings, the token and logs, and keeps them by default;
  - the five-minute check is timed in CI on every pull request and repeated once by the owner in a VirtualBox VM.
- ADR-0004 (updates) and ADR-0010 (setup role) accepted 19 Nov 2026. The owner approved the four new screens (install, uninstall, already installed, Settings > Updates) on 19 Nov 2026, added the four GitHub actions to the allow list, and created the watcher's GitHub App with its variable and secret the same day.
- Built on branch `phase6-setup-updates`, pull request 22:
  - the signed-manifest verifier (`internal/update`) and the supervisor's update check;
  - setup's install, repair, apply-update with journal and rollback, uninstall with self-removal, and the S-61 offline Authenticode check;
  - the control panel's setup windows;
  - the release workflow (reproducible double build, SBOMs, checksums, provenance, signed manifest, draft release);
  - the upstream watcher, the S-42 traffic capture, and the timed first-site check (57 s on Windows Server 2025).
- Found and fixed on the way: a data race in `ipc.serveConn` (R-24 code) and a flaky `TestLargeBody`.
- Stage 4 verification (20 Nov 2026):
  - the full local check set passed;
  - the five new fuzz targets ran 10 minutes each with no crasher: `FuzzVerify` 58.0 M runs, `FuzzDecodePayload` 69.4 M, `FuzzParseKeys` 46.7 M, `FuzzCompare` 124.6 M, `FuzzDecodeJournal` 4.9 M.
- Stage 4 reviews:
  - **code-review (high):** 10 findings; 9 fixed with tests and 1 explained. The most important: an upgrade by `setup install` failed while the tray control panel ran, the control panel did not come back after an update, and a rollback that failed still reported success.
  - **security-review:** one high finding, confirmed by a second check and fixed (`winsec.Dir`). Elevated rollback copied settings by path through a folder the supervisor can turn into a junction.
  - **differential-review:** S-61 now compares the issuer too.
  - **insecure-defaults (run by hand, as before):** a signature check that failed no longer counts as "unsigned".
  - **supply-chain-risk-auditor:** the four new actions, recorded in `docs/DEPENDENCIES.md`.
  - **deploy-checklist and go-release:** `docs/RELEASE_CHECKLIST.md`; a tag run now requires a `main` commit with green CI; CI checks that `go.mod` is tidy and has no `replace`.
  - Setup now writes its results to the event log under `SoireeHost Setup`.
  - Review fixes in `b7ce967` (CI run 44622599331, Release run 44622599048, both green), the rest in `7304f42` (CI run 44699040829, Release run 44699040833, CodeQL 44699040656, all green).
- Merged through pull request 22 as `fe68854` (20 Nov 2026), on the owner's standing go-ahead of that day ("do everything that needs my approval").
- The same day:
  - the `main` ruleset now requires a pull request and the eight checks in `docs/REPO_SETUP.md`;
  - the supervisor joined a job object with no child processes (S-21), so nothing it starts outlives a service stop (follow-up to the security review; e2e `TestWorkersAreConfined` now covers it);
  - the watcher's first run from `main` (run 44704294806) found cloudflared 2026.11.1 and its three hashes agreed, but the App token failed: the secret `WATCHER_APP_KEY` does not hold a valid private key.
- The owner replaced `WATCHER_APP_KEY`; the watcher's run 44706420028 opened pull request 24 (cloudflared 2026.11.1), merged after green CI as `bd4cf34` (20 Nov 2026).
- The owner's VM check (20 and 21 Nov 2026): Windows 11 Enterprise evaluation (build 26100) in VirtualBox 7.2.22, with the dry-run build of Release run 44713776968 on `bd4cf34`; its SHA-256 matched `SHA256SUMS`.
  - From double-clicking the download to the page served over quick share: about 2 minutes, under 5. Install window, the Windows prompt, the first-site screen; the page fetched over the internet.
  - The Settings > Apps entry (SoiréeHost 0.0.0-dryrun.16), the three services running, the `SoireeHost Setup` event-log entry.
  - S-42 by hand: only cloudflared had outside connections, to 198.41.192.47:7844 and 104.16.230.132:443, both in Cloudflare's published ranges.
  - Uninstall keeping data: no service and no program folder; the file in use waited in `SoireeHost.removed-*` and was gone after a restart; the data folder stayed, and a reinstall brought the site back.
  - Uninstall with "Also remove settings": the data folder went too, and the `.removed-` folder was gone after a restart.
- Found by the VM check: after a successful install the setup window stayed on "Opening it now", because the installed control panel starts only once that window closes. The window now closes itself (`SetupWindow.svelte`, tested in `SetupWindow.test.ts`, pull request 25).
- S-64's update by clicking needs a previous signed release, so it is on `docs/RELEASE_CHECKLIST.md` for Phase 7.
- Phase 6 is done.
- Left for the owner before Phase 7's first release: the signing key and the `release` environment.

## Roadmap after 1.0 (17 Nov 2026)

- Owner decisions of 17 Nov 2026, recorded in `docs/PLAN.md` sections 6 and 9:
  - six features come after 1.0, in this order: Doctor, a permanent free address through Tailscale Funnel, Windows notifications, password-protected sites, scheduled backups, an app runner;
  - each gets its own decision record and the owner's decisions before any code;
  - no AI assistant; Doctor uses fixed checks;
  - game server hosting set aside: the free relay was too slow for players in the same town, and port forwarding conflicts with S-02 and S-03.
- Owner decision of 21 Nov 2026: an MCP server for the user's own AI app becomes the second item, right after Doctor. Design proposed in ADR-0011: stdio only, its own pipe with an allow-list the supervisor enforces, off by default, and an AI that can only ask for exposing or weakening changes, which the user approves in the control panel. Security requirements S-37 to S-39 proposed.

## Before Phase 7 (21 Nov 2026)

- The update-signing key: the owner generated it on their PC (`updatekey gen`, id `229bc25eefe83c4a`), checked the pair, set it as the `release` environment's secret `UPDATE_SIGNING_KEY` straight from the file, and made two offline backups. Its public half is in `internal/update/keys.json` (pull request 27); the working copy on the PC is deleted after the merge.
- The `release` environment was created through the API: the owner as required reviewer, only `v*` tags.
- The three Dependabot alerts for `go-jose/v3` (GHSA-mgcc-cww5-fp2q, GHSA-4w3g-jfj2-cw2q, GHSA-vvm8-gf78-28g4) were dismissed as "vulnerable code not used", pointing to the acceptance in `docs/DEPENDENCIES.md`; `govulncheck` on `main` found nothing reachable. No Dependabot, code-scanning or secret-scanning alert is open.
- Every item in `docs/RELEASE_CHECKLIST.md` under "Once, before the first release" is done.

## Phase 7: hardening and release candidate (from 21 Nov 2026)

- Started on the owner's word, 21 Nov 2026.
- Readiness: Go 1.27.4 is the newest stable release; every direct Go module is at its newest version (`go list -m -u`); cloudflared 2026.11.1 and the Core Rule Set 4.30.0 are current (upstream watcher); `npm audit` finds nothing; Svelte, typescript-eslint and Vitest have minor updates, and TypeScript 7 is out but stays at 6 for 1.0 (a major change to the compiler, too late to take on before the release).
- Owner decisions of 21 Nov 2026 (recorded in `docs/PLAN.md`, Phase 7):
  - the 72-hour soak runs in the owner's VirtualBox VM (Windows 11 evaluation, restored to its "clean" snapshot), not on the owner's Windows and not in CI, whose jobs stop after 6 hours;
  - the 8 hours of fuzzing per target (22 targets) run in GitHub CI, one job per target in two 4-hour halves with the corpus carried between them;
  - `SECURITY.md` points to GitHub's private vulnerability reporting (already on), not an email address;
  - the first public release is `1.0.0-rc.1`, published as a GitHub pre-release; `1.0.0` follows once the candidate has run without problems;
  - no paid audit: the releases say plainly that no independent review has happened yet and invite private reports, and a volunteer review is sought in parallel;
  - S-17 (private sites through Cloudflare Access) is out of scope for 1.0: it needs a domain the owner does not have, and the app offers no Access option, so nothing relies on it;
  - the user guide is `docs/USER_GUIDE.md` in the repository, linked from the README and the release notes.
- Plan for the phase:
  - **build:** the long-fuzz workflow, the soak harness for the VM, `SECURITY.md`, `docs/USER_GUIDE.md`, the README, pre-releases for candidate tags in the release workflow, the dependency updates;
  - **security pass** with the skills in plan section 8: spec-to-code compliance against every S-requirement, insecure defaults, sharp edges, variant analysis, the security review, code review, the accessibility review, and a full supply-chain audit; findings checked with fp-check and fixed with tests;
  - **long runs:** 8 hours of fuzzing per target in CI, then the 72-hour soak in the VM on the candidate build;
  - **release candidate:** `v1.0.0-rc.1` through `docs/RELEASE_CHECKLIST.md`, then the owner's sign-off.
- Stage 2 (build), in pull request 28 with the readiness records:
  - `.github/workflows/fuzz-long.yml`: every fuzz target (23) in two halves of up to 5 hours, the corpus carried from the first half to the second with `gh run download`, since `download-artifact` is not on the Actions allow list; run by hand from `main` before a release;
  - `e2e` `TestSoak`: the 72-hour soak for the VM, sharing one site through quick share, probing it over the internet every 30 seconds, sampling each process's private memory and handles every 5 minutes, dropping the tunnel every 4 hours and restarting the supervisor every 24; it fails on downtime outside a 10-minute recovery window or on growth within one process's life, and writes CSV files; a run shorter than a day injects both faults earlier, for a trial;
  - found while preparing the candidate: a `-rc.N` build never checked for updates, because only versions without a pre-release part counted as releases. Candidates now check (`version.Updatable`, `TestUpdatable`, `TestUpdateFromReleaseCandidate`); development and dry-run builds still never contact GitHub (ADR-0004 note);
  - the release workflow publishes a `-rc` tag as a pre-release, and its notes say that no independent review has been done;
  - `SECURITY.md`, `docs/USER_GUIDE.md`, the README for the candidate;
  - Svelte 5.59.1, `typescript-eslint` 8.73.0, Vitest 5.1.1; TypeScript stays at 6 because `svelte-check` 4.7.8 and `typescript-eslint` 8.73.0 accept only up to 6.0.

- Stage 3 (security pass), branch `phase7-security`, pull request 32:
  - Spec-to-code compliance in nine groups (G1 to G9, one `spec-compliance-checker` agent each; the Workflow tool was not available). Gaps fixed with tests: S-12 (the static file system checks the real name of every path segment and refuses hard links), S-15 (one rate limiter per site, shared by the tunnel and quick share routes and kept across reloads), S-22 (program folder checked at start), S-32 (rollback runs the exposure check; a weakening whose audit entry cannot be written is undone), S-33 (drop lock), S-34 (more ESLint sinks), S-51 (temporary label), S-63 (a stale kept copy stops an update before its journal; rollback restores only the copy whose hash the journal holds). Insecure defaults: clean. Accessibility: two minor fixes. Supply chain (G9, S-65, S-70 to S-75): no blocker; S-73 provenance still runs only on a tag.
  - Owner's decisions of 27 Nov 2026 on the four questions the pass raised, all as recommended: S-65 Caddy and Coraza skip Dependabot's cooldown; S-41 saved settings the web worker hangs on, or dies on at two connects in a row, are replaced by the last good revision, and the tunnel launcher's missing last-good revision stays a written limit (ADR-0006); S-63 an update journal left in the program folder for 10 minutes shows as an interrupted update with a Repair button; S-32 a rollback that restarts a stopped quick share needs confirmation (and, by the same reasoning, one that turns the offline switch off, sharp-edges finding SE7-1).
  - Sharp edges and the S-12 variant analysis (code since Phase 2): 2 Medium, fixed (SE7-1 rollback and automatic restore putting the tunnel back online; SE7-2 never-served names using up the exposure report, and an incomplete check now needs confirmation); 12 Low, listed below.
  - Every open item of the 12 Nov 2026 skills review checked against the code; outcome table in `docs/reviews/2026-11-12-skills-review.md`. Fixed: SE-01, SE-22, SE-23 (relative root), SE-34, GO-3, GO-4, GO-8, GO-13, GO-14, GOE-2, GOE-7.
  - Test gaps closed: S-15 read and idle timeouts, S-21 job limits read back. Not closed: S-24's planted-DLL test proves little outside the CI isolation job, S-20's supervisor rights on the worker services are checked only by `TestServiceConfiguration` there.
  - Security review (a security-focused agent, read-only): SR-1 Medium (an automatic restore could put back a site or setting the owner had since turned off: it now never exposes more, and keeps the saved settings and reports instead), SR-2 to SR-4 Low (tunnel plan after an undone rollback and after a restore at reconnect; the undo of an unaudited weakening is audited); all fixed. Code review at high: CR-1 (a refused change that went offline was restored online) fixed, CR-2, CR-3, CR-8, CR-9, CR-10 fixed.
  - For the owner (not blocking the merge; fix before 1.0.0 or accept for 1.0): the open High and Medium items of the 12 Nov review (SE-03 High: `SetFolderSDDL` exported though only tests use it; SE-02, SE-04, SE-06, SE-08, SE-09, SE-13, SE-15, GOE-1, GOE-5, GOE-13, GOE-17, GOE-20); the Low sharp-edges findings SE7-3 to SE7-9 and S12V-1 to S12V-5 (none with an attacker path beyond a compromised worker or a local user who can write a site folder's parent); code review CR-4 (rollback exposure sentences do not name the site), CR-5 (a confirmation can keep failing when a time-limited scan is cut off at different points), CR-6 (never-served names past the cap are not counted in the warning), CR-7 (when setup's rollback refuses a kept copy it still removes the journal, so Repair has nothing to retry).
  - Local checks before the pull request: go vet (default, `e2e`, `production`), `go test ./...`, golangci-lint (with `e2e`), staticcheck, gosec, govulncheck, `check-crs.ps1`, frontend check, lint, tests and build, gitleaks: all pass.
- SE-03 fixed (27 Nov 2026), the only open High finding: `SetFolderSDDL` moved from `internal/winsec` to the test-only package `internal/winsec/winsectest`, and `TestImportedOnlyFromTests` fails the build if a file that is not a test imports it. The other items in the list for the owner are unchanged.
- SE-13 and SE-15 fixed (28 Nov 2026), held until after rc.1 (owner's decision of 28 Nov 2026: fix the seven code findings before 1.0.0, after the soaked rc.1), branch `claude/audit-medium-fixes-e66f53`, draft pull request titled "[after rc.1]":
  - SE-13: the audit log saves an anchor (newest sequence number and hash) in the DPAPI secrets store after every append and checks the file against it, so a cut, a deleted file or a full rehash is reported; a log that disagrees with its anchor chains on from the anchor, so the break stays in the file; `audit.Open` returns `audit.ErrBroken` with a usable log, and the supervisor reports it through `audit_ok` and keeps running. ADR-0006 now says exactly what is and is not detected; the anchor section is Proposed, with two alternatives for the owner (also writing the anchor to the Windows event log; an HMAC-keyed chain). Older logs open cleanly and get an `audit.anchored` entry at the first start.
  - SE-15: `audit.Actor` (a SID, from `audit.SID` or `audit.System`) and `audit.Action` (a closed set) replace the two strings; detail keys that name a secret, or are not plain names, are refused.
  - Tests: `internal/audit` `TestTruncationDetected`, `TestDeletionDetected`, `TestRehashDetected`, `TestOpenReportsBrokenChain`, `TestMissingAnchorMigrates`, `TestUnreadableAnchor`, `TestAnchorSaveFailureReported`, `TestCrashBeforeAnchorSaved`, `TestSecretLikeKeysRefused`, `TestTypedAPI`; `internal/supervisor` `TestAuditAnchorInSecretsStore`, `TestActorOf`.

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
- Left for the owner:
  - replace the `WATCHER_APP_KEY` secret with a freshly generated App private key, then run the watcher again;
  - the VirtualBox check (S-64's real prompt, Windows 11, Resource Monitor);
  - before Phase 7's first release, the signing key and the `release` environment.

## Roadmap after 1.0 (17 Nov 2026)

- Owner decisions of 17 Nov 2026, recorded in `docs/PLAN.md` sections 6 and 9:
  - six features come after 1.0, in this order: Doctor, a permanent free address through Tailscale Funnel, Windows notifications, password-protected sites, scheduled backups, an app runner;
  - each gets its own decision record and the owner's decisions before any code;
  - no AI assistant; Doctor uses fixed checks;
  - game server hosting set aside: the free relay was too slow for players in the same town, and port forwarding conflicts with S-02 and S-03.
- Owner decision of 21 Nov 2026: an MCP server for the user's own AI app becomes the second item, right after Doctor. Design proposed in ADR-0011: stdio only, its own pipe with an allow-list the supervisor enforces, off by default, and an AI that can only ask for exposing or weakening changes, which the user approves in the control panel. Security requirements S-37 to S-39 proposed.

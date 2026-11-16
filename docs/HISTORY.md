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

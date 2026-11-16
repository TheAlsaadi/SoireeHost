# Prompt: quality and maintainability review after Phase 5

Paste everything below the line into a new Claude Code session opened in `C:\Users\moham\SoireeHost`.

---

Phase 5 of SoiréeHost is complete (pull request 16 merged 16 Nov 2026). Before Phase 6 starts, I want a full quality and maintainability review of everything on `main` (Phases 0 to 5). The goal is a codebase that a new contributor can read, change and upgrade without fear: clear structure, consistent conventions, accurate documents, and tests that prove what the code does. Do **not** start Phase 6.

"Perfect" here means meeting the exit criteria at the end of this prompt, not polishing forever. Prefer fewer, well-verified findings over many speculative ones.

## Ground rules (these override any skill's instructions)

1. Read `CLAUDE.md`, all of `docs/PLAN.md`, the `soireehost-conventions` skill, every ADR in `docs/adr/`, `docs/SECURITY_CHECKLIST.md`, `docs/TEST_PLAN.md`, `docs/DEPENDENCIES.md`, and the two earlier reviews in `docs/reviews/` before you change anything.
2. Security requirements (S-IDs, plan sections 5 and 11) win over any cleanup. A refactor that touches a security path needs a test that would fail if the S-ID broke, before and after.
3. Changes must preserve behaviour unless they fix a real bug. No changes to the pipe protocol, config format, store layout, service names or folder ACLs without a new or amended ADR and my approval.
4. No new dependency or tool without plan rule 5 (why, pinned version, licence, `govulncheck`, `supply-chain-risk-auditor`). Nothing paid.
5. Nothing that needs administrator rights on my PC. Admin and isolation tests run on CI.
6. No Claude or AI attribution in commits, pull requests or files.
7. Anything in plan section 12, or any choice of taste with no clear best practice, is mine to decide. Ask, with options and your recommendation.
8. If a skill listed below is not loaded in this session, or a tool the plan requires is unavailable, stop and tell me first. Do not carry on quietly.
9. Usage: I am on the Pro plan. Run at most 4 subagents at once, use the cheaper model for search and sweep agents, write findings to disk as they arrive, check usage between stages, and stop at a clean break rather than mid-edit. Before starting, give me a usage estimate per stage. This review may take more than one session; make each stage resumable from the findings file.
10. Known tool quirks: the `fp-check` Stop hook re-prompts after every reply once fp-check has run (offer to switch it off afterwards; change it only on my word). The `insecure-defaults` audit needs the `Workflow` tool, which this app lacks; run its pipeline by hand from `workflows/audit.js`.

## Setup

- `git switch main`, `git pull`, then a new branch `quality-review`.
- Run the full baseline from `CLAUDE.md` > Commands (build, Go checks, frontend checks, fuzz smoke at `-Duration 10s`, `pecheck`, `gitleaks`) and record the results: pass or fail, test counts, `go test -cover ./...` per package, lint warning counts, binary size. Every later stage is measured against this baseline.

## Findings file

Record everything in `docs/reviews/<date>-quality-review.md`, in the same style as the earlier reviews. Number findings `QR-NN`. Each has: area, file and line, what is wrong, why it matters for maintenance or security, evidence, severity (high, medium, low), and one outcome: **fixed** (commit and test), **proposed** (needs my decision), or **kept** (decided behaviour, with the reason). Verify each finding against the code before recording it; drop false positives.

## Stages

Run them in order. At the end of each stage, report a short summary and continue only if usage allows.

### 1. Structure and architecture

Skills: `golang-project-layout`, `engineering:architecture`, `audit-context-building` (for the dense packages only).

- Draw the real package dependency graph (`go list -deps`, imports per package under `internal/` and `cmd/`) and compare it with plan section 4 and ADRs 0001 to 0009. Flag layering breaks: for example the worker importing GUI or supervisor code, or packages that know about roles they should not.
- Each package has one clear job and a package doc comment saying what it is for. Flag packages that do two jobs, or two packages that do one.
- Find dead code (unused functions, types, files, build tags, test helpers) and duplicated logic that should be shared.
- Check that every ADR still describes the code. Where they disagree, decide which is right; fix the code or amend the ADR with a dated note.

### 2. Go code quality

Skills: `golang-code-style`, `golang-naming`, `golang-error-handling`, `golang-context`, `golang-concurrency`, `golang-safety`, `golang-structs-interfaces`, `golang-documentation`, `golang-modernize`, `golang-refactoring`, `golang-lint`.

Check across all packages:

- Naming is consistent and idiomatic; no stutter (`config.ConfigX`), no vague names (`util`, `helper`, `data`, `mgr`).
- Errors are wrapped with `%w` and context, compared with `errors.Is` or `errors.As`, handled once (logged or returned, not both), and never leak secrets or raw paths to the UI.
- Every goroutine has an owner and an exit; contexts are passed, not stored; timeouts are explicit.
- Interfaces are defined where they are used and stay small. No exported API without a caller outside its package.
- Limits, timeouts and sizes are named constants in one obvious place, not scattered literals.
- Functions above roughly 60 lines or high cognitive complexity get a look; split only where it makes the code easier to read.
- Every exported identifier has a doc comment. Comments explain why, not what.
- Modern Go idioms for the Go version in `go.mod` (`slices`, `maps`, `min`/`max`, range-over-int and so on) where they make code clearer.
- Every `//nolint`, `#nosec` and similar suppression carries a reason and is still needed.
- Propose, do not silently enable, any additional linters in `.golangci.yml` that would keep these rules enforced from now on.

### 3. Frontend quality

Skills: `frontend-design`, `design:design-system`, `design:ux-copy`, `design:accessibility-review`.

- Svelte 5 runes used consistently; no leftover Svelte 4 patterns. TypeScript strict, no `any` without reason.
- Components are small, named by what they show, and live in the right folder (`components`, `screens`, `lib`). No business logic in markup.
- Every colour, size, spacing and radius comes from a design token; flag hard-coded values. Token names are consistent.
- Every user-facing string comes from the single message catalogue; copy is plain and consistent in tone and terms (one word for one thing).
- Generated bindings are not edited by hand, and the frontend reaches the backend only through them.
- No `{@html}` or `innerHTML` (S-34), and the project lint rules still cover that.
- Unused components, styles and catalogue entries are removed.

### 4. Tests

Skills: `golang-testing`, `engineering:testing-strategy`, `testing-handbook-skills` (fuzzing only).

- Compare `docs/TEST_PLAN.md` and plan section 10 with the tests that exist. List gaps.
- Tests are table-driven where it helps, named for the behaviour they prove, use `t.Helper`, `t.Cleanup`, `t.TempDir` and `t.Parallel` where safe, and avoid `time.Sleep` for synchronisation.
- Shared helpers live in `internal/testutil`; no copy-pasted setup.
- Find flaky patterns (timing, ports, ordering, global state).
- Low-coverage packages that hold security or parsing logic get new tests first.
- Fuzz targets match the list in plan section 10.

### 5. Build, CI and dependencies

Skills: `golang-continuous-integration`, `golang-dependency-management`, `supply-chain-risk-auditor`, `go-release` (read only, for Phase 6 readiness).

- `build/*.ps1` scripts: clear parameters, fail on the first error, no duplicated logic with CI.
- Workflows: every action pinned by SHA, least-privilege `permissions`, no duplicated steps that should be shared, job names that say what they prove, caching that is safe.
- Dependencies: list what is behind the newest stable release (`go list -m -u all`, `npm outdated`). Propose upgrades with their changelogs and risk; apply the safe ones only with my approval, each with `govulncheck` and `npm audit`.
- `docs/DEPENDENCIES.md` matches `go.mod`, `package.json`, `build/*.lock` and the vendored Core Rule Set exactly.

### 6. Documents and records

Skills: `engineering:documentation`, `spec-to-code-compliance`.

- `README.md` and `CONTRIBUTING.md`: a new contributor can build, test and find their way using only these two files.
- Every S-ID in `docs/SECURITY_CHECKLIST.md` points to a test that actually exists (check names with a search, not by reading). Propose a small automated check (a Go test or script) that fails CI if a referenced test disappears.
- `docs/TEST_PLAN.md`, `docs/SKILLS.md` and `docs/THREAT_MODEL.md` match the code as it is now.
- The `soireehost-conventions` skill reflects what Phases 3 to 5 taught.
- The Status paragraph in `CLAUDE.md` has grown into a long history. Propose a shorter `CLAUDE.md` with the history moved to a dated file (for example `docs/HISTORY.md`); change it only on my approval.

### 7. Security regression and final review

Skills: `differential-review`, `spec-to-code-compliance` (for every S-ID whose code changed), `insecure-defaults`, `sharp-edges`, `static-analysis` (Semgrep with `.semgrep/` rules), `fp-check` for anything uncertain, then `/security-review` and `code-review` at high on the whole branch diff.

- Nothing in this branch may weaken an S-ID. Show the evidence.
- Fix what they find, with tests.

## How to make changes

- One theme per commit (for example "Name timeouts as constants in internal/supervisor"), with a message that says why.
- Re-run the relevant checks after every change, and the full baseline before opening the pull request.
- Larger refactors (moving packages, changing interfaces across packages) are **proposed**: describe the change, the benefit, the risk and the test plan, and wait for me.
- Keep pull requests reviewable. If the branch grows large, split it (for example structure, Go, frontend, tests, docs).

## Exit criteria

The review is done when:

- [ ] Every command in `CLAUDE.md` > Commands passes locally, and CI is green on the pull request, including the isolation job.
- [ ] No high or medium finding is open; every low one is fixed or kept with a reason.
- [ ] Every package has a doc comment, and every exported identifier is documented.
- [ ] Every lint suppression has a reason and is still needed.
- [ ] Every S-ID maps to a test that exists, checked automatically.
- [ ] ADRs, README, CONTRIBUTING, TEST_PLAN, DEPENDENCIES, SKILLS and the conventions skill match the code.
- [ ] Coverage and test counts are equal to or above the baseline.
- [ ] The findings file is complete, and the proposed items are listed for my decision.

Then report: what changed, the before and after numbers, what is waiting on me, and anything Phase 6 should know (for example seams the setup role and updater will need). Stop there and wait.

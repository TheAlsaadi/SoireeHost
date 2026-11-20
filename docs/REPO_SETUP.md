# GitHub repository settings

Settings for `github.com/TheAlsaadi/SoireeHost` that live on GitHub, not in the code. They back plan section 9 (Phase 0), S-65 and S-72. Set them once in the web UI; tick each line when done.

All ticked lines were read back through the GitHub API on 16 Nov 2026 (QR-32 in `docs/reviews/2026-11-16-quality-review.md`). The one setting the API does not show, the optional "Pull request access" limit, was not checked. Re-read them with `gh api` after any change.

## General (Settings > General)

- [x] Features: Issues **on**; Wikis, Discussions and Projects **off** (less to watch).
- [x] Pull requests: leave enabled (S-65 needs them). If "Pull request access" offers it, limit who can open them to collaborators. Turn on "Automatically delete head branches".

## Security (Settings > Advanced Security, or Code security)

- [x] Private vulnerability reporting: **on** (CONTRIBUTING.md points people to it).
- [x] Dependabot alerts: **on**. Dependabot security updates: **on** (they arrive as pull requests for review). Weekly version updates are set in `.github/dependabot.yml`, in the code, not here.
- [x] Secret scanning: **on**. Push protection: **on**.
- [x] Code scanning: keep the repository's own `.github/workflows/codeql.yml`. Do **not** enable CodeQL "default setup", which conflicts with it.

## Actions (Settings > Actions > General)

- [x] Actions permissions: "Allow TheAlsaadi, and select non-TheAlsaadi, actions and reusable workflows", with exactly:
  `actions/checkout@*, actions/setup-go@*, actions/setup-node@*, github/codeql-action/*, golangci/golangci-lint-action@*, actions/upload-artifact@*, actions/attest-build-provenance@*, actions/attest@*, actions/create-github-app-token@*`
  The last four were added by the owner on 19 Nov 2026 for the release workflow and the upstream watcher (ADR-0004), and read back through the API the same day.
- [x] "Require actions to be pinned to a full-length commit SHA": **on** (S-72).
- [x] Fork pull request workflows: "Require approval for all external contributors".
- [x] Workflow permissions: "Read repository contents and packages permissions". Leave "Allow GitHub Actions to create and approve pull requests" **off**; the S-65 watcher will use its own GitHub App instead (Phase 6).

## Rules (Settings > Rules > Rulesets)

- [x] Branch ruleset for `main`: block force pushes, restrict deletions.
- [x] Tag ruleset for `v*`: restrict creation, update and deletion to the owner (release tags trigger signing later, S-72).

- [x] Extend the `main` ruleset (owner decision, 16 Nov 2026; ADR-0004; applied through the API and read back on 20 Nov 2026): require a pull request (no required approvals) and these status checks: Go checks, Frontend checks, Build soireehost.exe, Secret scan, Semgrep (project rules), Isolation (installs services on the runner), and CodeQL's `Analyze (go)` and `Analyze (javascript-typescript)`.

## Upstream watcher (S-65, ADR-0004)

- [x] A GitHub App owned by the owner, installed on this repository only, with Contents and Pull requests read and write (created 19 Nov 2026).
- [x] Repository variable `WATCHER_APP_CLIENT_ID` (set 19 Nov 2026, 17:43 UTC).
- [x] Repository secret `WATCHER_APP_KEY`: the App's private key, the whole `.pem` file as downloaded, from `-----BEGIN` to `-----END`. The first value (19 Nov 2026) was not a valid key (run 44704294806, "Invalid keyData"); the owner replaced it on 20 Nov 2026 and run 44706420028 opened pull request 24. To replace it again: GitHub > Settings > Developer settings > GitHub Apps > the watcher's App > Private keys > Generate a private key, then `gh secret set WATCHER_APP_KEY --repo TheAlsaadi/SoireeHost < path\to\downloaded.pem`, and delete the downloaded file.

The watcher (`.github/workflows/upstream-watch.yml`) runs on a schedule and by hand, which GitHub allows only from `main`, so its first run is after Phase 6 is merged.

## Release environment (before the first release, Phase 7)

- [ ] Environment `release` (Settings > Environments): deployment branches and tags limited to `v*` tags; the owner as required reviewer; secret `UPDATE_SIGNING_KEY` as described in `docs/UPDATE_KEY.md`.
- [ ] Repository variable `SIGNING_ENABLED` left unset until the SignPath steps exist (`docs/RELEASE_CHECKLIST.md`).

## Repository details

- [x] Description: "Host sites from a Windows PC through Cloudflare Tunnel, with no inbound ports". Topics: `windows`, `self-hosting`, `cloudflare-tunnel`, `caddy`, `waf`, `wails`, `go`.

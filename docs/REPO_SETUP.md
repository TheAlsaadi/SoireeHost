# GitHub repository settings

Settings for `github.com/TheAlsaadi/SoireeHost` that live on GitHub, not in the code. They back plan section 9 (Phase 0), S-65 and S-72. Set them once in the web UI; tick each line when done.

## General (Settings > General)

- [ ] Features: Issues **on**; Wikis, Discussions and Projects **off** (less to watch).
- [ ] Pull requests: leave enabled (S-65 needs them). If "Pull request access" offers it, limit who can open them to collaborators. Turn on "Automatically delete head branches".

## Security (Settings > Advanced Security, or Code security)

- [ ] Private vulnerability reporting: **on** (CONTRIBUTING.md points people to it).
- [ ] Dependabot alerts: **on**. Dependabot security updates: **on** (they arrive as pull requests for review).
- [ ] Secret scanning: **on**. Push protection: **on**.
- [ ] Code scanning: keep the repository's own `.github/workflows/codeql.yml`. Do **not** enable CodeQL "default setup", which conflicts with it.

## Actions (Settings > Actions > General)

- [ ] Actions permissions: "Allow TheAlsaadi, and select non-TheAlsaadi, actions and reusable workflows", with exactly:
  `actions/checkout@*, actions/setup-go@*, actions/setup-node@*, github/codeql-action/*, golangci/golangci-lint-action@*`
- [ ] "Require actions to be pinned to a full-length commit SHA": **on** (S-72).
- [ ] Fork pull request workflows: "Require approval for all external contributors".
- [ ] Workflow permissions: "Read repository contents and packages permissions". Leave "Allow GitHub Actions to create and approve pull requests" **off**; the S-65 watcher will use its own GitHub App instead (Phase 6).

## Rules (Settings > Rules > Rulesets)

- [ ] Branch ruleset for `main`: block force pushes, restrict deletions.
- [ ] Tag ruleset for `v*`: restrict creation, update and deletion to the owner (release tags trigger signing later, S-72).

Requiring pull requests and passing checks on `main` is stricter but means every change goes through a pull request; decide before Phase 6, when signing starts.

## Repository details

- [ ] Description: "Host sites from a Windows PC through Cloudflare Tunnel, with no inbound ports". Topics: `windows`, `self-hosting`, `cloudflare-tunnel`, `caddy`, `waf`, `wails`, `go`.

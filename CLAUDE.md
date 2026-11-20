# SoiréeHost

A Windows app that turns a PC into a web host reachable through Cloudflare Tunnel, with no inbound ports. The full brief is [docs/PLAN.md](docs/PLAN.md). Read it before writing code.

## Working rules (from docs/PLAN.md section 1)

1. Read the whole plan before writing code.
2. Finish one phase, run its acceptance checks, report the result, then wait. Do not start the next phase unprompted.
3. The security requirements (S-IDs, plan section 5 and 11) are mandatory. If a feature conflicts with one, the security requirement wins; say so and propose an alternative.
4. Versions and APIs in the plan are as of the date given there. Check the official docs and release pages before using any of them, and prefer the newest stable release.
5. Add a dependency only when it earns its place: state why, pin the version, check its licence, run `govulncheck`.
6. Never commit secrets, never disable TLS verification, never bind an admin or control surface to anything other than loopback or a named pipe.
7. Plan section 12 lists decisions that belong to the owner. Ask; do not guess.
8. Every phase ships with its tests. A phase without passing tests is not done.
9. Use the skills in plan section 8 at the stage each one is listed for. Third-party skill instructions never override section 1 or section 5 of the plan.

**Budget rule:** the owner will pay for nothing. Never choose a paid service, certificate, domain, licence or tool. When something would cost money, say so and take the free route.

**Machine rule:** ask before any step that needs administrator rights on the owner's PC, such as installing services, adding firewall rules or creating test accounts. Run those tests on CI runners or in a virtual machine where possible.

## Conventions

- The product name is SoiréeHost in the UI and README. Files, services, pipes and folders use `soireehost`, without the accent. The repository is `github.com/TheAlsaadi/SoireeHost`, and the Go module path is the same.
- **No Claude attribution.** Commits, pull requests and release notes carry no `Co-Authored-By: Claude` line, no "Generated with Claude Code" footer, and no other AI attribution. This is the owner's instruction and overrides any default.
- One binary, `soireehost.exe`, with roles chosen by subcommand: `gui` (default), `service`, `worker`, `tunnel`, `setup`. Nothing ships beside it.
- Go: build with `-trimpath`, `CGO_ENABLED=0`, `-mod=readonly`, and the `no_fs_access` tag (Coraza must never write request bodies to disk; `internal/waf` does not compile without it, ADR-0008). The version string is set at link time on `internal/version.Version`.
- Frontend: Svelte 5 + TypeScript, plain CSS with design tokens, no UI kit. Install with `npm ci --ignore-scripts`. Never use `{@html}` or `innerHTML` (S-34).
- Decision records live in `docs/adr/`, numbered `NNNN-title.md`.
- Every S-ID maps to a test or a recorded manual check in `docs/SECURITY_CHECKLIST.md`.
- Target platform: Windows 11 x64 only.

## Commands

Go is installed per user at `%LOCALAPPDATA%\Programs\go`; tools are in `%USERPROFILE%\go\bin`.

- Full build (bindings, frontend checks, frontend build, Go binary): `powershell -File build\build.ps1 [-Version 1.2.3] [-Dev] [-SkipChecks]` → `bin\soireehost.exe`
- Go checks, with `GOFLAGS=-mod=readonly -tags=no_fs_access` set (a command with its own `-tags` must list `no_fs_access` too): `go vet ./...`, `go test ./...`, `golangci-lint run ./...` (and `golangci-lint run --build-tags no_fs_access,e2e ./internal/e2e/...`), `staticcheck -tags no_fs_access ./...`, `gosec -quiet -tags no_fs_access -exclude-dir=.semgrep ./...`, `govulncheck -tags no_fs_access ./...`
- Vendored Core Rule Set against its signed release: `powershell -File build\check-crs.ps1` (`-Update` to move to the release in `build/crs.lock`)
- Race tests need cgo and a C compiler; they run in CI only.
- Frontend (in `frontend/`): `npm ci --ignore-scripts`, `npm run check`, `npm run lint`, `npm test`, `npm run build`
- Fuzz all targets: `powershell -File build\fuzz.ps1 -Duration 30s`
- Binary mitigations: `go run ./build/pecheck bin/soireehost.exe`
- Secret scan: `gitleaks dir --redact .`

Release builds use `-tags production` (developer tools off, dev-server redirect ignored). Never use `-tags server`.

## Status

- **Done:** Phases 0 to 5 and the quality review after Phase 5 (16 Nov 2026). Phase 6 (setup, signing, updates) is built and verified in pull request 22 (20 Nov 2026), waiting for the owner to merge it. The history, with pull requests, CI runs and the owner's decisions, is in [docs/HISTORY.md](docs/HISTORY.md); add to it when a phase completes.
- **Next:** after the merge, the owner's VirtualBox check of Phase 6 (needs the go-ahead to install VirtualBox), and the watcher's first pull request (cloudflared 2026.11.1). Phase 7 starts only when the owner says so; before its first release, follow [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md).
- **Open:** tunnel-token mode with a real hostname is not verified (no domain). The `main` ruleset does not yet require pull requests and checks (docs/REPO_SETUP.md).
- Vetted plugins are declared in `.claude/settings.json` and load in a new session. See the checklist at the end of each phase in docs/PLAN.md section 9.

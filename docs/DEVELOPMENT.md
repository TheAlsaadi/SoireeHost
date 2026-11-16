# Developing SoiréeHost

How to build, test and find your way around the code. The design is in [PLAN.md](PLAN.md) and the decision records in [adr/](adr/); the rules every change follows are in [CLAUDE.md](../CLAUDE.md) and in the project skill [`.claude/skills/soireehost-conventions`](../.claude/skills/soireehost-conventions/SKILL.md), which also lists the Windows pitfalls already found.

SoiréeHost targets Windows 11 x64 only, and so does its development.

## Tools

| Tool | Version | Notes |
| --- | --- | --- |
| Go | the `go` line in [go.mod](../go.mod) | `GOTOOLCHAIN=local` in CI |
| Node.js | 22.12 or later in 22, or 24 and later (CI uses the `NODE_VERSION` in [ci.yml](../.github/workflows/ci.yml)) | for the control panel |
| `wails3` CLI | the `WAILS_VERSION` in ci.yml | generates the UI bindings |
| `golangci-lint`, `staticcheck`, `gosec`, `govulncheck`, `gitleaks` | the versions in ci.yml's `env` block | install with `go install` at those exact versions |

Every Go command needs `GOFLAGS=-mod=readonly -tags=no_fs_access`. Without the `no_fs_access` tag Coraza would write request bodies to temporary files, so `internal/waf` refuses to compile (ADR-0008). A command that passes its own `-tags` must list `no_fs_access` too.

## Build

```
powershell -File build\build.ps1 [-Version 1.2.3] [-Dev] [-SkipChecks] [-Cloudflared]
```

It regenerates the bindings, runs the frontend checks (skipped with `-SkipChecks`), builds the frontend and links `bin\soireehost.exe`. `-Cloudflared` downloads the pinned cloudflared, checks its SHA-256 and embeds it; without it the binary has no tunnel. `-Dev` turns developer tools on and is never for a release.

To work on the control panel without the service, run `npm run dev:fake` in `frontend/`: the Vite server on `127.0.0.1:9245` with a stand-in for the supervisor. A release bundle cannot contain the stand-in; `frontend/scripts/check-bundle.mjs` refuses it.

## Checks

| What | Command |
| --- | --- |
| Go tests | `go test ./...` (race tests need cgo and run in CI only) |
| Go static analysis | `go vet ./...`, `golangci-lint run ./...`, `golangci-lint run --build-tags no_fs_access,e2e ./internal/e2e/...`, `staticcheck -tags no_fs_access ./...`, `gosec -quiet -tags no_fs_access -exclude-dir=.semgrep ./...` |
| Known vulnerabilities | `govulncheck -tags no_fs_access ./...`; `npm audit` in `frontend/` |
| Frontend | in `frontend/`: `npm ci --ignore-scripts`, `npm run check`, `npm run lint`, `npm test` |
| Fuzzing | `powershell -File build\fuzz.ps1 -Duration 30s` (every target, one after another) |
| Rule set | `powershell -File build\check-crs.ps1` (the vendored Core Rule Set matches its signed release) |
| Binary mitigations | `go run ./build/pecheck bin/soireehost.exe` |
| Secrets | `gitleaks dir --redact .` |
| Project Semgrep rules | `semgrep scan --metrics=off --config .semgrep --error --exclude=.semgrep` |

Tests that install services or need administrator rights live in `internal/e2e` (build tag `e2e`) and run only in the CI `isolation` job, on a throwaway runner. Never run them on your own PC.

## Where things live

One binary, `soireehost.exe`, with its role chosen by the first argument: `gui` (the default), `service`, `worker`, `tunnel`, `setup`.

| Path | Holds |
| --- | --- |
| `cmd/soireehost` | `main`: picks the role |
| `internal/gui` | Control-panel role: Wails window, tray, the bindings the UI calls |
| `internal/supervisor` | Service role: validates and stores settings, holds secrets, starts and watches the workers, answers the control pipe |
| `internal/worker` | Web worker role: embedded Caddy, its modules (guard, rate limit, log filters), the Caddy config builder |
| `internal/waf` | The web application firewall: Coraza with the vendored Core Rule Set, as a Caddy handler |
| `internal/tunnel` | Tunnel launcher role: the embedded cloudflared, confined, and its health reports |
| `internal/setup` | Setup role: install, repair, uninstall (elevated) |
| `internal/svcrun` | Running a role as a Windows service; the service manager client |
| `internal/ipc` | Pipe framing, the typed control API, the worker messages, pipe server and client |
| `internal/config` | Settings schema, validation (no disk or network, so it can be fuzzed), versioned store |
| `internal/sitecheck` | Request path rules, static-folder checks, the exposure check |
| `internal/secrets` | DPAPI secret store |
| `internal/audit` | Hash-chained, append-only audit log |
| `internal/accesslog`, `internal/fwevent` | Reading the worker's access and firewall logs back, as untrusted input |
| `internal/logread` | Listing and reading rotated log files, shared by the two above |
| `internal/redact` | Masking request data before it is logged |
| `internal/winsec` | Windows security primitives: SIDs, access lists, confinement, pipe identity, socket checks |
| `internal/dllsearch` | Restricts DLL loading to System32 before any other package initialises |
| `internal/fsutil` | Atomic file writes |
| `internal/version` | The version string, set at link time |
| `internal/testutil` | Test helpers only |
| `internal/e2e` | Tests against an installed system (CI only) |
| `frontend/` | The control panel: Svelte 5 and TypeScript. `src/screens` are the five screens and the first run, `src/components` the shared pieces, `src/lib` state, the API wrapper and the message catalogue (`lib/i18n/en.ts`, every string), `src/styles` the design tokens and styles. `bindings/` is generated; never edit it by hand |
| `build/` | Build, fuzz and rule-set scripts; `pecheck` (binary mitigations); `docscheck` (documented tests exist) |
| `.semgrep/` | The project's own Semgrep rules, each with its test cases |
| `docs/` | The plan, threat model, decision records, security checklist, test plan, dependency record, reviews and design screens |

## Records to keep up to date

A change that touches one of these updates it in the same pull request:

- [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md): every S-ID with the tests that prove it and their latest CI result. `build/docscheck` fails if a test named there, in TEST_PLAN.md, PLAN.md or an ADR no longer exists.
- [TEST_PLAN.md](TEST_PLAN.md): which kind of test proves what, and where it runs.
- [DEPENDENCIES.md](DEPENDENCIES.md): every dependency with its version, licence and reason.
- [adr/](adr/): a new record, or a dated note on an existing one, when a design decision changes.
- [HISTORY.md](HISTORY.md): a section per phase (pull requests, CI runs, owner decisions). The Status section of `CLAUDE.md` stays short: done, next, open.

# Dependencies

Every dependency needs a reason, a pinned version, a licence check and a `govulncheck` or `npm audit` pass (plan section 1 rule 5, S-70, S-75). Update this file in the same change that adds or upgrades a dependency.

Last reviewed: 12 Nov 2026 (Phase 1).

## Linked into soireehost.exe (Go)

From `go version -m bin/soireehost.exe`:

| Module | Version | Licence | Why |
| --- | --- | --- | --- |
| `github.com/wailsapp/wails/v3` | v3.1.0 | MIT | Window, tray, Go-to-UI bindings, updater (ADR-0003) |
| `golang.org/x/sys` | v0.50.0 | BSD-3-Clause | Windows APIs: services, ACLs, DPAPI, job objects, tokens |
| `github.com/go-ole/go-ole` | v1.3.0 | MIT | Pulled in by Wails for COM (WebView2) |
| `github.com/caddyserver/caddy/v2` | v2.11.9 | Apache-2.0 | Web worker: HTTP server, file server, reverse proxy, headers, body limits, rotating logs (plan section 3, ADR-0005). Added in Phase 1. Imported packages only: `caddy`, `modules/caddyhttp` (+ `fileserver`, `headers`, `requestbody`, `reverseproxy`), `modules/caddytls`, `modules/caddyfs`, `modules/logging` |
| `go.uber.org/zap` | v1.28.0 | MIT | Caddy's logger; imported directly by the S-18 log filters |
| `github.com/Microsoft/go-winio` | v0.6.4 | MIT | Named pipes for the control and worker channels (plan section 3, ADR-0006): exclusive first instance, remote clients rejected, SDDL descriptors, Identification-level dialing. Was already in the graph at v0.6.2 through Wails; made direct and moved to the newest release in Phase 2 |

Linked in with Caddy (Phase 1): 150 Go modules in all, counted from `go version -m` on a development build that includes the worker. Licences, read from each module's licence file on 12 Nov 2026: Apache-2.0 62, MIT 53, BSD-3-Clause 30, BSD-2-Clause 3, MPL-2.0 1 (`github.com/go-sql-driver/mysql` v1.10.1, used unmodified; MPL's file-level copyleft only asks that its source stays available, which upstream provides), public domain 1 (`github.com/zeebo/blake3`). No GPL or unknown licences. Most of these are linked but never called: Caddy's `caddyhttp` imports cobra (its CLI) and OpenTelemetry with gRPC (tracing), and `caddytls` imports the smallstep CA with its MySQL, PostgreSQL and Badger stores. Caddy adds about 45 MB to the binary (10 MB without the worker, 55 MB with it). The release build links the worker from Phase 2, when the service starts it; until then only development builds contain it.

Upgraded in Phase 1 above what Caddy selects, to clear `govulncheck` findings: `github.com/klauspost/compress` v1.20.1 to v1.20.4 (GO-2026-6865, a panic reachable from both the Wails updater path and Caddy; fixed in v1.20.2), `golang.org/x/net` to v0.62.0 (GO-2026-6866, GO-2026-6860, not reachable), `golang.org/x/crypto` to v0.59.0 (GO-2026-5932, not reachable). Also moved to the newest releases: `golang.org/x/sync` v0.25.0, `golang.org/x/term` v0.48.0, `golang.org/x/text` v0.44.0.

`govulncheck ./...` (v1.9.0, 12 Nov 2026): no vulnerabilities found.

## Embedded executable

| Program | Version | Licence | Why |
| --- | --- | --- | --- |
| `cloudflared-windows-amd64.exe` (Cloudflare) | 2026.11.0, SHA-256 `d5c1d82031da6253dcdcff64c944cd0fe063016edeb2e4fd088075fc9bd52d0a` | Apache-2.0 | The Cloudflare Tunnel connector (plan section 3, ADR-0002, ADR-0007). It has no library API, so the official release binary is embedded with `go:embed` and run as a child process. Pinned in `build/cloudflared.lock`; `build/fetch-cloudflared.ps1` downloads it from the official release and refuses it unless the hash matches (S-71). Moved from 2026.10.7 to 2026.11.0 on 14 Nov 2026: the new release fixes VULN-170057 (Access bypass with matrix parameters) and builds with Go 1.27.4; no other change |

## Bundled into the UI (npm, ends up in the binary)

| Package | Version | Licence | Why |
| --- | --- | --- | --- |
| `@wailsio/runtime` | 3.1.0 | MIT | Calls bound Go methods from the UI |
| `svelte` (runtime part) | 5.57.3 | MIT | UI framework (owner decision) |
| `esm-env`, `clsx` | 1.2.2, 2.1.1 | MIT | Svelte runtime dependencies |

## Build and test tools only (not shipped)

Pinned exactly in `frontend/package.json` and `frontend/package-lock.json`: Vite 8.3.8, `@sveltejs/vite-plugin-svelte` 7.3.1, TypeScript 6.0.3, `svelte-check` 4.7.8, ESLint 10.14.0, `eslint-plugin-svelte` 3.24.1, `typescript-eslint` 8.72.2, Vitest 5.1.0, `globals` 17.14.0, `@eslint/js` 10.0.1. Licences across the lockfile: MIT, Apache-2.0, ISC, BSD-2/3-Clause, 0BSD, BlueOak-1.0.0 and MPL-2.0 (Vite's CSS tooling). None of these is shipped.

TypeScript stays on 6.0.x because `svelte-check` 4.7.8 and `typescript-eslint` 8.72.2 do not yet support TypeScript 7.

Go tools, installed at pinned versions and also pinned in `.github/workflows/ci.yml`: `wails3` v3.1.0, `golangci-lint` v2.15.0, `staticcheck` v0.8.2, `gosec` v2.30.0, `govulncheck` v1.9.0, `gitleaks` v8.30.1.

Other CI and developer tools, pinned in the `env` block of `.github/workflows/ci.yml`:

| Tool | Version | Licence | Why |
| --- | --- | --- | --- |
| Semgrep (Community Edition, from PyPI) | 1.185.0 | LGPL-2.1-or-later | Plan section 10 requires Semgrep with the project's own rules (`.semgrep/`: S-01, S-34, S-40, R-14, CLAUDE.md rule 6), which golangci-lint and gosec cannot express. Runs offline with `--metrics=off`; no login or cloud platform. Developers install it per user with `python -m pip install --user semgrep==1.185.0` |

## Overrides

| Package | Forced to | Why |
| --- | --- | --- |
| `minimatch` | 11.0.8 | GHSA-g3hv-75wg-m249 (moderate, denial of service) affects 7.0.0 to 11.0.0, used by ESLint and `typescript-eslint`. Lint and tests pass with 11.0.8 |

## Accepted findings

| Finding | Severity | Where | Why accepted | Review again |
| --- | --- | --- | --- | --- |
| GHSA-gcqx-w48m-w2h4, `deepmerge` prototype poisoning | Low | `@sveltejs/vite-plugin-svelte`, build time only | No fixed version exists. It merges this project's own config files at build time; no attacker-controlled input reaches it, and nothing from it ships | When a fixed `deepmerge` or a plugin release without it appears |
| GHSA-4w3g-jfj2-cw2q, GHSA-mgcc-cww5-fp2q, GHSA-vvm8-gf78-28g4, `github.com/go-jose/go-jose/v3` v3.0.5 panics and denial of service on hostile JOSE input | Medium | Caddy `caddytls` → smallstep `certificates` → `go.step.sm/crypto/jose` | No v3 release fixes them (3.0.5 is the last); the fixes are in v4. `govulncheck` reports none reachable: the parsing runs only in Caddy's internal CA and ACME server, which the generated config never enables. `go-jose/v4`, which SoiréeHost does reach, is at v4.1.9 (newest) | When Caddy or smallstep drops go-jose v3, and at every Caddy upgrade |

CI runs `npm audit --audit-level=moderate`, so this low finding does not fail the build; a new moderate or higher one does.

## Watch list

- `github.com/mholt/caddy-ratelimit`: not adopted (ADR-0005). Its only tag is v0.1.0 from August 2024; the rate limiter is in-house. Revisit if it starts tagging releases.
- `frontend/node_modules` can contain Go source (for example `flatted`). `go.mod` has `ignore ./frontend/node_modules` so `./...` never compiles it.

## Pending

`supply-chain-risk-auditor` (Trail of Bits) is approved but not installed yet. Run it over the Go and npm dependencies once the owner installs the plugin (docs/SKILLS.md).

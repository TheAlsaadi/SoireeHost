# Dependencies

Every dependency needs a reason, a pinned version, a licence check and a `govulncheck` or `npm audit` pass (plan section 1 rule 5, S-70, S-75). Update this file in the same change that adds or upgrades a dependency.

Last reviewed: 15 Nov 2026 (Phase 4).

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

### Added in Phase 4: the web application firewall (ADR-0008), 15 Nov 2026

| Module | Version | Licence | Why |
| --- | --- | --- | --- |
| `github.com/corazawaf/coraza/v3` | v3.8.1 | Apache-2.0 | The web application firewall engine that runs the OWASP Core Rule Set (S-14, plan section 3). Used directly by `internal/waf` instead of `coraza-caddy`, whose logging writes matched request data and unmasked URIs (S-18) and which brings a rule set without five published security fixes. Built with the `no_fs_access` tag so request bodies never reach disk. Two of its transformations are replaced at start-up because of a Windows bug (Coraza issue 1140, ADR-0008 section 4) |
| `golang.org/x/sync` | v0.25.0 | BSD-3-Clause | Was already linked; now imported directly for `semaphore` (the firewall's body budget and inspection slots) |

Linked through Coraza, from `go version -m bin/soireehost.exe`, each with its licence read from the module's own licence file:

| Module | Version | Licence | Used by Coraza for |
| --- | --- | --- | --- |
| `github.com/corazawaf/libinjection-go` | v0.3.3 | BSD-3-Clause | `@detectSQLi` and `@detectXSS` (libinjection) |
| `github.com/petar-dambovaliev/aho-corasick` | v0.0.0-20250424160509-463d218d4745 | MIT | `@pm` and `@pmFromFile` phrase matching |
| `rsc.io/binaryregexp` | v0.2.0 | BSD-3-Clause | Regular expressions over raw bytes |
| `github.com/tidwall/gjson`, `match`, `pretty` | v1.18.0, v1.1.1, v1.2.1 | MIT | The JSON request body processor |
| `github.com/kaptinlin/jsonschema`, `go-i18n` | v0.4.6, v0.1.4 | MIT | The `@validateSchema` operator |
| `github.com/goccy/go-json`, `go-yaml` | v0.10.5, v1.19.2 | MIT | Pulled in by `kaptinlin/jsonschema` |
| `github.com/gotnospirit/makeplural`, `messageformat` | v0.0.0-20180622080156-a5f48d94d976, v0.0.0-20221001023931-dfe49f1eb092 | BSD-2-Clause | Pulled in by `kaptinlin/go-i18n` |
| `github.com/valllabh/ocsf-schema-golang` | v1.0.3 | Apache-2.0 | Coraza's OCSF audit log format; the audit log is off (`SecAuditEngine Off`) |

`govulncheck -tags no_fs_access ./...` (v1.9.0, 15 Nov 2026): no vulnerabilities found.

Supply-chain-risk-auditor pass (S-75), 15 Nov 2026, over `go.mod` (7 direct dependencies; 165 modules swept for advisories at their locked versions):

- **Coraza.** No advisories, repository active (pushed the day of the audit), security policy published. OpenSSF Scorecard: Dangerous-Workflow 10/10, Binary-Artifacts 10/10, Token-Permissions 10/10, Code-Review 7/10. Not assessable for Go: publisher concentration, provenance, download volume and deprecation.
- **The 13 modules Coraza brings.** None carries a known advisory. The audit checked advisories only at this depth.
- **Advisories in the sweep.** All come from modules already on `main` at the same versions, not from this change: the accepted go-jose v3 advisories (below) and GHSA-q7gw-24fr-5p69 in OpenTelemetry (below).

### Vendored rule set (data, not code)

| Data | Version | Licence | Why |
| --- | --- | --- | --- |
| OWASP Core Rule Set, request rules and their data files (30 files in `internal/waf/crs/`) | v4.30.0, archive SHA-256 `3d678a41fd5aade34760127fef5dd64fd7a77848913fc0f70dde0cf467c94427` | Apache-2.0 | The firewall's rules (S-14; owner decision of 15 Nov 2026). Copied byte for byte from the official signed release (signature checked with the CRS key `36006F0E0BA167832158821138EEACA1AB8A6E72`). Pinned in `build/crs.lock`, and `build/check-crs.ps1` fails CI if any file differs from the release. The response rules and their data files are left out (ADR-0008) |

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
| GHSA-q7gw-24fr-5p69, `go.opentelemetry.io/otel/sdk`, `sdk/log` and `trace` v1.46.0 / v0.22.0: `AttributeValueLengthLimit` bypassed by attribute values of U+FFFD runes | Medium | Caddy's tracing support (`caddyhttp` → OpenTelemetry) | Published 13 Nov 2026, fixed in v1.47.0. Already on `main` before Phase 4. `govulncheck` reports it not reachable: SoiréeHost never configures tracing, so no span or attribute is ever recorded | Raise to v1.47.0 or later in a dependency update, and at every Caddy upgrade |

CI runs `npm audit --audit-level=moderate`, so this low finding does not fail the build; a new moderate or higher one does.

## Watch list

- `github.com/mholt/caddy-ratelimit`: not adopted (ADR-0005). Its only tag is v0.1.0 from August 2024; the rate limiter is in-house. Revisit if it starts tagging releases.
- `frontend/node_modules` can contain Go source (for example `flatted`). `go.mod` has `ignore ./frontend/node_modules` so `./...` never compiles it.

## Pending

`supply-chain-risk-auditor` (Trail of Bits) is approved but not installed yet. Run it over the Go and npm dependencies once the owner installs the plugin (docs/SKILLS.md).

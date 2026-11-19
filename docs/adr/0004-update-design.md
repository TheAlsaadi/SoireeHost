# ADR-0004: Updates, release pipeline and upstream watcher

**Status:** Accepted by the owner on 19 Nov 2026
**Date:** 12 Nov 2026, revised 19 Nov 2026 with the owner's Phase 6 answers of 16 Nov 2026
**Deciders:** Owner

## Context

Updates are the most powerful channel into every install: whoever can ship an update runs code as the supervisor and, after the Windows prompt, as an administrator. Releases are hosted free on GitHub Releases. Code signing is not available at first (plan section 11), so origin must be proven another way. ADR-0002 makes `soireehost.exe` the only artifact, and ADR-0010 describes the setup role that installs it.

Requirements: S-42 (only the tunnel and the update check go out), S-60 to S-65 (updates and the upstream watcher), S-70 to S-75 (supply chain).

### Owner decisions (16 Nov 2026)

| Topic | Decision |
| --- | --- |
| Signing identity | Ship unsigned with SHA-256 checksums and a provenance attestation. Build the Authenticode step switched off. Apply to SignPath Foundation after the first release. Certum (€49) is out under the budget rule |
| Update install | One click in the control panel, then the Windows prompt runs the installed `soireehost.exe setup apply-update` (S-64). No unattended updater |
| Update-signing key | Generated offline on the owner's PC; offline backup kept by the owner; held by CI as a secret of a GitHub `release` environment that only `v*` tags may use and that needs the owner's approval for each run |
| Manifest hosting | GitHub Releases: `https://github.com/TheAlsaadi/SoireeHost/releases/latest/download/manifest.json` |
| Update check | On by default: once a day and on "Check now". Settings lists the connection and can turn it off |
| Upstream watcher (S-65) | A free GitHub App owned by the owner, installed on this repository only, with Contents and Pull requests read and write |
| Release in Phase 6 | Dry run only: the release workflow builds every output but publishes nothing. The first real release is in Phase 7 |
| Actions allow list | The owner adds GitHub's own provenance and App-token actions (exact list below) |
| `main` | Requires a pull request and green CI before merging (owner changes the ruleset) |

### What was checked on 16 Nov 2026

- **Wails v3.1.0 has an updater** (`pkg/updater`) with Ed25519 signature checks and a manifest provider. It runs inside the control panel's own process and swaps the running file in place, then starts a helper process of its own. The control panel is not elevated, so it cannot write `%ProgramFiles%`. The updater also knows nothing of the three services, of the double check in S-63, or of the rule that child processes start only through `winsec.StartConfined`. It does not fit, so it is not used (this replaces the 12 Nov wording, which allowed it with a manifest provider).
- **Everything needed is in the standard library:** `crypto/ed25519`, `crypto/sha256`, `encoding/json`, `net/http`, `debug/buildinfo`. No new Go module is added.

## Decision

### The pieces

```
CI, on a v* tag (or by hand, as a dry run)
  build twice, compare ──► soireehost.exe ──► [Authenticode, off] ──► provenance attestation
                                                 │
  release environment (owner approves) ──► sign manifest.json (Ed25519)
                                                 │
                                    GitHub Release: exe, manifest.json, SHA256SUMS, SBOMs

Supervisor (NT SERVICE\SoireeHost)                     Setup (elevated, one action)
  daily / "Check now"                                    the installed soireehost.exe setup apply-update
  GET manifest.json ─► verify (key, version) ─┐          verify manifest and file again
  GET soireehost.exe ─► size + SHA-256 ───────┴► updates\ ─► swap, keep previous, start, roll back on failure
  status.get: "Update ready: 1.3.0"                      (ADR-0010)
        │
Control panel: "Install update" ─► Windows prompt ─────────┘
```

### Trust anchor (S-60)

- **Keys.** The binary trusts the Ed25519 public keys in `internal/update/keys.json`, embedded with `go:embed`. The file holds one key, or two during a rotation. Each key has an id: the first 8 bytes of the SHA-256 of the raw public key, in hex.
- **No fallback.** An empty key list, an unknown key id, a missing signature or a bad signature means refusal. There is no "skip verification" setting, flag or build of any kind.
- **Test keys.** Tests that need a signed update generate a key pair at run time. Isolation-job builds that must trust a test key use the build tag `updatetestkey`, which swaps the embedded key file for one the job writes. The release workflow refuses to sign a binary unless the keys embedded in it equal the committed `keys.json`. A test also fails if `production` and `updatetestkey` are ever built together.

### Manifest format

`manifest.json` is a signed envelope, at most 64 KB:

```json
{
  "format": 1,
  "key": "<key id: 16 hex characters>",
  "payload": "<base64 of the payload bytes>",
  "sig": "<base64 of the Ed25519 signature>"
}
```

- **What is signed.** The signature covers `soireehost-update-manifest-v1\n` followed by the exact payload bytes. The prefix keeps this key's signatures from being valid for anything else.
- **No canonical JSON needed.** The payload is decoded only after the signature verifies.
- **The payload.** It is decoded strictly: unknown fields are refused, keys must match exactly (checked again with a decode into a map, as for the tunnel token), and duplicate keys are refused.

```json
{
  "product": "soireehost",
  "channel": "stable",
  "version": "1.3.0",
  "min_from": "1.0.0",
  "published": "2026-12-01T10:00:00Z",
  "artifact": {
    "name": "soireehost.exe",
    "url": "https://github.com/TheAlsaadi/SoireeHost/releases/download/v1.3.0/soireehost.exe",
    "size": 98765432,
    "sha256": "<64 hex characters>"
  }
}
```

**Checks**, all in the pure package `internal/update` (no disk or network, so it can be fuzzed):

- `product` and `channel` must be exactly the expected values.
- `version` and `min_from` must pass `version.Valid`.
- `version` must be newer than the running version (S-62), compared by semantic-version precedence, pre-releases included.
- The running version must not be older than `min_from`.
- `artifact.name` must be exactly `soireehost.exe`.
- The URL must start with `https://github.com/TheAlsaadi/SoireeHost/releases/download/v<version>/`.
- `size` must be between 1 MB and 512 MB.
- `sha256` must be 64 lowercase hex characters.

**The artifact is bound by the signature.** Its size and SHA-256 are inside the signed payload, so "the manifest and every artifact verify against the key" (S-60) holds with one signature.

### Update check and download (supervisor)

- **When.** A first check 10 minutes after the supervisor starts, then every 24 hours with up to 1 hour of random delay. `update.check` triggers one at once, at most once a minute. A check never runs while the supervisor is stopping.
- **Setting.** The check is on by default. The config stores the opposite, `updates.off`, so settings saved before Phase 6 keep the check on; the control call is `update.set_check`. Turning it off counts as a weakening action: it needs confirmation and writes an audit entry (S-32), like Detect only. Turning it back on needs neither.
- **HTTP client.**
  - Normal TLS verification against the Windows root store, never disabled, with TLS 1.2 or newer.
  - No proxy from the environment: a service has none.
  - Timeouts: 30 seconds to the first response byte, 10 minutes for the whole download.
  - Redirects only to `https` on `github.com`, `objects.githubusercontent.com` or `release-assets.githubusercontent.com`. These are the hosts Settings lists for S-42.
  - Limits: the manifest is read up to 64 KB and the artifact up to its signed `size` plus one byte. Anything longer, or shorter, is refused.
  - Tests inject their own root certificates through an unexported field. No production path changes how TLS is verified.
- **Staging (S-63).**
  - The manifest is verified first. If the version is not newer, the check ends with "up to date".
  - The supervisor remembers the newest version it has verified. A later manifest for an older version is not offered. It can only hold updates back (a freeze); see Consequences.
  - The artifact streams to `updates\soireehost-<version>.exe.partial` while the SHA-256 is computed. A wrong size or hash deletes the file.
  - Only a complete, matching file is renamed to `soireehost-<version>.exe`, and the verified envelope is written next to it as `manifest.json`. Both are plain files that take the folder's descriptor (convention rule 13).
  - The supervisor never runs, opens for execution, or loads anything from this folder.
- **Status.** `status.get` gains an `update` block:
  - `state`: `off`, `idle`, `checking`, `downloading`, `ready`, `failed`;
  - `version`: the version found;
  - `last_check`: when the last check finished;
  - `problem`: a closed-set code, never upstream text.

  The control panel shows "Update ready: 1.3.0" with an Install button.
- **Clean-up.** At start, the supervisor deletes staged files for its own version or older. It can delete them because only it writes that folder.

### Install (S-63, S-64)

The control panel's Install button raises the Windows prompt for the installed `%ProgramFiles%\SoireeHost\soireehost.exe setup apply-update`. The command takes no path or version argument: setup reads the fixed staging folder. ADR-0010 describes the swap, the start check and the rollback. In short:

1. **Verify again.** Setup verifies the staged `manifest.json` with its own compiled-in keys and opens the staged file without write or delete sharing. It checks that the file belongs to the supervisor's service SID and is not a link, then checks its size and SHA-256 from that handle.
2. **Swap.** It copies from that handle into the program folder, keeping the old binary as `soireehost.exe.previous`.
3. **Finish.** It starts the new version's repair step, which unpacks the new cloudflared and applies any new service or folder settings, then waits for the supervisor to answer `status.get` with the new version.
4. **Roll back on failure.** If any step fails, or the supervisor is not running the new version within 90 seconds, setup restores the previous binary, its cloudflared and the config snapshot, and starts that version.

The downloaded file is never run before both checks pass: the supervisor's at download, and setup's immediately before the swap.

### Authenticode (S-61), off until signing is approved

- **Release workflow.** It has an Authenticode job that runs only when the repository variable `SIGNING_ENABLED` is `true`. Until then it is skipped, and the release notes and README say the binary is unsigned. When it is turned on (SignPath, after the first release), it signs the exe before the manifest is made, so the manifest's hash covers the signed file.
- **Setup's check.**
  - If the running binary carries a valid Authenticode signature, the candidate must carry a valid one from the same subject. This is never signed to unsigned.
  - If the running binary is unsigned, the candidate may be either.
  - The check uses `WinVerifyTrust` through `windows.NewLazySystemDLL("wintrust.dll")` (convention rule 9).
  - This code ships in Phase 6. Its full test needs a signed build, so S-61 stays "not verified" until signing exists. Until then, a unit test covers the decision table.

### Release workflow (`.github/workflows/release.yml`)

**Triggers.** A `v*` tag (tags are limited to the owner by the tag ruleset), or `workflow_dispatch` as a dry run. In Phase 6 only the dry run is used.

| Job | Permissions | Does |
| --- | --- | --- |
| `build` | `contents: read` | Builds the release binary twice with `build.ps1 -Version X -Cloudflared` (`-tags production`, `-trimpath`, `CGO_ENABLED=0`, `-mod=readonly`, `no_fs_access`). The two builds run from different folders, and their SHA-256 must be equal (S-74). It also checks that the embedded update keys equal `keys.json`, runs `pecheck`, and writes `SHA256SUMS` and the SBOMs |
| `authenticode` | `contents: read` | Skipped unless `SIGNING_ENABLED` (S-61, S-72) |
| `attest` | `id-token: write`, `attestations: write`, `contents: read` | `actions/attest-build-provenance` on the exe (S-73) |
| `manifest` | `contents: read`; environment `release` | Signs `manifest.json` with `build/signmanifest`, then verifies the result with `internal/update`, the same code the app runs. This job runs no action other than `actions/checkout` and `actions/setup-go`. On a dry run there is no `release` environment (it allows `v*` tags only), so a key pair made in the job signs and verifies instead |
| `publish` | `contents: write`; tags only | `gh release create` with `soireehost.exe`, `manifest.json`, `SHA256SUMS` and the SBOMs, using the GitHub CLI already on the runner. A dry run uploads the same files as workflow artifacts, so the owner can use that build for the VM check |

**Other rules:**

- **SBOM (S-73).** No new tool: `build/sbom` reads the module list and `go.sum` hashes from the built exe with `debug/buildinfo`. It writes CycloneDX 1.6 JSON with cloudflared and the Core Rule Set added as components from their lock files. The frontend's SBOM comes from `npm sbom --sbom-format cyclonedx`, which is built into npm.
- **Secrets (S-72).** No pull-request build sees a secret. The signing key exists only in the `release` environment, and only the `manifest` job uses it, passed as an environment variable and never as an argument.
- **Allow list.** The owner adds `actions/attest-build-provenance@*`, `actions/attest@*` (which the provenance action calls), `actions/create-github-app-token@*` and `actions/upload-artifact@*` (dry-run outputs) to the repository's Actions allow list. All are GitHub's own, pinned by commit SHA.

### Signing key

- **Tool.** `build/updatekey` (standard library only), run on the owner's PC with no administrator rights. `gen` creates a key pair:
  - it writes the private key to a path outside the repository (it refuses any path inside it);
  - it prints the public key and its id, for `keys.json`.

  `check` reads the private key and confirms that its public half is in `keys.json`.
- **Storage.** The private key goes into the `release` environment's secret `UPDATE_SIGNING_KEY`. The owner keeps an offline backup, for example on a USB stick or in their password manager. The working copy is deleted from the PC after both are in place.
- **Documentation.** `docs/UPDATE_KEY.md` records generation, backup, rotation and what to do after a compromise.
- **Rotation.** Release N ships `keys.json` with the old and new keys. From release N+1, manifests are signed with the new key, and the old key is dropped one release later.
- **Compromise.** Rotate at once. Clients still on a release that trusts the old key can be served a forged update until they update. This is a limit of a single key; see Option D.

### Outbound connections (S-42)

Only two components make outbound connections:

- cloudflared, to Cloudflare, while a site is online;
- the supervisor's update check, to the three GitHub hosts above, while the check is on.

Settings already lists both. The CI isolation job proves it:

- **Capture.** It records a network trace with `netsh trace` (the Microsoft-Windows-Kernel-Network provider, which gives the process id for every TCP and UDP send) while a site is live through quick share and an update check runs.
- **Assertions.**
  - The web worker, the tunnel launcher and the control panel have no non-loopback destination.
  - cloudflared talks only to Cloudflare's published IP ranges.
  - The supervisor talks only to addresses listed for GitHub in `api.github.com/meta`.
- **By hand.** The owner's VM check repeats it with Resource Monitor.

### Upstream watcher (S-65)

`.github/workflows/upstream-watch.yml`, run daily and by hand:

- **What it watches.**
  - cloudflared (`build/cloudflared.lock`);
  - the Core Rule Set (`build/crs.lock`);
  - the Go toolchain (`go.mod` and `GO_VERSION` in `ci.yml`);
  - the `wails3` CLI (`WAILS_VERSION`).

  Caddy, Coraza and every other Go module are already covered by Dependabot. Its security updates are not delayed by the 7-day cooldown.
- **`check` job** (`contents: read`, the default `GITHUB_TOKEN`). It compares each pin with the newest stable release through the GitHub API.
- **`propose` job**, only when something is newer. It updates the pin with the repository's own scripts:
  - **cloudflared.** It downloads the asset, computes its SHA-256 and compares it with the hash in the release notes. Both must agree, or the job stops and opens an issue instead.
  - **Core Rule Set.** `check-crs.ps1 -Update`, which checks the release signature.

  It then mints a one-hour token with `actions/create-github-app-token` from the App's id and private key (repository secrets `WATCHER_APP_ID` and `WATCHER_APP_KEY`), pushes a branch `upstream/<component>-<version>` and opens a pull request with `gh`. That token is what makes CI run on the pull request.
- **Merging.** Nothing merges automatically. The owner reviews and merges. Target: a release within 7 days of an upstream security fix.

### `main` ruleset

The owner extends the `main` ruleset:

- **Pull request required**, with no required approvals: the owner is the only person who can approve.
- **Required checks.** Go checks, Frontend checks, Build soireehost.exe, Secret scan, Semgrep (project rules), Isolation (installs services on the runner) and CodeQL's `Analyze (go)` and `Analyze (javascript-typescript)`.

GitHub's auto-merge then waits for CI. The watcher's and Dependabot's pull requests go through the same checks.

## Options considered

### Option A: Own verifier with a pinned Ed25519 manifest (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium: about 300 lines of verifier plus the staging and the setup swap |
| Cost | Free |
| Security | Authenticity without code signing; independent of GitHub's integrity; fits the service model |

### Option B: Checksum file only

**Cons:** a checksum fetched from the same place as the binary proves integrity, not origin. Rejected (plan section 11).

### Option C: Authenticode only

**Cons:** not available for free until SignPath accepts the project; even then, a pinned key adds a second, independent check. Kept as an additional check (S-61).

### Option D: TUF (The Update Framework)

**Pros:** handles key rotation, thresholds, and freeze and rollback attacks formally.
**Cons:** it would be a new dependency, and it is heavier than a single-artifact app needs. Revisit if there are ever several signers or frequent rotations.

### Option E: The Wails v3 updater with its manifest provider

**Pros:** already in the dependency tree; it checks Ed25519 signatures.
**Cons:** it runs in the unelevated control panel and swaps the running file in place, so it cannot update `%ProgramFiles%` or the services. It starts an unconfined helper, and it has no double check or rollback across services. Rejected.

### Option F: Sign the manifest on the owner's PC

**Pros:** the key never reaches GitHub, so a takeover of the owner's GitHub account alone cannot forge updates.
**Cons:** a manual step in every release, and malware on the PC could take the key. The owner chose the CI environment.

## Trade-off analysis

- **Where verification happens.** The supervisor already runs as a service account with a folder only it can write, so it checks and stages. Setup is the only part with rights over `%ProgramFiles%`, so it checks again and swaps. Neither trusts the other's check. The control panel only shows state and raises the prompt, so a compromise of the user session cannot install anything without the prompt and a valid signature.
- **One signed envelope instead of two files.** A truncated download, a missing signature and a mismatched pair all fail the same single check.
- **The cost of the CI key.** It is automation, at the price of trusting GitHub's environment protection and the owner's account. That account is already the root of trust for the source, so the added risk is small.

## Consequences

- **Lost key.** If every copy of the private key is lost, existing installs can no longer update; users must reinstall by hand. The offline backup and `docs/UPDATE_KEY.md` exist for that.
- **Rotation** needs two releases (see Signing key).
- **Freeze attacks.** A network attacker can withhold updates, but cannot roll an install back or install anything (S-62, S-63). The control panel shows when the last successful check ran, so a long silence is visible. This is accepted for version 1 (Option D revisits it).
- **One prompt per update** in version 1 (S-64).
- **First use of the real key.** The real signing key is first used for the first real release (Phase 7). Phase 6 proves the pipeline with a key made in the job.
- **Owner actions.** The owner has four things to do:
  - change the `main` ruleset and the Actions allow list;
  - create the `release` environment;
  - generate the key;
  - create the watcher's GitHub App (steps in Stage 3).

## Action items

1. [x] Owner: accept or amend this record. Accepted 19 Nov 2026.
2. [x] `internal/update`: envelope, payload, key list, version precedence, artifact check; unit tests for tampered payload, tampered signature, wrong key, unknown key id, missing signature, truncated envelope and file, oversized input, older and equal versions, `min_from`, product, channel, name and URL; fuzz targets for the envelope and the payload.
3. [x] Supervisor: checker, download, staging, `update.check`, the `update` status block, the `updates.off` setting (`update.set_check`) with confirmation and audit; tests against a local TLS server (19 Nov 2026).
4. [ ] Setup `apply-update` with the double check, swap and rollback (ADR-0010); isolation-job tests for a good update and for tampered, wrong-key, truncated, older-version, failed-start and interrupted updates.
5. [ ] Control panel: "Update ready", Install (Windows prompt), "Check now", last check, the setting.
6. [ ] `build/updatekey`, `build/signmanifest`, `build/sbom`, `docs/UPDATE_KEY.md`.
7. [ ] `release.yml` (dry run) and `upstream-watch.yml`; the S-42 capture in the isolation job.
8. [ ] Owner, before the first release: generate the key, store the backup, commit `keys.json`, create the `release` environment and the GitHub App.

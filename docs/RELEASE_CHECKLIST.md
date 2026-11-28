# Release checklist

The steps for every SoiréeHost release, starting with the first real one (Phase 7). The release workflow is `.github/workflows/release.yml`; the design is ADR-0004, and the signing key is described in `docs/UPDATE_KEY.md`. Phase 6 ran the workflow as a dry run only (owner decision, 16 Nov 2026).

Written at the end of Phase 6 from the deploy-checklist review (20 Nov 2026). Items marked **(enforced)** fail the workflow if they do not hold; the rest are the owner's to check.

## Once, before the first release

- [x] (21 Nov 2026: key `229bc25eefe83c4a`, two offline backups kept by the owner.) The update-signing key exists, its offline backup is stored, and `internal/update/keys.json` holding its public half is merged (`docs/UPDATE_KEY.md`). **(enforced:** the manifest job refuses to sign when the binary's embedded key file differs from `keys.json`, and `update.Open` refuses an empty key list**)**
- [x] (21 Nov 2026.) The `release` environment exists, limited to `v*` tags, with the owner as required reviewer, holding the secret `UPDATE_SIGNING_KEY`.
- [x] (Ruleset `release-tags`, read back 21 Nov 2026.) The tag ruleset lets only the owner create `v*` tags.
- [x] (20 Nov 2026.) The `main` ruleset requires a pull request and the green checks ADR-0004 lists.
- [x] (Unset, 21 Nov 2026.) `SIGNING_ENABLED` is unset (or `false`) until the SignPath steps exist. **(enforced:** the Authenticode job fails when it is `true`, and the manifest and the draft release then do not run**)**

## Before tagging

The ticks and the dated notes below are for `v1.0.0-rc.1`. Clear them and check each item again for the next release.

- [ ] Everything for the release is merged to `main`, and CI on that `main` commit is green: Go checks, frontend checks, build, secret scan, Semgrep, Isolation (with the timed first-site check and the S-42 capture), CodeQL. **(enforced:** a tag run refuses a commit that is not on `main` or has no successful CI run**)** (rc.1, 28 Nov 2026: not ticked. The commit to tag is chosen after the soak. The last completed `main` CI run checked was 46049051231 on `dc2e805`, with every job green, Isolation included; CodeQL 46049051065 green.)
- [x] No high-severity finding is open (`docs/SECURITY_CHECKLIST.md`, the Dependabot and code-scanning pages). (rc.1, 28 Nov 2026: the open Dependabot, code-scanning and secret-scanning alert lists are all empty (GitHub API). `docs/SECURITY_CHECKLIST.md` has no Fail row. The High items of the 12 Nov review are closed: SE-20 (`TestLoadJSONRefusesAdminAPI`), SE-22 (`TestNewRefusesWritableFolders`), SE-03 (pull request 35). Look at the alert pages again on the day of the tag.)
- [x] The version is newer than the last published release. Installs refuse an older or equal version (S-62), so a reused number would reach nobody. (rc.1, 28 Nov 2026: `gh release list` and `git ls-remote --tags origin` are both empty, so `1.0.0-rc.1` is the first release.)
- [x] `MIN_FROM` in `release.yml` is still right: raise it when this release can no longer read settings written by older ones. (rc.1, 28 Nov 2026: `0.1.0`, below `1.0.0-rc.1`. No release has written settings before; `config.SchemaVersion` is 1.)
- [x] Key rotation: if `keys.json` changed, the release follows the three-release plan in `docs/UPDATE_KEY.md`. (rc.1, 28 Nov 2026: not needed. `keys.json` holds the one key `229bc25eefe83c4a`, last changed by `0383256` on 21 Nov, before any release.)
- [x] `go.mod` and `go.sum` are tidy and `go.mod` has no `replace` directive. **(enforced** by CI's Go checks on the tagged commit**)** (rc.1, 28 Nov 2026: no `replace` directive; the tidy step passed in the Go checks of CI run 46049051231 on `dc2e805`, and neither file has changed since `03f57bb`. The tag run still requires CI on the tagged commit.)
- [x] The Go toolchain in `go.mod` is the current stable release (the upstream watcher proposes it), and no `godebug` entry pins a behaviour Go has removed. (rc.1, 28 Nov 2026: `go.mod` says `go 1.27.4`, and `https://go.dev/VERSION?m=text` answers `go1.27.4`. No `toolchain` or `godebug` line, and no `//go:debug` comment.)
- [x] The release notes name what changed, state the platform (Windows 11 x64 only), say the binary is not Authenticode-signed yet (until SignPath), and list known limits (tunnel-token mode with a real hostname not yet verified). (rc.1, 28 Nov 2026: `docs/release-notes/v1.0.0-rc.1.md`. The workflow writes its own short text on the draft, so put this file on the draft before publishing; the command is in `docs/HANDOFF.md`.)

## Release

1. Tag `vX.Y.Z` (an annotated tag, full semantic version, leading `v`) on the `main` commit and push the tag. Never move or reuse a tag: installs and the provenance attestation are tied to the bytes first released under it.
2. The workflow builds twice from separate clones and compares the hashes (S-74) **(enforced)**, checks ASLR, DEP and high-entropy VA (S-24) **(enforced)**, writes the SBOMs and `SHA256SUMS` (S-73), and attests the build provenance (S-73).
3. Approve the `manifest` job when GitHub asks (the `release` environment). It signs `manifest.json` and verifies it with the app's own code **(enforced)**.
4. The workflow creates a **draft** release. Nothing reaches installs yet: `releases/latest` ignores drafts.

## Before publishing the draft

VirtualBox on this PC runs on top of Hyper-V. Take snapshots with the VM powered off (a live snapshot froze it), and give it host I/O cache, the VMSVGA display and 2 CPUs. A restart inside the VM sometimes hangs on a black screen; a reset recovers it.


- [ ] Download the draft's files. `SHA256SUMS` matches every file.
- [ ] `gh attestation verify soireehost.exe --repo TheAlsaadi/SoireeHost` passes.
- [ ] Install the draft's `soireehost.exe` on a clean Windows 11 VM: install window, Windows prompt, Apps entry, a site live through quick share in under 5 minutes.
- [ ] On a VM running the previous release, the update is found, Install update raises one prompt, the new version runs, the control panel reopens, and the settings are kept (S-64; the first release has no previous one, so this starts with the second).
- [ ] Uninstall on the VM leaves no service, firewall rule, Apps entry or program file (moved files are gone after a restart).

## Publish

A release candidate (`vX.Y.Z-rc.N`) is published as a GitHub pre-release (owner decision, 21 Nov 2026). `releases/latest` skips pre-releases, so installs on a candidate are not offered a later candidate; they are offered the next full release. A later candidate is installed by hand over the earlier one.

- [ ] Publish the draft. From now on, every install's daily check finds it.

## After publishing

- [ ] `https://github.com/TheAlsaadi/SoireeHost/releases/latest/download/manifest.json` serves the new manifest.
- [ ] A VM on the previous release shows "Update ready" after Check now.
- [ ] HISTORY.md records the release, its workflow run and the checks above.

## If a published release is bad

There is no downgrade path, by design (S-62): installs refuse anything older than what they run.

- **Stop it spreading:** mark the release as a pre-release or delete it. `releases/latest` then points at the previous release again. Installs that have not updated yet find nothing newer. Installs that already staged it keep the staged file until they install it or a newer one replaces it.
- **Fix forward:** release `X.Y.Z+1` with the fix. Installs on the bad version update to it.
- **A release that cannot start** is rolled back on each PC by setup itself (ADR-0010: the previous binary, its cloudflared and the settings snapshot come back, exit code 22).
- **A leaked signing key:** follow "If the key is stolen" in `docs/UPDATE_KEY.md`.

## Rollback triggers

Decide these before publishing:

- the VM update check above fails, or setup rolls the update back on the VM;
- the S-42 capture or the timed first-site check fails on the release commit;
- a report of a failed update or a lost setting, from anyone, before the release has been out a week.

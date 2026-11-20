# Release checklist

The steps for every SoiréeHost release, starting with the first real one (Phase 7). The release workflow is `.github/workflows/release.yml`; the design is ADR-0004, and the signing key is described in `docs/UPDATE_KEY.md`. Phase 6 ran the workflow as a dry run only (owner decision, 16 Nov 2026).

Written at the end of Phase 6 from the deploy-checklist review (20 Nov 2026). Items marked **(enforced)** fail the workflow if they do not hold; the rest are the owner's to check.

## Once, before the first release

- [ ] The update-signing key exists, its offline backup is stored, and `internal/update/keys.json` holding its public half is merged (`docs/UPDATE_KEY.md`). **(enforced:** the manifest job refuses to sign when the binary's embedded key file differs from `keys.json`, and `update.Open` refuses an empty key list**)**
- [ ] The `release` environment exists, limited to `v*` tags, with the owner as required reviewer, holding the secret `UPDATE_SIGNING_KEY`.
- [ ] The tag ruleset lets only the owner create `v*` tags.
- [ ] The `main` ruleset requires a pull request and the green checks ADR-0004 lists.
- [ ] `SIGNING_ENABLED` is unset (or `false`) until the SignPath steps exist. **(enforced:** the Authenticode job fails when it is `true`, and the manifest and the draft release then do not run**)**

## Before tagging

- [ ] Everything for the release is merged to `main`, and CI on that `main` commit is green: Go checks, frontend checks, build, secret scan, Semgrep, Isolation (with the timed first-site check and the S-42 capture), CodeQL. **(enforced:** a tag run refuses a commit that is not on `main` or has no successful CI run**)**
- [ ] No high-severity finding is open (`docs/SECURITY_CHECKLIST.md`, the Dependabot and code-scanning pages).
- [ ] The version is newer than the last published release. Installs refuse an older or equal version (S-62), so a reused number would reach nobody.
- [ ] `MIN_FROM` in `release.yml` is still right: raise it when this release can no longer read settings written by older ones.
- [ ] Key rotation: if `keys.json` changed, the release follows the three-release plan in `docs/UPDATE_KEY.md`.
- [ ] `go.mod` and `go.sum` are tidy and `go.mod` has no `replace` directive. **(enforced** by CI's Go checks on the tagged commit**)**
- [ ] The Go toolchain in `go.mod` is the current stable release (the upstream watcher proposes it), and no `godebug` entry pins a behaviour Go has removed.
- [ ] The release notes name what changed, state the platform (Windows 11 x64 only), say the binary is not Authenticode-signed yet (until SignPath), and list known limits (tunnel-token mode with a real hostname not yet verified).

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

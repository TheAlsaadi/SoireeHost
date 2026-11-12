# ADR-0004: Update design

**Status:** Proposed
**Date:** 12 Nov 2026
**Deciders:** Owner

## Context

Updates are the most powerful channel into every install: whoever can ship an update runs code as the supervisor and, after the Windows prompt, as an administrator. Releases are hosted free on GitHub Releases. Code signing is not available at first (plan section 11), so origin must be proven another way. ADR-0002 makes `soireehost.exe` the only artifact.

## Decision

- **Trust anchor:** one Ed25519 public key compiled into `soireehost.exe` (S-60). The private key is generated offline, backed up offline, and stored only in the CI secret store for tagged builds from protected `main` (S-72).
- **Manifest:** a JSON document listing version, minimum version that may update to it, artifact URL, size and SHA-256, signed with the Ed25519 key. The artifact itself is also covered by the signature through its hash.
- **Check:** the supervisor fetches the manifest from GitHub Releases over HTTPS (normal TLS verification, never disabled), verifies the signature, refuses any version not newer than the running one (S-62).
- **Download:** to `%ProgramData%\SoireeHost\updates\` (supervisor write, Administrators read), then verified (S-63).
- **Install:** the user clicks "Update ready"; the Windows prompt runs the installed `soireehost.exe setup apply-update`, which verifies the staged file again, stops services, swaps the binary (keeping the previous one), unpacks cloudflared, restarts services, and rolls back if the supervisor fails to start (S-63, S-64).
- **Signed builds later:** once releases are Authenticode-signed, also require a valid signature from the expected publisher, and never move from signed to unsigned (S-61).
- **Wails updater:** use it only with the manifest or a custom provider. Never the default GitHub provider, which checks a SHA-256 file but no signature.

## Options considered

### Option A: Pinned Ed25519 manifest (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium |
| Cost | Free |
| Security | Authenticity without code signing; independent of GitHub's integrity |

### Option B: Checksum file only

**Cons:** a checksum fetched from the same place as the binary proves integrity, not origin. Rejected (plan section 11).

### Option C: Authenticode only

**Cons:** not available for free until SignPath accepts the project; even then, a pinned key adds a second, independent check. Kept as an additional check later.

### Option D: TUF (The Update Framework)

**Pros:** handles key rotation, freeze and rollback attacks formally.
**Cons:** heavier than a single-artifact app needs. Revisit if key rotation becomes frequent.

## Consequences

- Losing the private key means existing installs cannot update; users must reinstall by hand. Keep an offline backup and a written rotation plan.
- Rotation: a release signed with the old key ships the new public key; after that release, manifests are signed with the new key.
- Every update needs one elevation prompt in version 1 (owner decision pending; recommendation is one-click).

## Action items

1. [ ] Phase 6: manifest format, signing in CI, verification in the supervisor and setup role.
2. [ ] Phase 6: tests for tampered, wrong-key, truncated, older-version and interrupted updates.
3. [ ] Before first release: generate the key offline, store the backup, write the rotation plan.

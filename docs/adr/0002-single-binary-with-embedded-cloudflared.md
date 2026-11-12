# ADR-0002: One binary with embedded cloudflared

**Status:** Accepted by the owner on 12 Nov 2026 ("Everything should be inside soireehost, as one big app")
**Date:** 12 Nov 2026
**Deciders:** Owner

## Context

SoiréeHost needs cloudflared, which has no supported Go library API and must run as a separate process. The owner wants SoiréeHost to be one app: one file to download, one thing installed, one thing updated.

## Decision

- `soireehost.exe` is the only shipped file. It contains the control panel, supervisor, web worker, tunnel launcher and setup roles.
- The official `cloudflared-windows-amd64.exe` is embedded with `go:embed` at build time. CI downloads it from the official release and refuses to build unless its SHA-256 matches `build/cloudflared.lock` (S-71).
- The SHA-256 from the lock file is compiled into `soireehost.exe`.
- Only the elevated setup role writes `cloudflared.exe` to `%ProgramFiles%\SoireeHost\`, during install, update and repair. It is never unpacked to a temp or per-user folder, and never at each launch.
- The tunnel launcher checks the file's SHA-256 against the compiled-in value before every launch (S-23). On a mismatch it refuses, and the control panel offers Repair.
- There is no separate installer: `soireehost.exe setup install|repair|apply-update|uninstall`.

## Options considered

### Option A: Embed and unpack during elevated setup (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium: setup must unpack and verify |
| Cost | Free |
| Security | cloudflared lives in an admin-write-only folder; hash checked at every launch |
| User experience | One file to download and update |

### Option B: Ship cloudflared beside soireehost.exe in an installer

**Pros:** no unpacking step; antivirus sees two ordinary files.
**Cons:** two artifacts to download, verify and update; contradicts the owner's decision.

### Option C: Unpack to a temp folder at each launch

**Pros:** no setup step needed.
**Cons:** a user-writable or temp location invites tampering between write and run; classic antivirus red flag. Rejected.

## Trade-off analysis

Option A keeps the "one app" property while putting the executable where only administrators can write. The hash check at launch closes the remaining window. Binary size grows by the size of cloudflared (tens of megabytes), which is acceptable.

## Consequences

- Easier: one update replaces the app and cloudflared together (S-64); releases are one executable plus the manifest.
- Harder: some antivirus engines flag executables that carry other executables. Mitigated by unpacking only during elevated setup and, later, by code signing.
- Licences: cloudflared's Apache-2.0 notice is embedded and shown on the Licences screen.
- Revisit: if antivirus false positives become a real problem for users before signing is available.

## Action items

1. [ ] Phase 3: `internal/tunnel` embeds the verified binary; build fails if the hash does not match.
2. [ ] Phase 3: launcher hash check and Repair flow; test with a modified binary.
3. [ ] Phase 6: setup unpacks during install, update and repair; uninstall removes it.

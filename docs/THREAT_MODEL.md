# SoiréeHost threat model

**Status:** Proposed, awaiting owner acceptance (Phase 0)
**Date:** 12 Nov 2026
**Source:** docs/PLAN.md sections 4, 5 and 11

SoiréeHost turns a Windows 11 PC into a web host reachable only through an outbound Cloudflare Tunnel. This document says what it protects, from whom, and what it does not attempt.

## Assets

| Asset | Where it lives | Why it matters |
| --- | --- | --- |
| The PC and the home network behind it | The owner's machine and LAN | The main thing an internet attacker wants to reach |
| Cloudflare tunnel token | DPAPI blob in `%ProgramData%\SoireeHost\secrets\`; in memory of the supervisor and the tunnel launcher | Lets anyone run the owner's tunnel and receive the owner's traffic |
| Configuration | `%ProgramData%\SoireeHost\config\` | Decides what is published and how it is protected |
| Site content and hosted apps | Folders and local ports the owner chooses | What visitors see; may contain files never meant to be public |
| Update signing key | Offline, and in the CI secret store | Whoever holds it can ship code to every install |
| Audit, access and firewall logs | `%ProgramData%\SoireeHost\logs\` | Evidence of what happened; also attacker-influenced text |
| The control panel's user session | The signed-in user's desktop | Displays attacker-controlled data |

## Trust boundaries

1. **Internet to Cloudflare edge.** Cloudflare terminates TLS. Everything past this point that came from a visitor is untrusted.
2. **Cloudflare to the PC.** An outbound tunnel opened by cloudflared. No inbound port exists.
3. **Tunnel launcher to web worker.** Plain HTTP on loopback. The web worker treats every byte of the request as hostile.
4. **Web worker to sites.** Static folders (read-only) and loopback upstreams. A hosted app is outside SoiréeHost's control.
5. **Control panel to supervisor.** A named pipe with an ACL. The supervisor validates everything; the control panel is not trusted to validate.
6. **Supervisor to workers.** Named pipes that only each worker's service account can open.
7. **Update server to supervisor.** GitHub Releases over HTTPS, but trust comes only from the pinned Ed25519 signature.
8. **Upstream projects and CI to the release.** Dependencies, build tools and GitHub Actions.

## Attackers

| Attacker | Wants | Main defences | Requirements |
| --- | --- | --- | --- |
| Anyone on the internet | To exploit the web server or a hosted app and reach the PC or home network | No inbound ports, Cloudflare edge, firewall rules, sandboxed worker, loopback-only upstreams | S-01 to S-06, S-10, S-14, S-15, S-20, S-21 |
| Hostile request content | To traverse paths, or to poison logs and attack the control panel when it displays them | Strict path rules, logs treated as untrusted text | S-11 to S-13, S-18, S-33, S-34 |
| Another program or user on the same PC | To read secrets, change config, or impersonate the control panel | File ACLs, DPAPI, pipe ACL, no listening admin port | S-20, S-22, S-30, S-31, S-35, S-40 |
| Network attacker or compromised download host | To deliver a fake update | Signed manifest checked against a pinned key, Authenticode check once releases are signed, no downgrades | S-60 to S-63 |
| Compromised dependency or build step | To run code in the build or in the app | Pinned dependencies, vulnerability scans, minimal dependencies, hardened CI | S-23, S-70 to S-75 |
| The user, by mistake | To publish a folder containing secrets | Exposure check, blocked folders, safe defaults | S-11, S-12, S-14, S-32 |

## Main attack paths and what stops them

| Path | Stopped by |
| --- | --- |
| Visitor sends `/..%5c..%5cWindows\win.ini` or `/secret~1.txt` to read files outside the site | Caddy 2.11.6+ path normalisation, S-11, S-13; path traversal suite (plan section 10) |
| Visitor requests `/.env` or `/.git/config` in a published project folder | S-12 deny list, exposure check before publishing |
| Visitor exploits a hosted app and gets code execution in it | Out of scope to prevent (see below). Contained by: app reachable only on loopback, web worker cannot start processes or read secrets |
| Visitor exploits a bug in Caddy or Coraza and gets code execution in the web worker | S-20, S-21: separate low-privilege service account, restricted SID, no child processes, job object, no access to secrets or config |
| Visitor uses the proxy to reach the LAN or cloud metadata (SSRF) | S-10: loopback-only targets, link-local always refused, LAN only by explicit opt-in |
| Local malware reads the tunnel token | S-40 DPAPI under the service account, S-22 folder ACLs, S-23 token never on the command line |
| Local malware connects to the control pipe and changes settings | S-30 pipe ACL and caller SID check; it can still act as the signed-in user if that user is allowed (see below) |
| Attacker swaps `cloudflared.exe` on disk | Program Files is admin-write only; S-23 hash check before every launch |
| Log line containing `<script>` runs in the control panel | S-33 CSP with no inline script, S-34 text-only rendering enforced by lint |
| Fake update served by a hijacked mirror | S-60 pinned Ed25519 key, S-62 no downgrades, S-63 verify twice |
| Malicious dependency update | S-70 pinning, S-75 review, `govulncheck`, upstream watcher PRs reviewed by the owner |

## Not defended against

- **An attacker who already has administrator rights on the PC.** They can read any file, stop any service and replace any binary.
- **Malware running as a user who is allowed on the control pipe.** It can do anything that user can do in the control panel. Weakening actions still need confirmation and are audited (S-32), but a determined program can script around that.
- **Vulnerabilities inside hosted apps.** SoiréeHost contains them; it does not fix them.
- **A compromise of Cloudflare.** Cloudflare sees all traffic in clear text at its edge.
- **Physical access** to the PC.
- **Denial of service** beyond per-client rate limits. Cloudflare's free tier absorbs some volumetric attacks; a home connection cannot absorb the rest.

## Residual risks to watch

- Wails v3 is a new stable line; bugs in it affect the control panel (not the traffic path).
- `caddy-ratelimit` has no tagged releases; an in-house handler may be preferable (Phase 1 decision).
- Early releases are unsigned (plan section 11), so users must check checksums themselves until SignPath signing is in place.
- Embedding and unpacking cloudflared may trigger antivirus heuristics.

## Acceptance

The owner accepts this threat model by approving Phase 0. Changes after that are recorded here with a date.

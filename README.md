# SoiréeHost

**Local Hosting Control Center.** Host websites and local apps from a Windows PC, reachable from the internet through Cloudflare Tunnel, without opening any inbound port.

**Status: heading for its first release candidate.** Phases 0 to 6 of the [plan](docs/PLAN.md) are built; Phase 7 (hardening, long tests and the first release candidate, `1.0.0-rc.1`) is under way.

- One program, `soireehost.exe`, for Windows 11 x64.
- Sites are published only through an outbound tunnel; your home IP stays hidden and nothing listens for the internet on your PC.
- Share a folder or a local app in a few clicks: a temporary `trycloudflare.com` link with no account, or a permanent address on your own domain.
- Every site sits behind a web application firewall (the OWASP Core Rule Set), rate limits and security headers.
- The part that handles internet traffic runs boxed in, under its own Windows account, with no access to secrets or settings.
- No telemetry. The only outbound connections are the tunnel and a daily update check on GitHub.

SoiréeHost protects the path to a hosted app and contains the damage if the app is compromised. It cannot fix vulnerabilities inside the app you host.

## Get started

1. Download `soireehost.exe` from the [releases page](https://github.com/TheAlsaadi/SoireeHost/releases) and check it against `SHA256SUMS`.
2. Run it and choose **Install**. Windows asks for permission once.
3. Pick a folder or an app, choose **Quick share link**, and **Go live**.

The [user guide](docs/USER_GUIDE.md) covers each step, a permanent address on your own domain, protection settings, updates, uninstalling and troubleshooting.

## Downloads and signing

Releases are **not code-signed yet**, so Windows SmartScreen warns when you run one ("More info", then "Run anyway"). Each release lists SHA-256 checksums and a build provenance attestation, so you can check the file came from this repository's CI:

```powershell
gh attestation verify soireehost.exe --repo TheAlsaadi/SoireeHost
```

Builds are reproducible, and an update installs only if it is signed with the project's update key. The project plans to apply for free code signing through the SignPath Foundation once its first release is out.

## Security

**No independent security review has been done yet.** The project tests each of its security requirements ([docs/SECURITY_CHECKLIST.md](docs/SECURITY_CHECKLIST.md)) and runs static analysis, fuzzing and review tools on every change, but it is built by one person. Reviews are welcome. To report a vulnerability, see [SECURITY.md](SECURITY.md); please do not open a public issue for it.

## Building

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the tools, the build, the checks and a map of the code, and [docs/PLAN.md](docs/PLAN.md) for the design.

## Licence

Apache-2.0. See [LICENSE](LICENSE). Contributions are not accepted; see [CONTRIBUTING.md](CONTRIBUTING.md).

# SoiréeHost

**Local Hosting Control Center.** Host websites and local apps from a Windows PC, reachable from the internet through Cloudflare Tunnel, without opening any inbound port.

**Status: in development, not ready for use.** Phases 0 to 5 of the [plan](docs/PLAN.md) are built: the web worker, the supervisor, the tunnel, the firewall and the control panel. The installer, signing and updates come next.

- One program, `soireehost.exe`, for Windows 11 x64.
- Sites are published only through an outbound tunnel; your home IP stays hidden.
- The part that handles internet traffic runs boxed in, with no access to secrets or settings.
- No telemetry. The only outbound connections are the tunnel and the update check.

SoiréeHost protects the path to a hosted app and contains the damage if the app is compromised. It cannot fix vulnerabilities inside the app you host.

## Downloads and signing

Early releases are **not code-signed**, so Windows SmartScreen will warn when you run them. Each release lists SHA-256 checksums and a build provenance attestation so you can verify the file came from this repository's CI. The project plans to apply for free signing through the SignPath Foundation after its first release.

## Building

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the tools, the build, the checks and a map of the code, and [docs/PLAN.md](docs/PLAN.md) for the design.

## Licence

Apache-2.0. See [LICENSE](LICENSE). Contributions are not accepted; see [CONTRIBUTING.md](CONTRIBUTING.md).

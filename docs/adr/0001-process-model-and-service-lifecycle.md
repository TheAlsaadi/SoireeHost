# ADR-0001: Process model and service lifecycle

**Status:** Proposed
**Date:** 12 Nov 2026
**Deciders:** Owner

## Context

SoiréeHost parses hostile internet traffic and also holds a tunnel token and the configuration that decides what is published. If the code that parses traffic can read secrets or change configuration, one bug in Caddy, Coraza or a request handler gives an attacker everything. Sites must keep running when nobody is signed in and come back after a reboot. The owner's PC runs Windows 11 Home x64; there is no container runtime and none is wanted.

## Decision

Split `soireehost.exe` into roles that run as separate Windows processes under separate identities (plan section 4):

| Role | Process | Identity | Start type |
| --- | --- | --- | --- |
| Control panel | `soireehost.exe` | Signed-in user, not elevated | Started by the user (tray at sign-in) |
| Supervisor | `soireehost.exe service` | `NT SERVICE\SoireeHost` | Automatic |
| Web worker | `soireehost.exe worker` | `NT SERVICE\SoireeHostWeb` | Manual, started by the supervisor |
| Tunnel launcher | `soireehost.exe tunnel` (+ `cloudflared.exe` child) | `NT SERVICE\SoireeHostTunnel` | Manual, started by the supervisor |
| Setup | `soireehost.exe setup ...` | Signed-in user, elevated for one action | On demand |

Communication is only through named pipes with explicit ACLs. No role opens a TCP listener except the web worker, on loopback only.

Lifecycle:

- Only the supervisor starts at boot. It starts both workers, and stops both before it stops itself, including on `SERVICE_CONTROL_PRESHUTDOWN`.
- Each worker holds its pipe to the supervisor open and exits when the pipe closes, so a crashed or killed supervisor also ends the workers.
- The supervisor's service recovery actions restart it after a crash; it then restarts the workers.
- No Windows service dependencies between the three services: Windows refuses to stop a service while services that depend on it are running, which would break the supervisor's own shutdown.
- Each worker service's security descriptor lets `NT SERVICE\SoireeHost` start, stop and query it; Administrators keep full control; ordinary users can only query.

## Options considered

### Option A: Separate services with virtual accounts (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | High: three services, pipe ACLs, service security descriptors |
| Cost | Free; built into Windows |
| Isolation | Strong: Windows enforces file and pipe access per account |
| Familiarity | Windows service APIs via `golang.org/x/sys/windows/svc` are well documented |

**Pros:** the OS, not our code, keeps the web worker out of the secrets folder. Virtual accounts need no passwords. Restricted service SIDs further limit what each service can write.
**Cons:** more moving parts to install and uninstall; testing needs a VM or CI runner with admin rights.

### Option B: One service that starts restricted child processes

The supervisor starts workers as children with a restricted token derived from its own.

**Pros:** one service to install.
**Cons:** a restricted token derived from the supervisor still carries the supervisor's SID for deny-only checks and needs careful token surgery; harder to give the worker a distinct identity for ACLs. Rejected because Option A gets the same result with standard, auditable OS features.

### Option C: AppContainer for the web worker

**Pros:** the strongest sandbox Windows offers to desktop apps.
**Cons:** AppContainer from a service, with loopback listening and file access granted per site folder, is poorly documented for Go and would need loopback exemptions. Revisit after 1.0 as defence in depth.

## Trade-off analysis

Option A costs installation complexity once, in the setup role, and pays back on every request: a compromised web worker holds no secret and cannot write config. Option C is stronger but riskier to deliver; keeping S-21's job object and mitigation policies on top of Option A narrows the gap.

## Consequences

- Easier: reasoning about what a compromise of each role can reach; testing isolation (plan section 10).
- Harder: local development of services; needs a VM for install tests (Windows 11 Home has no Windows Sandbox).
- Revisit: AppContainer for the web worker after 1.0.

## Action items

1. [ ] Phase 2: service registration, security descriptors and pipe ACLs in the first `setup install`.
2. [ ] Phase 2: pipe-liveness watchdog in both workers; tests for "kill supervisor ends workers".
3. [ ] Phase 2: test that an ordinary user cannot start or stop the worker services.

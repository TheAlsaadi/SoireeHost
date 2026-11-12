# Self-hosting control center for Windows: build plan

Nov 11, 2026 · revised Nov 12, 2026 · @Mohammed

## 1. How to use this plan

This document is the complete brief for Claude Code: build the app one phase at a time, in the order of section 9, and stop at the end of each phase for review.

Working rules for Claude Code:

1. Read the whole plan before writing code. Save it in the repo as `docs/PLAN.md` and copy these rules into `CLAUDE.md`.
2. Finish one phase, run its acceptance checks, report the result, then wait. Do not start the next phase unprompted.
3. The security requirements in section 5 are mandatory. If a feature conflicts with one, the security requirement wins; say so and propose an alternative.
4. Versions and APIs here are as of 11 November 2026. Check the official docs and release pages before using any of them, and prefer the newest stable release.
5. Add a dependency only when it earns its place: state why, pin the version, check its licence, run `govulncheck`.
6. Never commit secrets, never disable TLS verification, never bind an admin or control surface to anything other than loopback or a named pipe.
7. Section 12 lists decisions that belong to the owner. Ask; do not guess.
8. Every phase ships with its tests. A phase without passing tests is not done.
9. Use the skills in section 8 at the stage each one is listed for.

**Budget rule:** the owner will pay for nothing. Never choose a paid service, certificate, domain, licence or tool. When something would cost money, say so and take the free route.

**Machine rule:** ask before any step that needs administrator rights on the owner's PC, such as installing services, adding firewall rules or creating test accounts. Run those tests on CI runners or in a virtual machine where possible.

## 2. What we are building

A single Windows app that turns a PC into a web host whose sites are reachable from the internet without opening any inbound port. Name: **SoiréeHost** (written soireehost, without the accent, in file, repository and service names).

The user is a developer or hobbyist hosting their own sites and apps from a home or office PC, who wants strong security without learning server administration.

In scope for version 1:

- Serve static sites from a folder, and reverse-proxy local apps (Node, Python, PHP, anything listening on localhost).
- Publish through Cloudflare Tunnel, so every connection is outbound and the home IP stays hidden.
- A desktop control panel: sites, live status, logs, security settings, backups.
- Run as a Windows service, so sites stay up after logoff and come back after a reboot.
- Ship as one program, `soireehost.exe`, that contains everything: control panel, services, web server, firewall, tunnel connector, and its own setup and uninstall.
- Signed, verified updates for the app and everything inside it, installed with one click.

Out of scope for version 1:

- Public exposure by router port forwarding. Tunnel-only is the security model, not a default that can be switched off.
- Remote administration over the internet. The control panel is local only.
- Containers, an app store, databases, mail or DNS hosting.
- macOS and Linux builds.

One limit to state honestly in the product: SoiréeHost protects the path to a hosted app and contains the damage if it is compromised. It cannot fix vulnerabilities inside the app being hosted.

## 3. Stack and components

One Go codebase compiles to one binary, `soireehost.exe`, and that binary is the whole app. Caddy and the web application firewall are compiled in, and the official cloudflared binary is embedded in it as hash-pinned bytes. There is no separate installer: install, repair, update and uninstall are roles of the same binary.

| Component | Role | Version confirmed 12 Nov 2026 | Licence | How it ships |
| --- | --- | --- | --- | --- |
| Go | Language and toolchain | 1.27.4 (Caddy, Coraza for Caddy and Wails v3 all require 1.26 or newer) | BSD-3 | Build tool only |
| [Wails v3](https://github.com/wailsapp/wails/releases/tag/v3.1.0) | Desktop shell: window, tray, Go-to-UI bindings, updater | v3.1.0 (fallback v2.17.1) | MIT | Compiled in |
| [Caddy](https://github.com/caddyserver/caddy/releases) | Web server and reverse proxy | v2.11.9 | Apache-2.0 | Compiled in as a library |
| [Coraza for Caddy](https://github.com/corazawaf/coraza-caddy) with the OWASP Core Rule Set | Web application firewall | `coraza-caddy/v2` v2.6.2, which brings `coraza-coreruleset/v4` v4.25 (the rule set's long-term-support line) | Apache-2.0 | Compiled in as a Caddy module |
| [cloudflared](https://github.com/cloudflare/cloudflared/releases) | Cloudflare Tunnel connector | 2026.10.7 | Apache-2.0 | Official binary embedded in `soireehost.exe`, unpacked by the setup role, run as a child process |
| Svelte 5, TypeScript, Vite | Control-panel UI | Svelte 5.57.3, Vite 8.3.8, TypeScript as supported by `svelte-check`; exact versions in `frontend/package-lock.json`. Node.js 26 LTS for builds | MIT, Apache-2.0 | Bundled into the binary |
| WebView2 | Renders the UI | Evergreen runtime in Windows | Microsoft | System component |
| `Microsoft/go-winio`, `golang.org/x/sys/windows` | Named pipes with ACLs, service API, DPAPI, job objects, tokens | go-winio v0.6.4; x/sys newest, pinned in `go.sum` | MIT, BSD-3 | Compiled in |

The cloudflared Windows binary for 2026.10.7 is `cloudflared-windows-amd64.exe`, SHA-256 `2493dbc168923bb3e59e5e7716f71deced92992eea9acd6e9d74f84ac7751343`, as published in the release notes. It is recorded in `build/cloudflared.lock`.

Points Claude Code must respect:

- **One app, one .exe.** `soireehost.exe` is the only file a user downloads and the only program SoiréeHost consists of. It runs as the control panel, the supervisor service, the web worker, the tunnel launcher or the setup tool depending on its subcommand. Started on a PC where it is not installed, it opens a window offering to install itself, which raises the Windows prompt and runs its setup role.
- **Wails v3 is new.** Its stable line is only weeks old, so pin the exact version and read the official docs instead of relying on memory, which will mix v2 and v3 APIs. If a blocking bug appears, raise it; Wails v2.17.0 is the fallback and the Svelte UI carries over.
- **Caddy must be 2.11.6 or newer.** That release rejects Windows 8.3 short names and tightens path normalisation, both of which matter for a Windows file server.
- **cloudflared is run, not imported.** It has no supported library API, so the official Windows binary is embedded as bytes (`go:embed`) after CI verifies its SHA-256 (S-71). The elevated setup role writes it into the install folder at install, update and repair. It is never unpacked to a temp folder or at each launch, which is safer and draws less attention from antivirus. Before every launch its hash is compared with the value compiled into `soireehost.exe` (S-23).
- **A rate-limit module is needed.** Candidate: `github.com/mholt/caddy-ratelimit`. As of 12 Nov 2026 it has no tagged releases, its last commit was 12 Jun 2026, its `go.mod` targets Caddy v2.10.0, and it pulls in the Prometheus client. Decide in Phase 1: adopt it only if it builds and passes tests against the pinned Caddy; otherwise write a small in-house handler, which is the leaning.
- **Licences.** Everything above is permissive. Ship a `THIRD_PARTY_NOTICES` file with each licence and NOTICE text, and show them on a Licences screen.

## 4. Architecture

The app is split into four running roles, plus a setup role used only to install, update, repair or remove it, so that the code which touches internet traffic holds no secrets and cannot change configuration. All five are the same `soireehost.exe`.

```
Request path (internet traffic)
  visitor --HTTPS--> Cloudflare edge --tunnel, opened outbound from the PC--> tunnel launcher + cloudflared
          --HTTP on 127.0.0.1:8787--> web worker (Caddy + Coraza) --loopback--> site

Control path (settings)
  control panel --\\.\pipe\soireehost-control--> supervisor --pipe--> web worker (Caddy JSON config)
                                                            --pipe--> tunnel launcher (tunnel token)
```

A request travels visitor, Cloudflare edge, tunnel, web worker, site. A settings change travels control panel, supervisor, worker. The two paths never share a process.

| Role | Runs as | Does | Must never |
| --- | --- | --- | --- |
| Control panel, `soireehost.exe` | The signed-in user, not elevated | Shows state, sends requests to the supervisor | Hold secrets, write config files, open a network port |
| Supervisor, `soireehost.exe service` | Windows service under the virtual account `NT SERVICE\SoireeHost` | Validates and stores config, keeps secrets, starts and watches workers, checks for updates, writes the audit log | Parse internet traffic |
| Web worker, `soireehost.exe worker` | Its own Windows service under `NT SERVICE\SoireeHostWeb`, started only by the supervisor; limits itself with a job object at start | Runs embedded Caddy and Coraza: static files, reverse proxy, firewall, access logs | Read secrets, start processes, write outside its log folder |
| Tunnel launcher, `soireehost.exe tunnel` | Its own Windows service under `NT SERVICE\SoireeHostTunnel`, started only by the supervisor; starts the unpacked `cloudflared.exe` inside a job object | Holds the tunnel to Cloudflare and forwards to the web worker on loopback | Read anything except its own token |
| Setup, `soireehost.exe setup` | The signed-in user, elevated through the Windows prompt, for one action at a time | Install, repair, apply a verified update, uninstall: copies the app into place, unpacks cloudflared, registers the three services, sets ACLs and firewall rules | Stay running, run without the Windows prompt, or act on a file it has not verified itself |

How the parts talk:

- **Supervisor to web worker.** The supervisor builds Caddy's JSON config and sends it over a second named pipe that only the web worker's service account can open. The worker loads it in-process with `caddy.Load`. Caddy's admin API is disabled (`"admin": {"disabled": true}`).
- **Tunnel to web worker.** Plain HTTP to a `127.0.0.1` port set in config (see tunnel-token mode and quick share below). TLS ends at Cloudflare's edge and the tunnel itself is encrypted, so the worker needs no certificates or private keys.
- **Control panel to supervisor.** A named pipe, `\\.\pipe\soireehost-control`, with typed request and response messages. No HTTP server, no localhost port.
- **Supervisor to tunnel launcher.** The supervisor hands over the tunnel token on a pipe only the tunnel service account can open. The launcher passes it to cloudflared as an environment variable, so the token is never written where a worker can read it.
- **Tunnel-token mode.** The web worker listens on one fixed loopback port (default `127.0.0.1:8787`, changeable). Every public hostname set up in Cloudflare points at that address and Caddy routes by Host header. The control panel shows the exact hostname and service URL to enter in the Cloudflare dashboard.
- **Quick share.** One cloudflared process per shared site, pointed at that site's own loopback port. The supervisor reads the assigned hostname from cloudflared's output and adds it to that site's allowed hostnames. Until it does, the port answers every request with 404, so S-06 holds for quick share too.
- **Lifecycle.** Only the supervisor starts at boot; the two worker services are set to manual start. The supervisor starts them, and stops both before it stops itself, including at system shutdown. Each worker keeps its pipe to the supervisor open and exits if that pipe closes, so a supervisor crash also ends the workers; the supervisor's service recovery settings restart it, and it restarts them. The services have no Windows service dependencies on each other, because Windows refuses to stop a service while services that depend on it are running.

Where data lives:

| Path | Holds | Access |
| --- | --- | --- |
| `%ProgramFiles%\SoireeHost\` | `soireehost.exe`, the `cloudflared.exe` that setup unpacks from it, licence notices | Administrators write; others read and execute |
| `%ProgramData%\SoireeHost\config\` | `config.json` and the last 10 good versions | Supervisor and Administrators only |
| `%ProgramData%\SoireeHost\secrets\` | DPAPI-encrypted blobs | Supervisor only |
| `%ProgramData%\SoireeHost\logs\` | Access, firewall, app and audit logs | Each worker appends to its own subfolder; supervisor reads |
| `%ProgramData%\SoireeHost\updates\` | Downloaded updates waiting to be installed | Supervisor writes; supervisor and Administrators read |
| Site folders the user picks | Site content | Web worker read-only, granted when the site is added |

Repository layout:

```
cmd/soireehost/        main: dispatches gui | service | worker | tunnel | setup
internal/gui/          Wails app and bindings (thin; calls the ipc client)
internal/ipc/          pipe server and client, message types, ACL
internal/supervisor/   service lifecycle, worker management
internal/worker/       embedded Caddy, config load, logging
internal/config/       schema, validation, atomic store, rollback
internal/secrets/      DPAPI wrapper
internal/tunnel/       embedded cloudflared, hash check, process management
internal/setup/        install, repair, apply update, uninstall (elevated role)
internal/sitecheck/    folder exposure scan, path rules
internal/update/       manifest verification, download, staged install
internal/audit/        hash-chained audit log
internal/winsec/       tokens, ACLs, job objects, firewall rules
frontend/              Svelte and TypeScript UI
build/                 signing, release and CI scripts
docs/                  PLAN.md, THREAT_MODEL.md, decision records
```

## 5. Security

Security here means four things at once: nothing on the PC is reachable from the internet, the code that handles traffic is boxed in, secrets and settings are out of reach of other local programs, and updates cannot be forged. Each requirement below has an ID; every ID must map to a test or a documented manual check before release.

### Threat model

| Attacker | Wants | Main defences |
| --- | --- | --- |
| Anyone on the internet | To exploit the web server or a hosted app and reach the PC or home network | No inbound ports, Cloudflare edge, firewall rules, sandboxed worker, loopback-only upstreams |
| Hostile request content | To traverse paths, or to poison logs and attack the control panel when it displays them | Strict path rules, logs treated as untrusted text |
| Another program or user on the same PC | To read secrets, change config, or impersonate the control panel | File ACLs, DPAPI, pipe ACL, no listening admin port |
| Network attacker or compromised download host | To deliver a fake update | Signed manifest checked against a pinned key, Authenticode check once releases are signed, no downgrades |
| Compromised dependency or build step | To run code in the build or in the app | Pinned dependencies, vulnerability scans, minimal dependencies, hardened CI |
| The user, by mistake | To publish a folder containing secrets | Exposure check, blocked folders, safe defaults |

Not defended against: an attacker who already has administrator rights on the PC, flaws inside hosted apps (contained, not fixed), a compromise of Cloudflare, and physical access. Write these into `docs/THREAT_MODEL.md` with the table above.

### 5.1 Network exposure

- **S-01** No listener on any non-loopback address. Config validation rejects it, and the worker checks its own listening sockets at start and exits if one is not `127.0.0.1` or `::1`.
- **S-02** Setup creates no inbound allow rule. It adds explicit block-inbound firewall rules for `soireehost.exe` and the unpacked `cloudflared.exe`.
- **S-03** Tunnel-only. There is no setting that exposes a site by port forwarding.
- **S-04** Caddy's admin API is disabled. No debug, profiling or metrics endpoint exists in release builds. cloudflared's metrics endpoint is bound to loopback or turned off.
- **S-05** The worker trusts `CF-Connecting-IP` for the client address only because cloudflared on loopback is its sole client. All other forwarded-for headers from the request are dropped.
- **S-06** A request whose Host header is not a configured site hostname gets a 404. This also blunts DNS-rebinding attempts from a browser on the same PC.

### 5.2 Web worker

- **S-10** Reverse-proxy targets are limited to `127.0.0.1` and `::1`. A LAN target needs a per-site opt-in with a warning. Link-local addresses (`169.254.0.0/16`, `fe80::/10`) and the app's own ports are always refused.
- **S-11** Static roots are canonicalised and checked. Refuse drive roots, `Windows`, `Program Files`, `ProgramData\SoireeHost`, a user-profile root, `AppData` and `.ssh`. Never follow a symlink or junction that leaves the root.
- **S-12** Never serve dotfiles, `.git`, `.env`, `*.pem`, `*.key`, `*.pfx`, `*.bak`, `*.sql`, `web.config`, `desktop.ini` or `Thumbs.db`. No directory listings unless the user turns them on for a site. The one exception is the `/.well-known/` folder, served only when the user turns it on for a site; everything inside it still follows these rules (owner decision, 12 Nov 2026).
- **S-13** Reject Windows path tricks: 8.3 short names, alternate data streams (`:`), trailing dots and spaces, reserved device names (`CON`, `NUL`, `COM1`), backslashes and encoded traversal.
- **S-14** Coraza with the OWASP Core Rule Set is on for every new site in blocking mode at paranoia level 1. Per site: Block, Detect only, or Off. Off shows a standing warning.
- **S-15** Limits per site: request body 10 MB by default, header size, read and idle timeouts, and a per-client rate limit (default 300 requests a minute).
- **S-16** Default response headers: `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Content-Security-Policy: frame-ancestors 'none'`, a minimal `Permissions-Policy`, and no `Server` header. Each can be changed per site.
- **S-17** When the private-sites feature ships (after 1.0), a site marked Private rejects any request without a valid Cloudflare Access token (`Cf-Access-Jwt-Assertion`), checked against the team's signing keys and the application's audience tag. Fail closed.
- **S-18** Access logs never store `Authorization`, `Cookie` or `Set-Cookie` values, and mask query parameters named like `token`, `key`, `password` or `secret`. Logs rotate with a size cap.

### 5.3 Process isolation on Windows

- **S-20** The supervisor and each worker run as separate Windows services, each under its own virtual service account with no administrator rights, so Windows itself keeps the web worker out of the secrets folder. Restricted service SID, privileges trimmed to the minimum, quoted binary path. Setup gives each worker service a security descriptor that lets `NT SERVICE\SoireeHost` start, stop and query it and nothing more; ordinary users can only query.
- **S-21** Each worker limits itself at start: it drops unneeded privileges, turns on the no-child-process mitigation policy, and joins a job object with kill on close, UI restrictions and a memory cap. The tunnel launcher applies the same limits to cloudflared when it starts it. Only the supervisor (and Administrators) may start and stop the worker services, enforced by the service security descriptors in S-20.
- **S-22** Folder ACLs match the table in section 4 and are checked at every start. The supervisor refuses to run if config or secrets are writable by ordinary users.
- **S-23** `cloudflared.exe` is unpacked from `soireehost.exe` only by the elevated setup role, into the install folder, and runs only from there. Its SHA-256 is compared with the value compiled into `soireehost.exe` before every launch; on a mismatch or a missing file the tunnel stays down and the control panel offers Repair, which reruns setup. It runs with `--no-autoupdate`. The tunnel token reaches it through `TUNNEL_TOKEN` or `--token-file`, never the command line.
- **S-24** At start, every role restricts DLL loading to System32. If the WebView2 runtime will not load in the control panel under that restriction, allow only the WebView2 runtime's own folder with `AddDllDirectory` and record why in a decision record. Build with `-trimpath` and CGO off. CI checks the binary for ASLR, DEP and high-entropy VA flags.

If part of S-21 cannot be made to work with Caddy or cloudflared, keep everything that does work and record the reason in a decision record. Do not drop the requirement silently.

### 5.4 Control plane and control panel

- **S-30** The pipe's ACL allows SYSTEM, Administrators and the users chosen at install. Remote clients are rejected. The supervisor checks the caller's SID on every connection.
- **S-31** The control API is small and typed. All validation happens in the supervisor. No method accepts a command to run or an arbitrary path to write.
- **S-32** Weakening actions (turning the firewall off, adding a LAN target, changing the tunnel, importing a backup) need an explicit confirmation and write an audit entry.
- **S-33** The webview loads only bundled content under a strict Content Security Policy: no remote scripts, fonts or images, no inline script, navigation locked to the app, developer tools off in release builds.
- **S-34** Hostnames, paths, user agents and log lines are attacker-controlled. Render them as text only. No `{@html}`, `innerHTML` or Markdown rendering of that data, enforced by a lint rule that fails the build.
- **S-35** Secrets are write-only from the control panel. It can set or replace a token and see when it was set, never read it back.
- **S-36** The audit log is append-only and each entry carries the hash of the previous one.

### 5.5 Secrets, config and privacy

- **S-40** Secrets are encrypted with DPAPI under the service account. They never appear in config, logs, crash output or backups.
- **S-41** Config is schema-validated, written atomically, and versioned. If a worker fails to start on a new config, the supervisor restores the last good one and reports why.
- **S-42** No telemetry. The only outbound connections are the tunnel and the update check, and Settings lists both.

### 5.6 Cloudflare credentials

- **S-50** The default connection method is a tunnel token, which can only run one tunnel. API-token mode (later) documents the exact minimum permissions and refuses a Global API Key.
- **S-51** Quick share links are labelled temporary and for testing.

Update and supply-chain requirements (S-60 onward) are in section 11.

## 6. Features

Version 1 does a small number of things well; everything else waits until the core is proven safe.

| Area | Version 1 | Later |
| --- | --- | --- |
| Sites | Static site from a folder; proxy to a local port; start, stop, rename, remove | Custom error and maintenance pages; PHP through FastCGI |
| Going online | Quick share link with no account; permanent address through a tunnel token | Create tunnels, DNS records and hostnames from the app with a scoped API token |
| Protection | Web application firewall per site, rate limits, security headers, exposure check | Private sites behind Cloudflare Access; rule exclusions picked from the firewall log |
| Visibility | Tunnel and site status in plain words; live access log with filters; firewall events | Traffic charts; Windows notifications for site down, attack spike, update ready |
| Running | Windows service, starts at boot, tray icon, one switch to take everything offline | Scheduled backups of site folders |
| Upkeep | Signed updates installed with one click; config export and import; licences screen | Unattended updates; more languages |

Quality-of-life details that belong in version 1:

- First run reaches a live site in three steps: choose a folder or port, choose quick share or tunnel, go live.
- The port picker lists what is listening locally with the process name, for example `3000 (node.exe)`.
- Each site has a health line that names the problem: "Port 3000 is not answering", not "Error".
- Copy-address button, and a locally generated QR code for testing on a phone.
- Drag a folder onto the window to start adding a site.
- The exposure check runs before a folder goes live and lists risky files it found, such as `.env` or a private key.
- Sites keep serving when the control panel is closed; the tray icon shows state and offers pause and resume.

## 7. UI and design direction

The control panel should look like a well-made Windows utility: quiet, precise, dense enough to be useful, with nothing decorative. Design is approved on static screens before any of it is implemented (Phase 5).

### Structure

- A left rail with five destinations: Sites, Activity, Security, Backups, Settings.
- One status line at the top of every screen, in plain words: "Online: 3 sites served through Cloudflare Tunnel" or "Offline: tunnel disconnected since 14:02".
- Sites is a list, not a card grid. Each row: name, address in monospace, type (Static or Proxy), status, on/off switch. Selecting a row opens its detail pane on the right.
- Security is a checklist of real protections with their actual state (On, Off, Not set up) and one line on what each does. No score, no gauge.
- Activity is a log table with filters by site, status and time. Blocked requests are marked and explain which rule fired.

### Visual rules

- **Type.** Segoe UI Variable for the interface and Cascadia Mono for addresses, paths and logs. Both ship with Windows 11, with Segoe UI and Consolas as fallbacks, so no font files and no network requests. Three sizes and two weights at most.
- **Colour.** Neutral greys carry the interface. One accent colour, used only for the primary action and the focus ring. Green, amber and red are reserved for status and always paired with a word and an icon shape.
- **Themes.** Light and dark are both designed, follow the system setting, and work in Windows high-contrast mode.
- **Shape and depth.** A 4 px spacing grid, 4 to 6 px corner radius, 1 px borders to separate regions. No drop shadows except on menus and dialogs.
- **Icons.** One set, bundled locally (Fluent System Icons or Lucide), at 16 and 20 px.
- **Motion.** Only where it explains a change, 120 to 160 ms, and off when the system asks for reduced motion.
- **Copy.** Buttons are verbs ("Add site", "Stop serving", "Copy address"). Errors say what happened and what to do next. No exclamation marks, no "Oops".
- **Empty states.** One sentence and one action.

### Banned

These are the marks of a generated interface and none of them may appear: purple or blue gradients, gradient text, glass or blur panels, glow and neon, emoji or sparkle icons, a hero banner inside the app, grids of identical rounded cards, pill badges on everything, vanity tiles such as "99.9% uptime" with no data behind them, charts drawn from invented numbers, animated counters, a fake-terminal look, a dark-only theme, and an untouched default component-library style.

### Build rules

- Svelte 5 and TypeScript with plain CSS and design tokens as CSS variables. About a dozen hand-built components (button, switch, input, select, table, dialog, menu, toast, tabs, status mark, empty state, log row). No UI kit.
- Every string goes through one message catalogue so other languages can be added. Use logical CSS properties (`margin-inline-start`, not `margin-left`) so a right-to-left layout stays possible.
- Meets WCAG 2.1 AA: contrast, full keyboard use, visible focus, screen-reader names, and text that follows the Windows text-size setting.
- Section 5 rules S-33 to S-35 apply to every component that shows data from outside.

## 8. Skills

Use three groups: skills already in the owner's account, one command built into Claude Code, and three third-party sets found on the web. None of the third-party sets is installed yet; installing and vetting them is a Phase 0 task.

### Already available

Run `/skills` first to confirm these are loaded in the session.

| Skill | Use it for | Phase |
| --- | --- | --- |
| `engineering:architecture` | Decision records for the process split, IPC and update design | 0 |
| `engineering:system-design` | Service boundaries and the control API | 0, 2 |
| `engineering:testing-strategy` | Turning section 10 into a concrete test plan | 0, then each phase |
| `engineering:code-review` | Review before every merge | All |
| `engineering:debug` | Structured debugging when something fails | As needed |
| `engineering:deploy-checklist` | Release checklist | 6, 7 |
| `engineering:documentation` | README, user guide, `SECURITY.md` | 7 |
| `frontend-design` | Visual direction and the approval screens | 5 |
| `design:design-system` | Tokens and component documentation | 5 |
| `design:ux-copy` | Labels, errors, empty states | 5 |
| `design:design-critique` | Critique of the screens before the owner sees them | 5 |
| `design:accessibility-review` | WCAG 2.1 AA audit | 5, 7 |
| `skill-creator` | Writing the project's own skills (see Gaps) | 2 |

### Built into Claude Code

Run `/security-review` on the pending changes at the end of every phase. It looks for common patterns such as injection, cross-site scripting, authentication flaws, unsafe data handling and vulnerable dependencies. [Anthropic's own guidance](https://support.claude.com/en/articles/11932705-automated-security-reviews-in-claude-code) is that it complements manual review and does not replace it, so it is one check among several here.

### To install

| Set | Install commands | Skills to use | Phase |
| --- | --- | --- | --- |
| [Trail of Bits skills](https://github.com/trailofbits/skills) (security firm; CC BY-SA 4.0) | `/plugin marketplace add trailofbits/skills` then `/plugin menu` | `insecure-defaults`, `sharp-edges`, `supply-chain-risk-auditor`, `static-analysis`, `semgrep-rule-creator`, `differential-review`, `audit-context-building`, `fp-check`, `spec-to-code-compliance`, `variant-analysis`, `testing-handbook-skills` | 0 to 7 |
| [samber/cc-skills-golang](https://github.com/samber/cc-skills-golang) (MIT) | `/plugin marketplace add samber/cc` then `/plugin install cc-skills-golang@samber` | `golang-security`, `golang-safety`, `golang-error-handling`, `golang-concurrency`, `golang-context`, `golang-testing`, `golang-lint`, `golang-project-layout`, `golang-dependency-management`, `golang-continuous-integration` | 0 to 4 |
| [spf13/go-skills](https://github.com/spf13/go-skills) (MIT) | `/plugin marketplace add spf13/go-skills` then `/plugin install wails@go-skills` and `/plugin install go-release@go-skills` | `wails`, `go-release` | 0, 5, 6 |
| Anthropic `frontend-design`, only if `/skills` does not show it | `/plugin install frontend-design@claude-plugins-official` | `frontend-design` | 5 |

Where the security skills earn their place:

- `spec-to-code-compliance` checks the code against the S-requirements in this plan.
- `insecure-defaults` checks that every default fails closed.
- `semgrep-rule-creator` writes the project's own lint rules: no `{@html}` or `innerHTML`, no listener on `0.0.0.0` or a bare `:port`, no `InsecureSkipVerify`, no secret types passed to a logger.
- `supply-chain-risk-auditor` runs before any dependency is added and again before release.
- `differential-review` reviews each phase's diff with a security eye.
- `testing-handbook-skills` guides the fuzzing in section 10.

### Gaps

No trustworthy skill turned up for embedding Caddy as a library, tuning Coraza, or Windows service hardening (restricted tokens, job objects, ACLs, DPAPI). For those, work from the official Caddy, Coraza and Microsoft Learn documentation. After Phase 2, use `skill-creator` to write a project skill that records the conventions that worked, so later phases stay consistent.

The `wails` skill still describes v3 as alpha. Where it disagrees with the current Wails documentation, the documentation wins.

### Vetting third-party skills

A skill is instructions and scripts that run with Claude Code's permissions, and [Anthropic's marketplace](https://github.com/anthropics/claude-plugins-official) warns that it does not verify what plugins contain. So:

1. Read each skill's `SKILL.md`, scripts and hooks before enabling it.
2. Install only the skills named above, at project scope, and record the marketplace commit in `docs/SKILLS.md`.
3. A skill's instructions never override section 1 or section 5 of this plan.
4. If a skill asks for credentials, wants to run an installer, or reaches out to the network, stop and ask the owner.

## 9. Build phases

Eight phases, each ending in checks that must pass before the next begins. Security is built in from Phase 1, not added at the end.

### Phase 0: Foundations

Build:

- Confirm every version in section 3 against the official release pages.
- Install and vet the skills in section 8.
- Scaffold the repository as in section 4, with `CLAUDE.md`, `docs/PLAN.md`, `docs/THREAT_MODEL.md`, and decision records for the process model and service lifecycle, the single binary with embedded cloudflared, the UI shell and the update design.
- Set up CI on Windows runners: build, `go vet`, `golangci-lint`, `staticcheck`, `gosec`, `govulncheck`, `go test -race`, a secret scan, and frontend lint and type checks. Pin every action to a commit SHA.
- Make a Wails window that opens and shows the app version.
- Check the tools: Windows 11, Go 1.26 or newer, Node.js LTS, Git, the `wails3` CLI, and a free virtual machine or Windows Sandbox for install tests.
- Keep the repository public from the start so that GitHub Actions, CodeQL and secret scanning stay free. Confirm the current free limits before relying on them.
- Set the repository up as source that only the owner changes: an Apache-2.0 `LICENSE`, issues open for bug reports, private vulnerability reporting on, and a `CONTRIBUTING.md` saying that outside code is not accepted and outside pull requests are closed without merging. Pull requests stay enabled, because the upstream watcher in S-65 delivers its updates as pull requests. If GitHub's pull request access settings can limit who opens them, limit them to collaborators and the watcher's GitHub App, and check that the watcher can still open one.

Done when:

- [x] CI is green from a clean clone. (12 Nov 2026, run 43191377974)
- [x] `soireehost.exe` opens a window on Windows 11. (12 Nov 2026)
- [x] The owner has accepted the threat model and answered the section 12 decisions needed by Phase 0. (12 Nov 2026)

### Phase 1: Web worker

Build embedded Caddy serving one static folder and one proxied port on loopback, with the config schema and validation, root and path rules, limits, headers, log redaction and the listener self-check.

Done when:

- [x] Tests pass for S-01, S-04 to S-06, S-10 to S-13, S-15, S-16 and S-18. (12 Nov 2026, local run; the CI-only S-01 test and the symbolic-link cases run after push. The cloudflared part of S-04 and quick share in S-06 belong to Phase 3)
- [x] The path traversal suite in section 10 passes. (12 Nov 2026, `TestPathTraversalSuite`)
- [x] Fuzzers for config and path validation run 10 minutes each without a crash. (12 Nov 2026, local: `FuzzDecode`, `FuzzHostname`, `FuzzTarget`, `FuzzRootSyntax`, `FuzzCheckStatic`, `FuzzCheckProxy`, 66 to 92 million executions each)

### Phase 2: Supervisor, IPC and isolation

Build the Windows service under its virtual account, the named pipe and control API, the DPAPI secret store, the versioned config store with rollback, the two worker services with their own accounts and self-imposed limits, the service lifecycle in section 4, ACL checks, and the audit log. Also build a first `soireehost.exe setup install` and `setup uninstall` (services, accounts, service security descriptors, folder ACLs) for use in the test virtual machine; Phase 6 completes the setup role.

Done when:

- [ ] Tests pass for S-20 to S-22, S-24, S-30 to S-32, S-35, S-36, S-40 and S-41.
- [ ] A second local user cannot open the pipe.
- [ ] A test build of the worker that tries to start `cmd.exe` fails.
- [ ] Stopping the supervisor ends both workers, and so does killing its process.
- [ ] An ordinary user cannot start or stop the worker services.

### Phase 3: Tunnel

Build the tunnel role: cloudflared embedded in `soireehost.exe` and unpacked by setup, the hash check before every launch, quick share with its hostname check, tunnel-token mode, health and reconnect, the offline switch, and the firewall block rules.

Done when:

- [ ] A site opens from a phone on mobile data through a quick share link.
- [ ] The same works with a tunnel token and a real hostname, if the owner has a domain. If not, mark this check as not yet verified in the release notes.
- [ ] `netstat` shows no non-loopback listener from either binary, and a port scan from a second machine finds nothing from the app.
- [ ] A canary token never appears in the process list, logs or config.
- [ ] A quick share port returns 404 for any hostname other than the one cloudflared assigned.
- [ ] A modified `cloudflared.exe` in the install folder is refused and the control panel offers Repair.
- [ ] Tests pass for S-02, S-03, S-23, S-50 and S-51.

### Phase 4: Protection

Build Coraza with the Core Rule Set, the per-site modes, rate limiting, the exposure check and the firewall event log.

Done when:

- [ ] Sample SQL injection, cross-site scripting and traversal requests get a 403 and appear in the firewall log.
- [ ] Browsing a normal static site and a typical proxied app triggers no block at paranoia level 1.
- [ ] The exposure check flags a planted `.env` file and private key.
- [ ] Tests pass for S-14.

### Phase 5: Control panel

Build in this order: design tokens and three static screens (Sites with its detail pane, Activity, Security) in light and dark; owner approval; then components, all five screens, the first-run flow and the tray icon.

Done when:

- [ ] The owner approved the static screens before implementation began.
- [ ] Nothing from the banned list in section 7 appears.
- [ ] The accessibility review passes at AA and the whole app works by keyboard.
- [ ] A request with script in its path and user agent shows as plain text in Activity.
- [ ] Tests pass for S-33 to S-35.

### Phase 6: Setup, signing and updates

Complete the setup role of `soireehost.exe`: install (copies itself to `%ProgramFiles%\SoireeHost\`, unpacks cloudflared, registers the three services, sets ACLs and firewall rules, adds the entry in Windows Settings > Apps), repair, and an uninstall that can remove its own executable. Then build an Authenticode signing step that switches on when free signing is approved, the signed update manifest, and staged updates with rollback.

Done when:

- [ ] On a fresh Windows 11 virtual machine, going from the downloaded `soireehost.exe` to the first live site takes under 5 minutes.
- [ ] Tampered, wrong-key, truncated and older-version updates are all refused (S-60 to S-63).
- [ ] Uninstall removes all three services, firewall rules and program files, and removes config and secrets when the user asks.
- [ ] A traffic capture shows no network connection other than the tunnel and the update check (S-42).
- [ ] Tests or recorded checks exist for S-64, S-65 and S-70 to S-75.

### Phase 7: Hardening and release candidate

Run the full security pass with the skills in section 8, long fuzz runs, the dependency audit and SBOM, the user guide and `SECURITY.md`, and a 72-hour soak test.

Done when:

- [ ] Every S-requirement in `docs/SECURITY_CHECKLIST.md` links to a passing test or a recorded manual check.
- [ ] No high-severity finding is open.
- [ ] The owner signs off.

After 1.0, in this order: Cloudflare API automation, private sites with Access (S-17), firewall exclusions in the UI, charts and notifications, unattended updates.

## 10. Testing and security verification

Every security requirement is proven by a test that tries to break it, not by reading the code.

| Check | How | Runs |
| --- | --- | --- |
| Unit and table tests | `go test -race` on all packages; Vitest for the UI | Every commit |
| Static analysis | `golangci-lint`, `staticcheck`, `gosec`, Semgrep with the project rules, CodeQL | Every commit |
| Vulnerable dependencies | `govulncheck`, `npm audit`, licence check | Every commit and nightly |
| Fuzzing | Go native fuzzing on config parsing, control-API decoding, hostname and path validation | 10 minutes per target in CI; 8 hours before release |
| Path traversal suite | `../`, `..%2f`, `%5c`, double encoding, 8.3 names, `::$DATA`, trailing dots, device names, junctions out of the root, hidden files in mixed case; each must return 400 or 404 | Every commit |
| Exposure | List the listening sockets of both binaries; port-scan the PC from a second machine | From Phase 3, and each release |
| Web application firewall | A fixed set of attack requests must be blocked and a fixed set of normal requests must pass | From Phase 4 |
| Isolation | Second local user on the pipe; worker starting a child; worker reading the secrets folder; ACL drift | From Phase 2 |
| Secrets | Plant canary tokens, then search logs, config, backups, crash output and process command lines | Each release |
| UI injection | Script and HTML in paths, hostnames, user agents and site names must render as text | From Phase 5 |
| Updates | Tampered binary, wrong key, truncated download, older version, interrupted install | From Phase 6 |
| Soak | 72 hours of serving with tunnel drops and restarts injected; watch memory and handle counts | Before release |

`docs/SECURITY_CHECKLIST.md` lists every S-ID with the test that proves it and its latest result. A requirement with no test is treated as not met.

These checks and Claude Code's own reviews catch a great deal, but they are not an independent audit. Before a public release that strangers will trust with their home network, have someone who did not build it review the design and the code, for example an experienced volunteer from the open-source community. Publish a `SECURITY.md` with a contact for vulnerability reports.

## 11. Release: signing, updates and supply chain

A release is `soireehost.exe` and one signed update manifest, both produced by CI from a tagged commit and hosted on GitHub Releases with SHA-256 checksums. The same executable is the download, the installed app and the update. It gains an Authenticode signature once free signing is approved.

### Code signing

Unsigned Windows software gets a strong SmartScreen block, and an app that unpacks and runs a second executable can look suspicious to antivirus. Unpacking cloudflared only during elevated setup, into Program Files, keeps that to a minimum. Signing matters once strangers download the app; for personal use on the owner's own PC it can be skipped.

| Route | Cost | Who can use it |
| --- | --- | --- |
| Azure Artifact Signing (formerly Trusted Signing) | About $9.99 a month | Organisations in the USA, Canada, EU and UK; individual developers in the USA and Canada only |
| OV certificate from a certificate authority | $150 to $300 a year | Individuals and organisations elsewhere; the key must sit on a hardware token or cloud HSM |
| EV certificate | $400 or more a year | No longer gives instant SmartScreen trust, so the premium buys nothing here |

Figures and eligibility are from [Microsoft's code signing guide](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options). With either of the first two routes, new files can still show a SmartScreen warning until the publisher has built reputation; signing every release with the same identity is what builds it.

**Decided on 11 November 2026:** the app is mainly for the owner and will also be published on GitHub for anyone to download. The owner will not pay for anything, so of the two cheaper routes below only SignPath Foundation is in scope:

| Route | Cost | Conditions |
| --- | --- | --- |
| [SignPath Foundation](https://signpath.org/terms) | Free | OSI-approved licence, a public repository the team owns, automated builds from that repository, and a project that is already released. The publisher shown to users is "SignPath Foundation". The project page must carry a code signing policy and a privacy statement |
| [Certum Open Source Code Signing in the Cloud](https://shop.certum.eu/open-source-code-signing-on-simplysign.html) | €49 | For individuals publishing open source. The certificate shows the person's name prefixed with "Open Source Developer". No hardware token |

Plan for a GitHub release: publish the first versions unsigned, with SHA-256 checksums and a build provenance attestation, and say so plainly in the README. Apply to SignPath Foundation once a release exists, because it only signs projects that are already released. Its terms also require warning users before changing system configuration and providing an uninstaller, both of which Phase 6 already covers.

### Updates

- **S-60** The app trusts one Ed25519 public key compiled into the binary. The manifest and every artifact must verify against it. A missing key, missing signature or bad signature means refusal.
- **S-61** Once releases are Authenticode-signed, the new binary's signature must be valid and from the expected publisher, and an update may never move from signed to unsigned. Until then, S-60 is the only proof of origin.
- **S-62** Any version not newer than the running one is refused.
- **S-63** Downloads land in `%ProgramData%\SoireeHost\updates\`, which only the supervisor can write and only the supervisor and Administrators can read. The supervisor verifies them there, and the elevated setup role of the installed, already-trusted `soireehost.exe` verifies them again immediately before the swap; the downloaded file never runs before both checks pass. The previous version is kept and restored automatically if the service fails to start.
- **S-64** Installing needs elevation because program files are administrator-only. In version 1 the control panel shows "Update ready" and one click raises the Windows prompt, which runs `soireehost.exe setup apply-update` from the install folder. Because cloudflared lives inside `soireehost.exe`, one update replaces both.
- **S-65** Caddy, Coraza, the rule set and cloudflared are updated through app releases. Target: a release within 7 days of an upstream security fix. A scheduled CI job watches the upstream release feeds and opens a pull request. A pull request opened with the default `GITHUB_TOKEN` does not trigger other workflows, so the job opens it with a token from a free GitHub App owned by the owner, limited to contents and pull requests on this repository, so that CI runs on it. The owner reviews and merges it; nothing merges automatically.

Wails v3 has a built-in updater with pinned-key signature checking. Its [self-update tutorial](https://v3.wails.io/tutorials/04-self-update-a-wails-app/) notes that the default GitHub provider checks a SHA-256 file but does not fetch signature files, and that a checksum proves integrity, not authenticity. So use the manifest provider or a custom provider; never ship checksum-only updates.

The update signing key is generated offline, kept out of the repository (CI secret store or a hardware key), and has a written rotation plan. Keep an offline backup: if the key is lost, existing installs can no longer update and users must reinstall by hand.

### Supply chain

- **S-70** Go modules are pinned with `go.sum`, builds use `-mod=readonly`, and the Go checksum database stays on. The UI uses a lockfile and `npm ci --ignore-scripts`.
- **S-71** CI downloads cloudflared from its official GitHub release and compares the SHA-256 with a value committed in the repository before embedding it. The same committed value is compiled into `soireehost.exe` for the launch check in S-23.
- **S-72** CI actions are pinned by commit SHA and run with least-privilege tokens. Pull-request builds see no secrets. Signing happens only on tagged builds from the protected main branch.
- **S-73** Each release publishes an SBOM (CycloneDX) and a build provenance attestation.
- **S-74** Builds are reproducible: the same commit gives the same binary hash before signing.
- **S-75** Every new dependency needs a written reason and a `supply-chain-risk-auditor` pass.

## 12. Open decisions for the owner

Audience, source, UI framework, Windows version, signing route, domain and a zero budget are settled, and the name is chosen. Claude Code asks about the other choices at the phase shown and uses the recommendation only if told to.

| Decision | Options | Recommendation | Needed by |
| --- | --- | --- | --- |
| Name | "Hostdeck" was the placeholder; the owner chose SoiréeHost over SoiréeServe | SoiréeHost: a soirée has a host, and the app hosts. Show the accent in the UI and README; use plain soireehost for repository, file, service, pipe and folder names. Decided on 11 Nov 2026. A web search on 11 Nov 2026 found no product with either exact name, though several event apps are called Soirée; this is not a trademark check | Phase 0 |
| Audience | Personal tool, or public release | Decided: personal use first, also published on GitHub for anyone to download | Phase 0 |
| Source | Open or closed, and which licence | Decided: source public on GitHub, no outside contributions. Pull requests stay enabled for the upstream watcher (S-65); outside pull requests are closed without merging. Apache-2.0, confirmed by the owner: anyone may copy, change and reuse the code. It is OSI-approved, which free signing requires | Phase 0 |
| UI framework | Svelte or React | Decided: Svelte | Phase 0 |
| Windows versions | Windows 11 and Server 2022 or newer; Windows 10; ARM64 | Decided: Windows 11 on x64. Other versions are untested and unsupported | Phase 0 |
| Domain | Use a domain on Cloudflare, or quick share only | Do not buy one. Use quick share, or a domain the owner already has. After 1.0, evaluate Tailscale Funnel as a second tunnel option: it offers a stable ts.net address on its free personal plan (check current terms) | Phase 3 |
| Firewall default | Block from day one, or Detect only for a site's first week | Block from day one | Phase 4 |
| Serving `/.well-known/` | Always blocked as a dotfile path; always allowed; allowed per site | Decided 12 Nov 2026: per site, off by default (`allow_well_known`) | Phase 1 |
| Languages | English only, or more in version 1 | English first; the UI rules in section 7 keep other languages and right-to-left possible | Phase 5 |
| Signing identity | Individual or organisation, and country | Ship unsigned with checksums first; apply to SignPath Foundation after the first release (section 11) | Phase 6 |
| Update install | One click with a Windows prompt, or unattended through an elevated updater | One click for version 1; unattended adds attack surface | Phase 6 |

## Sources

Read on 11 November 2026:

- [Wails v3.1.0 release](https://github.com/wailsapp/wails/releases/tag/v3.1.0)
- [Wails v3 self-update tutorial](https://v3.wails.io/tutorials/04-self-update-a-wails-app/)
- [Caddy releases](https://github.com/caddyserver/caddy/releases)
- [cloudflared releases](https://github.com/cloudflare/cloudflared/releases)
- [Coraza WAF module for Caddy](https://github.com/corazawaf/coraza-caddy)
- [Microsoft: code signing options for Windows app developers](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)
- [Trail of Bits skills](https://github.com/trailofbits/skills)
- [samber/cc-skills-golang](https://github.com/samber/cc-skills-golang)
- [spf13/go-skills](https://github.com/spf13/go-skills)
- [Anthropic: automated security reviews in Claude Code](https://support.claude.com/en/articles/11932705-automated-security-reviews-in-claude-code)
- [Anthropic: claude-plugins-official marketplace](https://github.com/anthropics/claude-plugins-official)
- [SignPath Foundation: conditions for open source projects](https://signpath.org/terms)
- [Certum: Open Source Code Signing in the Cloud](https://shop.certum.eu/open-source-code-signing-on-simplysign.html)
- [GitHub: repository settings for pull request access](https://github.blog/changelog/2026-02-13-new-repository-settings-for-configuring-pull-request-access/)

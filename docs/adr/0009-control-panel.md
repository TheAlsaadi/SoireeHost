# ADR-0009: Control panel

**Status:** Proposed
**Date:** 15 Nov 2026
**Deciders:** Owner

## Context

Phase 5 builds the control panel: the window the user sees, its tray icon, and the bindings between the Svelte UI and the supervisor's control pipe (plan sections 6, 7 and 9, S-30 to S-35). ADR-0003 chose Wails v3.1.0 and Svelte 5; ADR-0006 fixed the control API, its pipe and who may call it. This record fixes how the control panel is put together, what the supervisor adds for it, and the security items from the skills review that land in code this phase touches (SE-07, SE-27 to SE-30, DR-6).

The plan's build order is a hard gate. First come the design tokens and three static screens (Sites with its detail pane, Activity, Security) in light, dark and high contrast. The owner approves them, and only then do components, bindings, the other two screens, the first-run flow and the tray get built.

Owner decisions taken on 15 Nov 2026:

- **Languages.** English only in version 1. Every string goes through one message catalogue, and the CSS uses logical properties so a right-to-left layout stays possible (plan section 12).
- **Administrator rights.** Tests that need them run on the CI isolation job only, never on the owner's PC.
- **No domain.** Quick share is the way online for now.
- **Accent.** One fixed SoiréeHost accent colour, checked for WCAG AA in light, dark and high contrast, not the Windows accent colour.
- **Icons.** Fluent System Icons (MIT). Only the SVGs the app uses are copied into the repository; there is no npm package.
- **Tray.** Closing the window hides it to the tray. The control panel starts in the tray at sign-in, through a per-user entry that needs no administrator rights, and a switch in Settings turns that off.

## Decision

### Shell (Wails v3.1.0)

- **One window, one tray icon.** The control panel is a single-instance app (Wails `SingleInstance`): a second start, from the Start menu or the sign-in entry, shows the existing window instead of opening another.
- **Starting at sign-in.** `soireehost.exe gui --tray` starts hidden in the tray. The sign-in entry is a value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` that holds the quoted install path. The control panel writes or removes it only when the Settings switch changes; it never writes it for another user and never needs elevation. Phase 6 setup turns it on at install, and uninstall removes it.
- **Tray menu.** Shows the status line in plain words ("Online: 3 sites", "Offline"). Items: Open SoiréeHost, Take everything offline or Bring sites back online (the offline switch, `tunnel.set_offline`), Quit control panel. Quitting the control panel never stops a site; the menu says so.
- **Closing the window** hides it. The first time, a one-line notice in the tray explains that sites keep serving.

### Webview hardening (S-33)

- **Content Security Policy.** The policy already in `index.html` stays: `default-src 'none'`, `script-src 'self'`, `style-src 'self'`, `img-src 'self' data:`, `font-src 'self'`, `connect-src 'self'`, `base-uri 'none'`, `form-action 'none'`, `object-src 'none'`. The asset handler also sends it as a response header, together with `X-Content-Type-Options: nosniff`, so the meta tag is not the only copy. A Vite build check fails if the built `index.html` holds any inline script or `style` attribute, or any `http:` or `https:` URL.
- **No remote content.** Fonts are the system's (Segoe UI Variable, Cascadia Mono). Icons are inline SVG built from vendored path data. No image, font or script comes from the network.
- **Navigation lock.** Wails v3.1.0 neither exposes WebView2's `NavigationStarting` and `NewWindowRequested` events nor the WebView2 handle (checked in its source, 16 Nov 2026), so a navigation cannot be cancelled natively. The lock is built from what remains, in layers:
  - the UI has no link to any outside page, and `source-rules.test.ts` fails on an `http:`, `https:` or `javascript:` link, an inline handler or a `wml-` attribute in markup;
  - a capturing click guard in `App.svelte` cancels any click on a link;
  - the CSP forbids forms (`form-action 'none'`), frames, remote scripts and remote content, and nothing renders HTML from data (S-34), so injected markup cannot add a link or script;
  - the few outside pages the app needs (the Cloudflare dashboard, the tunnel-token help page, the project page) open in the user's default browser through `OpenKnownLink(name)`, whose `name` comes from a closed set, so the UI never passes an address; a site's own address opens through `OpenSiteAddress`, which accepts only `https://` and a valid hostname.

  Known limit: a script running in the page could still navigate it. That needs a script to run, which the CSP and S-34 prevent. Revisit when Wails exposes the navigation events.
- **Developer tools and dev server.** Release builds (`-tags production`, ADR-0003) turn off developer tools, the inspector, the default context menu and the `FRONTEND_DEVSERVER_URL` redirect. Wails turns developer tools off in `production` builds whatever the window options say (checked in its v3.1.0 source). The CI isolation job starts the installed control panel and checks that it holds no listening socket (`TestControlPanelOpensNoPort`).
- **One-binary rule.** Assets are embedded and served from memory by Wails' asset server, never from a port (ADR-0003).

### Untrusted text (S-34)

- Everything from outside (hostnames, paths, user agents, URIs, firewall rule messages, worker failure details, site names) is rendered through Svelte text interpolation only. The existing ESLint rules fail the build on `{@html}`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `DOMParser` and `createContextualFragment`.
- **Invisible and misleading characters.** A `visibleText` function, used by the log row and every field that shows outside data, does two things. It replaces C0 and C1 controls, bidirectional overrides and isolates (U+202A to U+202E, U+2066 to U+2069), zero-width characters and other format characters with a visible `⟨U+XXXX⟩` marker. It also cuts long values with an ellipsis, while the full value stays one click away in the detail pane, still as text. This stops a request from using right-to-left overrides to make a log line read differently from what it is.
- **Phase 5 acceptance check.** A request whose path and user agent hold `<script>` and `<img onerror>` payloads is sent through the real worker, read back through `access.list` and `firewall.events`, and rendered in Activity by a Vitest component test. The test checks that the payloads appear as literal text and that no element, attribute or script was created from them. The same payloads in a site name, hostname and folder path are checked on the Sites and Security screens.

### Secrets in the control panel (S-35)

- The tunnel token field is a password input that is never filled from data. Its binding, `SetTunnelToken(value, confirmation)`, passes the value to `secret.set` and keeps no copy. There is no binding that reads a secret. The UI shows only "Set on 15 Nov 2026, 14:02" from `secret.status`.
- The Go binding struct that carries the token redacts itself in `String` and `GoString`, like `ipc.SecretSetParams`. A canary test plants a token, drives the binding, and searches the binding's log output, errors and every result the UI receives for it.

### Bindings and data flow

- **One Go service.** `internal/gui` gains one bound service, `Control`, with one typed method per control call the UI needs (`Status`, `Sites`, `PutSite`, `SetSiteEnabled`, `RemoveSite`, `QuickShareStart`, `QuickShareStop`, `SetOffline`, `Activity`, `FirewallEvents`, `AuditList`, `History`, `Rollback`, `SetTunnelToken`, `SecretStatus`, `ExportConfig`, `ImportConfig`). Each method calls the `ipc` client and returns the supervisor's typed result or a typed error (code plus plain sentence). The control panel validates nothing on its own: the supervisor's answer is the truth (S-31).
- **Local-only helpers.** A few helpers never touch the supervisor:
  - `ListeningPorts` (the port picker) reads the TCP table of the user's own session and names each process where Windows allows it.
  - `GrantSiteAccess` adds the folder permissions, with SE-07 applied (below).
  - `Clipboard` copies text.
  - `QRCode(text)` returns the matrix of a QR code for a quick share URL, which the UI draws as SVG rectangles. The library is chosen at build time, with the dependency checks below; if none passes, a small in-house encoder is written instead.
- **No push channel.** The UI polls `status.get` every 3 seconds while the window is visible and pauses when it is hidden. Activity polls every 2 seconds while it is on screen, asking only for entries newer than the last one it has. This keeps the pipe protocol at one request at a time, as in ADR-0006.
- **New control methods:**

  | Method | Does | Policy |
  | --- | --- | --- |
  | `access.list` | Pages through the web worker's access log (`logs\web`), newest first, filtered by site, status class and time. Every entry is already cleaned and masked by the worker (S-18) and is display-only text | Read |
  | `config.export` | Returns the config as JSON for the user to save. It never contains secrets (S-40) | Read |
  | `config.import` | Replaces the config with an imported one after full validation. Weakening (S-32): it always needs a confirmation that names what changes | Weakening |

  Saving and opening the export file is done by the control panel, through the system file dialog. The supervisor never receives a path to write (S-31).
- **Developing without services.** For working on screens without installed services, a fake transport answers the bindings with fixture data. It is compiled only into the Vite development build (`import.meta.env.DEV`), never into a release asset, and a build check fails if the release bundle contains it.

### Confirmation becomes a server-issued nonce (SE-27, S-32)

- **How a weakening call works now.** A weakening call (firewall off or Detect only, a LAN target, replacing the tunnel token, importing a config, rolling back to a revision that adds a LAN target, removing or weakening a security header, putting a folder with exposed secrets live) no longer accepts `confirm: true`. The first call returns `confirmation_required` with a `confirmation` object: a 128-bit random `token`, the plain sentences describing exactly what will change, and an expiry.
- **What the supervisor keeps.** For each token it keeps the caller's SID, the method, a SHA-256 of the call's parameters in canonical form (with the token field left out), and an expiry of 2 minutes.
- **Confirming.** The control panel shows the supervisor's sentences in a confirmation dialog, as text. If the user confirms, it sends the same call again with `confirmation: <token>`. The supervisor accepts only when the token exists, has not expired, has not been used, was issued to the same caller SID for the same method, and the parameters hash the same. A token is consumed on its first use, whether the call succeeds or fails. At most 16 tokens are held per caller; the oldest is dropped first.
- **Tests:** a reused token, another caller's token, a token for other parameters or another method, an expired token, and a made-up token are all refused. Each refusal tells the caller to confirm again.

### Per-method policy table (SE-29, S-31)

- **One table.** Dispatch moves from a `switch` to one table in `internal/supervisor`: `method → {kind, handler}`. `kind` is `Read`, `Change` or `Weakening`. The server refuses before decoding any params when a method has no entry.
- **Checked before every handler.** The check runs before every handler:
  - The caller must be in the control set (unchanged from ADR-0006, and checked again per call, not only per connection).
  - A `Change` or `Weakening` call writes an audit entry naming the caller.
  - A `Weakening` call goes through the confirmation step above.
  - The `site.put` static root, the only path the API accepts, is checked by `sitecheck.CheckRoot` inside its handler, as now.
- **Tests:**
  - every method in `ipc.Methods()` has exactly one policy entry, and every policy entry is a method;
  - an unlisted method is refused;
  - every `Weakening` method refuses a call without a valid confirmation.

### Pipe client (SE-30)

- **Close on any error.** `ipc.Client.Call` closes the connection after any error (I/O, timeout, malformed reply, ID mismatch); the next call dials again.
- **Reply ID first.** A reply's `id` is checked before its result or error is looked at, so a stale error can never answer a later call.
- **Cancellation.** A context without a deadline is honoured: cancelling it closes the pipe handle, which unblocks the pending read.
- **Tests:** a server that replies with the wrong ID, one that never replies, and a cancelled context.

### Response headers (SE-28, S-16)

- `response_headers` refuses an empty value.
- A new per-site list, `remove_headers`, names the managed headers the site does not send. A header can only be removed by being listed there.
- **Warnings.** `Config.Warnings()` returns one plain sentence for each removed header and for each weakened value it can recognise:
  - `frame-ancestors` other than `'none'` or `'self'`;
  - `X-Content-Type-Options` other than `nosniff`;
  - a `Referrer-Policy` of `unsafe-url` or `no-referrer-when-downgrade`.

  It also warns about directory listing and `/.well-known/` being on. The Security screen shows each warning beside the protection it weakens.
- Removing a header or setting a value that triggers a warning is a weakening change and needs confirmation. Turning on directory listing or `/.well-known/` shows the warning but needs no confirmation: both are opt-ins the plan allows per site (S-12).
- **Config compatibility.** A saved config with an empty header value is migrated once at load: the header moves to `remove_headers`, and an audit entry records the migration. Nothing is silently weakened or strengthened.

### Worker failure reasons (DR-6)

- **Closed codes.** A worker's `failed` message carries a code from a closed set: `config_rejected`, `listen_failed`, `self_check_failed`, `limits_failed`, `start_failed`, `tunnel_refused`, `timeout` or `other`. It also carries a detail of at most 200 characters.
- **Cleaned detail.** The supervisor cleans the detail: it keeps printable characters only, turns controls and bidirectional or format characters into spaces, and collapses runs of spaces. It stores the code and the detail apart.
- **What the control panel shows.** It never shows the detail as its own words. It shows the sentence it owns for the code ("The web server refused the new settings"), then the detail in monospace under the label "Reported by the web server:".
- **Tests:** a reason with bidirectional overrides, newlines and 2 KB of text comes out as one clean line of 200 characters or fewer. An unknown code is refused at decoding.

### Site folder access (SE-07, re-audit of `GrantSiteAccess`)

The control panel calls `GrantSiteAccess` when a site is added. The new version works as follows:

1. Opens the folder once, with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS` and `READ_CONTROL | WRITE_DAC`, and refuses it if the handle is a reparse point (link or junction).
2. Resolves the handle's real path (`GetFinalPathNameByHandle`) and runs `sitecheck.CheckRoot` on that path. It refuses if the result is not the same folder (same volume serial and file ID as the handle).
3. Reads the DACL from the handle. It adds the two entries only when no equivalent entry for that SID is already there, so there are no duplicates on repeat calls.
4. Writes the DACL through the same handle. The supervisor's entry stays on the folder itself only. The web worker's entry is inheritable; existing children receive it through Windows' normal inheritance from the handle. No path-based call that could follow a link swapped in later is made.

**Tests:**
- a junction to `C:\Windows`, a folder under `AppData` and a drive root are refused;
- a second call adds no duplicate entry;
- the folder is changed only through the handle that was checked.

The test that swaps the path between check and write uses a junction, which a standard user may create, so it runs locally.

### Design system

- **Tokens.** Tokens are CSS custom properties in one file, in three layers:
  - primitives: the grey ramp, the accent and the status hues;
  - semantic roles: surface, text, border, accent, focus, and status OK, warning and danger;
  - component tokens.

  Light and dark come from `prefers-color-scheme`. High contrast comes from `@media (forced-colors: active)`, which maps the roles to system colours (`Canvas`, `CanvasText`, `Highlight`, `ButtonText`, `GrayText`, `LinkText`) and keeps a visible focus outline and borders.
- **Type.** Segoe UI Variable (Text, and Display for the one title size), falling back to Segoe UI; Cascadia Mono, falling back to Consolas. Three sizes in `rem`, so the Windows text-size setting scales them: 12 px caption, 14 px body, 20 px title. Two weights: 400 and 600.
- **Space and shape.**
  - Spacing on a 4 px grid.
  - Radius 4 px on controls, 6 px on panels.
  - 1 px borders between regions.
  - Shadows only on menus and dialogs.
- **Motion.** 120 to 160 ms, and none under `prefers-reduced-motion`.
- **Colour.**
  - The accent appears only on the primary button and the focus ring.
  - Status colours always come with a word and a distinct icon shape:
    - circle with a check for OK;
    - triangle for warning;
    - circle with an exclamation mark for danger;
    - hollow circle for off;
    - barred circle for a blocked request.

    Normal log results carry no mark.
- **The accent.** Soirée plum: `#6B3A60` on light, `#DBB6D1` on dark, measured at 8.8:1 and 9.6:1 against its button text. A solid colour, never a gradient. Switches use the strong text colour for "on", because on/off is state, not the primary action.
- **Small windows and 200 % zoom.**
  - Below 60rem the detail pane moves under the list, and the Sites list drops its address column (the pane shows it).
  - Below 45rem the rail shows icons only, keeping each name for screen readers, and Activity drops its visitor column.
  - In a short window the screen scrolls as one page.
- **Layout.** Logical properties only (`margin-inline-start`, `padding-block`, `inset-inline-end`). A Stylelint-free check in Vitest fails the build on any physical `left`, `right`, `margin-left` and similar property in `src/**/*.css` and `*.svelte`.
- **Copy.** Every string lives in `src/lib/i18n/en.ts` as typed keys, read through `t(key, params)`. A Vitest check fails on raw text in Svelte markup outside the catalogue. Buttons are verbs, errors say what happened and what to do next, there are no exclamation marks, and an empty state is one sentence and one action (plan section 7).
- **Icons.** Fluent System Icons, regular style, 16 and 20 px. Each used icon's path data is copied into `frontend/src/lib/icons/` with the licence in `THIRD_PARTY_NOTICES`, and an `Icon` component draws it through Svelte SVG elements (no `{@html}`).

### Screens

All five screens share the left rail (Sites, Activity, Security, Backups, Settings) and the one status line at the top.

- **Sites.** A list, one row per site: name, address in monospace, type (Static or Proxy), status, and an on/off switch. Selecting a row opens the detail pane on the right. The pane shows:
  - the address, with a Copy address button and a QR code for a quick share link;
  - quick share or permanent address;
  - the folder or port;
  - the health line;
  - the firewall mode;
  - limits and headers;
  - Stop serving and Remove site.

  You can drop a folder on the window to start adding a site.
- **Activity.** A log table with filters by site, status and time. A blocked row is marked with an icon and the word "Blocked", and its detail names the rule that fired (id and message).
- **Security.** A checklist of real protections with their actual state (On, Off, Not set up) and one line on what each does. Per-site exceptions (firewall Detect only or Off, LAN targets, removed headers, directory listing) are listed beside the protection they weaken. It shows the audit-chain check and the outbound connections (the tunnel and the update check, S-42).
- **Backups.** Export settings and Import settings (the import is weakening and confirmed), plus the config history with Restore.
- **Settings.**
  - Tunnel token (write-only) and the service URL to enter in Cloudflare.
  - Start at sign-in.
  - The offline switch.
  - Version and Repair (when `repair_needed`).
  - Licences.
  - The outbound connections list (S-42).
- **First run.** Three steps: choose a folder or a port, choose quick share or tunnel, go live (plan section 6).

### Dependencies

Each new dependency gets a reason, a pinned version, a licence check, `npm audit` or `govulncheck`, and a `supply-chain-risk-auditor` pass before it is added (S-75), recorded in `docs/DEPENDENCIES.md`. Expected candidates:

- a DOM environment for Vitest component tests (`jsdom` or `happy-dom`);
- a QR encoder.

Fluent System Icons are vendored data, not a package, and are recorded with their licence.

## Options considered

- **A push channel (events from the supervisor) instead of polling.** It would need the pipe protocol to carry unsolicited messages, which ADR-0006 rejected so that every reply can be matched to its request (and SE-30 tightens that). Polling a few small calls every 2 to 3 seconds costs little on a local pipe. Revisit with traffic charts after 1.0.
- **Confirmation as a client-side dialog only (`confirm: true`).** This was rejected by SE-27: a client that always sends the flag never asks, and the flag is not bound to what the user saw.
- **The Windows accent colour.** Rejected by the owner: a pale accent fails AA, and a fixed accent can be tested.
- **A component library.** This is banned by plan section 7 ("no UI kit"). About a dozen hand-built components instead.

## Consequences

- The control API changes shape:
  - `confirm` fields become `confirmation`;
  - `failed` reasons gain codes;
  - `response_headers` gains `remove_headers`.

  The control panel and the supervisor ship in the same binary, so there is no version skew. The e2e tests and fuzz targets are updated in the same change.
- The supervisor reads the web worker's access log folder, which ADR-0006 already allows (supervisor read on `logs\web`).
- The UI's correctness rests on Vitest component tests plus a small set of Go binding tests against an in-process supervisor. The real window and tray are checked on the CI isolation job and by the owner's own look at the finished app.

## Action items

1. [x] Owner: approve the tokens and the three static screens (Sites with detail pane, Activity, Security) in light, dark and high contrast before any component is built. Approved 15 Nov 2026.
2. [ ] Owner: accept or amend this record.
3. [ ] Phase 5 build after approval, with tests for S-33 to S-35, SE-07, SE-27 to SE-30 and DR-6, and the acceptance check above.

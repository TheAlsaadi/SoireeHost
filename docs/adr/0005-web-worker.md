# ADR-0005: Web worker on embedded Caddy

**Status:** Accepted by the owner on 12 Nov 2026
**Date:** 12 Nov 2026
**Deciders:** Owner

## Context

Phase 1 builds the web worker: embedded Caddy serving static folders and proxying local apps on loopback, with the protections in plan sections 5.1 and 5.2 (S-01, S-04 to S-06, S-10 to S-13, S-15, S-16, S-18). Caddy v2.11.9 provides the server, file server, reverse proxy, header handling, body limits and rotating log files. It does not provide Windows-specific path rules, a per-client rate limiter, a file system that cannot be escaped through junctions, or log redaction by allow-list. Plan section 3 asks for a decision in Phase 1 on `github.com/mholt/caddy-ratelimit`.

## Decision

The supervisor turns the SoiréeHost config (`internal/config`) into a Caddy JSON config (`worker.BuildCaddyJSON`), and the worker runs it in-process with `caddy.Load`. Four small SoiréeHost modules are compiled into Caddy:

| Module | ID | Does |
| --- | --- | --- |
| Guard | `http.handlers.soireehost_guard` | Drops forged forwarding headers (S-05); applies the S-12 and S-13 path rules from `internal/sitecheck` before any file or app is reached |
| Rate limit | `http.handlers.soireehost_ratelimit` | Per-client limit (S-15), GCRA, IPv6 grouped by /64, bounded table that fails closed when full |
| Rooted file system | `caddy.fs.soireehost_root` | Serves a static site from an `os.Root` opened on the checked, canonical folder (S-11, S-12) |
| Log filters | `caddy.logging.encoders.filter.soireehost_headers`, `..._query` | Header allow-list and secret query masking in every log (S-18) |

Each site is a Caddy route matched on its hostnames. Handler order: security headers, rate limit, guard, request body limit, then `file_server` or `reverse_proxy`. A last route answers every other Host with 404 (S-06). Server-level error routes add the security headers to every error response.

### Rate limiting: in-house, not `caddy-ratelimit`

`caddy-ratelimit`'s only tag is v0.1.0 (28 Aug 2024, `go 1.21`); everything since is untagged, so pinning it means a pseudo-version of an unreleased commit. Its distributed mode and storage features are not needed here. The in-house handler is about 120 lines with table tests on a fake clock and an integration test. Rejected for now; revisit if it gains releases and we need features it has.

### Path rules apply before Caddy and again inside the file system

`internal/sitecheck` decides from the decoded and the raw path: 400 for malformed input and Windows tricks (`..`, backslashes, `%5c`, `%00`, double encoding, `:` including `::$DATA`, trailing dots or spaces, reserved device names, `~digit` short names, control characters, a leading `//`); 404 for names that are never served (dotfiles in any case, `web.config`, `desktop.ini`, `Thumbs.db`, `.pem`, `.key`, `.pfx`, `.p12`, `.bak`, `.sql`, and, beyond the plan's list, the extensionless SSH keys `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `id_ecdsa_sk`, `id_ed25519_sk`, OpenSSH host keys `ssh_host_*_key`, PuTTY keys `.ppk` and KeePass databases `.kdbx`). The rooted file system repeats the name checks, hides links and special files, filters directory listings, and reports every failure as "not found", so an escape attempt is a 404, never a 500 that confirms something exists.

`.p12` is added to the plan's list because it is the same format as `.pfx`. The `~digit` rule also refuses some legitimate long names such as `draft~2.html`; that is accepted so that no short name can alias a hidden file.

### Proxied apps get the lighter rule set

A proxied app owns its URL space, so Windows file name rules (colons, trailing dots, device names) do not make a request malformed there; `/api/user:123` must work. Traversal, control characters, backslashes and the never-serve list still apply, so a dev server exposing its project folder does not publish `.env` or `.git`. Because such a server usually hands the path to Windows, which drops a `:stream` suffix and trailing dots and spaces and expands 8.3 names, the never-serve check also looks at each segment as Windows would open it, and 8.3-shaped segments (`GIT~1`, `ENV~1`, `SERVER~1.KEY`) get a 404. The end-of-phase security review found this gap (`/ENV~1`, `/server.key.`, `/server.key::$DATA` reached the app); it is fixed and covered by `TestCheckProxy` and `FuzzCheckProxy`.

Headers spelled with underscores (`X_Forwarded_For`) are dropped as well, because apps that read headers through CGI-style variables see them as the forwarded-for header.

### Static roots are checked by handle, twice

`sitecheck.CheckRoot` opens the folder, asks Windows for its final path (resolving junctions, symbolic links and 8.3 names), and checks that path against the blocked locations: drive roots, the Windows folder, both Program Files folders, all of `%ProgramData%` (the plan names only `%ProgramData%\SoireeHost`, but the rest holds other services' keys, such as OpenSSH's host keys in `ProgramData\ssh`), the Users folder and every profile root, anything containing `AppData` or `.ssh`, and the system folders Windows keeps at the top of every drive (`$Recycle.Bin`, `System Volume Information`, `Windows.old`, `Recovery`, `Config.Msi`, `$Windows.~BT`, `$Windows.~WS`, `$WinREAgent`, `$SysReset`, `MSOCache`). A blocked folder's parents and children are refused too. When the worker opens a site it repeats the check and confirms the `os.Root` it opened is the same folder (volume serial and file index) as the handle it checked, so swapping the folder for a junction in between is caught. Network folders are refused.

### Limits that are per server, not per site

Header size and the read, header and idle timeouts are set on the listener, because they apply before the Host header (and so the site) is known. Body size and rate limit are per site.

### Security headers do not overwrite the app's own

Each default header is set only when the response does not already carry it, so a proxied app with a stricter `Content-Security-Policy` keeps it. The `Server` header is always removed. Per-site overrides can change or remove the four managed headers.

### Logs keep an allow-list of headers

Request and response headers in the logs are reduced to `Accept`, `Accept-Encoding`, `Accept-Language`, `Cf-Connecting-Ip`, `Cf-Ipcountry`, `Cf-Ray`, `Content-Length`, `Content-Type`, `Referer` and `User-Agent`. Any query parameter whose name contains `token`, `key`, `password`, `passwd`, `pwd`, `secret`, `auth`, `session`, `signature` or `credential` has its value replaced with `REDACTED`, in the URI and in `Referer`. A query that cannot be parsed is masked whole. Logs rotate at 10 MB, keeping 5 files for up to 30 days.

### No disk writes outside the log folder

The generated config disables the admin API and config autosave (`admin.disabled`, `admin.config.persist: false`) and turns off the TLS app's storage check and cleaning, which would otherwise write `instance.uuid` and lock files under the service profile. HTTP/3 is off (`protocols: ["h1"]`), so no UDP socket is opened.

### Listener self-check

After every load, and every minute after that, the worker lists its own listening TCP and bound UDP sockets through `GetExtendedTcpTable` and `GetExtendedUdpTable` (iphlpapi.dll, loaded from System32). Anything other than `127.0.0.1` or `::1` stops Caddy and returns an error; so does a failure to read the tables.

The two extensions above the plan's lists came from the pre-commit code review on 12 Nov 2026, after the owner accepted this record. Both only refuse more, so they were applied and recorded here.

## Consequences

- Embedding `caddyhttp` and `caddytls` links in code SoiréeHost never calls: cobra (Caddy's CLI), OpenTelemetry exporters and gRPC (tracing), and the smallstep CA with its MySQL, PostgreSQL and Badger stores (Caddy's internal PKI). A development build with the worker is 55 MB against 10 MB without it, and 150 Go modules are linked. All licences are permissive (Apache-2.0, MIT, BSD, ISC, one MPL-2.0: `go-sql-driver/mysql`, unmodified). `govulncheck` covers them all. Forking Caddy to drop them is not worth the maintenance.
- Caddy keeps a log file open for the life of the process once it has opened it, shared across config reloads (one handle per log file, no growth). Tests therefore use one shared log folder per test run.
- The guard's 8.3 rule and the never-serve list refuse a few legitimate names. Both are deliberate.
- `/.well-known/` (RFC 8615) is the one dot-folder a site can publish, per site and off by default (`allow_well_known`; owner decision, 12 Nov 2026). Only the exact lower-case first path segment is exempt. Everything inside it keeps every other rule, so `/.well-known/.env` or `/.well-known/id.key` still get 404, and the folder stays out of directory listings. It is not treated as a weakening action under S-32, because it publishes only what the user put in that folder.

## Action items

1. [x] Owner: accept or amend this record. Accepted 12 Nov 2026.
2. [x] Owner: decide whether `/.well-known/` stays blocked. Decided 12 Nov 2026: per-site opt-in, off by default.
3. [ ] Phase 2: the supervisor runs `sitecheck.CheckRoot` before saving a site and stores the canonical path; the worker receives the Caddy JSON over its pipe.
4. [ ] Phase 4: Coraza joins the handler chain after the guard.

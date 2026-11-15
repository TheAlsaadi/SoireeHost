# ADR-0008: Web application firewall, firewall event log and exposure check

**Status:** Accepted by the owner on 15 Nov 2026
**Date:** 15 Nov 2026
**Deciders:** Owner

## Context

Phase 4 (plan section 9) adds the web application firewall: Coraza with the OWASP Core Rule Set (CRS), per-site modes, the firewall event log, and the exposure check. Rate limiting (S-15) already exists from Phase 1 (`internal/worker/ratelimit.go`). The requirements are S-14, with S-18 and S-40 for the event log, S-21 for the memory cap, S-31 for the new control method and S-32 for the weakening actions. ADR-0005 action item 4 places Coraza in the handler chain after the guard.

Owner decisions taken on 15 Nov 2026:

1. **Firewall default.** Block from day one. Every new site starts in Block mode at paranoia level 1, and a site can be set to Detect only or Off by hand. Off shows a standing warning (plan section 12, S-14).
2. **Rule set.** Pin CRS v4.30.0, the newest stable release, from the official CRS release, checked against a committed SHA-256 the same way cloudflared is (S-65, S-71). The other choices were the 4.25.2 long-term-support release and the `coraza-coreruleset` wrapper.
3. **Exposure check.** A static folder that holds a file which would be served and looks like a secret, such as a private key saved under an ordinary name, needs confirmation before the site goes live, and the confirmation is audited. Names the path rules never serve are only listed.
4. **Detect only counts as weakening.** Going from Block to Detect only, or from any mode to Off, needs confirmation and an audit entry. That includes a rollback to settings with a weaker mode. Detect only also gets a standing warning.
5. **File uploads.** The firewall keeps request bodies in memory and never on disk, and inspects up to 16 MB per request. In Block mode a body over 16 MB gets 413 and is never passed on uninspected.
6. **Body text.** Body text is inspected up to 128 KB: forms, JSON, XML, and the text fields of a multipart form, which is everything that is not an uploaded file. In Block mode more text gets 413; in Detect only the rest passes uninspected. The owner chose this after the measurement below; the other choices were 1 MB and 16 MB.
7. **Administrator rights.** Tests that need them run on the CI isolation job only, never on the owner's PC.

Facts checked on 15 Nov 2026:

- **Versions.** `github.com/corazawaf/coraza/v3` v3.8.1 (2 Oct 2026) and `coraza-caddy/v2` v2.6.2 are the newest tags; both are Apache-2.0 and have no OSV advisories. The newest `coraza-coreruleset/v4` tag is v4.25.0 (Mar 2026). Its `main` branch moved to CRS v4.30.0 on 9 Oct 2026 but has not been tagged. CRS v4.30.0 (2 Oct 2026) and the LTS release v4.25.2 (same day) both fix GHSA-575j-qr6p-9763, GHSA-89h9-2j8h-9gp2 and GHSA-qmx4-jfcv-fgww. v4.25.1 and later fix GHSA-6jp8-c2w2-x7wr and the ReDoS GHSA-f5qm-3h4p-8qhg. The wrapper's v4.25.0 has none of these fixes.
- **The CRS release.** `coreruleset-4.30.0-minimal.tar.gz` has SHA-256 `3d678a41fd5aade34760127fef5dd64fd7a77848913fc0f70dde0cf467c94427`, matching the digest GitHub reports for the asset. Its `.asc` signature verifies with the CRS key `3600 6F0E 0BA1 6783 2158 8211 38EE ACA1 AB8A 6E72`, the fingerprint published in the release's `docs/INSTALL.md`.
- **Antivirus.** Windows Defender quarantined `rules/web-shells-php.data` within seconds of extracting the archive on the owner's PC, as `Backdoor:PHP/Dirtelti.MTJ`. The file is a list of web-shell signatures, and only the response rule file `RESPONSE-955-WEB-SHELLS.conf` uses it.
- **coraza-caddy v2.6.2** (read in full):
  - Its error callback writes `MatchedRule.ErrorLog()` to Caddy's log at error level. That text carries the matched request data (`[data "..."]`), which can include query values, cookies and form fields.
  - It also logs `r.RequestURI` unmasked on every block. Both break S-18.
  - It merges the operating system's file system into the rule loader (`mergefs` with `OSFS`).
  - It imports the lagging `coraza-coreruleset` v4.25.0.
- **Coraza v3.8.1:**
  - Unless built with the `no_fs_access` tag, it writes request bodies above `SecRequestBodyInMemoryLimit`, and every multipart file part, to temporary files in `os.TempDir()`.
  - At start-up it checks that the temp folder is writable by creating a file there.
  - `SecTmpDir` is accepted and ignored, and `SecRequestBodyNoFilesLimit` is parsed but not enforced (Coraza issue 896).
  - Compiled regular expressions are memoised process-wide and shared between WAF instances.
  - `MatchedRule.Disruptive()` is true for every matched rule, `pass` included, so it cannot tell which rules would block.
- **A Coraza bug on Windows.** The `normalizePath` and `normalizePathWin` transformations use `filepath.Clean`, which on Windows turns every `/` into `\`. Every CRS rule that uses them then misses Unix-style paths. For example, rule 930120 does not see `etc/passwd` in `/view?file=/etc/passwd`, and `127.0.0.1;cat /etc/passwd` passes paranoia level 1. This is Coraza issue 1140 ("Windows: remaining fixes (normalisePath, ...)"), still open. Found here by the attack set.
- **CPU cost of body text** (measured locally, paranoia level 1, one request at a time):

  | Body | Inspection time |
  | --- | --- |
  | 128 KB of form or JSON text | 1.4 s |
  | 1 MB | 11.9 s |
  | 4 MB | 45 to 49 s |
  | 15 MB multipart file upload | 0.05 s |

  The profile is 93% Go's regular-expression engine, which runs CRS's large patterns on its slow path for long input. Coraza's experimental `SecRxPreFilter` saved about 20%. A raw body of an unlisted content type is worse: CRS rule 901340 forces it to be inspected as text, and 16 MB took 2 min 37 s.
- **Memory, measured locally** (Go heap after GC, request rules of CRS v4.30.0, `no_fs_access`):

  | Loaded | Heap in use | Build time |
  | --- | --- | --- |
  | Nothing | 2.4 MB | — |
  | One WAF | 18.9 MB | 113 ms |
  | Two WAFs | 22.2 MB | 32 ms for the second |
  | Eight WAFs (every mode and paranoia level) | 35.7 MB | — |

  The web worker's job memory cap is 1 GiB (`worker.Limits`). Go's garbage collector does not know about the cap, and by default lets the heap grow to twice what is live.
- **CRS defaults that matter.** The default `tx.allowed_methods` is `GET HEAD POST OPTIONS`, so at paranoia level 1 rule 911100 blocks `PUT`, `PATCH` and `DELETE`, which typical JSON APIs use. Rule 901001 returns 500 for every request unless `tx.crs_setup_version` is set.

## Decision

### 1. A SoiréeHost Caddy module on Coraza, not coraza-caddy

New package `internal/waf` registers `http.handlers.soireehost_waf`, a small handler written against `coraza/v3` directly. `coraza-caddy` and `coraza-coreruleset` are not used, because:

- their logging breaks S-18;
- they let rules be loaded from any file;
- they bring a rule set that lacks published security fixes;
- they intercept responses, which this design does not do (section 5).

The module takes only three fields: `site` (a site id), `mode` (`block` or `detect`) and `paranoia_level` (1 to 4). Provision refuses anything else. A site in Off mode has no firewall handler in its chain. No directive text ever comes from the config, so the control API has no way to inject rules (S-31). Custom rules and exclusions are post-1.0 work (plan section 9).

### 2. The rule set: CRS v4.30.0, request rules only, vendored and checked

- **What is vendored.** `internal/waf/crs/` holds the request rule files of CRS v4.30.0 (`REQUEST-901` to `REQUEST-999`, without the `.example` files), the 11 data files those rules reference, and the CRS `LICENSE`: 30 files in all. They are byte-for-byte copies from the signed release, kept that way by `-text` in `.gitattributes`. `go:embed` compiles them into the binary, and the rule loader sees only that embedded file system.
- **What is left out.** The response rules (`RESPONSE-950` to `RESPONSE-980`) and their data files (`web-shells-*.data`, `*-errors.data`), because responses are not inspected (section 5). Leaving them out also keeps the file Defender flags out of the repository and out of `soireehost.exe`.
- **The lock file.** `build/crs.lock` records the version, the asset URL, the tarball's SHA-256, the signing key's fingerprint, and the list of vendored files.
- **The CI check.** `build/check-crs.ps1` runs in CI. It downloads the tarball from the official release and refuses it unless the SHA-256 matches the lock. It then extracts only the listed files (never the one antivirus quarantines) and fails if any vendored file differs from its copy in the archive, or if a listed file is missing or an unlisted one is present. This is S-71 applied to the rule set.
- **Updates.** The S-65 watcher will treat CRS like cloudflared: a new release becomes a pull request that updates the lock, the vendored files (`check-crs.ps1 -Update`) and the version constant.
- **Version constant.** `TestCRSVersionMatchesLock` keeps `waf.CRSVersion` equal to the lock file.

Vendored files, rather than files fetched at build time like cloudflared's binary, mean `go test ./...` works from a clean clone and each rule change is a readable diff. The CI check gives the same proof of origin as a fetch.

Weighed against the alternatives:

- **The `coraza-coreruleset` wrapper** was rejected because its newest tag lacks five published fixes, and an untagged commit would be a pseudo-version pin.
- **CRS v4.25.2 LTS** would also have carried every fix. The owner chose v4.30.0 for its newer detections and because it is the newest stable release (CLAUDE.md rule 4).

### 3. No disk access: the `no_fs_access` build tag, enforced

Coraza is built with `no_fs_access`, so request bodies and uploaded files stay in memory and nothing is written to a temp folder. This keeps two rules:

- the web worker "never writes outside its log folder" (plan section 4);
- request bodies, which hold passwords and personal data, never reach a file, which follows S-18 and S-40.

`internal/waf/fsaccess_guard.go` is built only without the tag, and it does not compile. A build, test or lint run that forgets the tag therefore fails instead of quietly writing bodies to disk. Every Go command passes the tag:

- CI and CodeQL set `GOFLAGS=-mod=readonly -tags=no_fs_access`, and each command that sets its own `-tags` lists `no_fs_access` too;
- `build/build.ps1`, `build/fuzz.ps1` and `.golangci.yml` (`run.build-tags`) carry it;
- `CLAUDE.md` and the conventions skill say so.

### 4. Directives, and the Windows path fix

Each WAF is built from fixed text generated in code from the mode and the paranoia level:

- **Engine.** `SecRuleEngine On` in Block mode, `DetectionOnly` in Detect only.
- **Request bodies.** `SecRequestBodyAccess On`, with `SecRequestBodyLimit` and `SecRequestBodyInMemoryLimit` both at 16 MiB. `SecRequestBodyLimitAction` is `Reject` in Block mode (413, decision 5) and `ProcessPartial` in Detect only.
- **Off.** `SecResponseBodyAccess Off` and `SecAuditEngine Off`, with no debug log (a no-op logger). Coraza's full audit log is never turned on.
- **CRS setup.** In place of `crs-setup.conf`:
  - `tx.crs_setup_version=4300`;
  - `tx.blocking_paranoia_level` and `tx.detection_paranoia_level` set to the site's level;
  - `tx.crs_skip_response_analysis=1`;
  - `tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE`, so typical APIs pass at paranoia level 1. A static site answers those methods with 405 from the file server anyway.
  - Anomaly scoring keeps the CRS defaults: inbound threshold 5, blocking at rule 949110.
- **Body parsing.** The rules from Coraza's recommended configuration that choose the XML and JSON body processors, and that refuse with 400 a URI that cannot be parsed, a body that cannot be parsed, a multipart body that fails strict validation, and a request over the argument limit (`200000` to `200006`, `200009`).

`internal/waf/transform.go` registers corrected `normalizePath` and `normalizePathWin` transformations (and their `normalise` spellings) under Coraza's own names. Coraza's registry overwrites on registration, and Go runs our package's `init` after Coraza's. The corrected versions are Coraza's logic with `path.Clean`, which always keeps `/`, matching ModSecurity's definition (normalizePathWin first turns `\` into `/`). `TestUnixPathsDetectedOnWindows` is the regression test, and the transformation tables cover traversal, stream suffixes and trailing dots. When Coraza fixes issue 1140, the override can go.

One WAF is built per mode and paranoia level, at most eight in all. They are shared by every site with the same settings and kept across config reloads through a `caddy.UsagePool`. The worst case is about 36 MB.

### 5. Where it runs, and what it inspects

The handler order becomes:

1. security headers;
2. rate limit;
3. guard;
4. request body limit;
5. firewall;
6. `file_server` or `reverse_proxy`.

The firewall runs after the body limit, so it never reads past a site's own limit. When that limit stops the read, the firewall answers 413.

The module runs the request phases (connection, URI, headers, body) and the logging phase. It does not wrap the response writer, and it does not inspect responses. Buffering every response to inspect it would break streaming, server-sent events, WebSockets and large downloads, and would add another 16 MiB per request to memory. The CRS outbound rules detect leaks after the fact; S-14 is about stopping attacks on the site. This is recorded as a limit: CRS response rules are not used.

When the firewall blocks a request, the response is the site's normal error response: status 403, or the rule's own 400 or 413, with the security headers and a fixed body. A rule's `redirect` or `drop` is treated as a 403, and no rule-supplied URL is ever followed.

**Body text (decision 6).** For a body that is not `multipart/form-data`, the module hands Coraza at most 128 KiB.

- **Block mode.** A known `Content-Length` over the limit, or one byte read past it, is answered 413 at once. The event names SoiréeHost's rule 100001.
- **Detect only.** The first 128 KiB is inspected and the rest follows uninspected.
- **Multipart bodies.** Coraza buffers up to 16 MiB, so the module first counts the bytes in parts that are not files. A part is a file when its `Content-Disposition` names a `filename` or `filename*`, as Coraza decides. A body Go cannot parse counts as over the limit. Over the limit, Block mode answers 413; Detect only passes the body uninspected.

**Body budget (memory).** A process-wide weighted semaphore caps the request bodies being buffered at once at 192 MiB. A request reserves its `Content-Length`, capped at 16 MiB, or 16 MiB when the length is unknown. When the budget is exhausted the firewall answers 503 with `Retry-After: 5` rather than risk the 1 GiB job cap ending the worker (S-21). A request without a body reserves nothing.

**Inspection slots (CPU).** At most half the CPU cores, and at least two, run inspections at once. A request waits up to 10 seconds for a slot, then gets 503 with `Retry-After: 5`. Requests built to cost the most CPU can then never take every core from serving and from the supervisor.

The accepted limit: a client that holds many slow uploads open, or sends many costly requests, can make other requests wait or fail with 503 for a while. That is less harmful than the worker being killed, or the PC being saturated, with every site going down.

### 6. The firewall event log (S-18, S-40)

The event log holds attacker-controlled data, so it stores only fields that were built to be safe. One event is written per request that the firewall blocked, or would have blocked in Detect only, or refused for its size. "Would have blocked" means a match of CRS's blocking evaluation (949110, 949111) or one of the body-parsing refusal rules; Coraza's `Disruptive()` flag cannot be used (see Context).

Each event is one JSON line in `logs\web\firewall.log`. It is written through Caddy's logging with the same rotation as the other logs (10 MB, 5 old files, 30 days). Rotated files are not compressed, so the supervisor can read them. `fwevent.Event.Clean` builds every event, and its fields are:

| Field | Source | Safe because |
| --- | --- | --- |
| `time` | time | — |
| `site` | the module's site id | config value |
| `mode`, `action`, `status`, `paranoia_level` | the module | closed sets |
| `method` | request | kept only if it is an HTTP token of up to 16 characters, otherwise `OTHER` |
| `host` | request Host | must be a valid hostname, else empty |
| `uri` | request target | bytes outside printable ASCII percent-encoded, every query value masked by `redact.URI` (S-18), cut to 2048 bytes with any query then masked whole |
| `client_ip` | Caddy's client address (`CF-Connecting-IP` from cloudflared, S-05) | parsed as an IP address |
| `rules` | up to 10 matched rules: `id`, `severity`, `msg`, `where` | see below |

- **`id` and `severity`** come from the rule. CRS's setup rules (900000 to 901999) and rules without a message are left out. SoiréeHost's size refusals appear as rules 100001 (text over 128 KB) and 100002 (body over 16 MB).
- **`msg`** is the rule's message. CRS puts matched data in `logdata`, not `msg`, but some messages expand variables. A message is kept only if it is at most 160 printable ASCII characters and contains none of the matched values (three characters or longer). Otherwise it is replaced with `"matched"`.
- **`where`** is the collection the match was in (`ARGS`, `REQUEST_HEADERS`, `REQUEST_COOKIES`, `REQUEST_URI`, `REQUEST_FILENAME`, `REQUEST_BODY`, `FILES` ...). The key inside it is never stored: parameter, cookie and header names are attacker-chosen, and a bare query item such as `/?eyJhbGci...` arrives as a parameter name. Values are never stored.

Never stored: request or response headers, cookies, bodies, matched data, `logdata`, Coraza's `ErrorLog()` text, and the user agent. The access log already keeps the allow-listed headers under S-18, and an event can be matched to it by time and client address.

The module writes only through its own logger. Coraza's error callback is not used, because events are built from `tx.MatchedRules()` after processing. `TestEventsHoldNoSecrets` plants a canary in a query value, a bare query item, a header name, the `Authorization` and `Cookie` headers, the user agent and the body, in both modes, and finds it in no event. `FuzzClean` checks that a cleaned event always validates and never keeps a query value or a matched value.

`internal/redact` now holds the query masking (`redact.URI`), moved out of `internal/worker` so the event log uses the same rules without importing Caddy. `worker.RedactURI` remains as a thin wrapper.

### 7. Reading events: the `firewall.events` control method (S-31)

The control panel arrives in Phase 5, but the typed method arrives now:

- **Params.** `{"site_id": "", "before": "<RFC 3339 time>", "limit": 100}`. `site_id` is optional and must be a valid site id when set. `before` is optional, for paging back. `limit` runs from 1 to 500; zero means 100, and anything else is refused.
- **Result.** `{"events": [...], "skipped": n, "more": bool}`, newest first.
- **Reading.** The supervisor reads `firewall.log` and its rotated files (`firewall-*.log`), newest first. It reads only through its read-only view of the worker's log folder, never by a path from the request, and links are skipped. A line over 16 KiB is skipped, and so is a line that fails a strict decode into the event type (unknown fields refused) or fails validation. Every field is checked again as in section 6, and the `uri` must already be in its cleaned form. It stops after 64 MiB in all.
- **Trust.** A compromised worker can write fake events, so events are untrusted text for display (S-34) and never drive a decision.
- **Fuzzing.** The parser has a fuzz target, `FuzzParseLine`.

### 8. Per-site settings and weakening (S-14, S-32)

- **Config.** `site.firewall` gains `{"mode": "block" | "detect" | "off", "paranoia_level": 1-4}`. `Normalize` fills an empty mode with `block` and a zero level with `1`, and `Validate` treats both zero values as those defaults. Old configs therefore load as Block at level 1, which is the owner's default from day one. The schema version stays 1, because the new field is optional and old files decode unchanged.
- **Warnings.** `Warnings()` adds a standing warning for Off (S-14) and for Detect only (decision 4). It also adds a note for a Block-mode site whose body limit is above 16 MiB, that larger bodies are refused. Warnings appear in `status.get` and in every changing call's result.
- **Weakening (S-32).** Mode strength is Block above Detect only above Off. These need `confirm: true` and add `firewall` to the audit entry's `weakening` detail:
  - lowering a site's mode with `site.put`;
  - adding a site whose mode is below Block;
  - rolling back to a revision where any site's mode is lower than now, or a site absent now starts below Block.

  One confirmation covers every weakening in a change, and the message names them all. Lowering the paranoia level is not treated as weakening, because level 1 is the decided baseline.

### 9. The exposure check

`sitecheck.ScanExposure` walks a static site's folder through an `os.Root`. It never follows links or junctions, skips anything that is not a regular file or folder, and judges each name with the S-12 path rules, as the browser would request it.

- **Findings.**
  - Names the rules never serve are listed as `blocked_name`, and nothing under a refused folder is read: `.env`, `.git`, `*.key`, `*.pem`, `id_rsa`, `*.kdbx` and the rest of the S-12 list.
  - A file that would be served is listed as `private_key` if its first 4 KiB contains a PEM `PRIVATE KEY-----` marker (RSA, EC, DSA, OpenSSH, PGP, encrypted, PKCS#8) or a PuTTY key header, or starts with a KeePass signature.
  - A served file with the extension `.env` (`app/prod.env`) is listed as `env_file`.
- **Bounds.** At most 50,000 entries, a depth of 32, 4 KiB from each file, 200 findings and 30 seconds. A hit bound marks the report as incomplete, and so does a path the supervisor would refuse (control or bidirectional-override characters, over 1024 bytes), which is left out.
- **Where it runs.** In the web worker, which already has read access to every site folder (owner decision of 12 Nov 2026) and is the confined process meant to read untrusted content. The supervisor never reads site content.
  - The supervisor sends a new web-pipe message, `scan`, holding the canonical root and the site's `allow_well_known` choice.
  - The worker opens it with `sitecheck.OpenRoot`, which repeats every S-11 check, and answers `scanned` with the report or `failed`.
  - Both messages are validated for the web pipe only (SE-21): `scan` needs a valid root, and `scanned` needs a report whose kinds are a closed set and whose paths are relative and clean.
  - The pending-reply table is shared with loads. A load now succeeds only on an explicit `loaded`, which closes review finding SE-31.
- **When it runs.** On `site.put` for an enabled static site, and on `site.set_enabled` turning a static site on. `site.set_enabled` gains `confirm`.
  - **Served findings** need confirmation (decision 3). The answer is `confirmation_required`, naming up to 10 paths as text, and the confirmed change is audited with `exposed_files` in `weakening` and the count in `exposed`.
  - **`blocked_name` findings** come back as warnings, and the whole report as `exposure` in the result.
  - **A failed check refuses the change.** If the worker is not running the answer is `unavailable`; if the scan fails it is `invalid` with the worker's reason. A disabled site can still be saved without a check.
  - **Rollback** brings back folders that were checked when they were added and does not scan again.
- **What the report holds.** Relative paths, kinds and counts, with no file contents. The paths are names from the user's own folder, shown as text (S-34).

### 10. Memory against the job cap (S-21)

The web worker sets the Go runtime's soft memory limit to three quarters of its job cap (`debug.SetMemoryLimit(768 MiB)`) right after confining itself. The collector then works harder before a burst of inspected uploads could reach the cap.

Two measurements are recorded in `docs/SECURITY_CHECKLIST.md` under S-21:

- **In process (`worker` `TestFirewallMemory`).** Caddy runs eight sites, one for every mode and paranoia level. The test runs the attack set through each, then 16 concurrent 15 MB multipart uploads, with the same soft limit. It samples heap plus stack every 20 ms, records the peak, and fails above the soft limit. Every upload must end in a 200 with the whole body at the app, or a 503 from the body budget with `Retry-After`. The uploads go through Go's HTTP client with keep-alive, the client cloudflared uses towards the worker, and all of them send the same bytes. The first version wrote each upload as a raw `Connection: close` request, and the whole body before reading. That copied the 15 MB request once per upload, and it was flaky: for such a request Go's server closes at once when the firewall refuses the body unread, Windows resets the connection, and the reset can discard the 503 before the client reads it. A client like cloudflared's always gets the 503 (`TestRefusalBeforeBodyIsAnswered`: 16 concurrent refusals over three rounds; the raw client lost 27 of 640 refusals to resets, Go's client none). Measured on 15 Nov 2026 on the owner's PC with the first version: a peak of 458 to 471 MiB over three runs, but 419 to 867 MiB over later runs, depending on how many of the client's copies were alive at once. Measured again on 15 Nov 2026 with Go's client: a peak of 439 to 537 MiB over 40 runs, including the test's own client and upstream in the same process, and 43 to 75 MiB in use after GC; 12 uploads passed and 4 got 503 in every run.
- **On the installed system (`e2e` `TestFirewallOnInstalledSystem`, CI isolation job).** After the attack set and the same upload burst through the installed services, the test reads the confined web worker's peak committed memory (`PeakPagefileUsage`, the figure the job limit applies to) and fails above 75% of the cap. Measured in CI on 15 Nov 2026 (pull request 11, run 43704274901): 483 MiB of the 1024 MiB cap; 12 of the 16 uploads passed and 4 got 503 from the body budget.

### 11. Carried from the Phase 1–2 review backlog

Open items in code this phase changes (`worker/guard.go`, the handler chain, `worker/logfilter.go`, `sitecheck`, the web pipe):

- **R-13.** The guard serves origin-form request targets only and answers anything else with 400. cloudflared, the only client, sends nothing else, and in an absolute-form target Go takes the host from the target and drops the Host header, so S-06 could not judge it.
- **R-19.** The guard refuses a raw `#` in the request target with 400. CRS rule 920610 also flags it.
- **SE-26.** The zero `Verdict` is a refusal, not `Allow`, and the guard's mode is an explicit switch that refuses unknown modes.
- **SE-24.** `CheckRoot` and `OpenRoot` refuse a `Locations` value with an empty required field instead of switching that S-11 rule off.
- **SE-31.** A load is marked good only on an explicit `loaded` reply (section 9).
- **GOE-14.** `FuzzURI` places a canary as a query value and a bare item and checks it never survives, and that masking is idempotent. The event log depends on it.
- **GOE-15.** `TestStripForwardedTable`, `FuzzStripForwarded` and `TestGuardRefusesTargets` test the guard's header stripping and request-target handling directly.

Left in the backlog because this phase does not change that code:

- **SE-25**, the typed request path, a refactor of `sitecheck/path.go`;
- **R-12b**, reparse points in `RootFS`. The exposure scan skips them itself.

## Consequences

- **Dependencies.** New direct dependency `github.com/corazawaf/coraza/v3` v3.8.1. `golang.org/x/sync` becomes direct (`semaphore`). The release binary links 13 further modules through Coraza, listed in `docs/DEPENDENCIES.md` from `go version -m`: Apache-2.0, MIT, BSD-2-Clause and BSD-3-Clause. `govulncheck` finds nothing. The CRS rules are data, not code, and are recorded there under their own heading.
- **Build tag.** Every Go command needs `-tags no_fs_access` or the `GOFLAGS` equivalent; the compile guard makes forgetting it loud.
- **Response rules.** CRS outbound rules (data-leak detection) are not used. If they are ever wanted, they need response buffering and a separate memory budget, and Defender's reaction to `web-shells-php.data` must be dealt with first.
- **Size limits.** In Block mode, sites cannot take bodies over 16 MiB (decision 5), or over 128 KiB of text in forms, JSON or XML (decision 6). Raw bodies of other types (`application/octet-stream`) are inspected as text by CRS, so they fall under the 128 KiB limit too; CRS also blocks content types outside its allow list at paranoia level 1. Detect only or Off, both confirmed and warned, are the way out for a site that needs more.
- **Methods.** `PUT`, `PATCH` and `DELETE` are allowed by the rule set's method policy on every site. They are still inspected by every other rule.
- **503 under load.** The body budget and the inspection slots can answer 503 under heavy upload load or attack; the access log records it.
- **The Coraza override.** It replaces two transformations for the whole process. It must be removed or re-checked whenever Coraza is upgraded; `TestNormalisePathKeepsSlashes` would show a change in behaviour.
- **Untrusted events.** Events written by a compromised worker cannot be told from real ones. They are display data only.

## Action items

1. [x] Owner: accept or amend this record. Accepted 15 Nov 2026.
2. [x] Build it, with the firewall attack and normal request sets from `docs/TEST_PLAN.md` (`waf` `TestAttackSetBlocked`, `TestNormalSetPasses`; `worker` `TestFirewallInChain`), fuzz targets for every new parser (`FuzzParseLine`, `FuzzClean`, `FuzzURI`, `FuzzStripForwarded`; `FuzzDecodeWorkerMsg` and `FuzzDecodeRequest` gained the new messages), and the memory measurements.
3. [x] CI: `GOFLAGS` with `no_fs_access`, the `check-crs` step, the firewall checks in the isolation job.
4. [x] Record S-14 (and the S-18, S-21, S-31, S-32 additions) in `docs/SECURITY_CHECKLIST.md` with test names and run numbers. (pull request 11, run 43704274901)
5. [ ] Optional, owner's call: comment on Coraza issue 1140 with the reproduction, since this is public.

# ADR-0006: Supervisor, named pipes, stores and service setup

**Status:** Accepted by the owner on 12 Nov 2026
**Date:** 12 Nov 2026
**Deciders:** Owner

## Context

Phase 2 builds the supervisor and everything that keeps the web worker's internet-facing code away from secrets and settings (plan section 4, S-20 to S-24, S-30 to S-32, S-35, S-36, S-40, S-41). ADR-0001 fixed the process model: three services under three virtual accounts, talking only over named pipes. This record fixes the details: pipe protocol and ACLs, how each side proves who it is talking to, the control API, the stores on disk, worker self-limits, and what the Phase 2 `setup install` does.

Owner decisions taken on 12 Nov 2026:

- Admin-level tests (services, accounts, ACLs) run on GitHub's Windows runners only. Nothing admin-level runs on the owner's PC in this phase.
- The control pipe admits SYSTEM, elevated Administrators and the account that ran `setup install`, and nobody else.
- When a site is added, the control panel, running as the user who owns the folder, grants `NT SERVICE\SoireeHostWeb` read access to it. The supervisor checks the folder itself before serving it.

  The supervisor needs to open the folder for that check, and a folder inside a user profile admits no service account. So the control panel adds two entries with `winsec.GrantSiteAccess`:
  - `NT SERVICE\SoireeHostWeb`: read and list, inherited by everything inside;
  - `NT SERVICE\SoireeHost`: read-attributes and read-permissions on the folder itself only. This is enough to resolve its real path and read its access list, but not to read any file.

  Added after the Phase 2 code review.

## Requirements

Functional:

- The control panel reads status and config, changes sites, sets the tunnel token, reads the audit log and rolls config back, all through `\\.\pipe\soireehost-control-<random>`.
- The supervisor stores config and secrets, starts both workers, hands the web worker its Caddy config and the tunnel launcher its token, restarts a worker that dies, and stops both before it stops.
- A worker exits when its pipe to the supervisor closes.

Non-functional:

- One supervisor, at most a handful of control-panel connections, config changes a few times a day. Latency targets are human: a change applies within a second or two.
- Every message from outside the supervisor is untrusted until decoded strictly and validated.
- No TCP port anywhere in the control path.

## Design

```
control panel (user) ──\\.\pipe\soireehost-control-*──▶ supervisor (NT SERVICE\SoireeHost)
                                                       │  config\  secrets\  logs\audit\
                         \\.\pipe\soireehost-web-*  ◀──┤  (server side, owner = supervisor SID)
web worker (NT SERVICE\SoireeHostWeb) ─────client──────┘
tunnel launcher (NT SERVICE\SoireeHostTunnel) ──client── \\.\pipe\soireehost-tunnel
```

The supervisor is the server of all three pipes. Workers and the control panel are clients.

### Pipe protocol

Byte-mode pipes. Each message is a 4-byte big-endian length followed by that many bytes of JSON, at most 1 MiB. Decoding is strict: unknown fields, trailing data, wrong types and oversized frames end the connection.

Control requests are `{"id": n, "method": "...", "params": {...}}`; responses are `{"id": n, "result": {...}}` or `{"id": n, "error": {"code": "...", "message": "..."}}`. One request at a time per connection. Error codes are a closed set (`invalid`, `not_found`, `confirmation_required`, `forbidden`, `unavailable`, `internal`); messages are plain sentences for the control panel to show as text (S-34).

Worker messages are a closed set of types: supervisor to worker `load` (Caddy JSON or tunnel token) and `stop`; worker to supervisor `hello` (role and version), `loaded`, `failed` (reason) and `status`.

### Who is on the other end

| Check | How | Defends against |
| --- | --- | --- |
| Pipe DACL (control) | `SYSTEM`, `Administrators` and the installing user's SID get read and write-data (`0x12008b`), never `GENERIC_WRITE`, whose append bit on a pipe is the right to create a new pipe instance; `NETWORK` (S-1-5-2) is denied; nothing else | Other local users (S-30), remote access, a client standing up a rogue instance of the control pipe |
| Pipe DACL (workers) | Only that worker's service SID (`NT SERVICE\SoireeHostWeb` or `...Tunnel`) gets read and write-data | Any other local process |
| Remote clients | `PIPE_REJECT_REMOTE_CLIENTS` on every instance, plus the `NETWORK` deny | SMB access to the pipe |
| Caller identity, every connection | `ImpersonateNamedPipeClient`, read the thread token's user and groups, `RevertToSelf`. Clients connect at `SecurityIdentification`, so no impersonation privilege is needed and the supervisor cannot act as the caller. The SID must be the installing user's, `SYSTEM`'s, or carry an enabled Administrators group | Anything the DACL let through by mistake |
| Server identity, every client | The supervisor creates each pipe with `FILE_FLAG_FIRST_PIPE_INSTANCE` and sets its own service SID as owner. Clients read the pipe's owner with `GetSecurityInfo` and refuse to send anything unless it is `NT SERVICE\SoireeHost`'s SID (S-1-5-80-…, computed from the service name). Only a process running as that service can own the object | Pipe squatting: a local program that creates the pipe name first to collect the tunnel token or feed a worker a hostile config. The names carry 128 random bits chosen at every start (review finding DR-1, 12 Nov 2026): any user may create a named pipe, so a fixed name could be held while the supervisor restarts and keep it from starting. The supervisor writes each name to a pipe-name file in a folder of its own under `config` (`pipe-control\control.pipe`, `pipe-web\web.pipe`, `pipe-tunnel\tunnel.pipe`). Setup creates each folder with inheritable permissions that let only the pipe's clients, SYSTEM and Administrators read the file, and the supervisor writes it as a plain new file, which it owns and which takes those permissions (it cannot pass a descriptor of its own: the OWNER RIGHTS entry refuses any descriptor given at creation); clients open that known path (SeChangeNotifyPrivilege bypasses the folder's traverse check), check the file's owner, and dial that exact name, so they never search the pipe namespace and decoys cannot get in the way |

If the supervisor cannot create a pipe because the name already exists, it logs that someone else holds the name and refuses to start.

### Control API (Phase 2 set)

| Method | Does | Notes |
| --- | --- | --- |
| `status.get` | Version, supervisor state, each worker's state and last error, config warnings | |
| `config.get` | Current config | Never contains secrets (S-40) |
| `config.history` | Revisions with time, actor and summary | |
| `config.rollback` | Restore a revision | Validated again; audit entry |
| `site.put` | Add or replace a site | Full validation, root resolved with `sitecheck.CheckRoot` and the canonical path stored; checks from the folder's access list (`winsec.GrantsRead`) that the web worker's account, or a group every service account belongs to, can read it, and says how to fix it if not; `allow_lan` needs `confirm: true` (S-32) |
| `site.remove`, `site.set_enabled` | | Audit entry |
| `secret.set` | Set or replace the tunnel token | Write-only (S-35); confirmation required when one is already set (changing the tunnel is S-32) |
| `secret.status` | Which secrets are set, and when | No values, ever |
| `audit.list` | Page through the audit log | Includes the result of a chain check |

No method takes a command line, and the only path any method accepts is a site folder to publish, which is resolved and checked, never written (S-31). Weakening actions return `confirmation_required` unless the request says `confirm: true`, and every accepted change writes an audit entry naming the caller's SID (S-32).

### Stores (all under `%ProgramData%\SoireeHost\`)

- **Config (S-41).** `config\current.json` holds `{revision, saved_at, actor, summary, config}`. A change is validated, written to a temporary file in the same folder, flushed, and moved over `current.json` with `MoveFileEx(REPLACE_EXISTING | WRITE_THROUGH)`. The previous file is copied to `config\history\<revision>.json` first, and the ten newest history files are kept. The supervisor remembers the last revision the web worker loaded. If the worker reports `failed` for a new revision, the supervisor restores the last good one, reloads it, and returns the worker's reason to the caller.
- **Secrets (S-40).** `secrets\<name>.bin` holds `CryptProtectData` output under the supervisor's account (not machine scope), with fixed per-purpose entropy and `CRYPTPROTECT_UI_FORBIDDEN`. `secrets\<name>.json` holds only the time it was set. The value never appears in config, logs, audit entries or errors.
- **Audit (S-36).** `logs\audit\audit.log` is JSON lines: `{seq, time, actor, action, detail, prev, hash}`, where `hash` is the SHA-256 of the entry without `hash`, and `prev` is the previous entry's hash. The file is opened for append only. At start, and on every `audit.list`, the chain is verified; a break is reported, not repaired. `detail` never contains secret values.

### Worker self-limits (S-21, S-24)

At the start of every role, `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`. The control panel's WebView2 loads under it unchanged (checked on 12 Nov 2026: the window opens and `msedgewebview2.exe` starts), so no exception for the WebView2 runtime folder is needed.

Each worker, before it touches the network or its pipe:

1. Removes every privilege except `SeChangeNotifyPrivilege` from its token.
2. Joins a new job object with kill-on-close, one active process, all UI restrictions, and a memory cap (1 GiB for the web worker, 256 MB for the tunnel launcher; cloudflared gets its own job in Phase 3).
3. Turns on the child-process mitigation policy (`ProcessChildProcessPolicy`, no child processes). The tunnel launcher skips this one step, because it must start cloudflared; its job allows exactly two processes instead.

A worker that cannot apply a limit exits instead of running unconfined.

### Services and setup (Phase 2 subset)

`soireehost.exe setup install`, run elevated:

- Copies itself to `%ProgramFiles%\SoireeHost\soireehost.exe`.
- Creates `%ProgramData%\SoireeHost\{config,secrets,logs\audit,logs\web,logs\tunnel,updates}` with protected (non-inherited) DACLs:

  | Folder | Access |
  | --- | --- |
  | `config` | SYSTEM full, Administrators full, supervisor modify |
  | `secrets` | SYSTEM full and owner, supervisor modify; no one else (the S-22 check allows only these two) |
  | `logs\audit` | SYSTEM full, Administrators read, supervisor append and read |
  | `logs\web` | SYSTEM full, Administrators read, supervisor read, web worker modify |
  | `logs\tunnel` | SYSTEM full, Administrators read, supervisor read, tunnel launcher modify |
  | `updates` | SYSTEM full, Administrators read, supervisor modify |

- Registers the three services:
  - **Binary path.** Quoted, with the role as the argument.
  - **Accounts.** `NT SERVICE\SoireeHost`, `...Web` and `...Tunnel`, with no password.
  - **SID type.** Restricted service SID.
  - **Privileges.** Required privileges limited to `SeChangeNotifyPrivilege`.
  - **Start type.** Supervisor automatic, with recovery restarts and pre-shutdown notification. The two workers manual.
  - **Worker service security descriptors.** The supervisor's SID may start, stop and query; Administrators and SYSTEM have full control; interactive users may only query (S-20).
- Creates each missing folder with its final descriptor in the same call (`CreateDirectory` with security attributes), so a new folder never carries `%ProgramData%`'s permissions, even briefly. Otherwise a standard user could race setup to plant a file such as `control-users.json` (Phase 2 security review).
- Gives every folder an explicit owner: Administrators, or SYSTEM for `secrets`.
- Writes `control-users.json` as a new file, so it always takes the config folder's descriptor.
- Refuses to install over an existing `%ProgramData%\SoireeHost` that is a link or junction, that another account owns, or that holds any link, hard-linked file or entry owned by anyone but Administrators, SYSTEM or a SoiréeHost service. A standard user can create folders in `%ProgramData%`, so one could pre-create this folder with a planted config before the first install. Whether the folder exists is decided by creating it, so no gap is left between a check and the creation (DR-8).
- Refuses to install from a folder that anyone but the person running setup, Administrators, SYSTEM or TrustedInstaller could change, and holds the program open without write or delete sharing from the start, copying from that handle (DR-9).
- Records the installing user's SID in `config\control-users.json`, which the supervisor reads and only setup writes.

`setup uninstall` stops and deletes the three services and removes the program folder. With `--purge` it also removes `%ProgramData%\SoireeHost`. It first waits for every service process to exit, and keeps the folder if one does not (DR-7). It then takes ownership of every entry by walking the tree through open handles: each entry is opened relative to its parent's handle without following reparse points, and its descriptor is set on that handle, so a junction swapped in during the walk is never entered (`winsec.WalkTree`). It skips re-permissioning any file with more than one hard link, so a link planted in a log folder cannot carry the change to its target, and simply unlinks those.

Phase 6 adds:
- the Windows prompt;
- the Apps entry;
- firewall rules (in Phase 3);
- repair;
- self-delete;
- unpacking cloudflared (in Phase 3).

### Lifecycle

1. **Supervisor start.**
   1. Verify the folder ACLs; refuse to run if config or secrets are writable by anyone but SYSTEM, Administrators and itself (S-22).
   2. Verify the audit chain.
   3. Load the config.
   4. Create the three pipes.
   5. Start both worker services through the service control manager.
   6. Wait up to 30 seconds for each to say `hello`.
   7. Send each its `load`.
2. **A worker's pipe closes, or the worker service stops.** Mark it down, restart it with backoff (1, 2, 4 … 60 seconds), and record each restart in the worker log.
3. **Supervisor stop or pre-shutdown.** Send `stop` to both workers, stop both services, wait up to 10 seconds, then exit.
4. **Supervisor crash or kill.** The pipes close, both workers see end-of-file and exit; Windows recovery restarts the supervisor, which starts them again.

## Trade-offs

- **Length-prefixed JSON over a pipe, rather than gRPC or protobuf.** JSON reuses the strict decoding already used for config and needs no new dependency or code generator. The API is small, so a schema compiler would buy little.
- **Supervisor as the server of every pipe.** Workers never accept a connection, and a single owner check on the client side answers "is this really the supervisor". The cost: a worker started before the supervisor has its pipe up fails and is retried, which only the supervisor does anyway.
- **Identification-level impersonation, rather than reading the client's process token.** A non-admin service cannot open another user's process token. Identification level gives the SID and groups without the right to act as the caller.
- **The control panel grants folder access (owner decision).** It avoids a Windows prompt per site, because only the folder's owner can change its ACL without elevation. The supervisor still checks, through `sitecheck.CheckRoot`, everything that S-11 and the blocked-folder rules require. A folder the user does not own needs the user to fix access themselves; the error says how.
- **The installing user is the elevated token's user.** With over-the-shoulder elevation (a different admin types their password), that admin is recorded instead of the desktop user. Accepted for version 1; rerunning setup from the right account fixes it.

## Revisit later

- Several control-panel users picked at install (owner chose installing user only for now).
- AppContainer for the web worker (ADR-0001).
- A second machine-scope DPAPI key for backups (Phase 6/7, with backup export).

## Action items

1. [x] Owner: accept or amend this record. Accepted 12 Nov 2026.
2. [x] Phase 2: CI job on an admin runner that installs, runs the isolation checks, and uninstalls. Green on 12 Nov 2026 (run 43281534909).

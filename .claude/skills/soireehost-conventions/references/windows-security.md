# Windows security patterns in SoiréeHost

The code lives in `internal/winsec`; the design and its reasons are in `docs/adr/0006-supervisor-ipc-and-stores.md`. Use these helpers rather than calling the Windows API from other packages, so each lesson below stays in one place.

## Identities

- Service SIDs come from `winsec.ServiceSID(name)`, which computes `S-1-5-80-…` from the service name (SHA-1 of the upper-case name in UTF-16LE). It works before the service exists; `LookupAccountName` does not.
- A virtual service account's token user is its service SID, so a service can name itself as owner of an object it creates (for example a pipe, with `O:<sid>` in the SDDL).
- The services run with `SERVICE_SID_TYPE_RESTRICTED`, which makes their tokens write-restricted: a write is allowed only if both the normal SIDs and the restricting SIDs (the service SID, Everyone, write-restricted) are granted it. Grant writes to the service SID itself, not to a group it belongs to.
- Required privileges are trimmed to `SeChangeNotifyPrivilege`, so a service cannot impersonate. Pipe callers are identified at Identification level, which needs no privilege.
- Under UAC an unelevated administrator's token carries Administrators as deny-only. Code that admits "Administrators" admits only elevated processes; name the installing user's SID explicitly where an unelevated user must get in.

## Descriptors

Builders are in `winsec/sddl.go`. Conventions:

- Every folder descriptor is protected (`D:P`) and carries `(A;OICI;RC;;;S-1-3-4)`, an OWNER RIGHTS entry that limits whoever creates a file to reading its permissions. Side effect: even the folder's creator cannot change its descriptor later without SeRestorePrivilege, which is why setup uses `ForceSDDL`.
- Setup prefixes an explicit owner: `O:BA` for everything, `O:SY` for `secrets`.
- SDDL access masks are either right codes concatenated (`FRFW`) or one hex number. `FR|0x2` is not valid; write `0x12008b`.
- Masks in use: `0x1301bf` modify; `0x12008d` read and append (file); `0x12008b` read plus bit 0x2, which means add-file on a folder and write-data on a pipe (so the same number serves the audit folder and every pipe client); `0x1200a9` read and traverse; `0x120080` read-attributes and read-permissions.
- `winsec.CheckWriters(path, allowed...)` is the S-22 check: it fails if any allow entry with a write right names a SID outside `allowed`, if the owner is outside `allowed`, if the DACL is missing, or if an entry type is unexpected.
- `winsec.GrantsRead(path, sids...)` answers "can this account read the folder" from the DACL alone, for accounts we cannot impersonate (the web worker). Pass `winsec.WorkerGroups(webSID)` so access through Users, Authenticated Users, Everyone or SERVICE counts.
- `winsec.GrantSiteAccess(path, web, supervisor)` is what the control panel runs, as the folder's owner, when a site is added: read and list for the web worker (inherited), and read-attributes plus read-permissions on the folder only for the supervisor (enough to resolve and inspect it, not to read files). Without the supervisor entry, folders inside a user profile cannot be published at all.

## Creating and changing folders

| Need | Use | Why not the obvious call |
| --- | --- | --- |
| New protected folder | `winsec.CreateFolderSDDL(path, sddl)` | `MkdirAll` then set leaves the parent's permissions on it for a moment |
| Change an existing descriptor | `winsec.ForceSDDL(path, sddl)` after `winsec.EnablePrivileges("SeRestorePrivilege", "SeTakeOwnershipPrivilege")` | `SetSecurityInfo` and `SetNamedSecurityInfo` propagate down the tree without the privilege and fail at locked children |
| Take back a tree to delete it | `winsec.ForceSDDLUnlessLinked` per entry, walking top-down | A file with several hard links would carry the new descriptor to its other ends |
| Test fixture with fixed descriptor | `winsec.SetFolderSDDL` (applies the owner too if the SDDL names one) | — |

`ForceSDDL` opens with `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`, so it never follows a junction, and writes with `SetKernelObjectSecurity`, which changes that one object only. Protection comes from the descriptor's own `D:P`.

Before installing over an existing `%ProgramData%\SoireeHost`, setup refuses one that is a link or junction, or that is owned by anyone but Administrators or SYSTEM: standard users can create folders in `%ProgramData%`.

## Files

- Append-only: `CreateFile(path, FILE_APPEND_DATA|SYNCHRONIZE, FILE_SHARE_READ, nil, OPEN_ALWAYS, …)` then `os.NewFile`. `FlushFileBuffers` works on such a handle.
- Atomic replace: `fsutil.WriteAtomic` (temporary file in the same folder, flush, `MoveFileEx` with `REPLACE_EXISTING | WRITE_THROUGH`). The new file takes the folder's inheritable entries.
- A file setup writes into a protected folder is deleted and created anew (`O_CREATE|O_EXCL`), so it takes the folder's descriptor rather than keeping an older file's.

## Named pipes

- Server: `ipc.Listen(path, sddl)` (go-winio). The first instance is created exclusively; a squatter on the name makes the supervisor refuse to start rather than share it. Remote clients are always rejected, and descriptors also deny NETWORK.
- Client: `ipc.Dial(ctx, path, wantOwnerSID)` dials at Identification level with `winsec.PipeClientAccess` and refuses the pipe unless its owner is the expected SID.
- Server-side identity: `winsec.PipeCaller(handle)` on a locked OS thread, after the first frame has been read. It panics if `RevertToSelf` fails.
- Frames are 4-byte big-endian length plus strict JSON, capped at 1 MiB; one malformed request ends the connection.

## Services

- `internal/svcrun` runs a role as a service (see SKILL.md rule 1). On failure it writes the error to the Application event log under the service's name; setup registers the three sources and uninstall removes them.
- The supervisor starts and stops workers through `svcrun.SCM`, which asks for `SC_MANAGER_CONNECT` and only `SERVICE_START`, `SERVICE_STOP` or `SERVICE_QUERY_STATUS`, matching the worker service descriptors.
- `mgr.CreateService` quotes a path with spaces itself; `UpdateConfig` needs the quotes added by hand (`setup.quote`).
- `SERVICE_REQUIRED_PRIVILEGES_INFO` is not defined in x/sys: pass a struct holding one pointer to a double-null-terminated UTF-16 string.

## Confinement

`winsec.Confine(winsec.Limits{…})` drops every privilege but SeChangeNotifyPrivilege, joins a kill-on-close job with process, memory and UI limits, and (for the web worker) turns on the no-child-process mitigation. The tunnel launcher allows two processes and no mitigation, because it starts cloudflared. A worker that cannot confine itself exits.

## Caddy specifics

- Admin API off and config autosave off (`admin.disabled`, `admin.config.persist: false`); TLS app with `disable_storage_clean` and `disable_storage_check`, so nothing is written to the service profile; HTTP/1 only, so no UDP socket.
- Caddy's default `Server` header is set before routes run; error routes in the generated config add the security headers to every error response.
- `caddy.Load` is process-global; `worker.LoadJSON` runs the listener self-check (S-01) after every load.

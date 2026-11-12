---
name: soireehost-conventions
description: Conventions, pitfalls and the working process for the SoiréeHost repository (Windows 11 service app in Go with embedded Caddy, named pipes, DPAPI, folder ACLs, a Svelte control panel). Use it before writing or changing any code, test, CI job or setup step in this repository, and whenever starting, reviewing, finishing or recording a phase of docs/PLAN.md. It matters most for anything touching Windows security descriptors, services, named pipes, Caddy, the setup role, or tests that need administrator rights, even when the task looks small.
---

# SoiréeHost conventions

What Phases 1 and 2 taught, so later phases do not relearn it. `CLAUDE.md` and `docs/PLAN.md` are the brief and win over this skill; the decision records in `docs/adr/` explain the design. This file says how to work inside that design without falling into the holes we already found.

Read the reference that matches the task:

- `references/windows-security.md`: security descriptors, folder creation, pipes, services, confinement. Read before touching `internal/winsec`, `internal/ipc`, `internal/setup`, `internal/svcrun` or any code that creates folders or files under `%ProgramData%\SoireeHost`.
- `references/testing.md`: where each kind of test may run, the CI isolation job, fuzzing, lint rules and their suppressions. Read before writing tests or CI.

## Where things live

| Package | Holds | Notes |
| --- | --- | --- |
| `internal/config` | Schema, pure validation, versioned store | Validation never touches disk or network, so it can be fuzzed |
| `internal/sitecheck` | Request path rules, static root checks | `CheckRoot` resolves through the real path (junctions, 8.3 names) |
| `internal/worker` | Embedded Caddy, its modules, config builder | Caddy is process-global: one worker per process |
| `internal/winsec` | SIDs, SDDL builders, ACL checks, confinement, pipe identity | All Windows security primitives go here, not in callers |
| `internal/ipc` | Frames, typed control API, pipe server and client | Strict decoding everywhere |
| `internal/supervisor` | Service core, control handlers, worker managers | `ServiceControl` interface lets tests run workers in-process |
| `internal/secrets`, `internal/audit` | DPAPI store, hash-chained audit log | Secret values never appear in errors, logs or audit details |
| `internal/svcrun` | Running a role as a Windows service; SCM client | Must never import Caddy (see below) |
| `internal/setup` | Elevated install and uninstall | Runs only on CI runners or a VM, never on the owner's PC |
| `internal/e2e` | Tests against an installed system | Build tag `e2e`, CI isolation job only |
| `internal/testutil` | Test helpers (junctions, publishable site folders) | Imported only from tests |

## Rules that are easy to break

1. **Never call `svc.Run` from `golang.org/x/sys/windows/svc`.** Caddy's own `init()` calls it whenever the process runs as a service. That package keeps its handler in one package-level variable, so the last `svc.Run` call wins, and a process can start the dispatcher only once. `internal/svcrun` speaks the service protocol directly and starts the dispatcher from its `init()`, which the Go spec runs before Caddy's because `github.com/TheAlsaadi/...` sorts before `github.com/caddyserver/...`. Keep `svcrun` free of any Caddy import; `TestInitRunsBeforeCaddy` guards both conditions. `svc.IsWindowsService()` is fine to call.
2. **Nothing in an `init()` may wait for a callback from Windows.** The Go runtime holds callbacks from foreign threads until every `init()` has returned, so such a wait deadlocks until its timeout.
3. **Create protected folders in one call:** `winsec.CreateFolderSDDL`. `os.MkdirAll` followed by setting a descriptor leaves a window in which the folder carries its parent's permissions; under `%ProgramData%` that lets a standard user plant files.
4. **Change an existing descriptor with `winsec.ForceSDDL`**, never `SetSecurityInfo` or `SetNamedSecurityInfo`. Those re-apply inheritance to everything below and fail at the first child that admits no administrators (the secrets folder), or silently change files you did not mean to touch.
5. **Name the owner in every descriptor setup applies.** An elevated administrator's new objects are owned by Administrators; the secrets folder must be owned by SYSTEM, because the S-22 check allows only SYSTEM and the supervisor there.
6. **Open append-only files with `CreateFile(FILE_APPEND_DATA | SYNCHRONIZE)`** (see `audit.openAppendOnly`). `os.OpenFile` with `O_APPEND` also asks for write-attributes, write-EA and read-permissions, which an append-only ACE does not grant; the first open of a new file still works, which hides the bug until the second write.
7. **Pipe clients ask for `winsec.PipeClientAccess` (`0x12008b`), and descriptors grant that, never `GRGW`.** On a pipe, the append bit inside generic write is `FILE_CREATE_PIPE_INSTANCE`, which would let a client stand up a rogue instance of the server's pipe.
8. **Every pipe client checks the pipe's owner** (`ipc.Dial` with the supervisor's service SID) before sending anything; the server identifies the caller after the first frame (Windows refuses earlier) at Identification level.
9. **Load DLLs only with `windows.NewLazySystemDLL`.** Every role calls `winsec.RestrictDLLSearch` first thing in `main`; WebView2 works under it.
10. **Caddy keeps a log file open for the life of the process** once it has written to it, shared across reloads. Tests must use one log folder per test run (cleared in `TestMain`), never `t.TempDir()`, whose cleanup would fail.
11. **`t.TempDir()` is under `AppData`, which S-11 refuses to publish.** Static site fixtures come from `testutil.SiteDir`.
12. **Never write a secret where it can be printed.** Types that carry one (`ipc.WorkerMsg`, `ipc.SecretSetParams`) implement `String`/`GoString` that redact it; keep that true for any new one, and keep canary sweeps in tests.

## How a phase runs

1. Read the phase in `docs/PLAN.md` and the plan's section 12 decisions it needs; ask the owner those, and anything that needs administrator rights on their PC (machine rule), with `AskUserQuestion` before designing.
2. Check every version the phase uses against the official release page or the Go module proxy; prefer the newest stable release; record new dependencies in `docs/DEPENDENCIES.md` with reason, licence and a `govulncheck` run.
3. Write the design as a decision record (`docs/adr/NNNN-title.md`, status Proposed) before the code. The plan's `engineering:system-design` and `engineering:architecture` skills are listed for this.
4. Build with tests alongside. Run the full local check set from `references/testing.md`, then the phase's fuzz targets for 10 minutes each in the background.
5. Before committing: the pre-merge code review (`code-review` at `high`) and the end-of-phase security review (`security-review`, or a security-focused subagent), and fix what they find, including findings just under their reporting bar when they are real.
6. Commit on a branch, never on `main` directly for a phase. No AI attribution of any kind in commits or pull requests. Open the pull request with the GitHub CLI at `C:\Program Files\GitHub CLI\gh.exe` (signed in as the owner), then bind it in the app and offer Auto-fix.
7. Read CI failures with `gh run view <id> --log` or `--log-failed`; the isolation job prints the services' event-log entries on failure.
8. When CI is green, record it: `docs/SECURITY_CHECKLIST.md` rows (test names and run number), the phase checkboxes in `docs/PLAN.md`, `docs/TEST_PLAN.md`, the status in `CLAUDE.md`, and the ADR status once the owner accepts it.
9. **Before pushing anything after the pull request was opened, check whether it has been merged** (`gh pr view N --json state`). A commit pushed to an already-merged branch never reaches `main`; it then has to be cherry-picked and the branch looks unmerged on GitHub.
10. Report, then wait. The next phase starts only when the owner says so.

## Editing gotchas in this environment

- Go source with backslash escapes (`\u003e`, `\\`) gets mangled when it passes through shell heredocs or `sed`, and the Edit tool turns `\u003e` into `>`. Write such files with the Write tool, or build the string at run time.
- `gofmt` re-aligns table-driven test maps after an edit, so the next exact-match replacement on those lines fails; anchor on a regular expression or re-read the file.
- The owner's PC runs PowerShell 5.1 and Git Bash; Go is at `%LOCALAPPDATA%\Programs\go\bin`, tools at `%USERPROFILE%\go\bin`. Prefix commands with `export PATH="$LOCALAPPDATA/Programs/go/bin:$USERPROFILE/go/bin:$PATH"` in Bash.

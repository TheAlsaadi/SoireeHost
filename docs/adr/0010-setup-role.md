# ADR-0010: The setup role: install, repair, update, uninstall

**Status:** Accepted by the owner on 19 Nov 2026
**Date:** 19 Nov 2026
**Deciders:** Owner

## Context

Plan Phase 6 completes the setup role of `soireehost.exe`. It must:

- install by copying itself to `%ProgramFiles%\SoireeHost\`, unpacking cloudflared, registering the three services, setting ACLs and firewall rules, and adding the Settings > Apps entry;
- repair;
- apply a verified update with rollback;
- uninstall, removing its own executable.

ADR-0006 built the Phase 2 subset (services, folders, `control-users.json`, the DR-7 to DR-9 protections), and ADR-0007 added cloudflared unpacking and the firewall block rules. ADR-0004 decides how an update reaches the staging folder.

Constraints:

- **One elevation, one action.** Setup must not stay running, must not run without the Windows prompt, and must not act on a file it has not verified itself (plan section 4).
- **SignPath's conditions** (to apply after the first release): warn before changing system configuration, and provide an uninstaller.
- **The binary is a GUI-subsystem program** (`-H windowsgui`), so setup started from the prompt has no console. Whatever it reports must reach the control panel another way.
- **Machine rule.** Nothing here runs with administrator rights on the owner's PC. It is tested in the CI isolation job, and once by hand in a VM (owner decision, 16 Nov 2026).

### Owner decisions (16 Nov 2026)

- One click and the Windows prompt for updates (S-64).
- Uninstall asks whether to remove settings, the tunnel token and logs; the default keeps them. Program files, services, firewall rules and the Apps entry are always removed.
- The "under 5 minutes from download to a live site" check is timed in CI on every pull request and repeated once by the owner in a VirtualBox VM running the Windows 11 evaluation (installing VirtualBox needs the owner's go-ahead).

## Decision

### Commands

| Command | Started by | Runs from | Does |
| --- | --- | --- | --- |
| `setup install` | The install window (below), or an elevated prompt | The downloaded file | Fresh install, or an upgrade over an older install |
| `setup repair` | Repair in the control panel; the second half of an update | The installed binary only | Every install step except the copy |
| `setup apply-update` | Install in the control panel | The installed binary only | ADR-0004's second check, swap, start check, rollback |
| `setup uninstall [--purge]` | The uninstall window (below), or an elevated prompt | The installed binary or any copy | Removal; `--purge` also removes `%ProgramData%\SoireeHost` |

**Rules for every command:**

- **Arguments.** None takes a path or version argument. Each acts on fixed folders (`setup.DefaultLayout`) and refuses any extra argument.
- **Installed binary only.** `repair` and `apply-update` refuse unless the running file is `%ProgramFiles%\SoireeHost\soireehost.exe`: only the installed, already-trusted binary may act on an install.
- **One at a time.** Every command first takes a named mutex, `Global\soireehost-setup`, created with a descriptor that admits only SYSTEM and Administrators. If the mutex exists and is owned by anyone else, setup refuses. Standard users lack `SeCreateGlobalPrivilege`, so they cannot squat it.
- **Interrupted updates first.** Every command except a fresh install finishes or reverses an interrupted update before it does anything else (see the journal below).
- **Reporting.**
  - Each failure maps to one closed-set exit code (`setup.Code`). The control panel turns the code into a sentence from the message catalogue.
  - Setup writes its detail to the Application event log under the source `SoireeHost Setup`, which it registers.
  - Setup never prints secrets. If it was started with redirected standard error (CI, or an elevated terminal), it also writes there.

### The install window and the first run

When `soireehost.exe` starts as the control panel (no arguments), it checks two things: whether the `SoireeHost` service exists, and whether the running file is the installed one.

- **Not installed.** The control panel opens a small window, Install SoiréeHost. It says what will change, as SignPath requires: the program folder, three Windows services, two firewall rules that block inbound traffic, the data folder, the Settings > Apps entry, and starting at sign-in. It has one button, Install. The button raises the Windows prompt with `ShellExecuteExW` (verb `runas`) for this same file with the fixed arguments `setup install`, and waits for it. On success it starts the installed copy, unelevated, and exits. On failure it shows the code's sentence and keeps the window open.
- **Installed, but another copy runs.** It offers to open the installed copy. If the copy is newer than the installed version, the window instead offers to upgrade to that version, which is `setup install` again.
- **No ShellExecute from setup.** The installed control panel is never started from the elevated setup process, because it would inherit the elevation.

The DR-9 checks stay unchanged: setup refuses to install from a folder another account can change, and copies from a handle it holds without write or delete sharing.

### Install and upgrade

These are the Phase 2 and 3 steps (ADR-0006, ADR-0007), with these additions:

1. **Versions.** Setup reads the installed version from the Apps entry (below), which only Administrators can write.
   - The same version is a repair.
   - An older installed version is upgraded.
   - A newer installed version is refused: "A newer SoiréeHost (1.4.0) is already installed." This avoids running a config written by a newer schema. The way back is uninstall, then install.

   A file the user downloads and runs is their own trust decision, as with any installer. S-62 governs the automatic update channel only.
2. **The Apps entry.** Setup writes `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SoireeHost` in the 64-bit view:

   | Value | Content |
   | --- | --- |
   | `DisplayName` | `SoiréeHost` |
   | `DisplayVersion` | the version being installed |
   | `Publisher` | `SoiréeHost project` (no personal name) |
   | `DisplayIcon` | `"%ProgramFiles%\SoireeHost\soireehost.exe",0` |
   | `InstallLocation` | the program folder |
   | `UninstallString` | `"%ProgramFiles%\SoireeHost\soireehost.exe" gui --uninstall` |
   | `NoModify`, `NoRepair` | `1` (Repair is in the control panel) |
   | `EstimatedSize` | the size of the program folder in KB |
   | `URLInfoAbout` | `https://github.com/TheAlsaadi/SoireeHost` |

   The key inherits `HKLM\SOFTWARE`'s permissions, so only Administrators and SYSTEM can write it.
3. **Starting at sign-in.** Setup writes the installing user's Run entry pointing at the installed binary. This is the owner decision of 15 Nov 2026, the same value the control panel writes.
4. **Order.** Setup copies the binary, unpacks cloudflared, adds the firewall rules, creates the folders, writes `control-users.json`, registers the services and the event sources, writes the Apps entry, then starts the supervisor. A failure before the services are registered removes what this run created (the program folder only if it did not exist before). On a failure after that, Repair can finish the job.

### Repair

`setup repair` runs every install step except copying the binary:

- unpack cloudflared;
- re-add the firewall rules;
- re-apply the folder descriptors after the DR-8 content check;
- re-apply the service configuration and descriptors;
- re-register the event sources;
- rewrite the Apps entry;
- start the supervisor.

The control panel's Repair button, today a sentence ("Run SoiréeHost setup again"), becomes a button that raises the Windows prompt for it. It shows wherever `repair_needed` is reported (Settings, Security, the status line).

### Applying an update

ADR-0004 decides when an update is ready. `setup apply-update`, run by the installed binary:

1. **Verify.** It verifies `updates\manifest.json` with its own compiled-in keys: a newer version, `min_from`, product, channel, name and URL. It opens `updates\soireehost-<version>.exe` without following links and without write or delete sharing, and checks five things:
   - it is a plain file with one link;
   - it is owned by the supervisor's service SID;
   - its size and SHA-256 match;
   - the Authenticode rule in S-61 holds.
2. **Journal.** It writes `%ProgramFiles%\SoireeHost\update.json` (write-through):
   - the old and new versions;
   - the step reached;
   - the SHA-256 of both binaries.

   Each step below updates it before acting.
3. **Snapshot.** It copies `config\config.json` and its version history to `%ProgramFiles%\SoireeHost\rollback\config\`, a folder setup creates with an Administrators-and-SYSTEM-only descriptor. A newer release may migrate the config, and the previous one must be able to read it after a rollback.
4. **Stage.** It copies the verified file from its open handle to `soireehost.exe.new` in the program folder and checks the copy's SHA-256 against the manifest.
5. **Stop.** It stops the three services, the supervisor first, and waits for every process to exit, as uninstall does (DR-7).
6. **Swap.** On the same volume, with write-through:
   - rename `cloudflared.exe` to `cloudflared.exe.previous`;
   - rename `soireehost.exe` to `soireehost.exe.previous`. Windows allows renaming a running program, so this works while the control panel and this setup process still run from it;
   - rename `soireehost.exe.new` to `soireehost.exe`.

   An older `.previous` pair is deleted first.
7. **Finish.** It starts the new binary, elevated through this process, as `setup repair` and waits up to 5 minutes. The new version unpacks its own cloudflared, applies any new folder, service or firewall settings of its release, and starts the supervisor.
8. **Check.** It waits up to 90 seconds for the supervisor to answer `status.get` over the control pipe with the new version. Elevated Administrators are admitted to the control pipe (ADR-0006). The workers' own state is not part of this check: a site that fails because of its own config is not a failed update.
9. **Done or rolled back.**
   - **Success.** It deletes the journal and the config snapshot. It keeps the `.previous` pair until the next update (S-63). The supervisor deletes the staged files at its next start.
   - **Failure at any step from 5 on.** It stops the services, puts back the `.previous` binaries, restores the config snapshot, and then runs its own repair step in this process: it is the previous version, already loaded, so it unpacks its own cloudflared again. It then starts the supervisor, writes `update.rollback` to the event log, and exits with the `rolled_back` code. The control panel then says the update failed and the previous version is running.

**Interrupted update.** If setup is killed or the PC loses power, the journal remains. The next setup command, or `setup repair`, reads it:

- before the swap: it removes the leftovers;
- after the swap: it checks the installed binary's SHA-256 against the journal and either finishes (repair, then the check) or rolls back.

If the power fails in the instant between the two renames of step 6, `soireehost.exe` is missing and the services cannot start. The user then runs any downloaded `soireehost.exe`: the install window finds the journal and offers Repair, which completes the swap. This window is two renames long, and the journal makes it recoverable.

### Uninstall

`UninstallString`, the Settings > Apps button, opens `soireehost.exe gui --uninstall`. This is the control panel role, unelevated, in a small Uninstall SoiréeHost window:

- one line on what will be removed;
- a check box, off by default: "Also remove settings, the tunnel token and logs" (owner decision);
- an Uninstall button that raises the Windows prompt for `setup uninstall` or `setup uninstall --purge`.

`setup uninstall` keeps the Phase 2 steps and adds:

- **What is removed.** The Apps entry, the event sources, and the installing user's Run entry. Other users' Run entries cannot be reached and become harmless dangling entries; the release notes say so.
- **Removing its own executable**, without a helper script, `cmd.exe`, or a delete-on-close trick that antivirus tools flag:
  1. Setup creates `%ProgramFiles%\SoireeHost.removed-<random>` with an Administrators-and-SYSTEM-only descriptor (`winsec.CreateFolderSDDL`). It is on the same volume as the program folder, which allows a rename.
  2. It renames every file in the program folder that is still in use into it: its own running binary, and the binary of any control panel still open. Windows allows renaming a running program.
  3. It deletes the rest of the program folder, then the folder itself.
  4. It marks the moved files and the `.removed-` folder with `MoveFileEx(..., MOVEFILE_DELAY_UNTIL_REBOOT)`, the method Windows Installer uses for files in use. Nothing runnable is left in `%ProgramFiles%\SoireeHost`, and the leftovers vanish at the next restart.

  If nothing is in use (setup was run from a copy elsewhere), everything goes at once.
- **Control panels still open** notice that the service is gone and the installed file has moved. They say "SoiréeHost was uninstalled" and exit, removing their own Run entry.

### What setup changes on the system (the list the install window shows)

| Change | Where | Removed by uninstall |
| --- | --- | --- |
| Program and cloudflared | `%ProgramFiles%\SoireeHost\` | Yes |
| Three services | `SoireeHost`, `SoireeHostWeb`, `SoireeHostTunnel` | Yes |
| Two firewall rules, block inbound only | Windows Defender Firewall | Yes |
| Data folders | `%ProgramData%\SoireeHost\` | Only if the user ticks the box |
| Event log sources | Application log | Yes |
| Apps entry | `HKLM\...\Uninstall\SoireeHost` | Yes |
| Start at sign-in | The installing user's `Run` key | Yes, for that user |

### Tests and checks

- **Unit tests** (everywhere): the Apps-entry values, argument parsing (no extra arguments), the exit-code mapping and its catalogue keys, the version decision of install, the journal state machine (every step crossed with fail, kill and resume), and the uninstall plan (what moves, what is deleted at once).
- **CI isolation job** (the runner is elevated):
  - fresh install, Apps entry present, repair;
  - upgrade over an older build;
  - newer installed version refused;
  - `apply-update` with a good update;
  - tampered, wrong-key, truncated and older-version updates refused (S-60 to S-63);
  - a candidate built to fail at start, rolled back;
  - a setup killed at each journal step, then recovered. A `setuptesthooks` build tag adds the kill points. It is not allowed together with `production`, and the release workflow checks that it is absent;
  - uninstall with and without `--purge`, then a check that no service, firewall rule, Apps entry or program file is left (the moved files exist until a restart, which the job checks by their delayed-delete record);
  - the elevation call itself (`ShellExecuteExW runas` from the control-panel code). The runner's administrator has the prompt turned off, so this proves the wiring, not the prompt.
- **The five-minute check (CI).** A job step times the whole path on Windows Server 2025: copy the built exe to a fresh folder, `setup install`, add a static site over the control pipe, start a quick share, fetch the page over the internet. It fails if this takes 5 minutes or more. Windows Server is a stand-in for Windows 11; the VM check covers the real target.
- **The five-minute check (owner, once).** Windows 11 Enterprise evaluation in VirtualBox, using the dry-run release build. It covers the real Windows prompts, the Apps entry in Settings, the S-42 capture with Resource Monitor, an update installed by clicking (S-64) and uninstall. It is recorded in `docs/SECURITY_CHECKLIST.md`. Installing VirtualBox needs administrator rights, so it waits for the owner's go-ahead.

### Notes added during the build and the Stage 4 reviews (19 and 20 Nov 2026)

- **Journal names its process.** The journal holds the PID of the `apply-update` process. The new version's `setup repair`, started by that process while it holds the setup lock, is admitted without the lock only when its parent is that PID and the journal is at the swap step.
- **Step order.** The settings snapshot is taken after the services stop, so no change made meanwhile is lost: verified, staged, stopped, snapshot, swapped, finished. An interruption at any step before the swap is cleaned up. Stale `.previous` files from an earlier update are deleted before the journal is first written, so every `.previous` file present while a journal exists belongs to this update (code review, 20 Nov 2026).
- **Settings through handles.** The snapshot and the restore open `%ProgramData%\SoireeHost\config` and its `history` folder by handle and every file relative to it, never through a junction, a mount point or a file with several hard links (`winsec.Dir`). The supervisor's account can change that folder, and path-based copying would have let a compromised supervisor make an elevated rollback write or delete files anywhere (security review, 20 Nov 2026, confirmed true positive and fixed).
- **Rollback result.** Exit code 22 means the previous version was restored and started. A rollback that could not restore it exits with code 1 and names both causes, so the control panel never says the previous version runs when it may not.
- **Upgrade over a running control panel.** Windows refuses to replace a running program, and the tray starts at sign-in. `setup install` therefore moves the old program aside and deletes it at the next restart, as uninstall does.
- **After an update**, the control panel that raised the prompt closes. The installed one it starts waits for it to exit, because Wails holds its single-instance lock until the process ends.
- **S-61 publisher.** The publisher compared is the signer's name together with its issuer. A running program whose own signature does not verify offline refuses every update; a failed check never counts as "unsigned" (differential review and insecure-defaults audit, 20 Nov 2026).
- **Uninstall does not recover an interrupted update.** It removes the program folder, `.previous` files and journal included, whatever state they are in.
- **The supervisor is confined** (20 Nov 2026), like the workers: a kill-on-close job object that allows no child process. Nothing it could start outlives the service stop that `apply-update` waits for before it touches the supervisor's folders.
- **Event log.** Setup registers the source `SoireeHost Setup` with the services' sources and writes each command's result there: information on success, a warning tagged `update.rollback`, and an error otherwise. The event id is the exit code.

## Options considered

### Removing the running executable

| Option | Assessment |
| --- | --- |
| Rename aside, delete at restart (chosen) | The standard Windows Installer method. Nothing runnable stays in Program Files. Leaves a file until the next restart |
| Copy itself to a temporary folder and re-run from there | The temporary folder is writable by others, which risks a planted DLL or binary next to an elevated process. Rejected |
| `cmd.exe /c` with a delay, then `del` | A classic malware pattern that antivirus flags. It also starts an unconfined shell from an elevated process. Rejected |
| Rename the default data stream, then delete on close | Works on NTFS, but it is a known evasion technique and the same antivirus risk. Rejected |

### Uninstall user interface

| Option | Assessment |
| --- | --- |
| Control-panel window (`gui --uninstall`) (chosen) | Reuses the Svelte components, the message catalogue, accessibility and S-33. Elevates only for the action |
| A Win32 task dialog from setup | Needs a common-controls manifest and a second set of strings outside the catalogue. Elevates before the user has chosen |

### Update swap

| Option | Assessment |
| --- | --- |
| Old setup verifies and swaps; the new binary's `setup repair` finishes (chosen) | Each release owns its own install steps and migrations, and the trusted old binary decides rollback. The new binary runs only after both checks |
| Old setup does everything | It cannot unpack the new cloudflared without parsing the new executable, and it would apply old install steps to a new release |
| `ReplaceFileW` | Not atomic across a crash either, and its partial-failure states are harder to journal than two renames |

## Consequences

- **Setup coverage.** Setup gains most of its coverage in the CI isolation job, which grows longer: plan for its runs (quality review note, 16 Nov 2026).
- **Two kinds of leftovers** remain after uninstall until the next restart: the moved binaries in `%ProgramFiles%\SoireeHost.removed-*`, and other users' Run entries. Both are harmless and documented.
- **Rollback costs disk space:** the `.previous` binary (about 100 MB with cloudflared) stays until the next update.
- **Revisit:** several control-panel users (ADR-0006), and unattended updates after 1.0 (plan section 9).

## Action items

1. [x] Owner: accept or amend this record. Accepted 19 Nov 2026.
2. [x] `internal/setup`: mutex, journal, `repair`, `apply-update`, the Apps entry, the Run entry, the uninstall plan and self-removal, exit codes, event source (pull request 22, CI green 20 Nov 2026).
3. [x] `internal/gui`: install window, upgrade offer, Repair and Install buttons, uninstall window, the elevation call, exit after uninstall (pull request 22, CI green 20 Nov 2026; the owner approved the four new screens on 19 Nov 2026).
4. [x] `cmd/soireehost`: the new subcommands; refuse extra arguments (pull request 22, CI green 20 Nov 2026).
5. [x] CI isolation job: every check above, plus the timed five-minute path (57 s on 20 Nov 2026; pull request 22, CI green 20 Nov 2026).
6. [x] Owner: the VirtualBox check (20 Nov 2026, pull request 25). Everything passed except one bug, now fixed: the install window did not close, so the installed control panel did not open. The update by clicking waits for a previous signed release (`docs/RELEASE_CHECKLIST.md`).

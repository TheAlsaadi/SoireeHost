# Hand-over

Written 27 Nov 2026, updated 28 Nov 2026. The Claude subscription that built SoiréeHost so far ends around 1 Dec 2026, and another Claude account continues the work. This file lets that account start cold. Read it after `CLAUDE.md` and before `docs/PLAN.md`. Keep it current until the release of 1.0.0, then delete it.

## Where the project stands

- Phases 0 to 6 are done. `docs/HISTORY.md` has the record, with pull requests, CI runs and the owner's decisions.
- **Phase 7 (hardening and release candidate)** runs in five stages, listed in `docs/HISTORY.md` under "Plan for the phase":
  1. readiness, done;
  2. build, pull request 28, done;
  3. security pass, pull request 32, merged 27 Nov 2026, done;
  4. **long runs, now in progress** (below);
  5. the release candidate `v1.0.0-rc.1`, prepared but not tagged (see "rc.1 status" below).
- Stage 4 (fuzz, soak candidate) ran on `main` `03f57bb`, the merge of pull request 32. Since then `main` has taken pull requests 33 to 35 (workflow pins, this file, SE-03).

## Stage 4: long runs

### Fuzzing in CI

The workflow is `.github/workflows/fuzz-long.yml`, run by hand from `main`. It lists every `Fuzz` function itself (23 targets at the runs below; 25 since `FuzzReadFrame` and `FuzzDecodeResponse` were added on 28 Nov 2026), each in two 4-hour halves (owner decision, 21 Nov 2026).

| Run | Commit | State |
| --- | --- | --- |
| 44891777368 | `a6ea514` (21 Nov, before Stage 3) | Passed, every target |
| **46010926821** | `03f57bb` (after Stage 3) | **Passed:** all 47 jobs, no crash, finished 28 Nov 06:05 UTC |

Stage 4's fuzzing is done. Run the workflow again from `main` before the release only if fuzzed code changes.

Check it with:

```powershell
gh run view 46010926821 --json conclusion,jobs --jq '{conclusion, notok:[.jobs[]|select(.conclusion!="success")|{name,conclusion}]}'
```

`gh` is at `C:\Program Files\GitHub CLI\gh.exe`, signed in as the owner. A failed job uploads its crasher. Read it with `gh run view <run> --log-failed` and `gh run download`. Triage each crash with the `fp-check` skill. Fix real bugs on a branch, add the crasher as a regression test (a seed in `testdata/fuzz/<Target>/`), and open a pull request. Then run the workflow again from `main`.

### The 72-hour soak in the owner's VM

The soak runs without Claude. The owner runs it in the VirtualBox VM "SoireeHost-check", restored to its "clean" snapshot.

**State (28 Nov 2026):**

- Trial 1 (27 Nov) failed at 98.65%: the VM stalled while VirtualBox ran on Hyper-V.
- Trial 2 (28 Nov, 2 hours) passed at 99.574% of 235 probes.
- **The 72-hour run started 28 Nov 2026 at 00:29:44 UTC (03:29:44 local, +03:00), writing to `C:\soak` in the VM. It is due to end about 1 Dec 2026 at 00:30 UTC.**
- For the run, the owner turned off the host's hypervisor features (memory integrity, virtualization-based security, hypervisor launch). They must be turned back on afterwards, which needs admin on the owner's PC, so it is the owner's step. After the soak's files are collected:

  1. If BitLocker is on, run `manage-bde -protectors -disable C: -RebootCount 1` first.
  2. In Terminal (Admin), run:

     ```powershell
     reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
     reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\WindowsHello" /v Enabled /t REG_DWORD /d 1 /f
     reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 1 /f
     bcdedit /set hypervisorlaunchtype auto
     ```

  3. Restart. Check that `(Get-CimInstance Win32_ComputerSystem).HypervisorPresent` is True and that Memory integrity is on.
  4. Resume Windows Update.
  5. Restore the VM snapshot "clean".

  Docker and WSL do not work until this is done.
- Windows Update is paused in the VM until 4 Dec, and on the host until 2 Dec.
- Collect the files before powering off the VM. Section E of `SOAK-INSTRUCTIONS.md` explains how to copy them out through a temporary writable VirtualBox share.

- **Kit:** `C:\Users\moham\SoireeHost-soak-kit` on the owner's PC, outside the repository.
  - `soireehost.exe`: the candidate, from Release dry run 46011058681 (`0.0.0-dryrun.24`, commit `03f57bb`, built twice and compared). SHA-256 `aeb0f84c2c2e16a7066585613190fb68ae8dc6fdadd7fe16e6a3d48d212dea91`.
  - `SHA256SUMS`, written by the same run.
  - `e2e.test.exe`: built from `03f57bb` with `go test -c -trimpath -tags e2e,no_fs_access ./internal/e2e/` and `CGO_ENABLED=0`. SHA-256 `c29c2868ecf1430a762ffc1a61fc44992dcb4714f551d1a7a7deed0c0f1b9bfd`.
  - `SOAK-INSTRUCTIONS.md`: the owner's steps.
- **Order:**
  1. A 2-hour trial into `C:\soak-trial`. It drops the tunnel at 30 minutes and restarts the supervisor at 1 hour.
  2. If the trial passes, the 72-hour run into `C:\soak`. It drops the tunnel every 4 hours and restarts the supervisor every 24 hours.
- **The test:** `internal/e2e/soak_test.go` `TestSoak`. It judges the run itself and ends with `PASS` or `FAIL` and the reasons. It fails on:
  - availability under 99% outside the 10-minute recovery window after each fault;
  - a fault the site does not recover from;
  - memory or handle growth within one process's life.
- **Results:** the owner puts these files in a folder on the PC (suggested: `C:\Users\moham\SoireeHost-soak-results`) and says where:
  - `output.txt`;
  - `probes.csv`, `samples.csv`, `faults.csv`;
  - `events.txt` (the services' Application event log);
  - notes on any interruption.
- **Reading a failure:**
  - `faults.csv` shows when each fault happened;
  - `probes.csv` shows each probe's status and error;
  - `samples.csv` shows private bytes and handles per process (pid and role);
  - `events.txt` shows the services' own account of what happened.

  Reproduce on a CI runner where possible: the CI Isolation job installs the services there. Never install the services on the owner's PC.
- **If the soak fails because of SoiréeHost:** fix it on a branch with a test, merge, build a new candidate (Release dry run from `main`), and ask the owner to soak again.
- **If something outside the test stopped it** (the host slept, Windows Update restarted the VM): ask the owner to run it again. Do not count a partial run as a pass.

### Recording Stage 4

When the fuzz run has passed and the soak has passed, open one small pull request that:

- adds a "Stage 4 (long runs)" entry to the Phase 7 section of `docs/HISTORY.md`, with the fuzz run id, its commit, the soak's dates, availability and peak memory per role, and the candidate's hashes;
- updates `docs/SECURITY_CHECKLIST.md` rows whose evidence includes a fuzz target (search for `Fuzz`), naming the run, and its "Last updated" line;
- updates the Status section of `CLAUDE.md` (done, now, open);
- updates this file.

Run `gitleaks dir --redact . >/dev/null 2>&1 &&` before every commit (chained with `&&`, never piped).

## rc.1 status

As of 28 Nov 2026. Nothing is tagged or released, and the release workflow has not been run for a tag. Tagging needs a passed soak and the owner's word.

### Ready

- Release notes: `docs/release-notes/v1.0.0-rc.1.md`.
- `docs/RELEASE_CHECKLIST.md`, "Before tagging": every item but the first is ticked, with its evidence.
- Fuzzing passed (run 46010926821).
- Owner decision, 28 Nov 2026: SE-02, SE-04, SE-06, SE-08, SE-09, SE-13 and SE-15 stay open in rc.1 as known issues and are fixed before 1.0.0. GOE-1, GOE-5, GOE-13, GOE-17 and GOE-20 are test gaps, closed now without changing the program. Record both in `docs/HISTORY.md` with the soak result.

### Left

1. The 72-hour soak ends about 1 Dec 00:30 UTC. It must end in `PASS`. Collect its files, restore the host's settings (above), and record the result (see "Recording Stage 4").
2. Choose the commit to tag (below). The first "Before tagging" item is ticked for that commit.
3. On the day of the tag, look again at the Dependabot, code-scanning and secret-scanning pages.
4. The owner gives the word, tags, approves the `manifest` job, checks the draft in the VM, decides the rollback triggers and publishes.
5. Record the release in `docs/HISTORY.md`.

### The commit to tag

The soak runs the build of `03f57bb`. `main` has moved since. When these notes were written, the only changes outside `docs/` and tests were workflow action pins (pull request 33; its Release dry run 46008430451 passed), the removal of the test-only `SetFolderSDDL` from `internal/winsec` (pull request 35), and notes for Claude sessions (`CLAUDE.md`, `.claude/`). If the list below shows any other program code, the soak does not cover it: do not tag that commit without the owner's decision. The fixes for the seven SE findings should wait until after the tag. If one is merged first, update the release notes too.

If the GOE test gaps are not all closed on the tagged commit, add the open ones to the known issues in the release notes.

### Commands

Run them in PowerShell, in an up-to-date checkout of the repository, in one window (later commands use `$sha`, `$run` and `$d`).

Choose the commit and list what changed in it since the soaked build:

```powershell
git fetch origin
```

```powershell
$sha = git rev-parse origin/main
```

```powershell
git diff --stat 03f57bb $sha -- . ':(exclude)docs' ':(exclude)*_test.go'
```

CI must show `success` for that commit (the tag run refuses it otherwise):

```powershell
gh run list --workflow ci.yml --commit $sha
```

Only after the soak has passed and the owner says so, tag and push. Never move or reuse a tag: if the tag run fails after the push, fix the cause and release `rc.2`.

```powershell
git tag -a v1.0.0-rc.1 $sha -m "v1.0.0-rc.1"
```

```powershell
git push origin v1.0.0-rc.1
```

Find the Release run, open it, and approve the `manifest` job ("Review deployments", environment `release`):

```powershell
$run = gh run list --workflow release.yml --branch v1.0.0-rc.1 --limit 1 --json databaseId --jq '.[0].databaseId'
```

```powershell
gh run view $run --web
```

```powershell
gh run watch $run --exit-status
```

The run creates a draft pre-release. Replace its short text with the release notes:

```powershell
git switch --detach $sha
```

```powershell
gh release edit v1.0.0-rc.1 --notes-file docs/release-notes/v1.0.0-rc.1.md
```

Download the draft into a new folder and check it. Every line must end in `True`:

```powershell
$d = "$env:USERPROFILE\Downloads\soireehost-rc1"
```

```powershell
gh release download v1.0.0-rc.1 --dir $d
```

```powershell
Get-Content "$d\SHA256SUMS" | ForEach-Object { $h, $n = $_ -split '\s+', 2; "$n $((Get-FileHash (Join-Path $d $n)).Hash -eq $h)" }
```

```powershell
gh attestation verify "$d\soireehost.exe" --repo TheAlsaadi/SoireeHost
```

Then, in the VM restored to "clean": install the draft's `soireehost.exe` and check the install and uninstall items in the checklist. The update item starts with the second release. When they pass, and the owner says so, publish:

```powershell
gh release edit v1.0.0-rc.1 --draft=false --prerelease
```

```powershell
gh release view v1.0.0-rc.1 --json isDraft,isPrerelease,url
```

The first two "After publishing" items cannot hold for a candidate: `releases/latest` skips pre-releases, so the manifest address answers 404 until 1.0.0, and no earlier release exists. An rc.1 install's update check reports "Could not reach GitHub" until then. The release notes say so.

### Noticed while preparing, not yet fixed

- `docs/USER_GUIDE.md` says the change history "cannot be rewritten". SE-13 shows that is too strong.
- The user guide's download link goes to the latest full release, so it does not lead to the candidate's files until 1.0.0.
- S-03, S-04, S-06, S-21, S-64 and S-73 still read "Partial" in `docs/SECURITY_CHECKLIST.md`. Phase 7 needs every row linked to a passing test or a recorded check, so settle them before the sign-off. S-73 needs the tag run; S-64 needs the update from rc.1 to 1.0.0.

## Open pull requests and branches

- Merged since this file was first written:
  - 33: Dependabot actions update;
  - 34: this file;
  - 35: SE-03.
- `phase7-stage4-records`: the Stage 4 records (fuzz result, soak start), with auto-merge on.
- The soak's result still needs its own records pull request when it is in.

## Decisions waiting for the owner

Fix each of these before `1.0.0`, or have the owner accept it for 1.0. The full rows are in `docs/HISTORY.md` (Phase 7, Stage 3) and `docs/reviews/2026-11-12-skills-review.md`.

- Decided by the owner on 28 Nov 2026 ("tests now, code later"), for the Medium items of the 12 Nov 2026 review:
  - the seven code findings **SE-02, SE-04, SE-06, SE-08, SE-09, SE-13 and SE-15 stay open for `v1.0.0-rc.1`**, are listed as known issues in its release notes, and are fixed before `1.0.0`;
  - the five test and CI findings GOE-1, GOE-5, GOE-13, GOE-17 and GOE-20 were fixed on 28 Nov 2026 without changing the binary.
  - **SE-03 (High): fixed** in pull request 35 (27 Nov 2026). `SetFolderSDDL` moved to the test-only package `internal/winsec/winsectest`, and `TestImportedOnlyFromTests` guards it. No High finding is open now.

Fix each of the rest before `1.0.0`, or have the owner accept it for 1.0:

- Low sharp-edges findings: SE7-3 to SE7-9 and S12V-1 to S12V-5.
- Code review leftovers:
  - CR-4: rollback exposure sentences do not name the site.
  - CR-5: a confirmation can keep failing when a time-limited scan is cut off at different points.
  - CR-6: never-served names past the cap are not counted in the warning.
  - CR-7: when setup's rollback refuses a kept copy, it still removes the journal.
- Phase 7 is done only when:
  - every S-requirement in `docs/SECURITY_CHECKLIST.md` links to a passing test or a recorded manual check;
  - no high-severity finding is open;
  - the owner signs off.

- **UPD-1, the update rolled back for nothing (owner decision, draft pull request "[decision] ...").** Found 28 Nov 2026 from a CI flake (run 46130645262, attempt 1, `TestSignedUpdates`: "rolled back: the supervisor reports version 1.1.0, not 1.3.0"; the re-run passed). Cause, in the product: the supervisor service has restart recovery actions (5, 30, 60 s). An earlier failure leaves a restart on the service manager's timer, and if it fires while `apply-update` has the services stopped and before the swap, the old program starts again from the old path. It keeps serving the control pipe while the new one is installed, so the version check fails and the update is rolled back. In the CI run the 1.2.0 test build that refuses to start failed at 09:47:19; the 60 s restart came due at 09:48:19, while the next update had the services stopped. The service manager's events show the web and tunnel services stopping at 09:48:39 and starting at 09:48:40 with no supervisor start: the old one was already running again. Seen once in the last 40 CI runs. A user sees a failed update that rolls back safely; trying again works. The fix in the draft re-checks that the services stay stopped before the settings snapshot, after the swap and in the rollback, and re-sends the stop to a service that was still starting. A `setuptesthooks` restart hook makes the e2e good update reproduce it. Options: ship rc.1 as soaked and fix in rc.2 or 1.0.0, or merge before rc.1 and soak again briefly.

## Findings for after rc.1

Found or recorded while the candidate's code was frozen. Do these once `v1.0.0-rc.1` is out, before `1.0.0`.

- The seven code findings above (rows in `docs/reviews/2026-11-12-skills-review.md`).
- Coverage below the 85% target (GOE-5). `build/check-coverage.ps1` holds each floor at today's value; raise it to 85 as tests are added:
  - `internal/ipc`: 80.1% on 28 Nov 2026, floor 80;
  - `internal/secrets`: 83.3% on 28 Nov 2026, floor 83.

## Next steps, in order

1. **Finish Stage 4** (above): the fuzz result, the soak result, the records pull request.
2. **Open findings.** SE-03 and the five GOE findings are fixed, and the seven code findings wait until after rc.1 (owner, 28 Nov 2026). Ask the owner which of the Low findings and review leftovers above to fix and which to accept. Record the answers in `docs/HISTORY.md`. Until rc.1 is tagged, do not change production code: the soak runs the candidate built from `03f57bb`. Since that commit the only change to non-test Go code on `main` is the SE-03 fix (`winsec.SetFolderSDDL`, which no production code called, moved to `winsectest`); check `git diff 03f57bb <tag commit>` before tagging.
3. **Stage 5, `v1.0.0-rc.1`.** Follow `docs/RELEASE_CHECKLIST.md` from "Before tagging". In short:
   - Main is green.
   - No high finding is open.
   - The release notes name the platform, list SE-02, SE-04, SE-06, SE-08, SE-09, SE-13 and SE-15 as known issues (one sentence each, from their review rows), and name the known limits:
     - not Authenticode-signed yet;
     - no independent review yet, with private reports invited;
     - tunnel-token mode with a real hostname not verified.
   - The owner (only the owner may create `v*` tags) pushes the annotated tag `v1.0.0-rc.1` on the `main` commit.
   - The owner approves the `manifest` job in the `release` environment.
   - The workflow creates a draft release.
   - Verify the draft: `SHA256SUMS` matches, `gh attestation verify soireehost.exe --repo TheAlsaadi/SoireeHost` passes, and the install and uninstall checks pass in the VM.
   - Publish the draft as a **pre-release** (owner decision, 21 Nov 2026).
   - Run the "After publishing" checks.
   - Record the release in `docs/HISTORY.md`.
4. **The owner's sign-off on Phase 7**, recorded in `docs/HISTORY.md` and the Phase 7 checkboxes in `docs/PLAN.md`.
5. **`v1.0.0`**, once the candidate has run without problems (owner decision, 21 Nov 2026). Use the same checklist. This time "On a VM running the previous release" applies: install rc.1 in the VM, then check that the update to 1.0.0 is found and installed with one prompt, and that the settings are kept (S-64).
6. **After 1.0:** the order in `docs/PLAN.md` (Phase 7, "After 1.0"). Each item gets a decision record and the owner's decisions before any code.

## Working arrangements the new account should know

These lived in the old account's private memory, so they are written here:

- **Standing go-ahead (owner, 20 Nov 2026).** Merge on green and change repository settings without asking. Hand back to the owner only credentials, administrator steps on the owner's PC, and very serious matters.
- **Repository settings.** Auto-merge is on for the repository. `main` requires 8 checks, so `gh pr merge --auto --merge` waits for green CI.
- **Before pushing to an open pull request,** check it is not already merged (`gh pr view N --json state`).
- **Ask before any administrator step on the owner's PC.** The VM and CI runners are fine. VirtualBox runs on Hyper-V there:
  - snapshot with the VM powered off;
  - a restart inside the VM sometimes hangs on a black screen, and a reset recovers it.
- **Usage pacing.** Run at most 4 agents at once. Keep the context small and start a fresh session per stage: every tool call re-reads the whole context.
- **Tools that misbehaved.** The Workflow tool was not available; use one agent per group instead. The fp-check skill's stop hook looped after use.
- **Release prerequisites are done** (21 Nov 2026):
  - update-signing key `229bc25eefe83c4a`, with two offline backups kept by the owner;
  - the `release` environment and its secret;
  - the tag ruleset.
- **Conventions.** The project skill `soireehost-conventions` (in `.claude/skills/`) holds the conventions and pitfalls. Load it before changing code.

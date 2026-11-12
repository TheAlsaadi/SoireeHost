# Testing in SoiréeHost

`docs/TEST_PLAN.md` is the plan; this is how it works in practice.

## Where a test may run

| Kind of test | Runs | How it is kept off the owner's PC |
| --- | --- | --- |
| Unit, table, fuzz | Everywhere | Needs nothing special |
| In-process integration (worker with real Caddy, supervisor with real pipes) | Everywhere | Uses random loopback ports and unique pipe names (`\\.\pipe\soireehost-test-<random>`) |
| Confinement (job object, no child processes) | Everywhere | The test re-runs its own binary with an environment variable (`TestConfineHelper`), so the limits never apply to the test runner |
| Binding a non-loopback address | CI only | `TestSelfCheckStopsPublicListener` skips unless `CI` is set: on a desktop, Windows Firewall would prompt |
| Symbolic links | CI (where the runner is admin) | Creating one needs Developer Mode or admin; the test logs instead of failing when it cannot. Junctions need neither and run everywhere |
| Anything needing administrator rights: services, setup, second user, ACL drift | CI `isolation` job only | `internal/e2e` has build tag `e2e` and exits unless `SOIREEHOST_E2E=1` |

The machine rule in `CLAUDE.md` forbids administrator-level steps on the owner's PC without asking; the CI runner is thrown away after each job.

## The CI isolation job

In `.github/workflows/ci.yml`, after `Go checks`:

1. Build the release binary (`-tags production`).
2. `soireehost.exe setup install` (the runner is elevated).
3. `go test -tags e2e -timeout 25m ./internal/e2e/`. `TestMain` first waits up to two minutes for the supervisor to run and exits with a clear message if it never does, instead of every test timing out.
4. `setup install` again over the running install, then wait for all three services.
5. On failure: service states, plus the services' Application event-log entries and the service manager's messages, as annotations.
6. Always `setup uninstall --purge`, then fail if any service, the program folder or the data folder is left.

Things learned there:

- The runner is elevated, so folders a test creates are owned by Administrators. Tests that depend on ownership must name the owner in the SDDL.
- `net user NAME PASS /add` stops to ask a yes/no question when the password is longer than 14 characters. Keep test passwords at 14.
- A new local user can log on interactively on the runner, so `LogonUser(…, LOGON32_LOGON_INTERACTIVE, …)` plus `ImpersonateLoggedOnUser` on a locked OS thread is the way to act as a second user, with no second process.
- Service failures are invisible without the event log: a service has no console.

## Local check set

Run before every commit (Bash, with Go on `PATH`):

```
go vet ./... && go vet -tags production ./... && go vet -tags e2e ./internal/e2e
go test -count=1 ./...
golangci-lint run ./... && golangci-lint run --build-tags e2e ./internal/e2e/...
staticcheck ./... && staticcheck -tags e2e ./internal/e2e
gosec -quiet ./...
govulncheck ./...
gitleaks dir --redact --no-banner .
```

Race tests need cgo and run in CI only. Fuzz each new or changed target for 10 minutes in the background (`go test -run '^$' -fuzz '^FuzzX$' -fuzztime 10m ./pkg/`); `build/fuzz.ps1` runs them all. The nightly CI job fuzzes every target for 10 minutes. Fuzzers are slow to share the machine with, so expect linters to be slow while they run.

## Lint suppressions

- `gosec` run on its own ignores `//nolint`. In production code write `// #nosec G### -- reason`; in tests write `//nolint:gosec // G###: reason` (golangci-lint runs gosec on tests, standalone gosec does not).
- `nolintlint` requires a reason and fails on a directive that no longer suppresses anything; remove stale ones.
- `noctx`: use `net.ListenConfig{}.Listen(ctx, …)`, `net.Dialer{}.DialContext`, `exec.CommandContext`.
- `errcheck` flags discarding an error received from a channel (`<-done`); bind it.
- G115 integer conversions need a bound stated in the suppression reason.

## Patterns worth reusing

- Raw TCP requests (`h.raw`) for path tests, so no HTTP client cleans or re-encodes the path.
- A planted marker string (`PLANTED-SECRET`, `CANARY-…`) in every secret a test creates, then a sweep of every file, log line and process command line for it.
- `startHarness` / `start` helpers that build a full config, start the real component, and clean up in `t.Cleanup`; tests mutate the config through a callback.
- For timing-sensitive checks (listeners closing, services stopping) poll with a deadline instead of asserting immediately.

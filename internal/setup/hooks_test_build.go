//go:build setuptesthooks

package setup

import "os"

// testKillAt ends the process at step when SOIREEHOST_TEST_KILL_AT names
// it, as a power cut would. Only the CI isolation job builds with this tag,
// and a production build with it does not compile (guard_hooks.go).
func testKillAt(step Step) {
	if os.Getenv("SOIREEHOST_TEST_KILL_AT") == string(step) {
		os.Exit(99)
	}
}

// testRestartAt starts the supervisor at step when SOIREEHOST_TEST_RESTART_AT
// names it, as a recovery action scheduled by an earlier failure would
// (the CI flake of 28 Nov 2026, run 46130645262).
func testRestartAt(step Step) {
	if os.Getenv("SOIREEHOST_TEST_RESTART_AT") == string(step) {
		_ = startSupervisor()
	}
}

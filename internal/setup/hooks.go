//go:build !setuptesthooks

package setup

// testKillAt does nothing in a normal build. Builds with the
// setuptesthooks tag stop the process at a chosen update step, so the CI
// isolation job can check recovery from an interrupted update (ADR-0010).
func testKillAt(Step) {}

// testRestartAt does nothing in a normal build. Builds with the
// setuptesthooks tag start the supervisor at a chosen update step, as the
// service manager's recovery action can, so the CI isolation job can check
// that an update survives it.
func testRestartAt(Step) {}

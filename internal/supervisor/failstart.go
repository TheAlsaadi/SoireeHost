//go:build !updatetestfail

package supervisor

// failStartForTest is false in every normal build. The CI isolation job
// builds an update candidate with the updatetestfail tag whose supervisor
// refuses to start, to check that setup rolls the update back (ADR-0010).
const failStartForTest = false

//go:build updatetestfail

package supervisor

// failStartForTest makes this build's supervisor exit at once (see
// failstart.go). A production build with this tag does not compile
// (guard_failstart.go).
const failStartForTest = true

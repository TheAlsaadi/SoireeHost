//go:build production && updatetestfail

package supervisor

// A release build must start. This file compiles only when both tags are
// set, and it does not compile (ADR-0010).
var _ = production_builds_must_not_use_updatetestfail_see_ADR_0010

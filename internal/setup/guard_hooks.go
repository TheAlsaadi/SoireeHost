//go:build production && setuptesthooks

package setup

// A release build must not carry the test kill points. This file compiles
// only when both tags are set, and it does not compile (ADR-0010).
var _ = production_builds_must_not_use_setuptesthooks_see_ADR_0010

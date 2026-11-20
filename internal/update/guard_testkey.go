//go:build production && updatetestkey

package update

// A release build must trust only the committed keys. This file compiles
// only when both tags are set, and it does not compile, so such a build
// fails here (ADR-0004).
var _ = production_builds_must_not_use_updatetestkey_see_ADR_0004

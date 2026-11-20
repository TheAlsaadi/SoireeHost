//go:build updatetestkey

package update

import _ "embed"

// embeddedKeys is a test key file that the CI isolation job writes before
// it builds the binaries for its update tests (ADR-0004). The file is never
// committed, and a production build with this tag does not compile
// (guard_testkey.go).
//
//go:embed testkey.json
var embeddedKeys []byte

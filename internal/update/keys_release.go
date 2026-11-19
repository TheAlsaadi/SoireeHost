//go:build !updatetestkey

package update

import _ "embed"

// embeddedKeys is the committed key file: the update-signing public keys
// every release trusts (S-60). It holds no key until the owner generates
// one (docs/UPDATE_KEY.md); until then every update is refused.
//
//go:embed keys.json
var embeddedKeys []byte

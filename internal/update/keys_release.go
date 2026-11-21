//go:build !updatetestkey

package update

import _ "embed"

// embeddedKeys is the committed key file: the update-signing public keys
// every release trusts (S-60). The owner generated the first key,
// 229bc25eefe83c4a, on 21 Nov 2026 (docs/UPDATE_KEY.md); with an empty file
// every update would be refused.
//
//go:embed keys.json
var embeddedKeys []byte

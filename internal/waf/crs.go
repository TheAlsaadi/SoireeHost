// Package waf is the web application firewall: Coraza with the request rules
// of the OWASP Core Rule Set, as the Caddy handler soireehost_waf (S-14,
// ADR-0008). The rules are compiled into the binary; nothing is read from
// disk and nothing is written to it.
package waf

import (
	"embed"
	"io/fs"
)

// CRSVersion is the vendored Core Rule Set release. build/crs.lock holds the
// same value; TestCRSVersionMatchesLock keeps them equal.
const CRSVersion = "4.30.0"

// crsSetupVersion is what CRS rule 901001 expects in tx.crs_setup_version.
const crsSetupVersion = "4300"

//go:embed crs/LICENSE crs/rules
var vendored embed.FS

// rulesFS is the file system the rule loader sees: the vendored CRS only.
func rulesFS() fs.FS {
	sub, err := fs.Sub(vendored, "crs")
	if err != nil {
		panic("waf: embedded rule set missing: " + err.Error())
	}
	return sub
}

// Test cases for the go-no-insecure-skip-verify rule (CLAUDE.md rule 6).
// Not compiled: the go tool skips directories whose name starts with a dot.
package tlsconf

import (
	"crypto/tls"
	"net/http"
)

func literals() *tls.Config {
	// ruleid: go-no-insecure-skip-verify
	a := &tls.Config{InsecureSkipVerify: true}
	b := tls.Config{
		MinVersion: tls.VersionTLS13,
		// ruleid: go-no-insecure-skip-verify
		InsecureSkipVerify: true,
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			// ruleid: go-no-insecure-skip-verify
			InsecureSkipVerify: true, // #nosec G402
		},
	}
	_, _ = b, tr
	return a
}

func assignments(cfg *tls.Config, tr *http.Transport, debug bool) {
	// ruleid: go-no-insecure-skip-verify
	cfg.InsecureSkipVerify = true
	// ruleid: go-no-insecure-skip-verify
	tr.TLSClientConfig.InsecureSkipVerify = true
	if debug {
		for i := 0; i < 1; i++ {
			// ruleid: go-no-insecure-skip-verify
			cfg.InsecureSkipVerify = true
		}
	}
}

func throughConstant() *tls.Config {
	skip := true
	// ruleid: go-no-insecure-skip-verify
	return &tls.Config{InsecureSkipVerify: skip}
}

func throughFalseConstant() *tls.Config {
	verify := false
	// ok: go-no-insecure-skip-verify
	return &tls.Config{InsecureSkipVerify: verify}
}

func safe(cfg *tls.Config) *tls.Config {
	// ok: go-no-insecure-skip-verify
	cfg.InsecureSkipVerify = false
	// ok: go-no-insecure-skip-verify
	c := &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS13}
	// ok: go-no-insecure-skip-verify
	d := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "example.com"}
	// ok: go-no-insecure-skip-verify
	verified := !cfg.InsecureSkipVerify
	_, _ = d, verified
	return c
}

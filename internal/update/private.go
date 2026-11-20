package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
)

// The signing tools (build/updatekey, build/signmanifest) keep a private key
// as the base64 of its 32-byte seed: one line, which fits a GitHub secret
// and an offline backup. The app itself never holds a private key.

// EncodePrivateKey returns the text form of priv.
func EncodePrivateKey(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv.Seed())
}

// ParsePrivateKey reads the text form, ignoring surrounding white space.
// The error never contains the input.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	seed, err := unbase64(strings.TrimSpace(s))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("not an update signing key (expected the base64 of a 32-byte Ed25519 seed)")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

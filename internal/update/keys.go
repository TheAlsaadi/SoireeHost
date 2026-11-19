package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
)

// Key is one trusted update-signing public key (S-60).
type Key struct {
	ID     string
	Public ed25519.PublicKey
}

// KeySet is the list of trusted keys: one, or two during a rotation
// (ADR-0004).
type KeySet []Key

// maxKeys is the most keys a binary may trust at once.
const maxKeys = 2

// KeyID names a public key: the first 8 bytes of its SHA-256, in hex.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// find returns the key named id.
func (ks KeySet) find(id string) (Key, bool) {
	for _, k := range ks {
		if k.ID == id {
			return k, true
		}
	}
	return Key{}, false
}

// ParseKeys reads a key file: {"keys":[{"id":"...","public":"<base64>"}]}.
// Each id must be the KeyID of its key, and no key may appear twice. An
// empty list is valid and trusts nothing, so every update is refused.
func ParseKeys(data []byte) (KeySet, error) {
	top, err := object(data, "keys")
	if err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	var items []json.RawMessage
	if len(top["keys"]) == 0 || top["keys"][0] != '[' {
		return nil, fmt.Errorf("key file: %w", malformed("keys is not a list"))
	}
	if err := json.Unmarshal(top["keys"], &items); err != nil {
		return nil, fmt.Errorf("key file: %w", malformed("keys is not a list"))
	}
	if len(items) > maxKeys {
		return nil, fmt.Errorf("key file: %w", malformed("more than two keys"))
	}
	var ks KeySet
	for _, it := range items {
		f, err := object(it, "id", "public")
		if err != nil {
			return nil, fmt.Errorf("key file: %w", err)
		}
		id, err := text(f["id"])
		if err != nil {
			return nil, fmt.Errorf("key file: %w", err)
		}
		enc, err := text(f["public"])
		if err != nil {
			return nil, fmt.Errorf("key file: %w", err)
		}
		pub, err := unbase64(enc)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key file: %w", malformed("public key is not 32 bytes of base64"))
		}
		k := Key{ID: id, Public: ed25519.PublicKey(pub)}
		if KeyID(k.Public) != id {
			return nil, fmt.Errorf("key file: %w", malformed("id does not match its key"))
		}
		if _, dup := ks.find(id); dup {
			return nil, fmt.Errorf("key file: %w", malformed("key listed twice"))
		}
		ks = append(ks, k)
	}
	return ks, nil
}

// EncodeKeys writes a key file that ParseKeys reads back.
func EncodeKeys(pubs ...ed25519.PublicKey) ([]byte, error) {
	type entry struct {
		ID     string `json:"id"`
		Public string `json:"public"`
	}
	if len(pubs) > maxKeys {
		return nil, malformed("more than two keys")
	}
	f := struct {
		Keys []entry `json:"keys"`
	}{Keys: []entry{}}
	for _, p := range pubs {
		if len(p) != ed25519.PublicKeySize {
			return nil, malformed("public key is not 32 bytes")
		}
		f.Keys = append(f.Keys, entry{ID: KeyID(p), Public: base64.StdEncoding.EncodeToString(p)})
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// trusted parses the embedded key file once.
var trusted = sync.OnceValues(func() (KeySet, error) { return ParseKeys(embeddedKeys) })

// Trusted returns the keys compiled into this binary (S-60). A binary whose
// key file does not parse trusts nothing.
func Trusted() (KeySet, error) { return trusted() }

package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// testKey derives a fixed key from n, so failures reproduce.
func testKey(n byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize))
	return priv.Public().(ed25519.PublicKey), priv
}

func keySet(pubs ...ed25519.PublicKey) KeySet {
	var ks KeySet
	for _, p := range pubs {
		ks = append(ks, Key{ID: KeyID(p), Public: p})
	}
	return ks
}

// artifactBytes is a stand-in executable of the smallest accepted size.
var artifactBytes = bytes.Repeat([]byte("MZ-soireehost-test-"), MinArtifactSize/19+1)

func validManifest() Manifest {
	sum := sha256.Sum256(artifactBytes)
	return Manifest{
		Product:   Product,
		Channel:   Channel,
		Version:   "1.3.0",
		MinFrom:   "1.0.0",
		Published: time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC),
		Artifact: Artifact{
			Name:   ArtifactName,
			URL:    ReleaseURL + "1.3.0/" + ArtifactName,
			Size:   int64(len(artifactBytes)),
			SHA256: hex.EncodeToString(sum[:]),
		},
	}
}

func mustPayload(t testing.TB, m Manifest) []byte {
	t.Helper()
	p, err := EncodePayload(m)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	return p
}

func mustSign(t testing.TB, payload []byte, priv ed25519.PrivateKey) []byte {
	t.Helper()
	env, err := Sign(payload, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return env
}

// editEnvelope decodes an envelope into a map, lets f change it, and
// encodes it again.
func editEnvelope(t testing.TB, env []byte, f func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(env, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyAccepts(t *testing.T) {
	pub, priv := testKey(1)
	want := validManifest()
	env := mustSign(t, mustPayload(t, want), priv)
	got, err := Verify(env, keySet(pub), "1.2.0")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != want {
		t.Fatalf("Verify returned %+v, want %+v", got, want)
	}
	// a second trusted key during a rotation
	other, _ := testKey(2)
	if _, err := Verify(env, keySet(other, pub), "1.2.0"); err != nil {
		t.Fatalf("Verify with two trusted keys: %v", err)
	}
}

// TestVerifyRefusesForgeries covers S-60: tampered, wrong-key and unsigned
// manifests.
func TestVerifyRefusesForgeries(t *testing.T) {
	pub, priv := testKey(1)
	otherPub, otherPriv := testKey(2)
	payload := mustPayload(t, validManifest())
	env := mustSign(t, payload, priv)
	b64 := base64.StdEncoding.EncodeToString

	tampered := bytes.Replace(payload, []byte(`"1.3.0"`), []byte(`"9.3.0"`), 1)
	noContext := ed25519.Sign(priv, payload)

	tests := []struct {
		name string
		env  []byte
		keys KeySet
		want error
	}{
		{"tampered payload", editEnvelope(t, env, func(m map[string]any) { m["payload"] = b64(tampered) }), keySet(pub), ErrBadSignature},
		{"tampered signature", editEnvelope(t, env, func(m map[string]any) {
			s, _ := base64.StdEncoding.DecodeString(m["sig"].(string))
			s[10] ^= 1
			m["sig"] = b64(s)
		}), keySet(pub), ErrBadSignature},
		{"signed by an untrusted key", mustSign(t, payload, otherPriv), keySet(pub), ErrUnknownKey},
		{"untrusted key claiming the trusted id", editEnvelope(t, mustSign(t, payload, otherPriv), func(m map[string]any) { m["key"] = KeyID(pub) }), keySet(pub), ErrBadSignature},
		{"trusted key missing from this build", env, keySet(otherPub), ErrUnknownKey},
		{"no keys compiled in", env, nil, ErrNoKeys},
		{"signature missing", editEnvelope(t, env, func(m map[string]any) { delete(m, "sig") }), keySet(pub), ErrMalformed},
		{"signature empty", editEnvelope(t, env, func(m map[string]any) { m["sig"] = "" }), keySet(pub), ErrBadSignature},
		{"signature too short", editEnvelope(t, env, func(m map[string]any) { m["sig"] = b64(noContext[:63]) }), keySet(pub), ErrBadSignature},
		{"signature without the context prefix", editEnvelope(t, env, func(m map[string]any) { m["sig"] = b64(noContext) }), keySet(pub), ErrBadSignature},
		{"signature not base64", editEnvelope(t, env, func(m map[string]any) { m["sig"] = "!!" }), keySet(pub), ErrBadSignature},
		{"payload not canonical base64", editEnvelope(t, env, func(m map[string]any) { m["payload"] = m["payload"].(string)[:8] + "\n" + m["payload"].(string)[8:] }), keySet(pub), ErrMalformed},
		{"unknown envelope field", editEnvelope(t, env, func(m map[string]any) { m["note"] = "x" }), keySet(pub), ErrMalformed},
		{"unknown format", editEnvelope(t, env, func(m map[string]any) { m["format"] = 2 }), keySet(pub), ErrMalformed},
		{"format as text", editEnvelope(t, env, func(m map[string]any) { m["format"] = "1" }), keySet(pub), ErrMalformed},
		{"key id as number", editEnvelope(t, env, func(m map[string]any) { m["key"] = 7 }), keySet(pub), ErrMalformed},
		{"oversized", append(bytes.Repeat([]byte(" "), MaxManifestSize), env...), keySet(pub), ErrTooLarge},
		{"empty", nil, keySet(pub), ErrMalformed},
		{"not an object", []byte(`[]`), keySet(pub), ErrMalformed},
		{"data after the object", append(append([]byte{}, env...), []byte(`{}`)...), keySet(pub), ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Verify(tt.env, tt.keys, "1.2.0")
			if !errors.Is(err, tt.want) {
				t.Fatalf("Verify error = %v, want %v", err, tt.want)
			}
			if m != (Manifest{}) {
				t.Fatalf("Verify returned a manifest with %v", err)
			}
		})
	}
}

// TestVerifyRefusesTruncated covers the truncated-download case of S-60 and
// S-63 for the manifest: every prefix of a valid envelope is refused.
func TestVerifyRefusesTruncated(t *testing.T) {
	pub, priv := testKey(1)
	env := bytes.TrimSpace(mustSign(t, mustPayload(t, validManifest()), priv))
	for n := range env {
		if _, err := Verify(env[:n], keySet(pub), "1.2.0"); err == nil {
			t.Fatalf("a %d-byte prefix of a %d-byte envelope verified", n, len(env))
		}
	}
}

// TestVerifyVersions covers S-62: older and equal versions are refused, and
// min_from keeps a release from being applied over a version too old for it.
func TestVerifyVersions(t *testing.T) {
	pub, priv := testKey(1)
	env := mustSign(t, mustPayload(t, validManifest()), priv) // 1.3.0, min_from 1.0.0
	tests := []struct {
		running string
		want    error
	}{
		{"1.2.9", nil},
		{"1.3.0-rc.1", nil},
		{"1.0.0", nil},
		{"1.3.0", ErrNotNewer},
		{"1.3.1", ErrNotNewer},
		{"2.0.0", ErrNotNewer},
		{"0.9.0", ErrTooOld},
		{"1.0.0-rc.1", ErrTooOld},
		{"not-a-version", ErrNotNewer},
	}
	for _, tt := range tests {
		m, err := Verify(env, keySet(pub), tt.running)
		if !errors.Is(err, tt.want) {
			t.Errorf("running %s: error = %v, want %v", tt.running, err, tt.want)
		}
		if (errors.Is(err, ErrNotNewer) || errors.Is(err, ErrTooOld)) && tt.running != "not-a-version" && m.Version != "1.3.0" {
			t.Errorf("running %s: a refused but authentic manifest should still be returned", tt.running)
		}
	}
}

// TestVerifyRefusesPayloads signs payloads that are authentic but wrong:
// the signature alone must not be enough.
func TestVerifyRefusesPayloads(t *testing.T) {
	pub, priv := testKey(1)
	good := mustPayload(t, validManifest())
	replace := func(old, repl string) []byte {
		if !bytes.Contains(good, []byte(old)) {
			t.Fatalf("payload has no %s", old)
		}
		return bytes.Replace(good, []byte(old), []byte(repl), 1)
	}
	edit := func(f func(*Manifest)) []byte {
		m := validManifest()
		f(&m)
		b, _ := json.Marshal(m) // bypasses EncodePayload's own check
		return b
	}
	tests := []struct {
		name    string
		payload []byte
		want    error
	}{
		{"unknown field", replace(`"product"`, `"extra":1,"product"`), ErrMalformed},
		{"key in another case", replace(`"version"`, `"Version"`), ErrMalformed},
		{"key given twice", replace(`"version":"1.3.0"`, `"version":"1.3.0","version":"9.0.0"`), ErrMalformed},
		{"field missing", replace(`"channel":"stable",`, ``), ErrMalformed},
		{"data after the object", append(append([]byte{}, good...), ' ', '1'), ErrMalformed},
		{"size as a fraction", replace(fmt.Sprintf(`"size":%d`, len(artifactBytes)), `"size":1048576.5`), ErrMalformed},
		{"size as text", replace(fmt.Sprintf(`"size":%d`, len(artifactBytes)), `"size":"1048576"`), ErrMalformed},
		{"version as number", replace(`"version":"1.3.0"`, `"version":130`), ErrMalformed},
		{"null artifact", edit(func(m *Manifest) {})[:0], ErrMalformed},
		{"published not a time", replace(`"published":"2026-12-01T10:00:00Z"`, `"published":"yesterday"`), ErrMalformed},
		{"other product", edit(func(m *Manifest) { m.Product = "other" }), ErrWrongRelease},
		{"other channel", edit(func(m *Manifest) { m.Channel = "beta" }), ErrWrongRelease},
		{"invalid version", edit(func(m *Manifest) { m.Version = "v1.3.0" }), ErrWrongRelease},
		{"min_from above version", edit(func(m *Manifest) { m.MinFrom = "1.4.0" }), ErrWrongRelease},
		{"other file name", edit(func(m *Manifest) { m.Artifact.Name = "setup.exe" }), ErrWrongRelease},
		{"other repository", edit(func(m *Manifest) {
			m.Artifact.URL = strings.Replace(m.Artifact.URL, "TheAlsaadi/SoireeHost", "someone/SoireeHost", 1)
		}), ErrWrongRelease},
		{"plain http", edit(func(m *Manifest) { m.Artifact.URL = strings.Replace(m.Artifact.URL, "https:", "http:", 1) }), ErrWrongRelease},
		{"other release's file", edit(func(m *Manifest) { m.Artifact.URL = ReleaseURL + "1.2.0/" + ArtifactName }), ErrWrongRelease},
		{"too small", edit(func(m *Manifest) { m.Artifact.Size = MinArtifactSize - 1 }), ErrWrongRelease},
		{"too large", edit(func(m *Manifest) { m.Artifact.Size = MaxArtifactSize + 1 }), ErrWrongRelease},
		{"hash in capitals", edit(func(m *Manifest) { m.Artifact.SHA256 = strings.ToUpper(m.Artifact.SHA256) }), ErrWrongRelease},
		{"hash too short", edit(func(m *Manifest) { m.Artifact.SHA256 = m.Artifact.SHA256[:62] }), ErrWrongRelease},
		{"no publication time", edit(func(m *Manifest) { m.Published = time.Time{} }), ErrWrongRelease},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.payload) == 0 {
				tt.payload = []byte(`{"product":"soireehost","channel":"stable","version":"1.3.0","min_from":"1.0.0","published":"2026-12-01T10:00:00Z","artifact":null}`)
			}
			_, err := Verify(mustSign(t, tt.payload, priv), keySet(pub), "1.2.0")
			if !errors.Is(err, tt.want) {
				t.Fatalf("Verify error = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestCheckFile covers the artifact half of S-60 and the truncated
// download of S-63.
func TestCheckFile(t *testing.T) {
	a := validManifest().Artifact
	if err := CheckFile(bytes.NewReader(artifactBytes), a); err != nil {
		t.Fatalf("CheckFile on the right file: %v", err)
	}
	flipped := bytes.Clone(artifactBytes)
	flipped[len(flipped)/2] ^= 0x40
	for name, data := range map[string][]byte{
		"truncated by one byte": artifactBytes[:len(artifactBytes)-1],
		"truncated to half":     artifactBytes[:len(artifactBytes)/2],
		"empty":                 nil,
		"one byte longer":       append(bytes.Clone(artifactBytes), 0),
		"one bit changed":       flipped,
	} {
		if err := CheckFile(bytes.NewReader(data), a); !errors.Is(err, ErrArtifactMismatch) {
			t.Errorf("%s: CheckFile = %v, want ErrArtifactMismatch", name, err)
		}
	}
	bad := a
	bad.SHA256 = "zz"
	if err := CheckFile(bytes.NewReader(artifactBytes), bad); !errors.Is(err, ErrArtifactMismatch) {
		t.Errorf("malformed hash: CheckFile = %v", err)
	}
	bad = a
	bad.Size = -1
	if err := CheckFile(bytes.NewReader(artifactBytes), bad); !errors.Is(err, ErrArtifactMismatch) {
		t.Errorf("negative size: CheckFile = %v", err)
	}
}

func TestEncodePayloadRefusesInvalid(t *testing.T) {
	m := validManifest()
	m.Artifact.URL = "https://example.com/soireehost.exe"
	if _, err := EncodePayload(m); !errors.Is(err, ErrWrongRelease) {
		t.Fatalf("EncodePayload of a bad manifest = %v", err)
	}
}

func TestSignRefusesBadInput(t *testing.T) {
	_, priv := testKey(1)
	if _, err := Sign(nil, priv); err == nil {
		t.Error("Sign accepted an empty payload")
	}
	if _, err := Sign([]byte(`{}`), priv[:10]); err == nil {
		t.Error("Sign accepted a short key")
	}
	if _, err := Sign(bytes.Repeat([]byte("a"), MaxManifestSize), priv); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Sign of an oversized payload = %v", err)
	}
}

func TestParseKeys(t *testing.T) {
	p1, _ := testKey(1)
	p2, _ := testKey(2)
	p3, _ := testKey(3)
	two, err := EncodeKeys(p1, p2)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := ParseKeys(two)
	if err != nil || len(ks) != 2 || !ks[0].Public.Equal(p1) || !ks[1].Public.Equal(p2) {
		t.Fatalf("ParseKeys round trip = %v, %v", ks, err)
	}
	empty, _ := EncodeKeys()
	if ks, err := ParseKeys(empty); err != nil || len(ks) != 0 {
		t.Fatalf("ParseKeys of an empty list = %v, %v", ks, err)
	}
	if _, err := EncodeKeys(p1, p2, p3); err == nil {
		t.Error("EncodeKeys accepted three keys")
	}
	id1, b1 := KeyID(p1), base64.StdEncoding.EncodeToString(p1)
	entry := func(id, pub string) string { return fmt.Sprintf(`{"id":%q,"public":%q}`, id, pub) }
	for name, file := range map[string]string{
		"three keys":        `{"keys":[` + entry(id1, b1) + `,` + entry(KeyID(p2), base64.StdEncoding.EncodeToString(p2)) + `,` + entry(KeyID(p3), base64.StdEncoding.EncodeToString(p3)) + `]}`,
		"id of another key": `{"keys":[` + entry(KeyID(p2), b1) + `]}`,
		"short key":         `{"keys":[` + entry(id1, base64.StdEncoding.EncodeToString(p1[:31])) + `]}`,
		"key twice":         `{"keys":[` + entry(id1, b1) + `,` + entry(id1, b1) + `]}`,
		"unknown field":     `{"keys":[{"id":"` + id1 + `","public":"` + b1 + `","note":"x"}]}`,
		"keys not a list":   `{"keys":{}}`,
		"keys null":         `{"keys":null}`,
		"other top field":   `{"keys":[],"x":1}`,
		"not json":          `keys`,
	} {
		if _, err := ParseKeys([]byte(file)); err == nil {
			t.Errorf("%s: ParseKeys accepted %s", name, file)
		}
	}
}

// TestEmbeddedKeys: the committed key file parses, so a release build never
// fails open or panics on it.
func TestEmbeddedKeys(t *testing.T) {
	if _, err := Trusted(); err != nil {
		t.Fatalf("embedded keys.json does not parse: %v", err)
	}
}

func TestKeyIDIsStable(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if id := KeyID(pub); len(id) != 16 || id != KeyID(bytes.Clone(pub)) {
		t.Fatalf("KeyID = %q", id)
	}
}

func TestCode(t *testing.T) {
	for err, want := range map[error]string{
		ErrNoKeys:                              "no_keys",
		ErrBadSignature:                        "bad_signature",
		fmt.Errorf("x: %w", ErrNotNewer):       "not_newer",
		malformed("y"):                         "malformed",
		fmt.Errorf("%w: url", ErrWrongRelease): "wrong_release",
		ErrArtifactMismatch:                    "artifact_mismatch",
		errors.New("network down"):             "failed",
	} {
		if got := Code(err); got != want {
			t.Errorf("Code(%v) = %q, want %q", err, got, want)
		}
	}
}

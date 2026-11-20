// Package update verifies signed update manifests and the files they
// describe (S-60, S-62; ADR-0004). It touches no disk and no network, so
// every check here can be unit-tested and fuzzed; the supervisor downloads
// and stages, and the setup role verifies again and installs.
package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/version"
)

// Fixed values every manifest must carry.
const (
	Product      = "soireehost"
	Channel      = "stable"
	ArtifactName = "soireehost.exe"
	// ReleaseURL is the only place an artifact may come from; the version
	// and the file name follow it exactly.
	ReleaseURL = "https://github.com/TheAlsaadi/SoireeHost/releases/download/v"

	// MaxManifestSize bounds the signed envelope.
	MaxManifestSize = 64 << 10
	// MinArtifactSize and MaxArtifactSize bound the executable: the real
	// one, with cloudflared inside, is about 100 MB.
	MinArtifactSize = 1 << 20
	MaxArtifactSize = 512 << 20

	envelopeFormat = 1
	// signingContext is signed before the payload, so a signature made with
	// the update key means "this is a SoiréeHost update manifest" and
	// nothing else.
	signingContext = "soireehost-update-manifest-v1\n"
)

// Errors, one per kind of refusal. Code maps them to the closed set of
// problem codes the supervisor reports; no upstream text is ever shown.
var (
	ErrNoKeys           = errors.New("this build trusts no update key")
	ErrTooLarge         = errors.New("manifest is too large")
	ErrMalformed        = errors.New("manifest is malformed")
	ErrUnknownKey       = errors.New("manifest is signed with a key this build does not trust")
	ErrBadSignature     = errors.New("manifest signature is not valid")
	ErrWrongRelease     = errors.New("manifest does not describe a SoiréeHost release")
	ErrNotNewer         = errors.New("update is not newer than the running version")
	ErrTooOld           = errors.New("running version is too old to update to this release")
	ErrArtifactMismatch = errors.New("downloaded file does not match the manifest")
)

func malformed(why string) error { return fmt.Errorf("%w: %s", ErrMalformed, why) }

// Code returns the problem code for an error from this package, or
// "failed" for any other.
func Code(err error) string {
	for _, c := range []struct {
		err  error
		code string
	}{
		{ErrNoKeys, "no_keys"},
		{ErrTooLarge, "too_large"},
		{ErrMalformed, "malformed"},
		{ErrUnknownKey, "unknown_key"},
		{ErrBadSignature, "bad_signature"},
		{ErrWrongRelease, "wrong_release"},
		{ErrNotNewer, "not_newer"},
		{ErrTooOld, "too_old"},
		{ErrArtifactMismatch, "artifact_mismatch"},
	} {
		if errors.Is(err, c.err) {
			return c.code
		}
	}
	return "failed"
}

// Artifact is the file a manifest describes.
type Artifact struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest is a verified update manifest's payload.
type Manifest struct {
	Product   string    `json:"product"`
	Channel   string    `json:"channel"`
	Version   string    `json:"version"`
	MinFrom   string    `json:"min_from"`
	Published time.Time `json:"published"`
	Artifact  Artifact  `json:"artifact"`
}

// Check reports whether m describes a SoiréeHost release, independently of
// the running version: product, channel, versions, file name, URL, size and
// hash format.
func (m Manifest) Check() error {
	switch {
	case m.Product != Product, m.Channel != Channel:
		return fmt.Errorf("%w: product or channel", ErrWrongRelease)
	case !version.Valid(m.Version), !version.Valid(m.MinFrom):
		return fmt.Errorf("%w: version", ErrWrongRelease)
	case m.Published.IsZero():
		return fmt.Errorf("%w: publication time", ErrWrongRelease)
	case m.Artifact.Name != ArtifactName:
		return fmt.Errorf("%w: file name", ErrWrongRelease)
	case m.Artifact.URL != ReleaseURL+m.Version+"/"+ArtifactName:
		return fmt.Errorf("%w: download address", ErrWrongRelease)
	case m.Artifact.Size < MinArtifactSize, m.Artifact.Size > MaxArtifactSize:
		return fmt.Errorf("%w: file size", ErrWrongRelease)
	case !lowerHex(m.Artifact.SHA256, sha256.Size):
		return fmt.Errorf("%w: file hash", ErrWrongRelease)
	}
	if c, err := version.Compare(m.MinFrom, m.Version); err != nil || c > 0 {
		return fmt.Errorf("%w: min_from is above the version", ErrWrongRelease)
	}
	return nil
}

func lowerHex(s string, n int) bool {
	if len(s) != 2*n {
		return false
	}
	for i := range len(s) {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// Verify checks a signed envelope against keys and the running version, and
// returns its manifest. The signature is checked before the payload is
// decoded. With ErrNotNewer or ErrTooOld the manifest is also returned: its
// signature is valid, it just is not an update for this version. Any other
// error returns no manifest.
func Verify(envelope []byte, keys KeySet, running string) (Manifest, error) {
	payload, err := Open(envelope, keys)
	if err != nil {
		return Manifest{}, err
	}
	m, err := DecodePayload(payload)
	if err != nil {
		return Manifest{}, err
	}
	if err := m.Check(); err != nil {
		return Manifest{}, err
	}
	newer, err := version.Compare(m.Version, running)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: running version", ErrNotNewer)
	}
	if newer <= 0 {
		return m, ErrNotNewer // S-62: older and equal versions are refused
	}
	if c, _ := version.Compare(running, m.MinFrom); c < 0 {
		return m, ErrTooOld
	}
	return m, nil
}

// Open checks an envelope's signature and returns the signed payload bytes.
func Open(envelope []byte, keys KeySet) ([]byte, error) {
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}
	if len(envelope) > MaxManifestSize {
		return nil, ErrTooLarge
	}
	f, err := object(envelope, "format", "key", "payload", "sig")
	if err != nil {
		return nil, err
	}
	if n, err := integer(f["format"]); err != nil || n != envelopeFormat {
		return nil, malformed("unknown format")
	}
	id, err := text(f["key"])
	if err != nil {
		return nil, err
	}
	k, ok := keys.find(id)
	if !ok {
		return nil, ErrUnknownKey
	}
	p, err := text(f["payload"])
	if err != nil {
		return nil, err
	}
	payload, err := unbase64(p)
	if err != nil {
		return nil, err
	}
	s, err := text(f["sig"])
	if err != nil {
		return nil, err
	}
	sig, err := unbase64(s)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrBadSignature
	}
	if !ed25519.Verify(k.Public, signedMessage(payload), sig) {
		return nil, ErrBadSignature
	}
	return payload, nil
}

// signedMessage is what the key signs: the context, then the payload. Both
// callers bound the payload by MaxManifestSize first.
func signedMessage(payload []byte) []byte {
	return append([]byte(signingContext), payload...)
}

// DecodePayload decodes a payload strictly: exactly the manifest's fields,
// each of its JSON type, nothing else.
func DecodePayload(payload []byte) (Manifest, error) {
	f, err := object(payload, "product", "channel", "version", "min_from", "published", "artifact")
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	for name, dst := range map[string]*string{
		"product": &m.Product, "channel": &m.Channel, "version": &m.Version, "min_from": &m.MinFrom,
	} {
		if *dst, err = text(f[name]); err != nil {
			return Manifest{}, err
		}
	}
	pub, err := text(f["published"])
	if err != nil {
		return Manifest{}, err
	}
	if m.Published, err = time.Parse(time.RFC3339, pub); err != nil {
		return Manifest{}, malformed("published is not an RFC 3339 time")
	}
	a, err := object(f["artifact"], "name", "url", "size", "sha256")
	if err != nil {
		return Manifest{}, err
	}
	for name, dst := range map[string]*string{
		"name": &m.Artifact.Name, "url": &m.Artifact.URL, "sha256": &m.Artifact.SHA256,
	} {
		if *dst, err = text(a[name]); err != nil {
			return Manifest{}, err
		}
	}
	if m.Artifact.Size, err = integer(a["size"]); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// EncodePayload writes a manifest's payload. It refuses a manifest that
// Check refuses, so the signing tool cannot publish one the app would
// reject.
func EncodePayload(m Manifest) ([]byte, error) {
	m.Published = m.Published.UTC().Truncate(time.Second)
	if err := m.Check(); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// Sign wraps payload in an envelope signed with priv.
func Sign(payload []byte, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key is not an Ed25519 private key")
	}
	if len(payload) == 0 {
		return nil, malformed("empty payload")
	}
	// the envelope's base64 is a third larger, so a payload this size can
	// never fit; refusing it here keeps every signed message bounded
	if len(payload) > MaxManifestSize {
		return nil, ErrTooLarge
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	env := struct {
		Format  int    `json:"format"`
		Key     string `json:"key"`
		Payload string `json:"payload"`
		Sig     string `json:"sig"`
	}{
		Format:  envelopeFormat,
		Key:     KeyID(pub),
		Payload: base64.StdEncoding.EncodeToString(payload),
		Sig:     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signedMessage(payload))),
	}
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(b) > MaxManifestSize {
		return nil, ErrTooLarge
	}
	return append(b, '\n'), nil
}

// CheckFile reads r to its end, up to one byte past the expected size, and
// reports whether it is exactly the artifact: the signed size and SHA-256
// (S-60, S-63). A short, long or different file is ErrArtifactMismatch.
func CheckFile(r io.Reader, a Artifact) error {
	if a.Size < 0 || a.Size > MaxArtifactSize {
		return ErrArtifactMismatch
	}
	want, err := hex.DecodeString(a.SHA256)
	if err != nil || len(want) != sha256.Size {
		return ErrArtifactMismatch
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, a.Size+1))
	if err != nil {
		return fmt.Errorf("reading the file: %w", err)
	}
	if n != a.Size || subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		return ErrArtifactMismatch
	}
	return nil
}

// ManifestURL is where the supervisor looks for the newest release's
// manifest (owner decision, 16 Nov 2026: GitHub Releases).
const ManifestURL = "https://github.com/TheAlsaadi/SoireeHost/releases/latest/download/manifest.json"

// Hosts are the only hosts the update check may connect to, redirects
// included. Settings lists them as SoiréeHost's update connection (S-42).
var Hosts = []string{"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}

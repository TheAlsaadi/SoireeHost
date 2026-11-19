// Command signmanifest writes the signed update manifest for a release
// build (S-60, ADR-0004). It runs in the release workflow's manifest job and
// reads the private key only from the UPDATE_SIGNING_KEY environment
// variable, never from an argument.
//
//	go run ./build/signmanifest -exe bin/soireehost.exe -version 1.3.0 -min-from 1.0.0 -out dist/manifest.json
//
// Before writing, it checks that the executable embeds exactly the
// committed key file (so a build with test keys is never signed), and it
// verifies the result with the same code the app runs.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/update"
)

// keyEnv names the environment variable holding the private key.
const keyEnv = "UPDATE_SIGNING_KEY"

type options struct {
	exe, version, minFrom, out string
	keys                       string // the key set the result must verify against
	embedded                   string // the committed key file the exe must contain
	published                  time.Time
}

func main() {
	if err := run(os.Args[1:], os.Getenv(keyEnv), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "signmanifest:", err)
		os.Exit(1)
	}
}

func run(args []string, key string, out io.Writer) error {
	fs := flag.NewFlagSet("signmanifest", flag.ContinueOnError)
	var o options
	var published string
	fs.StringVar(&o.exe, "exe", "", "the release executable")
	fs.StringVar(&o.version, "version", "", "the release version, without v")
	fs.StringVar(&o.minFrom, "min-from", "", "the oldest version that may update to this one")
	fs.StringVar(&o.out, "out", "", "where to write manifest.json")
	fs.StringVar(&o.keys, "keys", "internal/update/keys.json", "the key file the manifest must verify against")
	fs.StringVar(&o.embedded, "embedded", "internal/update/keys.json", "the committed key file the executable must embed")
	fs.StringVar(&published, "published", "", "publication time, RFC 3339 (default: now)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if o.exe == "" || o.version == "" || o.minFrom == "" || o.out == "" {
		return errors.New("-exe, -version, -min-from and -out are required")
	}
	o.published = time.Now().UTC()
	if published != "" {
		t, err := time.Parse(time.RFC3339, published)
		if err != nil {
			return fmt.Errorf("-published: %w", err)
		}
		o.published = t
	}
	if key == "" {
		return fmt.Errorf("%s is not set", keyEnv)
	}
	priv, err := update.ParsePrivateKey(key)
	if err != nil {
		return err
	}
	env, m, err := sign(o, priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(o.out, env, 0o644); err != nil { // #nosec G306 G703 -- the release workflow's own -out path; a public release file
		return err
	}
	_, err = fmt.Fprintf(out, "Signed %s %s (%d bytes, sha256 %s) with key %s.\n",
		m.Artifact.Name, m.Version, m.Artifact.Size, m.Artifact.SHA256, update.KeyID(priv.Public().(ed25519.PublicKey)))
	return err
}

// sign builds, signs and re-verifies the manifest for o.exe.
func sign(o options, priv ed25519.PrivateKey) ([]byte, update.Manifest, error) {
	exe, err := os.ReadFile(o.exe) // #nosec G304 -- the build output named by the workflow
	if err != nil {
		return nil, update.Manifest{}, err
	}
	committed, err := os.ReadFile(o.embedded) // #nosec G304 -- a repository file
	if err != nil {
		return nil, update.Manifest{}, err
	}
	if _, err := update.ParseKeys(committed); err != nil {
		return nil, update.Manifest{}, err
	}
	if !bytes.Contains(exe, committed) {
		return nil, update.Manifest{}, fmt.Errorf("%s does not embed %s byte for byte; it may have been built with test keys", o.exe, o.embedded)
	}
	keysFile, err := os.ReadFile(o.keys) // #nosec G304 -- a repository file, or the dry run's own key file
	if err != nil {
		return nil, update.Manifest{}, err
	}
	keys, err := update.ParseKeys(keysFile)
	if err != nil {
		return nil, update.Manifest{}, err
	}
	sum := sha256.Sum256(exe)
	m := update.Manifest{
		Product:   update.Product,
		Channel:   update.Channel,
		Version:   o.version,
		MinFrom:   o.minFrom,
		Published: o.published,
		Artifact: update.Artifact{
			Name:   update.ArtifactName,
			URL:    update.ReleaseURL + o.version + "/" + update.ArtifactName,
			Size:   int64(len(exe)),
			SHA256: hex.EncodeToString(sum[:]),
		},
	}
	payload, err := update.EncodePayload(m)
	if err != nil {
		return nil, update.Manifest{}, err
	}
	env, err := update.Sign(payload, priv)
	if err != nil {
		return nil, update.Manifest{}, err
	}
	// Verify with the app's own code: the key must be one the key file
	// trusts, and the file must match what was signed.
	signed, err := update.Open(env, keys)
	if err != nil {
		return nil, update.Manifest{}, fmt.Errorf("the new manifest does not verify against %s: %w", o.keys, err)
	}
	got, err := update.DecodePayload(signed)
	if err != nil {
		return nil, update.Manifest{}, err
	}
	if err := got.Check(); err != nil {
		return nil, update.Manifest{}, err
	}
	if err := update.CheckFile(bytes.NewReader(exe), got.Artifact); err != nil {
		return nil, update.Manifest{}, err
	}
	return env, got, nil
}

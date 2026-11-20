package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/update"
)

func keyPair(n byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize))
	return priv.Public().(ed25519.PublicKey), priv
}

// fixture writes a key file trusting pub and a fake executable that embeds
// the committed key file (embeds says whether it does).
func fixture(t *testing.T, pub ed25519.PublicKey, embeds bool) options {
	t.Helper()
	dir := t.TempDir()
	keys, err := update.EncodeKeys(pub)
	if err != nil {
		t.Fatal(err)
	}
	committed, _ := update.EncodeKeys()
	o := options{
		exe:       filepath.Join(dir, "soireehost.exe"),
		version:   "1.3.0",
		minFrom:   "1.0.0",
		out:       filepath.Join(dir, "manifest.json"),
		keys:      filepath.Join(dir, "keys.json"),
		embedded:  filepath.Join(dir, "committed.json"),
		published: time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC),
	}
	exe := bytes.Repeat([]byte{0x90}, update.MinArtifactSize)
	if embeds {
		exe = append(append(exe[:1000:1000], committed...), exe[1000:]...)
	}
	for p, b := range map[string][]byte{o.exe: exe, o.keys: keys, o.embedded: committed} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return o
}

func TestSignVerifies(t *testing.T) {
	pub, priv := keyPair(1)
	o := fixture(t, pub, true)
	env, m, err := sign(o, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := update.Verify(env, update.KeySet{{ID: update.KeyID(pub), Public: pub}}, "1.2.0")
	if err != nil || got != m {
		t.Fatalf("the app's Verify = %+v, %v", got, err)
	}
	exe, _ := os.ReadFile(o.exe)
	if err := update.CheckFile(bytes.NewReader(exe), got.Artifact); err != nil {
		t.Fatalf("the executable does not match its manifest: %v", err)
	}
}

func TestSignRefuses(t *testing.T) {
	pub, priv := keyPair(1)
	_, other := keyPair(2)
	t.Run("executable without the committed keys", func(t *testing.T) {
		if _, _, err := sign(fixture(t, pub, false), priv); err == nil {
			t.Fatal("signed a build that does not embed the committed key file")
		}
	})
	t.Run("key the key file does not trust", func(t *testing.T) {
		_, _, err := sign(fixture(t, pub, true), other)
		if !errors.Is(err, update.ErrUnknownKey) {
			t.Fatalf("sign with an untrusted key = %v", err)
		}
	})
	t.Run("invalid version", func(t *testing.T) {
		o := fixture(t, pub, true)
		o.version = "v1.3.0"
		if _, _, err := sign(o, priv); err == nil {
			t.Fatal("signed an invalid version")
		}
	})
	t.Run("min-from above version", func(t *testing.T) {
		o := fixture(t, pub, true)
		o.minFrom = "2.0.0"
		if _, _, err := sign(o, priv); err == nil {
			t.Fatal("signed min_from above the version")
		}
	})
}

func TestRunReadsKeyOnlyFromEnvironment(t *testing.T) {
	pub, priv := keyPair(1)
	o := fixture(t, pub, true)
	args := []string{"-exe", o.exe, "-version", "1.3.0", "-min-from", "1.0.0", "-out", o.out, "-keys", o.keys, "-embedded", o.embedded}
	if err := run(args, "", io.Discard); err == nil || !strings.Contains(err.Error(), keyEnv) {
		t.Fatalf("run without %s = %v", keyEnv, err)
	}
	if err := run(args, "garbage-key", io.Discard); err == nil || strings.Contains(err.Error(), "garbage-key") {
		t.Fatalf("run with a malformed key = %v (must fail without echoing it)", err)
	}
	var out bytes.Buffer
	key := update.EncodePrivateKey(priv)
	if err := run(args, key, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out.String(), key) {
		t.Fatal("run printed the private key")
	}
	if _, err := os.Stat(o.out); err != nil {
		t.Fatalf("no manifest written: %v", err)
	}
}

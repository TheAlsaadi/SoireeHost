// Command updatekey makes and checks the Ed25519 key that signs update
// manifests (S-60, ADR-0004, docs/UPDATE_KEY.md). It runs on the owner's PC
// and needs no administrator rights.
//
//	go run ./build/updatekey gen -out D:\keys\soireehost-update.key
//	go run ./build/updatekey check -key D:\keys\soireehost-update.key
//
// gen writes the private key to -out, which must be outside the repository
// and must not exist yet, and adds the public key to
// internal/update/keys.json. check confirms that a private key's public half
// is in keys.json. The private key is never printed.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/TheAlsaadi/SoireeHost/internal/update"
)

const defaultKeys = "internal/update/keys.json"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "updatekey:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: updatekey gen -out PATH | check -key PATH")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	keys := fs.String("keys", defaultKeys, "the public key file the app embeds")
	switch args[0] {
	case "gen":
		dst := fs.String("out", "", "where to write the new private key (outside the repository)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		root, err := repoRoot()
		if err != nil {
			return err
		}
		id, err := gen(*dst, *keys, root)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "New update key %s.\nPrivate key written to %s. Store it as the release environment secret UPDATE_SIGNING_KEY, keep an offline backup, then delete this file.\nPublic key added to %s; commit that file.\n", id, *dst, *keys)
		return err
	case "check":
		src := fs.String("key", "", "the private key file to check")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		id, err := check(*src, *keys)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "Key %s is trusted by %s.\n", id, *keys)
		return err
	}
	return fmt.Errorf("unknown command %q", args[0])
}

// gen creates a key pair, writes the private key to dst (outside root, never
// over an existing file) and adds the public key to the key file.
func gen(dst, keysPath, root string) (string, error) {
	if dst == "" {
		return "", errors.New("-out is required")
	}
	abs, err := filepath.Abs(dst)
	if err != nil {
		return "", err
	}
	if inside(abs, root) {
		return "", fmt.Errorf("refusing to write a private key inside the repository (%s); choose a folder outside it", root)
	}
	existing, err := readKeys(keysPath)
	if err != nil {
		return "", err
	}
	if len(existing) >= 2 {
		return "", errors.New("keys.json already holds two keys; remove the retired one first (docs/UPDATE_KEY.md)")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	pubs := make([]ed25519.PublicKey, 0, len(existing)+1)
	for _, k := range existing {
		pubs = append(pubs, k.Public)
	}
	keysFile, err := update.EncodeKeys(append(pubs, pub)...)
	if err != nil {
		return "", err
	}
	// O_EXCL: an existing key file is never overwritten, so a slip of the
	// path cannot destroy the only copy of an older key
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 G703 -- the owner's own -out path, checked to be outside the repository
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(update.EncodePrivateKey(priv) + "\n"); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.WriteFile(keysPath, keysFile, 0o644); err != nil { // #nosec G306 G703 -- the owner's own -keys path; public keys, committed
		return "", err
	}
	return update.KeyID(pub), nil
}

// check reads a private key and reports its id if keys.json trusts it.
func check(src, keysPath string) (string, error) {
	b, err := os.ReadFile(src) // #nosec G304 G703 -- the owner's own -key path
	if err != nil {
		return "", err
	}
	priv, err := update.ParsePrivateKey(string(b))
	if err != nil {
		return "", err
	}
	ks, err := readKeys(keysPath)
	if err != nil {
		return "", err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	id := update.KeyID(pub)
	for _, k := range ks {
		if k.ID == id && k.Public.Equal(pub) {
			return id, nil
		}
	}
	return "", fmt.Errorf("key %s is not in %s", id, keysPath)
}

func readKeys(path string) (update.KeySet, error) {
	b, err := os.ReadFile(path) // #nosec G304 G703 -- the owner's own -keys path
	if err != nil {
		return nil, err
	}
	return update.ParseKeys(b)
}

// repoRoot is the nearest folder above the working directory holding go.mod.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("run updatekey from inside the repository")
		}
		dir = parent
	}
}

// inside reports whether path is root or below it, ignoring case as
// Windows does.
func inside(path, root string) bool {
	rel, err := filepath.Rel(strings.ToLower(root), strings.ToLower(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

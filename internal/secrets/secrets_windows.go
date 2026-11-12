// Package secrets stores secrets encrypted with DPAPI under the account that
// runs the supervisor (S-40). Values are write-only from the outside: the
// store can set, check and remove a secret, and only the supervisor's own
// code reads one back (S-35).
package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/fsutil"
)

// TunnelToken is the name of the Cloudflare tunnel token secret.
const TunnelToken = "tunnel_token"

// MaxValueLen bounds a secret's size. A tunnel token is a few hundred bytes.
const MaxValueLen = 16 << 10

// entropy binds every blob to SoiréeHost: another program running as the same
// account cannot decrypt it without also knowing this value. It is not a
// secret key; DPAPI's protection is the account.
var entropy = []byte("SoireeHost secret v1")

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// Store is a folder of DPAPI blobs.
type Store struct {
	dir string
	now func() time.Time
}

// Status says whether a secret is set and when, never what it is.
type Status struct {
	Name  string    `json:"name"`
	Set   bool      `json:"set"`
	SetAt time.Time `json:"set_at,omitzero"`
}

// Open returns the store in dir, which must already exist.
func Open(dir string) (*Store, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("secrets folder: %w", err)
	}
	if !fi.IsDir() {
		return nil, errors.New("secrets folder is not a folder")
	}
	return &Store{dir: dir, now: time.Now}, nil
}

func validName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid secret name %q", name)
	}
	return nil
}

func (s *Store) blobPath(name string) string { return filepath.Join(s.dir, name+".bin") }
func (s *Store) metaPath(name string) string { return filepath.Join(s.dir, name+".json") }

// Set encrypts value and stores it, replacing any earlier value.
func (s *Store) Set(name string, value []byte) error {
	if err := validName(name); err != nil {
		return err
	}
	if len(value) == 0 || len(value) > MaxValueLen {
		return fmt.Errorf("a secret must be 1 to %d bytes", MaxValueLen)
	}
	blob, err := protect(value)
	if err != nil {
		return err
	}
	if err := fsutil.WriteAtomic(s.blobPath(name), blob); err != nil {
		return err
	}
	meta, err := json.Marshal(struct {
		SetAt time.Time `json:"set_at"`
	}{s.now().UTC()})
	if err != nil {
		return err
	}
	return fsutil.WriteAtomic(s.metaPath(name), meta)
}

// Get decrypts a secret. Only the supervisor's own code calls this, to hand
// the value to the worker that needs it; no control-API method returns it.
func (s *Store) Get(name string) ([]byte, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	blob, err := os.ReadFile(s.blobPath(name))
	if err != nil {
		return nil, fmt.Errorf("secret %s: %w", name, err)
	}
	return unprotect(blob)
}

// Status reports whether name is set and when.
func (s *Store) Status(name string) (Status, error) {
	if err := validName(name); err != nil {
		return Status{}, err
	}
	st := Status{Name: name}
	if _, err := os.Stat(s.blobPath(name)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, nil
		}
		return Status{}, err
	}
	st.Set = true
	if b, err := os.ReadFile(s.metaPath(name)); err == nil {
		var m struct {
			SetAt time.Time `json:"set_at"`
		}
		if json.Unmarshal(b, &m) == nil {
			st.SetAt = m.SetAt
		}
	}
	return st, nil
}

// Remove deletes a secret. Removing one that is not set is not an error.
func (s *Store) Remove(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	for _, p := range []string{s.blobPath(name), s.metaPath(name)} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func blobOf(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]} // #nosec G115 -- lengths are bounded by MaxValueLen
}

func protect(plain []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptProtectData(blobOf(plain), nil, blobOf(entropy), 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("encrypting secret: %w", err)
	}
	return takeBlob(&out), nil
}

func unprotect(blob []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blobOf(blob), nil, blobOf(entropy), 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("decrypting secret: %w", err)
	}
	return takeBlob(&out), nil
}

// takeBlob copies a DPAPI output buffer into Go memory, wipes it and frees it.
func takeBlob(b *windows.DataBlob) []byte {
	// #nosec G103 -- DPAPI returns a LocalAlloc buffer of b.Size bytes at b.Data
	src := unsafe.Slice(b.Data, b.Size)
	out := make([]byte, len(src))
	copy(out, src)
	clear(src)
	// #nosec G103 -- freeing the buffer DPAPI allocated, as its documentation requires
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	return out
}

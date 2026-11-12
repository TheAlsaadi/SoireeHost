package worker

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"

	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
)

func init() {
	caddy.RegisterModule(RootFS{})
}

// blockedLocations reads the Windows known folders once per process; they do
// not move while the worker runs.
var blockedLocations = sync.OnceValues(sitecheck.DefaultLocations)

// RootFS is the file system behind every static site (S-11, S-12, S-13). It
// is an os.Root opened on the checked site folder, so no name and no symbolic
// link or junction can reach outside the folder. Names that the path rules
// refuse are reported as not existing, special files are hidden, and
// directory listings leave refused names out.
type RootFS struct {
	Root string `json:"root"`
	// AllowWellKnown serves /.well-known/ (the site's opt-in). The folder
	// itself is still left out of directory listings.
	AllowWellKnown bool `json:"allow_well_known,omitempty"`

	root *os.Root
}

// CaddyModule returns the Caddy module information.
func (RootFS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.fs.soireehost_root",
		New: func() caddy.Module { return new(RootFS) },
	}
}

// Provision resolves, checks and opens the folder.
func (rfs *RootFS) Provision(caddy.Context) error {
	loc, err := blockedLocations()
	if err != nil {
		return err
	}
	r, err := sitecheck.OpenRoot(rfs.Root, loc)
	if err != nil {
		return fmt.Errorf("site folder %s: %w", rfs.Root, err)
	}
	rfs.root = r
	return nil
}

// Cleanup closes the folder.
func (rfs *RootFS) Cleanup() error {
	if rfs.root != nil {
		return rfs.root.Close()
	}
	return nil
}

func notExist(op, name string) error {
	return &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
}

// clean turns the OS-style relative name Caddy passes in into an fs.FS name,
// and refuses any name the static path rules refuse.
func (rfs *RootFS) clean(name string) (string, bool) {
	n := filepath.ToSlash(name)
	n = strings.TrimPrefix(n, "./")
	n = strings.TrimSuffix(n, "/")
	if n == "" || n == "." {
		return ".", true
	}
	if !fs.ValidPath(n) {
		return "", false
	}
	for i, seg := range strings.Split(n, "/") {
		if i == 0 && rfs.AllowWellKnown && seg == sitecheck.WellKnown {
			continue
		}
		if !sitecheck.CheckName(seg) {
			return "", false
		}
	}
	return n, true
}

// Open implements fs.FS.
func (rfs *RootFS) Open(name string) (fs.File, error) {
	n, ok := rfs.clean(name)
	if !ok {
		return nil, notExist("open", name)
	}
	f, err := rfs.root.Open(n)
	if err != nil {
		// escapes, links out of the root, device names and permission
		// problems all look like a missing file to the visitor
		return nil, notExist("open", name)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, notExist("open", name)
	}
	switch {
	case info.Mode().IsRegular():
		return f, nil
	case info.IsDir():
		return &dirFile{f: f}, nil
	default:
		_ = f.Close()
		return nil, notExist("open", name)
	}
}

// Stat implements fs.StatFS.
func (rfs *RootFS) Stat(name string) (fs.FileInfo, error) {
	n, ok := rfs.clean(name)
	if !ok {
		return nil, notExist("stat", name)
	}
	info, err := rfs.root.Stat(n)
	if err != nil || (!info.Mode().IsRegular() && !info.IsDir()) {
		return nil, notExist("stat", name)
	}
	return info, nil
}

// dirFile filters directory listings. It wraps the *os.File instead of
// embedding it, so the unfiltered Readdir and Readdirnames are not reachable.
type dirFile struct {
	f *os.File
}

func (d *dirFile) Stat() (fs.FileInfo, error) { return d.f.Stat() }
func (d *dirFile) Read(p []byte) (int, error) { return d.f.Read(p) }
func (d *dirFile) Close() error               { return d.f.Close() }

// ReadDir implements fs.ReadDirFile. Entries the path rules refuse, and
// anything that is not a plain file or folder (links, junctions, devices),
// are left out.
func (d *dirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if n <= 0 {
		entries, err := d.f.ReadDir(-1)
		return filterEntries(entries), err
	}
	for {
		// os.File.ReadDir(n) returns either some entries and a nil error, or
		// none and an error (io.EOF at the end). Keep reading while a whole
		// batch was filtered away, so an empty result always carries an error
		// as fs.ReadDirFile requires.
		entries, err := d.f.ReadDir(n)
		out := filterEntries(entries)
		if len(out) > 0 || err != nil {
			return out, err
		}
	}
}

func filterEntries(entries []fs.DirEntry) []fs.DirEntry {
	out := entries[:0]
	for _, e := range entries {
		t := e.Type()
		if (t.IsRegular() || t.IsDir()) && sitecheck.CheckName(e.Name()) {
			out = append(out, e)
		}
	}
	return out
}

var (
	_ fs.StatFS          = (*RootFS)(nil)
	_ caddy.Provisioner  = (*RootFS)(nil)
	_ caddy.CleanerUpper = (*RootFS)(nil)
	_ fs.ReadDirFile     = (*dirFile)(nil)
)

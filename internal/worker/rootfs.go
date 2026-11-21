package worker

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"golang.org/x/sys/windows"

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
//
// The name rules are applied twice: to the name asked for, and to the name
// of what was actually opened (Phase 7 compliance review, 21 Nov 2026). A
// link inside the folder (config.json -> .env), or a name the file system
// matches to another under its own case rules, would otherwise open a file
// the rules refuse by its real name. A file with a second hard link is
// refused too, since its other names cannot be checked.
type RootFS struct {
	Root string `json:"root"`
	// AllowWellKnown serves /.well-known/ (the site's opt-in). The folder
	// itself is still left out of directory listings.
	AllowWellKnown bool `json:"allow_well_known,omitempty"`

	root *os.Root
	// real is the site folder's path as Windows reports it for an open
	// handle, the prefix of every opened file's real path
	real string
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
	d, err := r.Open(".")
	if err != nil {
		_ = r.Close()
		return fmt.Errorf("site folder %s: %w", rfs.Root, err)
	}
	real, err := finalPath(d)
	_ = d.Close()
	if err != nil {
		_ = r.Close()
		return fmt.Errorf("site folder %s: %w", rfs.Root, err)
	}
	rfs.root, rfs.real = r, real
	return nil
}

// finalPath is the path Windows reports for an open file: links resolved,
// in the form and case the file system stores.
func finalPath(f *os.File) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	// flags 0: FILE_NAME_NORMALIZED, VOLUME_NAME_DOS
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(f.Fd()), &buf[0], uint32(len(buf)), 0)
	if err != nil {
		return "", err
	}
	if int(n) >= len(buf) {
		return "", fmt.Errorf("path longer than %d characters", len(buf))
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// opened reports whether f, opened under name, may be served: its real path
// is inside the site folder and every segment of it passes the name rules,
// and a plain file has no other hard link.
func (rfs *RootFS) opened(f *os.File, info fs.FileInfo) bool {
	p, err := finalPath(f)
	if err != nil {
		return false
	}
	if len(p) < len(rfs.real) || !strings.EqualFold(p[:len(rfs.real)], rfs.real) {
		return false
	}
	rest := p[len(rfs.real):]
	if rest == "" {
		return info.IsDir()
	}
	if rest[0] != '\\' {
		return false
	}
	if _, ok := rfs.clean(rest[1:]); !ok {
		return false
	}
	if info.Mode().IsRegular() {
		var d windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &d) != nil || d.NumberOfLinks != 1 {
			return false
		}
	}
	return true
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
	if err != nil || !rfs.opened(f, info) {
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

// Stat implements fs.StatFS. It opens the file, so it applies exactly the
// checks Open does.
func (rfs *RootFS) Stat(name string) (fs.FileInfo, error) {
	f, err := rfs.Open(name)
	if err != nil {
		return nil, notExist("stat", name)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
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

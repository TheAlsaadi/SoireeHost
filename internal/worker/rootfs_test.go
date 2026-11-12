package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
)

func provisionedRootFS(t *testing.T) (*RootFS, string) {
	t.Helper()
	base := testutil.SiteDir(t)
	root := filepath.Join(base, "site")
	writeFile(t, filepath.Join(root, "index.html"), "INDEX")
	writeFile(t, filepath.Join(root, "dir", "a.txt"), "A")
	writeFile(t, filepath.Join(root, "dir", ".env"), secretMarker)
	writeFile(t, filepath.Join(root, "dir", "id.key"), secretMarker)
	writeFile(t, filepath.Join(base, "outside", "secret.txt"), secretMarker)
	testutil.Junction(t, filepath.Join(root, "dir", "out"), filepath.Join(base, "outside"))
	rfs := &RootFS{Root: root}
	if err := rfs.Provision(caddyContext()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rfs.Cleanup() })
	return rfs, root
}

func TestRootFSOpenAndStat(t *testing.T) {
	rfs, _ := provisionedRootFS(t)
	for _, name := range []string{"index.html", `dir\a.txt`, "dir/a.txt", "./index.html"} {
		f, err := rfs.Open(name)
		if err != nil {
			t.Errorf("Open(%q): %v", name, err)
			continue
		}
		_ = f.Close()
		if _, err := rfs.Stat(name); err != nil {
			t.Errorf("Stat(%q): %v", name, err)
		}
	}
	for _, name := range []string{".", "dir", `dir\`} {
		if info, err := rfs.Stat(name); err != nil || !info.IsDir() {
			t.Errorf("Stat(%q) = %v, %v", name, info, err)
		}
	}
	refused := []string{
		`dir\.env`, "dir/id.key", `dir\out\secret.txt`, `dir\out`, `..\outside\secret.txt`, "../outside/secret.txt",
		`C:\Windows\win.ini`, "/index.html", "NUL", "dir/CON", "index.html::$DATA", "INDEX~1.HTM", "missing.txt",
	}
	for _, name := range refused {
		if f, err := rfs.Open(name); err == nil {
			b, _ := io.ReadAll(f)
			_ = f.Close()
			t.Errorf("Open(%q) succeeded: %q", name, b)
		} else if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Open(%q) error %v is not ErrNotExist (would become a 500)", name, err)
		}
		if _, err := rfs.Stat(name); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Stat(%q) = %v, want ErrNotExist", name, err)
		}
	}
}

func TestRootFSListingFiltered(t *testing.T) {
	rfs, _ := provisionedRootFS(t)
	f, err := rfs.Open("dir")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	d, ok := f.(fs.ReadDirFile)
	if !ok {
		t.Fatalf("directory is %T, not fs.ReadDirFile", f)
	}
	var names []string
	for {
		entries, err := d.ReadDir(1)
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) == 0 {
			t.Fatal("ReadDir(1) returned no entries and no error")
		}
	}
	if !slices.Equal(names, []string{"a.txt"}) {
		t.Fatalf("listing = %v, want only a.txt (no dotfile, key or junction)", names)
	}
}

func TestRootFSRefusesBlockedFolder(t *testing.T) {
	loc, err := testLocations()
	if err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{loc.Windows, loc.ProgramFiles[0], `C:\`} {
		rfs := &RootFS{Root: root}
		if err := rfs.Provision(caddyContext()); err == nil {
			_ = rfs.Cleanup()
			t.Errorf("provisioned %s", root)
		}
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	c := config.Default()
	c.Listen = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, Options{LogDir: logDir}) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := dial(t, c.Listen, time.Second)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not start listening")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	// Caddy closes its listeners while shutting the server down; allow a
	// moment for that before calling it a failure
	deadline = time.Now().Add(5 * time.Second)
	for {
		conn, err := dial(t, c.Listen, time.Second)
		if err != nil {
			break
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatal("still listening 5 seconds after Run returned")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// caddyContext is enough for modules whose Provision ignores the context.
func caddyContext() caddy.Context { return caddy.Context{} }

func testLocations() (sitecheck.Locations, error) { return sitecheck.DefaultLocations() }

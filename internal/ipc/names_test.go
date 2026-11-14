//go:build windows

package ipc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/fsutil"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// DR-1: pipe names are random at every start, so none can be taken in advance.
func TestNewPipeNameIsRandom(t *testing.T) {
	a, err := NewPipeName(WebPipePrefix)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPipeName(WebPipePrefix)
	if err != nil {
		t.Fatal(err)
	}
	if a == b || !strings.HasPrefix(a, pipeDir+WebPipePrefix) || len(a) != len(pipeDir+WebPipePrefix)+32 {
		t.Fatalf("names %q and %q", a, b)
	}
}

// writeNameFile writes a pipe-name file as the supervisor does and returns
// it with its owner: the test account here, Administrators on an elevated CI
// runner.
func writeNameFile(t *testing.T, content string) (file, owner string) {
	t.Helper()
	root := t.TempDir()
	if err := winsec.SetFolderSDDL(PipeFileFolder(root, WebPipeFile), winsec.PipeNameFolderSDDL(me(t), me(t))); err != nil {
		t.Fatal(err)
	}
	file = PipeFilePath(root, WebPipeFile)
	if err := fsutil.WriteAtomic(file, []byte(content)); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(file, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	o, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	return file, o.String()
}

// DR-1: a client reads the pipe's name from the supervisor's pipe-name file
// and dials exactly that pipe; it never searches the pipe namespace.
func TestDialFileConnects(t *testing.T) {
	s := serve(t, func(winsec.Caller) bool { return true })
	file, owner := writeNameFile(t, s.path)
	name, err := ReadPipeName(file, owner)
	if err != nil || name != s.path {
		t.Fatalf("read %q, %v", name, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn, err := Dial(ctx, name, me(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

// A pipe-name file not owned by the supervisor, or one that does not name a
// SoiréeHost pipe, is refused before any pipe is opened.
func TestReadPipeNameRefuses(t *testing.T) {
	good := `\\.\pipe\soireehost-web-` + strings.Repeat("a", 32)
	if file, _ := writeNameFile(t, good); true {
		if _, err := ReadPipeName(file, winsec.SIDSystem); err == nil {
			t.Error("a file owned by another account was accepted")
		}
	}
	for _, bad := range []string{`\\.\pipe\unrelated`, `\\.\pipe\soireehost-web\..\x`, `C:\soireehost-web`, ""} {
		file, owner := writeNameFile(t, bad)
		if _, err := ReadPipeName(file, owner); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	if _, err := ReadPipeName(filepath.Join(t.TempDir(), "missing.pipe"), me(t)); !os.IsNotExist(err) {
		t.Errorf("missing file: %v", err)
	}
}

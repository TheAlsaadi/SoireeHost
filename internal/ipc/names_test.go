//go:build windows

package ipc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func writeNameFile(t *testing.T, owner, content string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), WebPipeFile)
	if err := winsec.WriteFileSDDL(file, winsec.PipeNameFileSDDL(owner, owner), []byte(content)); err != nil {
		t.Fatal(err)
	}
	return file
}

// DR-1: a client reads the pipe's name from the supervisor's pipe-name file
// and dials exactly that pipe; it never searches the pipe namespace.
func TestDialFileConnects(t *testing.T) {
	s := serve(t, func(winsec.Caller) bool { return true })
	file := writeNameFile(t, me(t), s.path)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn, err := DialFile(ctx, file, me(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

// A pipe-name file not owned by the supervisor, or one that does not name a
// SoiréeHost pipe, is refused before any pipe is opened.
func TestReadPipeNameRefuses(t *testing.T) {
	good := `\\.\pipe\soireehost-web-` + strings.Repeat("a", 32)
	if _, err := ReadPipeName(writeNameFile(t, me(t), good), winsec.SIDSystem); err == nil {
		t.Error("a file owned by another account was accepted")
	}
	for _, bad := range []string{`\\.\pipe\unrelated`, `\\.\pipe\soireehost-web\..\x`, `C:\soireehost-web`, ""} {
		if _, err := ReadPipeName(writeNameFile(t, me(t), bad), me(t)); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	if _, err := ReadPipeName(filepath.Join(t.TempDir(), "missing.pipe"), me(t)); !os.IsNotExist(err) {
		t.Errorf("missing file: %v", err)
	}
}

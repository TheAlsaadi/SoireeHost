package logread

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeAt(t *testing.T, path, text string, mod time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
}

func names(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Base(p)
	}
	return out
}

// TestFilesOrderAndFilter: the live log and its rotated copies, newest first,
// the live one first on a tie; other files, folders and old files are left
// out.
func TestFilesOrderAndFilter(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	writeAt(t, filepath.Join(dir, "access.log"), "live\n", base.Add(2*time.Hour))
	writeAt(t, filepath.Join(dir, "access-2026-11-16T10-00-00.log"), "tie\n", base.Add(2*time.Hour))
	writeAt(t, filepath.Join(dir, "access-2026-11-16T09-00-00.log"), "older\n", base.Add(time.Hour))
	writeAt(t, filepath.Join(dir, "access-2026-11-15T09-00-00.log"), "oldest\n", base)
	writeAt(t, filepath.Join(dir, "firewall.log"), "other log\n", base.Add(3*time.Hour))
	writeAt(t, filepath.Join(dir, "access-notes.txt"), "not a log\n", base.Add(3*time.Hour))
	if err := os.Mkdir(filepath.Join(dir, "access-folder.log"), 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := Files(dir, "access.log", "access-", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	want := "access.log access-2026-11-16T10-00-00.log access-2026-11-16T09-00-00.log access-2026-11-15T09-00-00.log"
	if g := strings.Join(names(got), " "); g != want {
		t.Errorf("Files = %s\nwant    %s", g, want)
	}

	got, err = Files(dir, "access.log", "access-", base.Add(90*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if g := strings.Join(names(got), " "); g != "access.log access-2026-11-16T10-00-00.log" {
		t.Errorf("Files since = %s", g)
	}
}

// TestFilesMissingFolder: no log folder yet means no logs, not an error.
func TestFilesMissingFolder(t *testing.T) {
	got, err := Files(filepath.Join(t.TempDir(), "absent"), "access.log", "access-", time.Time{})
	if err != nil || got != nil {
		t.Fatalf("Files = %v, %v; want nil, nil", got, err)
	}
}

// TestNextLine: line endings are cut, and a line longer than the buffer is
// consumed whole and reported, so the next line reads cleanly.
func TestNextLine(t *testing.T) {
	long := strings.Repeat("x", 64)
	r := bufio.NewReaderSize(strings.NewReader("first\r\n"+long+"\nsecond\nlast"), 16)
	type line struct {
		text    string
		tooLong bool
	}
	var got []line
	for {
		b, tooLong, err := NextLine(r)
		if len(b) > 0 || tooLong {
			got = append(got, line{string(b), tooLong})
		}
		if err != nil {
			break
		}
	}
	want := []line{{"first", false}, {"", true}, {"second", false}, {"last", false}}
	if len(got) != len(want) {
		t.Fatalf("lines = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

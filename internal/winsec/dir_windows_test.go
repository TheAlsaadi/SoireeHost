package winsec

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
)

// TestDirNeverFollowsLinks: a folder or file inside a Dir that is a
// junction or a hard link is refused for reading and opening, a write
// replaces the name instead of writing through it, and a remove deletes the
// link, never its target (security review of 20 Nov 2026: elevated setup
// restored settings through a junction the supervisor could plant).
func TestDirNeverFollowsLinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "victim.txt")
	if err := os.WriteFile(target, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "plain.json"), []byte("plain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, filepath.Join(root, "hardlink.json")); err != nil {
		t.Fatal(err)
	}
	testutil.Junction(t, filepath.Join(root, "history"), outside)

	if _, err := OpenDir(filepath.Join(root, "history")); !errors.Is(err, errLink) {
		t.Fatalf("OpenDir on a junction: %v, want a refusal", err)
	}
	d, err := OpenDir(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close() //nolint:errcheck // test

	names, err := d.Names()
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"hardlink.json", "history", "plain.json"}) {
		t.Fatalf("Names = %v", names)
	}
	if b, err := d.ReadFile("plain.json", 100); err != nil || string(b) != "plain" {
		t.Fatalf("ReadFile(plain) = %q, %v", b, err)
	}
	if _, err := d.ReadFile("plain.json", 2); err == nil {
		t.Fatal("ReadFile read past its limit")
	}
	if _, err := d.ReadFile("hardlink.json", 100); !errors.Is(err, errLink) {
		t.Fatalf("ReadFile through a hard link: %v, want a refusal", err)
	}
	if _, err := d.Sub("history", false); err == nil {
		t.Fatal("Sub opened a junction")
	}
	if _, err := d.Sub("history", true); err == nil {
		t.Fatal("Sub with create opened a junction")
	}
	for _, bad := range []string{`history\victim.txt`, "../x", "", ".."} {
		if _, err := d.ReadFile(bad, 100); err == nil {
			t.Fatalf("ReadFile(%q) was allowed", bad)
		}
	}

	// writing over the hard link replaces the name; the target is untouched
	if err := d.WriteFile("hardlink.json", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "victim" { //nolint:gosec // G304: the test's own file
		t.Fatalf("the hard link's target was written: %q", b)
	}
	if b, err := d.ReadFile("hardlink.json", 100); err != nil || string(b) != "new" {
		t.Fatalf("after WriteFile: %q, %v", b, err)
	}
	// removing the junction removes the link only
	if err := d.Remove("history"); err == nil {
		t.Log("Remove deleted the junction itself")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("the junction's target is gone: %v", err)
	}
	if err := d.Remove("plain.json"); err != nil {
		t.Fatal(err)
	}
	if err := d.Remove("plain.json"); err != nil {
		t.Fatalf("removing a missing name: %v", err)
	}
	sub, err := d.Sub("made", true)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close() //nolint:errcheck // test
	if err := sub.WriteFile("1.json", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "made", "1.json")); string(b) != "one" { //nolint:gosec // G304: the test's own file
		t.Fatalf("file written in a new subfolder: %q", b)
	}
}

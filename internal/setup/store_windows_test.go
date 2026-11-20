package setup

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestStoreSnapshotAndRestore: the settings store goes to the snapshot and
// back, and revisions the new version added are pruned on restore.
func TestStoreSnapshotAndRestore(t *testing.T) {
	cfg, snap := t.TempDir(), t.TempDir()
	writeTree(t, cfg, map[string]string{"current.json": "c1", "good": "1", `history\1.json`: "r1"})
	if err := copyStorePaths(cfg, snap, false); err != nil {
		t.Fatal(err)
	}
	// the new version migrates the settings and adds a revision
	writeTree(t, cfg, map[string]string{"current.json": "c2", `history\2.json`: "r2"})
	if err := copyStorePaths(snap, cfg, true); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"current.json": "c1", "good": "1", `history\1.json`: "r1"} {
		if b, err := os.ReadFile(filepath.Join(cfg, name)); err != nil || string(b) != want { //nolint:gosec // G304: the test's own folder
			t.Fatalf("%s = %q, %v; want %q", name, b, err, want)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg, "history", "2.json")); !os.IsNotExist(err) {
		t.Fatalf("the new version's revision was not removed (%v)", err)
	}
}

// TestStoreRestoreRefusesJunction: the supervisor's account can empty
// config\history and make it a junction to any folder. The elevated restore
// must then neither delete files there nor write into it (security review
// of 20 Nov 2026), and the snapshot must not read through one either.
func TestStoreRestoreRefusesJunction(t *testing.T) {
	cfg, snap, victim := t.TempDir(), t.TempDir(), t.TempDir()
	writeTree(t, snap, map[string]string{"current.json": "c1", `history\payload.dll`: "attacker"})
	writeTree(t, victim, map[string]string{"service.dll": "real"})
	writeTree(t, cfg, map[string]string{"current.json": "c2"})
	testutil.Junction(t, filepath.Join(cfg, "history"), victim)

	if err := copyStorePaths(snap, cfg, true); err == nil {
		t.Fatal("the restore went through a junction")
	}
	es, err := os.ReadDir(victim)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"service.dll"}) {
		t.Fatalf("the junction's target now holds %v", names)
	}
	if err := copyStorePaths(cfg, t.TempDir(), false); err == nil {
		t.Fatal("the snapshot read through a junction")
	}
	// the config folder itself swapped for a junction is refused too
	cfgLink := filepath.Join(t.TempDir(), "config")
	testutil.Junction(t, cfgLink, victim)
	if err := copyStorePaths(snap, cfgLink, true); err == nil {
		t.Fatal("the restore wrote into a config folder that is a junction")
	}
}

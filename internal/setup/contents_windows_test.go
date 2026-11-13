//go:build windows

// Regression tests for DR-8 (docs/reviews/2026-11-12-skills-review.md): an
// existing data root is refused if anything inside it is a link or belongs to
// another account. Without administrator rights the test cannot create
// entries owned by Administrators, so the test's own account plays the part
// of an allowed service account, and a second, unlisted SID plays the
// planting user.

package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
)

func plantedRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "SoireeHost")
	if err := os.MkdirAll(filepath.Join(root, "config", "history"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config", "current.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestCheckContentsAcceptsAllowedOwners(t *testing.T) {
	if err := checkContents(plantedRoot(t), me(t)); err != nil {
		t.Fatalf("a tree owned by an allowed account was refused: %v", err)
	}
}

func TestCheckContentsRefusesOtherOwner(t *testing.T) {
	// the test account is not in the allowed list here, so every entry it
	// created counts as planted by another account
	err := checkContents(plantedRoot(t), "S-1-5-80-0")
	if err == nil || !strings.Contains(err.Error(), "created by another account") {
		t.Fatalf("got %v, want a refusal", err)
	}
}

func TestCheckContentsRefusesJunction(t *testing.T) {
	root := plantedRoot(t)
	outside := t.TempDir()
	testutil.Junction(t, filepath.Join(root, "logs"), outside)
	err := checkContents(root, me(t))
	if err == nil || !strings.Contains(err.Error(), "is a link") {
		t.Fatalf("got %v, want a refusal", err)
	}
}

func TestCheckContentsRefusesHardLink(t *testing.T) {
	root := plantedRoot(t)
	outside := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(root, "config", "linked.json")); err != nil {
		t.Skipf("cannot create a hard link here: %v", err)
	}
	err := checkContents(root, me(t))
	if err == nil || !strings.Contains(err.Error(), "is a link") {
		t.Fatalf("got %v, want a refusal", err)
	}
}

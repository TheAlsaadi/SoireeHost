//go:build windows && e2e

// The folder logic that needs administrator rights (GOE-17; DR-7, DR-8).
// Like internal/e2e it runs only in the CI isolation job, on a runner that is
// thrown away, never on a developer's PC. It works in a temporary folder and
// installs nothing.

package setup

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// adminRoot returns a data root path, taken back and removed after the test.
func adminRoot(t *testing.T) string {
	t.Helper()
	if os.Getenv("SOIREEHOST_E2E") != "1" {
		t.Skip("needs administrator rights: runs in the CI isolation job (SOIREEHOST_E2E=1)")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("SOIREEHOST_E2E is set but the test is not elevated")
	}
	if err := winsec.EnablePrivileges("SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege"); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "SoireeHost")
	t.Cleanup(func() {
		if err := takeBack(root); err != nil {
			t.Errorf("taking back: %v", err)
		}
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("removing: %v", err)
		}
	})
	return root
}

func owner(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	o, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	return o.String()
}

func TestAdminMakeFoldersAndReinstall(t *testing.T) {
	root := adminRoot(t)
	for _, run := range []string{"install", "reinstall"} {
		if err := makeFolders(root, me(t)); err != nil {
			t.Fatalf("%s: %v", run, err)
		}
		if err := checkDataRoot(root); err != nil {
			t.Fatalf("%s: the new root is refused: %v", run, err)
		}
		if got := owner(t, root); got != winsec.SIDAdministrators {
			t.Errorf("%s: root owned by %s", run, got)
		}
		// the S-22 check allows only SYSTEM and the supervisor
		if got := owner(t, filepath.Join(root, "secrets")); got != winsec.SIDSystem {
			t.Errorf("%s: secrets folder owned by %s", run, got)
		}
	}
}

// DR-7 and DR-8: a junction inside an existing root is refused, and its
// target keeps its owner and contents.
func TestAdminMakeFoldersRefusesPlantedJunction(t *testing.T) {
	root := adminRoot(t)
	if err := makeFolders(root, me(t)); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	ownedByMe(t, target)
	before := descriptor(t, target)
	testutil.Junction(t, filepath.Join(root, "planted"), target)
	wantRefusal(t, makeFolders(root, me(t)), "is a link")
	if after := descriptor(t, target); after != before {
		t.Errorf("the junction's target was changed: %s, was %s", after, before)
	}
	if got := entries(t, target); len(got) != 0 {
		t.Errorf("written through the junction: %v", got)
	}
}

// DR-7: takeBack takes everything inside the root and nothing outside it,
// neither through a junction nor through a hard link.
func TestAdminTakeBack(t *testing.T) {
	root := adminRoot(t)
	ownedByMe(t, root)
	inside := filepath.Join(root, "logs")
	ownedByMe(t, inside)

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	ownedByMe(t, target)
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	testutil.Junction(t, filepath.Join(inside, "junction"), target)
	if err := os.Link(victim, filepath.Join(inside, "hardlink.txt")); err != nil {
		t.Fatal(err)
	}
	beforeTarget, beforeVictim := descriptor(t, target), descriptor(t, victim)

	if err := takeBack(root); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{root, inside} {
		if got := owner(t, p); got != winsec.SIDAdministrators {
			t.Errorf("%s owned by %s", p, got)
		}
	}
	if after := descriptor(t, target); after != beforeTarget {
		t.Errorf("the junction's target was changed: %s, was %s", after, beforeTarget)
	}
	if after := descriptor(t, victim); after != beforeVictim {
		t.Errorf("the hard link's other end was changed: %s, was %s", after, beforeVictim)
	}
}

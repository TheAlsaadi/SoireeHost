//go:build windows

// Tests of the elevated role's folder logic (review finding GOE-17; DR-7 to
// DR-9) as far as it runs without administrator rights. The paths that need
// them are in admin_windows_test.go; DR-9's refusals are in
// self_windows_test.go, and takeBack's walk in takeback_windows_test.go.

package setup

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// ownedByMe creates a folder owned by the test account, standing for one a
// standard user created before setup ran. The owner is set explicitly: on an
// elevated CI runner new folders are owned by Administrators.
func ownedByMe(t *testing.T, path string) {
	t.Helper()
	sid := me(t)
	if err := winsec.CreateFolderSDDL(path, "O:"+sid+"D:P(A;OICI;FA;;;"+sid+")"); err != nil {
		t.Fatal(err)
	}
}

func descriptor(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range list {
		names = append(names, e.Name())
	}
	return names
}

func wantRefusal(t *testing.T, err error, text string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), text) {
		t.Fatalf("got %v, want a refusal saying %q", err, text)
	}
}

func TestCheckDataRoot(t *testing.T) {
	dir := t.TempDir()
	if err := checkDataRoot(filepath.Join(dir, "absent")); err != nil {
		t.Errorf("a root that does not exist was refused: %v", err)
	}
	// %ProgramData% belongs to SYSTEM; the check only reads it
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkDataRoot(programData); err != nil {
		t.Errorf("a folder owned by SYSTEM was refused: %v", err)
	}
	mine := filepath.Join(dir, "mine")
	ownedByMe(t, mine)
	wantRefusal(t, checkDataRoot(mine), "created by another account")

	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	wantRefusal(t, checkDataRoot(file), "not a plain folder")

	// a junction is refused even when its target would be accepted
	link := filepath.Join(dir, "link")
	testutil.Junction(t, link, programData)
	wantRefusal(t, checkDataRoot(link), "not a plain folder")
}

// DR-8: a root another account created first is refused, and neither it nor
// anything beside it is changed.
func TestMakeFoldersRefusesPreCreatedRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "SoireeHost")
	ownedByMe(t, root)
	if err := os.Mkdir(filepath.Join(root, "config"), 0o700); err != nil {
		t.Fatal(err)
	}
	before := descriptor(t, root)
	wantRefusal(t, makeFolders(root, me(t)), "created by another account")
	if after := descriptor(t, root); after != before {
		t.Errorf("the refused root was changed: %s, was %s", after, before)
	}
	if got := entries(t, root); len(got) != 1 || got[0] != "config" {
		t.Errorf("folders were made in a refused root: %v", got)
	}
}

// DR-7 and DR-8: a root that is a junction is refused, and its target is
// neither re-permissioned nor written to.
func TestMakeFoldersRefusesJunctionRoot(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	ownedByMe(t, target)
	before := descriptor(t, target)
	root := filepath.Join(dir, "SoireeHost")
	testutil.Junction(t, root, target)
	wantRefusal(t, makeFolders(root, me(t)), "not a plain folder")
	if after := descriptor(t, target); after != before {
		t.Errorf("the junction's target was changed: %s, was %s", after, before)
	}
	if got := entries(t, target); len(got) != 0 {
		t.Errorf("folders were made in the junction's target: %v", got)
	}
}

func TestMakeFoldersRefusesFileRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "SoireeHost")
	if err := os.WriteFile(root, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantRefusal(t, makeFolders(root, me(t)), "not a plain folder")
	if b, err := os.ReadFile(root); err != nil || string(b) != "planted" { //nolint:gosec // G304: a file this test made
		t.Errorf("the file was changed: %q, %v", b, err)
	}
}

// Without administrator rights the root cannot be given its owner, so
// nothing is created: never a root with another descriptor.
func TestMakeFoldersWithoutRightsMakesNothing(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("elevated: the owner can be set here")
	}
	dir := t.TempDir()
	if err := makeFolders(filepath.Join(dir, "SoireeHost"), me(t)); err == nil {
		t.Fatal("made the data folders without administrator rights")
	}
	if got := entries(t, dir); len(got) != 0 {
		t.Errorf("left behind: %v", got)
	}
}

// copyProgram writes content to a file and opens it, as openSelf leaves it,
// with its offset moved to show that the whole program is copied.
func copyProgram(t *testing.T, content string) (*os.File, string) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "soireehost.exe")
	if err := os.WriteFile(src, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(src) //nolint:gosec // G304: a file this test made
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close() })
	if _, err := in.Seek(3, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	return in, src
}

func wantContent(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: a file this test made
	if err != nil || string(b) != want {
		t.Errorf("%s holds %q, %v; want %q", path, b, err, want)
	}
}

func TestCopyBinaryInstallsAndReplaces(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "Program Files", "SoireeHost", "soireehost.exe")
	for _, content := range []string{"the first program", "second"} {
		in, src := copyProgram(t, content)
		if err := copyBinary(in, src, dst); err != nil {
			t.Fatal(err)
		}
		wantContent(t, dst, content)
		if got := entries(t, filepath.Dir(dst)); len(got) != 1 {
			t.Errorf("program folder holds %v", got)
		}
	}
}

// A reinstall run from the installed program copies nothing onto itself.
func TestCopyBinaryOntoItself(t *testing.T) {
	in, src := copyProgram(t, "program")
	if err := copyBinary(in, src, strings.ToUpper(src)); err != nil {
		t.Fatal(err)
	}
	wantContent(t, src, "program")
	if got := entries(t, filepath.Dir(src)); len(got) != 1 {
		t.Errorf("program folder holds %v", got)
	}
}

// DR-9: what is installed is the program held open, not whatever is at its
// path when the copy runs.
func TestCopyBinaryCopiesTheOpenProgram(t *testing.T) {
	in, src := copyProgram(t, "the program that was checked")
	if err := os.Rename(src, src+".moved"); err != nil {
		t.Skipf("cannot rename an open file here: %v", err)
	}
	if err := os.WriteFile(src, []byte("swapped in"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "soireehost.exe")
	if err := copyBinary(in, src, dst); err != nil {
		t.Fatal(err)
	}
	wantContent(t, dst, "the program that was checked")
}

// A program that can be neither replaced nor moved aside stays as it is.
func TestCopyBinaryKeepsALockedProgram(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "soireehost.exe")
	if err := os.WriteFile(dst, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		t.Fatal(err)
	}
	// shared for reading only, so no rename or delete
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h) //nolint:errcheck // test
	in, src := copyProgram(t, "new")
	if err := copyBinary(in, src, dst); err == nil {
		t.Fatal("replaced a program that was held open")
	}
	wantContent(t, dst, "old")
}

func TestTakeBackMissingRoot(t *testing.T) {
	if err := takeBack(filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Fatal(err)
	}
}

// Without the privileges takeBack changes nothing and says so (SE-01).
func TestTakeBackWithoutRights(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("elevated: the privileges are held here")
	}
	root := filepath.Join(t.TempDir(), "SoireeHost")
	ownedByMe(t, root)
	before := descriptor(t, root)
	err := takeBack(root)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v, want a refusal", err)
	}
	if after := descriptor(t, root); after != before {
		t.Errorf("the root was changed: %s, was %s", after, before)
	}
}

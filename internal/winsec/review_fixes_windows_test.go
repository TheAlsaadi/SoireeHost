package winsec

// Tests for the Medium review findings SE-02, SE-04, SE-06, SE-08 and SE-09
// (docs/reviews/2026-11-12-skills-review.md).

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec/winsectest"
)

// SE-02: keepOnlyTokenPrivileges keeps the privileges it is given and
// removes every other one. It runs on a copy of the test process's token, so
// the test runner keeps its own.
func TestKeepOnlyTokenPrivileges(t *testing.T) {
	var proc windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &proc); err != nil {
		t.Fatal(err)
	}
	defer proc.Close() //nolint:errcheck // test token
	before, err := tokenPrivileges(proc)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) < 2 {
		t.Skipf("the test token holds %d privilege(s); nothing to remove", len(before))
	}
	var dup windows.Token
	if err := windows.DuplicateTokenEx(proc, windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &dup); err != nil {
		t.Fatal(err)
	}
	defer dup.Close() //nolint:errcheck // test token
	if err := keepOnlyTokenPrivileges(dup, "SeChangeNotifyPrivilege"); err != nil {
		t.Fatal(err)
	}
	var notify windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeChangeNotifyPrivilege"), &notify); err != nil {
		t.Fatal(err)
	}
	after, err := tokenPrivileges(dup)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(after, []windows.LUID{notify}) {
		t.Fatalf("kept %v, want only SeChangeNotifyPrivilege %v (had %v)", after, notify, before)
	}
	if again, _ := tokenPrivileges(proc); len(again) != len(before) {
		t.Fatalf("the process token changed too: %d privileges, had %d", len(again), len(before))
	}
	if err := keepOnlyTokenPrivileges(dup, "SeNoSuchPrivilege"); err == nil {
		t.Fatal("an unknown privilege name was accepted")
	}
}

// SE-04: every applier refuses a descriptor without a protected, non-NULL
// DACL, before it creates or changes anything, and still applies a valid one.
func TestAppliersRefuseUnprotectedDescriptors(t *testing.T) {
	user := me(t)
	bad := map[string]string{
		"NULL DACL":           "D:NO_ACCESS_CONTROL",
		"protected NULL DACL": "D:PNO_ACCESS_CONTROL",
		"missing P":           "D:(A;OICI;FA;;;" + user + ")",
		"no DACL":             "O:" + user,
		"group":               "G:" + user + "D:P(A;OICI;FA;;;" + user + ")",
	}
	base := t.TempDir()
	existing := filepath.Join(base, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	was := daclOf(t, existing)
	for name, sddl := range bad {
		created := filepath.Join(base, "new-"+strings.ReplaceAll(name, " ", "-"))
		if err := CreateFolderSDDL(created, sddl); err == nil {
			t.Errorf("CreateFolderSDDL accepted %s", name)
		}
		if _, err := os.Lstat(created); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("CreateFolderSDDL created a folder for %s: %v", name, err)
		}
		if err := ForceSDDL(existing, sddl); err == nil {
			t.Errorf("ForceSDDL accepted %s", name)
		}
		if err := ForceSDDLUnlessLinked(existing, sddl); err == nil || errors.Is(err, ErrHardLinked) {
			t.Errorf("ForceSDDLUnlessLinked accepted %s: %v", name, err)
		}
		fixture := filepath.Join(base, "fixture-"+strings.ReplaceAll(name, " ", "-"))
		file := filepath.Join(base, "file-"+strings.ReplaceAll(name, " ", "-"))
		if err := WriteFileSDDL(file, sddl, []byte("x")); err == nil {
			t.Errorf("WriteFileSDDL accepted %s", name)
		}
		if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("WriteFileSDDL wrote a file for %s: %v", name, err)
		}
		if err := winsectest.SetFolderSDDL(fixture, sddl); err == nil {
			t.Errorf("SetFolderSDDL accepted %s", name)
		}
		if _, err := os.Lstat(fixture); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("SetFolderSDDL created a folder for %s: %v", name, err)
		}
	}
	if now := daclOf(t, existing); now != was {
		t.Fatalf("a refused descriptor changed the folder: %s, was %s", now, was)
	}
	good := "D:P(A;OICI;FA;;;" + SIDSystem + ")(A;OICI;FA;;;" + user + ")"
	if err := ForceSDDL(existing, good); err != nil {
		t.Fatalf("ForceSDDL refused a valid descriptor: %v", err)
	}
	if s := daclOf(t, existing); !strings.HasPrefix(s, "D:P") {
		t.Fatalf("descriptor not applied: %s", s)
	}
}

// SE-06: the role SIDs are distinct types, so a call with two of them
// swapped does not compile.
func TestRoleSIDsAreDistinctTypes(t *testing.T) {
	sup, web, tun := reflect.TypeFor[SupervisorSID](), reflect.TypeFor[WebSID](), reflect.TypeFor[TunnelSID]()
	if sup == web || sup == tun || web == tun || sup.Kind() != reflect.String {
		t.Fatal("the role SID types are not distinct string types")
	}
	check := func(name string, fn any, want ...reflect.Type) {
		t.Helper()
		ft := reflect.TypeOf(fn)
		var got []reflect.Type
		for in := range ft.Ins() {
			if in.Kind() == reflect.String && in != reflect.TypeFor[string]() {
				got = append(got, in)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s takes role SIDs %v, want %v", name, got, want)
		}
	}
	check("GrantSiteAccess", GrantSiteAccess, web, sup)
	check("DataRootSDDL", DataRootSDDL, sup, web, tun)
	check("WorkerLogFolderSDDL[WebSID]", WorkerLogFolderSDDL[WebSID], sup, web)
	check("WorkerLogFolderSDDL[TunnelSID]", WorkerLogFolderSDDL[TunnelSID], sup, tun)
	check("WorkerPipeSDDL[WebSID]", WorkerPipeSDDL[WebSID], sup, web)
	check("ControlPipeSDDL", ControlPipeSDDL, sup)
	check("PipeNameFolderSDDL", PipeNameFolderSDDL, sup)
	if string(SupervisorAccount()) != ServiceSID(SupervisorService) || string(WebAccount()) != ServiceSID(WebService) ||
		string(TunnelAccount()) != ServiceSID(TunnelService) {
		t.Fatal("an account helper returns the wrong SID")
	}
}

// SE-06: the builders put each role where its own name says.
func TestWorkerLogFolderSDDLRoles(t *testing.T) {
	s := WorkerLogFolderSDDL(SupervisorAccount(), WebAccount())
	if !strings.Contains(s, "(A;OICI;FR;;;"+ServiceSID(SupervisorService)+")") ||
		!strings.Contains(s, "(A;OICI;"+fileModify+";;;"+ServiceSID(WebService)+")") {
		t.Fatalf("roles misplaced: %s", s)
	}
}

// SE-08: a hard-linked file is left alone and reported with ErrHardLinked;
// a file with one link gets the descriptor.
func TestForceSDDLUnlessLinked(t *testing.T) {
	user := me(t)
	sddl := "D:P(A;;FA;;;" + user + ")(A;;FR;;;" + SIDSystem + ")"
	dir := t.TempDir()
	single := filepath.Join(dir, "single.txt")
	if err := os.WriteFile(single, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ForceSDDLUnlessLinked(single, sddl); err != nil {
		t.Fatalf("a file with one link: %v", err)
	}
	if s := daclOf(t, single); !strings.HasPrefix(s, "D:P") || !strings.Contains(s, ";;;SY)") {
		t.Fatalf("descriptor not applied: %s", s)
	}

	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("cannot create a hard link here: %v", err)
	}
	was := daclOf(t, target)
	err := ForceSDDLUnlessLinked(filepath.Join(dir, "link.txt"), sddl)
	if !errors.Is(err, ErrHardLinked) {
		t.Fatalf("hard-linked file: %v, want ErrHardLinked", err)
	}
	if now := daclOf(t, target); now != was {
		t.Fatalf("hard-linked file was changed: %s, was %s", now, was)
	}

	// a folder has no hard links to follow
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ForceSDDLUnlessLinked(sub, sddl); err != nil {
		t.Fatalf("a folder: %v", err)
	}
}

// SE-09: the writer check refuses a junction, whether it is the object
// itself or a folder above it, and checks the folders above for anyone who
// could replace what is below.
func TestCheckWritersLinksAndParents(t *testing.T) {
	user := me(t)
	allowed := []string{SIDSystem, SIDAdministrators, user}
	locked := "D:P(A;OICI;FA;;;" + SIDSystem + ")(A;OICI;FA;;;" + SIDAdministrators + ")(A;OICI;FA;;;" + user + ")"
	base := t.TempDir()

	target := filepath.Join(base, "real")
	if err := winsectest.SetFolderSDDL(target, locked); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(target, "inner")
	if err := winsectest.SetFolderSDDL(inner, locked); err != nil {
		t.Fatal(err)
	}
	if err := CheckWriters(inner, allowed...); err != nil {
		t.Fatalf("a locked folder under locked folders was refused: %v", err)
	}
	if err := CheckOwnerAndWriters(inner, allowed, allowed); err != nil {
		t.Fatalf("CheckOwnerAndWriters: %v", err)
	}

	link := filepath.Join(base, "link")
	testutil.Junction(t, link, target)
	if err := CheckWriters(link, allowed...); err == nil || !strings.Contains(err.Error(), "junction") {
		t.Fatalf("a junction was checked through: %v", err)
	}
	if err := CheckWriters(filepath.Join(link, "inner"), allowed...); err == nil || !strings.Contains(err.Error(), "junction") {
		t.Fatalf("a junction above the folder was followed: %v", err)
	}

	// a parent that lets Users delete or rename its entries
	for name, ace := range map[string]string{
		"delete child": "(A;;0x40;;;" + SIDUsers + ")",
		"delete":       "(A;;SD;;;" + SIDUsers + ")",
		"write DACL":   "(A;;WD;;;" + SIDUsers + ")",
		"full control": "(A;;FA;;;" + SIDUsers + ")",
		"write owner":  "(A;;WO;;;" + SIDUsers + ")",
		"generic all":  "(A;;GA;;;" + SIDUsers + ")",
	} {
		parent := filepath.Join(base, "open-"+strings.ReplaceAll(name, " ", "-"))
		child := filepath.Join(parent, "child")
		if err := winsectest.SetFolderSDDL(child, locked); err != nil {
			t.Fatal(err)
		}
		if err := winsectest.SetFolderSDDL(parent, locked+ace); err != nil {
			t.Fatal(err)
		}
		err := CheckWriters(child, allowed...)
		if err == nil || !strings.Contains(err.Error(), SIDUsers) || !strings.Contains(err.Error(), "replaced") {
			t.Errorf("a parent granting Users %s was not reported: %v", name, err)
		}
	}

	// rights that only add entries, or apply only to what is inside, cannot
	// replace an existing child (as in %ProgramData%)
	addOnly := filepath.Join(base, "add-only")
	child := filepath.Join(addOnly, "child")
	if err := winsectest.SetFolderSDDL(child, locked); err != nil {
		t.Fatal(err)
	}
	if err := winsectest.SetFolderSDDL(addOnly, locked+"(A;CI;0x116;;;"+SIDUsers+")(A;OICIIO;FA;;;"+SIDUsers+")"); err != nil {
		t.Fatal(err)
	}
	if err := CheckWriters(child, allowed...); err != nil {
		t.Fatalf("add-only and inherit-only rights on a parent were refused: %v", err)
	}
	if err := CheckWriters(filepath.Join(link, "inner"), allowed...); !errors.Is(err, ErrLinkInPath) {
		t.Fatalf("a junction above the folder: %v, want ErrLinkInPath", err)
	}

	// a symbolic link to a file (needs developer mode or the privilege)
	file := filepath.Join(inner, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, filepath.Join(inner, "symlink.txt")); err != nil {
		t.Logf("no symbolic link test: %v", err)
	} else if err := CheckWriters(filepath.Join(inner, "symlink.txt"), allowed...); !errors.Is(err, ErrLinkInPath) {
		t.Fatalf("a symbolic link was checked through: %v", err)
	}
}

// SE-09: the parent rule on descriptors that cannot be made on disk without
// administrator rights.
func TestCheckParent(t *testing.T) {
	trusted := []string{SIDSystem, SIDAdministrators, SIDTrustedInstaller}
	const dir, root = `C:\Parent`, `C:\`
	cases := []struct {
		name, dir, sddl string
		ok              bool
	}{
		{"locked", dir, "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true},
		{"untrusted owner", dir, "O:BUD:P(A;OICI;FA;;;SY)", false},
		{"no owner", dir, "D:P(A;OICI;FA;;;SY)", false},
		{"NULL DACL", dir, "O:SYD:NO_ACCESS_CONTROL", false},
		{"object entry", dir, "O:SYD:P(OA;;FA;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)", false},
		{"deny entry", dir, "O:SYD:P(D;;FA;;;BU)(A;;FA;;;SY)", true},
		{"inherit-only full control", dir, "O:SYD:P(A;OICIIO;FA;;;BU)", true},
		{"add-only", dir, "O:SYD:P(A;CI;0x116;;;BU)", true},
		{"modify for users", dir, "O:SYD:P(A;OICI;0x1301bf;;;AU)", false},
		{"modify for users on a volume root", root, "O:SYD:P(A;OICI;0x1301bf;;;AU)", true},
		{"delete child on a volume root", root, "O:SYD:P(A;;0x40;;;AU)", false},
		{"app container full control", dir, "O:SYD:P(A;;FA;;;S-1-15-3-1024-1)", true},
		{"app package full control", dir, "O:SYD:P(A;;FA;;;S-1-15-2-1)", true},
		{"logon SID full control", dir, "O:SYD:P(A;;FA;;;S-1-5-5-0-1)", false},
	}
	for _, c := range cases {
		sd, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if err := checkParent(sd, c.dir, trusted); (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok = %v", c.name, err, c.ok)
		}
	}
}

// SE-09: what Windows itself has above the program and data folders passes.
func TestCheckParentsOfSystemFolders(t *testing.T) {
	for _, env := range []string{"ProgramData", "ProgramFiles"} {
		dir := os.Getenv(env)
		if dir == "" {
			continue
		}
		if err := checkParents(filepath.Join(dir, "SoireeHost"), []string{SIDSystem, SIDAdministrators}); err != nil {
			t.Errorf("%s: %v", env, err)
		}
	}
}

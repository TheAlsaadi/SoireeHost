package winsec

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestServiceSID(t *testing.T) {
	// Windows publishes these: NT SERVICE\TrustedInstaller and NT SERVICE\WinDefend.
	cases := map[string]string{
		"TrustedInstaller": "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
		"trustedinstaller": "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
		"WinDefend":        "S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736",
	}
	for name, want := range cases {
		if got := ServiceSID(name); got != want {
			t.Errorf("ServiceSID(%q) = %s, want %s", name, got, want)
		}
	}
	if ServiceSID(SupervisorService) == ServiceSID(WebService) {
		t.Fatal("service SIDs collide")
	}
}

// The service SID must match what Windows itself resolves for an existing
// service account.
func TestServiceSIDMatchesWindows(t *testing.T) {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
	if err != nil {
		t.Skipf("cannot resolve NT SERVICE\\TrustedInstaller here: %v", err)
	}
	if got := ServiceSID("TrustedInstaller"); got != sid.String() {
		t.Fatalf("computed %s, Windows says %s", got, sid)
	}
}

func me(t *testing.T) string {
	t.Helper()
	c, err := CurrentCaller()
	if err != nil {
		t.Fatal(err)
	}
	return c.SID
}

func TestSDDLParses(t *testing.T) {
	sup, web, tun, user := ServiceSID(SupervisorService), ServiceSID(WebService), ServiceSID(TunnelService), me(t)
	all := map[string]string{
		"control pipe":   ControlPipeSDDL(sup, user),
		"worker pipe":    WorkerPipeSDDL(sup, web),
		"worker service": WorkerServiceSDDL(sup),
		"config":         ConfigFolderSDDL(sup),
		"secrets":        SecretsFolderSDDL(sup),
		"logs":           LogsFolderSDDL(sup),
		"audit":          AuditFolderSDDL(sup),
		"web logs":       WorkerLogFolderSDDL(sup, web),
		"updates":        UpdatesFolderSDDL(sup),
		"data root":      DataRootSDDL(sup, web, tun),
	}
	for name, s := range all {
		if _, err := windows.SecurityDescriptorFromString(s); err != nil {
			t.Errorf("%s: %q does not parse: %v", name, s, err)
		}
	}
	// S-30: the control pipe denies network logons and names nobody else
	cp := ControlPipeSDDL(sup, user)
	if !strings.Contains(cp, "(D;;GA;;;"+SIDNetwork+")") || strings.Contains(cp, "GW") || strings.Contains(cp, SIDUsers) ||
		strings.Contains(cp, SIDEveryone) || strings.Contains(cp, SIDAuthenticated) || strings.Contains(cp, SIDInteractive) {
		t.Errorf("control pipe descriptor %s", cp)
	}
	// S-40: secrets name only SYSTEM and the supervisor (and OWNER RIGHTS, read-control only)
	if s := SecretsFolderSDDL(sup); strings.Contains(s, SIDAdministrators) || strings.Contains(s, web) {
		t.Errorf("secrets descriptor %s", s)
	}
	// S-20: interactive users can only query a worker service
	if s := WorkerServiceSDDL(sup); !strings.Contains(s, "(A;;CCLCSWLORC;;;"+SIDInteractive+")") {
		t.Errorf("worker service descriptor %s", s)
	}
}

// S-22: the writer check passes a locked folder and fails one others can write.
func TestCheckWriters(t *testing.T) {
	user := me(t)
	dir := filepath.Join(t.TempDir(), "config")
	if err := SetFolderSDDL(dir, ConfigFolderSDDL(user)); err != nil {
		t.Fatal(err)
	}
	if err := CheckWriters(dir, SIDSystem, SIDAdministrators, user); err != nil {
		t.Fatalf("locked folder refused: %v", err)
	}
	if err := CheckWriters(dir, SIDSystem, SIDAdministrators); err == nil {
		t.Fatal("a writer missing from the allowed list was not reported")
	}

	open := filepath.Join(t.TempDir(), "open")
	sddl := ConfigFolderSDDL(user) + "(A;OICI;0x1301bf;;;" + SIDUsers + ")"
	if err := SetFolderSDDL(open, sddl); err != nil {
		t.Fatal(err)
	}
	err := CheckWriters(open, SIDSystem, SIDAdministrators, user)
	if err == nil || !strings.Contains(err.Error(), SIDUsers) {
		t.Fatalf("folder writable by Users not reported: %v", err)
	}

	readOnly := filepath.Join(t.TempDir(), "ro")
	if err := SetFolderSDDL(readOnly, ConfigFolderSDDL(user)+"(A;OICI;FR;;;"+SIDUsers+")"); err != nil {
		t.Fatal(err)
	}
	if err := CheckWriters(readOnly, SIDSystem, SIDAdministrators, user); err != nil {
		t.Fatalf("read access reported as write: %v", err)
	}
	if err := CheckWriters(filepath.Join(t.TempDir(), "missing"), SIDSystem); err == nil {
		t.Fatal("missing folder passed")
	}
}

// S-21: a confined process cannot start cmd.exe and keeps only
// SeChangeNotifyPrivilege. The check runs in a fresh copy of the test binary
// so the limits do not apply to the test runner itself.
func TestConfineStopsChildProcesses(t *testing.T) {
	out := runHelper(t, "worker")
	if !strings.Contains(out, "CHILD-REFUSED") {
		t.Fatalf("confined worker started a child process:\n%s", out)
	}
	if !strings.Contains(out, "PRIVILEGES 1") {
		t.Fatalf("privileges not trimmed:\n%s", out)
	}
	if !strings.Contains(out, "DLL-RESTRICTED") {
		t.Fatalf("DLL search not restricted:\n%s", out)
	}
}

// The tunnel launcher keeps the ability to start exactly one child.
func TestConfineAllowsOneChildForTunnel(t *testing.T) {
	out := runHelper(t, "tunnel")
	if !strings.Contains(out, "CHILD-STARTED") {
		t.Fatalf("tunnel profile could not start a child:\n%s", out)
	}
}

func runHelper(t *testing.T, profile string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestConfineHelper$", "-test.v") //nolint:gosec // G204, G702: re-runs this test binary
	cmd.Env = append(os.Environ(), "SOIREEHOST_CONFINE_HELPER="+profile)
	out, _ := cmd.CombinedOutput()
	return string(out)
}

// TestConfineHelper only does something when re-run by the tests above.
func TestConfineHelper(t *testing.T) {
	profile := os.Getenv("SOIREEHOST_CONFINE_HELPER")
	if profile == "" {
		t.Skip("helper for TestConfine*")
	}
	if err := RestrictDLLSearch(); err != nil {
		fmt.Println("DLL-ERROR", err)
	} else {
		fmt.Println("DLL-RESTRICTED")
	}
	l := Limits{MemoryBytes: 512 << 20, ActiveProcesses: 1, NoChildProcesses: true}
	if profile == "tunnel" {
		l = Limits{MemoryBytes: 512 << 20, ActiveProcesses: 2}
	}
	if err := Confine(l); err != nil {
		fmt.Println("CONFINE-ERROR", err)
		return
	}
	privs, err := Privileges()
	fmt.Println("PRIVILEGES", len(privs), err)
	cmd := exec.CommandContext(t.Context(), "cmd.exe", "/c", "exit", "0")
	if err := cmd.Run(); err != nil {
		fmt.Println("CHILD-REFUSED", err)
	} else {
		fmt.Println("CHILD-STARTED")
	}
}

func TestConfineRejectsZeroLimits(t *testing.T) {
	if err := Confine(Limits{}); err == nil {
		t.Fatal("accepted empty limits")
	}
}

func TestCurrentCaller(t *testing.T) {
	c, err := CurrentCaller()
	if err != nil || !strings.HasPrefix(c.SID, "S-1-5-") {
		t.Fatalf("caller %+v, %v", c, err)
	}
}

// ADR-0006: the control panel's grant gives the web worker read access and
// the supervisor only enough to inspect the folder; GrantsRead sees both.
func TestGrantSiteAccess(t *testing.T) {
	user := me(t)
	web, sup := ServiceSID(WebService), ServiceSID(SupervisorService)
	dir := filepath.Join(t.TempDir(), "site")
	if err := SetFolderSDDL(dir, "D:P(A;OICI;FA;;;"+SIDSystem+")(A;OICI;FA;;;"+user+")"); err != nil {
		t.Fatal(err)
	}
	if ok, err := GrantsRead(dir, WorkerGroups(web)...); err != nil || ok {
		t.Fatalf("locked folder readable by the worker: %v %v", ok, err)
	}
	if err := GrantSiteAccess(dir, web, sup); err != nil {
		t.Fatal(err)
	}
	if ok, err := GrantsRead(dir, WorkerGroups(web)...); err != nil || !ok {
		t.Fatalf("worker cannot read after the grant: %v %v", ok, err)
	}
	if ok, _ := GrantsRead(dir, sup); ok {
		t.Fatal("the supervisor was given read access to the files")
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if s := sd.String(); !strings.Contains(s, ";;;"+sup+")") || strings.Contains(s, "OICI;0x120080") {
		t.Fatalf("supervisor entry should be on the folder only: %s", s)
	}

	denied := filepath.Join(t.TempDir(), "denied")
	if err := SetFolderSDDL(denied, "D:P(D;OICI;FR;;;"+SIDUsers+")(A;OICI;FA;;;"+user+")(A;OICI;FR;;;"+web+")"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := GrantsRead(denied, WorkerGroups(web)...); ok {
		t.Fatal("a deny entry for Users was ignored")
	}
	public := filepath.Join(t.TempDir(), "public")
	if err := SetFolderSDDL(public, "D:P(A;OICI;FA;;;"+user+")(A;OICI;FR;;;"+SIDUsers+")"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := GrantsRead(public, WorkerGroups(web)...); !ok {
		t.Fatal("read access through Users not seen")
	}
}

// Phase 2 security review: a folder is created with its final descriptor in
// one call, and creating it twice fails rather than reusing what is there.
func TestCreateFolderSDDL(t *testing.T) {
	user := me(t)
	dir := filepath.Join(t.TempDir(), "made")
	sddl := "D:P(A;OICI;FA;;;" + SIDSystem + ")(A;OICI;FA;;;" + user + ")"
	if err := CreateFolderSDDL(dir, sddl); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if s := sd.String(); !strings.HasPrefix(s, "D:P") || strings.Contains(s, SIDUsers) || strings.Contains(s, ";;;BU)") {
		t.Fatalf("descriptor %s", s)
	}
	if err := CreateFolderSDDL(dir, sddl); err == nil {
		t.Fatal("created an existing folder again")
	}
}

// A file with several hard links is never re-permissioned.
func TestForceSDDLSkipsHardLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("cannot create a hard link here: %v", err)
	}
	skipped, err := ForceSDDLUnlessLinked(filepath.Join(dir, "link.txt"), "D:P(A;;FA;;;"+SIDAdministrators+")")
	if err != nil || !skipped {
		t.Fatalf("hard-linked file: skipped=%v err=%v", skipped, err)
	}
}

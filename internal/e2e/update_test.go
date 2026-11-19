//go:build e2e

package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/setup"
	"github.com/TheAlsaadi/SoireeHost/internal/supervisor"
	"github.com/TheAlsaadi/SoireeHost/internal/update"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// The CI isolation job builds these with the updatetestkey tag, which
// trusts the test key it generated (ADR-0004), installs 1.0.0, then runs
// TestApplyUpdate with SOIREEHOST_UPDATE_E2E=1.
//
//	1.0.0.exe       installed first (setuptesthooks)
//	1.1.0.exe       a good update (setuptesthooks)
//	1.2.0-fail.exe  1.2.0 whose supervisor refuses to start (updatetestfail)
//	1.2.0.exe       a good 1.2.0, for the interrupted update
const updateBins = `C:\soireehost-ci\upd`

// stageUpdate writes a manifest and program into the updates folder as the
// supervisor would: owned by its service SID. Writing a file owned by
// another account needs SeRestorePrivilege, which the elevated runner has.
func stageUpdate(t *testing.T, manifest, exe []byte, ver string) {
	t.Helper()
	clearStaged(t)
	dir := supervisor.Paths{Root: layout(t).DataRoot}.Updates()
	// Administrators may only read the updates folder. While the files are
	// written they get full control of it, inheritable, so a plain new file
	// is theirs to write; each file is then given the supervisor as owner
	// through a backup-semantics handle. A file created with its own
	// descriptor is refused in an OWNER RIGHTS folder (convention rule 13),
	// so none is passed at creation. The folder's exact descriptor is put
	// back before anything else runs, so the supervisor's S-22 check never
	// sees the change.
	if err := winsec.EnablePrivileges("SeBackupPrivilege", "SeRestorePrivilege"); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	orig := sd.String()
	if err := winsec.ForceSDDL(dir, orig+"(A;OICI;FA;;;"+winsec.SIDAdministrators+")"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := winsec.ForceSDDL(dir, orig); err != nil {
			t.Fatalf("restoring the updates folder's descriptor: %v", err)
		}
	}()
	if exe != nil {
		writeAsSupervisor(t, filepath.Join(dir, "soireehost-"+ver+".exe"), exe)
	}
	if manifest != nil {
		writeAsSupervisor(t, filepath.Join(dir, "manifest.json"), manifest)
	}
}

// writeAsSupervisor writes path as a plain new file, then makes the
// supervisor's service SID its owner, as the supervisor's own downloads
// are. Naming another owner needs SeRestorePrivilege.
func writeAsSupervisor(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // G703: a fixed name in the updates folder
		t.Fatalf("writing %s: %v", path, err)
	}
	sup := winsec.ServiceSID(winsec.SupervisorService)
	if err := winsec.ForceSDDL(path, "O:"+sup+"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;"+sup+")"); err != nil {
		t.Fatalf("making the supervisor the owner of %s: %v", path, err)
	}
}

func clearStaged(t *testing.T) {
	t.Helper()
	dir := supervisor.Paths{Root: layout(t).DataRoot}.Updates()
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
}

func sign(t *testing.T, ver string, exe []byte, priv ed25519.PrivateKey) []byte {
	t.Helper()
	sum := sha256.Sum256(exe)
	p, err := update.EncodePayload(update.Manifest{
		Product: update.Product, Channel: update.Channel, Version: ver, MinFrom: "0.1.0",
		Published: time.Now().UTC(),
		Artifact: update.Artifact{Name: update.ArtifactName, URL: update.ReleaseURL + ver + "/" + update.ArtifactName,
			Size: int64(len(exe)), SHA256: hex.EncodeToString(sum[:])},
	})
	if err != nil {
		t.Fatal(err)
	}
	env, err := update.Sign(p, priv)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// runSetup runs the installed program's setup with extra environment and
// returns its exit code.
func runSetup(t *testing.T, env []string, args ...string) setup.Code {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), layout(t).Exe(), append([]string{"setup"}, args...)...) // #nosec G204 -- the installed program with fixed test arguments
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		t.Logf("setup %v exited %d: %s", args, ee.ExitCode(), out)
		return setup.Code(ee.ExitCode())
	}
	if err != nil {
		t.Fatalf("setup %v: %v", args, err)
	}
	return setup.CodeOK
}

func hashOf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test file
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func runningVersion(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		var st ipc.StatusResult
		if err := call(t, control(t), ipc.MethodStatus, nil, &st); err == nil {
			return st.Version
		}
		if time.Now().After(deadline) {
			t.Fatal("the supervisor is not answering")
		}
		time.Sleep(2 * time.Second)
	}
}

// TestApplyUpdate covers S-60 to S-64 on an installed system: tampered,
// wrong-key, truncated, older and equal-version updates are refused with
// nothing changed; a good update is installed and the previous version
// kept; an update whose supervisor does not start is rolled back; and an
// update interrupted after the swap is undone by the next setup command.
func TestApplyUpdate(t *testing.T) {
	if os.Getenv("SOIREEHOST_UPDATE_E2E") != "1" {
		t.Skip("set SOIREEHOST_UPDATE_E2E=1 after installing the 1.0.0 test build")
	}
	l := layout(t)
	keyText, err := os.ReadFile(os.Getenv("SOIREEHOST_UPDATE_KEY")) //nolint:gosec // G703: the CI job names its own test key file
	if err != nil {
		t.Fatal(err)
	}
	priv, err := update.ParsePrivateKey(string(keyText))
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bin := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(updateBins, name)) // #nosec G304 -- test builds
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	v110, v120fail, v120 := bin("1.1.0.exe"), bin("1.2.0-fail.exe"), bin("1.2.0.exe")
	if got := runningVersion(t); got != "1.0.0" {
		t.Fatalf("installed version %s, want the 1.0.0 test build", got)
	}
	installed := hashOf(t, l.Exe())

	refused := func(name string, want setup.Code) {
		t.Helper()
		if code := runSetup(t, nil, "apply-update"); code != want {
			t.Errorf("%s: apply-update exited %d, want %d", name, code, want)
		}
		if h := hashOf(t, l.Exe()); h != installed {
			t.Errorf("%s: the installed program changed", name)
		}
		if exists(l.Exe()+".new") || exists(l.JournalPath()) {
			t.Errorf("%s: leftovers in the program folder", name)
		}
		if got := runningVersion(t); got != "1.0.0" {
			t.Errorf("%s: running %s after a refused update", name, got)
		}
	}

	clearStaged(t)
	refused("nothing staged", setup.CodeNoUpdate)

	flipped := bytes.Clone(v110)
	flipped[len(flipped)/2] ^= 1
	stageUpdate(t, sign(t, "1.1.0", v110, priv), flipped, "1.1.0")
	refused("tampered program", setup.CodeUpdateRefused)

	stageUpdate(t, sign(t, "1.1.0", v110, otherPriv), v110, "1.1.0")
	refused("wrong key", setup.CodeUpdateRefused)

	stageUpdate(t, sign(t, "1.1.0", v110, priv), v110[:len(v110)-4096], "1.1.0")
	refused("truncated program", setup.CodeUpdateRefused)

	good := sign(t, "1.1.0", v110, priv)
	stageUpdate(t, good[:len(good)/2], v110, "1.1.0")
	refused("truncated manifest", setup.CodeUpdateRefused)

	stageUpdate(t, sign(t, "1.0.0", v110, priv), v110, "1.0.0")
	refused("equal version", setup.CodeUpdateRefused)

	stageUpdate(t, sign(t, "0.9.0", v110, priv), v110, "0.9.0")
	refused("older version", setup.CodeUpdateRefused)

	// a good update
	stageUpdate(t, good, v110, "1.1.0")
	if code := runSetup(t, nil, "apply-update"); code != setup.CodeOK {
		t.Fatalf("good update: apply-update exited %d", code)
	}
	if got := runningVersion(t); got != "1.1.0" {
		t.Fatalf("after the update the supervisor runs %s", got)
	}
	if h := hashOf(t, l.Exe()+".previous"); h != installed {
		t.Fatal("the previous version was not kept")
	}
	if exists(l.JournalPath()) || exists(l.RollbackDir()) {
		t.Fatal("the journal or the settings snapshot was left behind")
	}
	installed = hashOf(t, l.Exe())

	// a new version that does not start is rolled back
	stageUpdate(t, sign(t, "1.2.0", v120fail, priv), v120fail, "1.2.0")
	if code := runSetup(t, nil, "apply-update"); code != setup.CodeRolledBack {
		t.Fatalf("failing update: apply-update exited %d, want %d", code, setup.CodeRolledBack)
	}
	if h := hashOf(t, l.Exe()); h != installed {
		t.Fatal("the failing version is still installed")
	}
	if got := runningVersion(t); got != "1.1.0" {
		t.Fatalf("after the rollback the supervisor runs %s", got)
	}

	// an update interrupted just after the swap is undone by the next
	// setup command, run from the program now in place
	stageUpdate(t, sign(t, "1.2.0", v120, priv), v120, "1.2.0")
	if code := runSetup(t, []string{"SOIREEHOST_TEST_KILL_AT=swapped"}, "apply-update"); code != 99 {
		t.Fatalf("interrupted update exited %d, want the test kill code 99", code)
	}
	if !exists(l.JournalPath()) {
		t.Fatal("no journal after the interruption")
	}
	if code := runSetup(t, nil, "repair"); code != setup.CodeRolledBack {
		t.Fatalf("repair after the interruption exited %d, want %d", code, setup.CodeRolledBack)
	}
	if h := hashOf(t, l.Exe()); h != installed {
		t.Fatal("the interrupted update was not undone")
	}
	if got := runningVersion(t); got != "1.1.0" {
		t.Fatalf("after recovery the supervisor runs %s", got)
	}
	if exists(l.JournalPath()) {
		t.Fatal("the journal is still there after recovery")
	}
	clearStaged(t)
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// TestSignedUpdates covers S-61 on an installed system, after
// TestApplyUpdate left 1.1.0 (unsigned) installed. The CI job signs test
// builds with two throwaway code-signing certificates it trusts on the
// runner only: an unsigned install may move to a signed version, and once
// signed it refuses an unsigned update and one from another publisher, and
// accepts the same publisher's.
func TestSignedUpdates(t *testing.T) {
	if os.Getenv("SOIREEHOST_SIGNED_E2E") != "1" {
		t.Skip("set SOIREEHOST_SIGNED_E2E=1 after the signed test builds are made")
	}
	l := layout(t)
	keyText, err := os.ReadFile(os.Getenv("SOIREEHOST_UPDATE_KEY")) //nolint:gosec // G703: the CI job names its own test key file
	if err != nil {
		t.Fatal(err)
	}
	priv, err := update.ParsePrivateKey(string(keyText))
	if err != nil {
		t.Fatal(err)
	}
	bin := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(updateBins, "signed", name)) // #nosec G304 -- test builds
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if got := runningVersion(t); got != "1.1.0" {
		t.Fatalf("installed version %s, want 1.1.0 from TestApplyUpdate", got)
	}
	apply := func(name, ver string, exe []byte, want setup.Code) {
		t.Helper()
		before := hashOf(t, l.Exe())
		stageUpdate(t, sign(t, ver, exe, priv), exe, ver)
		if code := runSetup(t, nil, "apply-update"); code != want {
			t.Fatalf("%s: apply-update exited %d, want %d", name, code, want)
		}
		if want != setup.CodeOK && hashOf(t, l.Exe()) != before {
			t.Fatalf("%s: the installed program changed", name)
		}
	}
	apply("unsigned to signed", "1.3.0", bin("1.3.0-a.exe"), setup.CodeOK)
	if got := runningVersion(t); got != "1.3.0" {
		t.Fatalf("after the signed update the supervisor runs %s", got)
	}
	apply("signed to unsigned", "1.4.0", bin("1.4.0.exe"), setup.CodeUpdateRefused)
	apply("signed to another publisher", "1.4.0", bin("1.4.0-b.exe"), setup.CodeUpdateRefused)
	apply("signed to the same publisher", "1.4.0", bin("1.4.0-a.exe"), setup.CodeOK)
	if got := runningVersion(t); got != "1.4.0" {
		t.Fatalf("after the same publisher's update the supervisor runs %s", got)
	}
	clearStaged(t)
}

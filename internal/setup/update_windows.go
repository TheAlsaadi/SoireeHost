package setup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/TheAlsaadi/SoireeHost/internal/fsutil"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/supervisor"
	"github.com/TheAlsaadi/SoireeHost/internal/update"
	"github.com/TheAlsaadi/SoireeHost/internal/version"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// Timings of an update (ADR-0010).
const (
	finishTimeout  = 5 * time.Minute  // the new version's own repair
	confirmTimeout = 90 * time.Second // its supervisor answering with the new version
)

// Program-folder names used by an update.
const (
	newSuffix    = ".new"
	prevSuffix   = ".previous"
	failedSuffix = ".failed"
)

// ApplyUpdate installs the update the supervisor staged, from the installed
// program only (S-63, S-64; ADR-0010): it verifies the staged manifest and
// file again with this binary's own keys, keeps the previous version, lets
// the new version finish its own install, and rolls back if the new
// supervisor does not answer with the new version.
func ApplyUpdate(l Layout) error {
	sid, err := requireAdmin()
	if err != nil {
		return err
	}
	unlock, err := lockSetup()
	if err != nil {
		return err
	}
	defer unlock()
	if err := requireInstalledCopy(l); err != nil {
		return err
	}
	if err := winsec.EnablePrivileges("SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege"); err != nil {
		return err
	}
	// opening the services' processes to wait for them
	_ = winsec.EnablePrivileges("SeDebugPrivilege")
	if rolled, err := recoverUpdate(l, sid); err != nil {
		return err
	} else if rolled {
		return fail(CodeRolledBack, errors.New("an interrupted update was undone; install the update again"))
	}
	staged, m, err := openStaged(l)
	if err != nil {
		return err
	}
	defer staged.Close() //nolint:errcheck // read-only
	oldHash, err := fileHash(l.Exe())
	if err != nil {
		return err
	}
	j := Journal{From: version.Current(), To: m.Version, Step: StepVerified, OldHash: oldHash, NewHash: m.Artifact.SHA256,
		Started: time.Now().UTC(), PID: os.Getpid()}
	step := func(s Step) error {
		j.Step = s
		return writeJournal(l, j)
	}
	// Stale .previous files from an earlier update go before the journal
	// exists, so while there is a journal every .previous file belongs to
	// this update and a rollback can only restore the version running now.
	if err := removePrevious(l); err != nil {
		return err
	}
	if err := step(StepVerified); err != nil {
		return err
	}
	// Before the swap, a failure only needs the leftovers removed.
	abort := func(cause error) error {
		cleanupBeforeSwap(l)
		_ = startSupervisor()
		return cause
	}
	if err := step(StepStaged); err != nil {
		return abort(err)
	}
	if err := copyVerified(staged, l.Exe()+newSuffix, m.Artifact); err != nil {
		return abort(fail(CodeUpdateRefused, fmt.Errorf("staging the new program: %w", err)))
	}
	if err := step(StepStopped); err != nil {
		return abort(err)
	}
	if !stopServices() {
		return abort(errors.New("a SoiréeHost service did not stop; nothing was changed"))
	}
	testKillAt(StepStopped)
	// The settings are copied only once the supervisor has stopped, so no
	// change made meanwhile is lost and the copy is consistent.
	if err := step(StepSnapshot); err != nil {
		return abort(err)
	}
	if err := snapshotConfig(l); err != nil {
		return abort(fmt.Errorf("copying the settings aside: %w", err))
	}
	// From here on, any failure puts the previous version back.
	if err := step(StepSwapped); err != nil {
		return rollback(l, sid, j, true, err)
	}
	if err := swapIn(l); err != nil {
		return rollback(l, sid, j, true, fmt.Errorf("swapping the program: %w", err))
	}
	testKillAt(StepSwapped)
	if err := runNewRepair(l); err != nil {
		return rollback(l, sid, j, true, fmt.Errorf("the new version's setup: %w", err))
	}
	if err := step(StepFinished); err != nil {
		return rollback(l, sid, j, true, err)
	}
	testKillAt(StepFinished)
	if err := confirmVersion(l, m.Version, confirmTimeout); err != nil {
		return rollback(l, sid, j, true, err)
	}
	finishUpdate(l)
	return nil
}

// openStaged verifies the staged manifest with this binary's keys and
// opens the staged program so that nobody can change it until setup ends:
// a plain file with one link, owned by the supervisor, matching the
// manifest's size and SHA-256 (S-60, S-62, S-63).
func openStaged(l Layout) (*os.File, update.Manifest, error) {
	dir := supervisor.Paths{Root: l.DataRoot}.Updates()
	env, err := winsec.ReadOwnedFile(filepath.Join(dir, "manifest.json"), winsec.ServiceSID(winsec.SupervisorService), update.MaxManifestSize)
	if errors.Is(err, os.ErrNotExist) {
		return nil, update.Manifest{}, fail(CodeNoUpdate, errors.New("no update is waiting to be installed"))
	}
	if err != nil {
		return nil, update.Manifest{}, fail(CodeUpdateRefused, fmt.Errorf("reading the update's manifest: %w", err))
	}
	keys, err := update.Trusted()
	if err != nil {
		keys = nil
	}
	m, err := update.Verify(env, keys, version.Current())
	if err != nil {
		return nil, update.Manifest{}, fail(CodeUpdateRefused, fmt.Errorf("the update's manifest: %w", err))
	}
	path := filepath.Join(dir, "soireehost-"+m.Version+".exe")
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, update.Manifest{}, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, update.Manifest{}, fail(CodeUpdateRefused, fmt.Errorf("opening the staged program: %w", err))
	}
	f := os.NewFile(uintptr(h), path)
	if err := checkStagedFile(h); err != nil {
		_ = f.Close()
		return nil, update.Manifest{}, fail(CodeUpdateRefused, err)
	}
	if err := update.CheckFile(f, m.Artifact); err != nil {
		_ = f.Close()
		return nil, update.Manifest{}, fail(CodeUpdateRefused, fmt.Errorf("the staged program: %w", err))
	}
	if err := checkSignatures(path, h); err != nil {
		_ = f.Close()
		return nil, update.Manifest{}, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, update.Manifest{}, err
	}
	return f, m, nil
}

// checkStagedFile refuses a link, a file with several hard links, or one
// not owned by the supervisor, which alone may write the updates folder.
func checkStagedFile(h windows.Handle) error {
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return err
	}
	if fi.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || fi.NumberOfLinks != 1 {
		return errors.New("the staged program is not a plain file")
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	o, _, err := sd.Owner()
	if err != nil || o == nil || o.String() != winsec.ServiceSID(winsec.SupervisorService) {
		return errors.New("the staged program was not written by SoiréeHost's service")
	}
	return nil
}

// copyVerified copies src to dst while checking it against a, then checks
// the written copy again.
func copyVerified(src io.Reader, dst string, a update.Artifact) error {
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755) // #nosec G302 G304 -- program file under Program Files
	if err != nil {
		return err
	}
	cerr := update.CheckFile(io.TeeReader(src, out), a)
	if err := out.Sync(); err != nil && cerr == nil {
		cerr = err
	}
	if err := out.Close(); err != nil && cerr == nil {
		cerr = err
	}
	if cerr == nil {
		var got string
		if got, cerr = fileHash(dst); cerr == nil && got != a.SHA256 {
			cerr = update.ErrArtifactMismatch
		}
	}
	if cerr != nil {
		_ = os.Remove(dst)
	}
	return cerr
}

// fileHash is the SHA-256 of a file, in lower-case hex.
func fileHash(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- a program file under Program Files
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck // read-only
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeJournal(l Layout, j Journal) error {
	b, err := j.Encode()
	if err != nil {
		return err
	}
	return fsutil.WriteAtomic(l.JournalPath(), b)
}

// moveFile renames on the same volume, replacing dst, written through.
func moveFile(src, dst string) error {
	from, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// programFiles are the two program files an update replaces.
func programFiles(l Layout) []string { return []string{l.Cloudflared(), l.Exe()} }

// removePrevious deletes the .previous pair of an earlier update. A file
// still in use (an old control panel) is renamed out of the way and
// deleted at the next restart.
// A .previous file that can be neither deleted nor moved stops the update
// before its journal exists (S-63): a rollback would otherwise find it and
// restore the wrong version.
func removePrevious(l Layout) error {
	for _, f := range programFiles(l) {
		prev := f + prevSuffix
		if !exists(prev) {
			continue
		}
		if os.Remove(prev) == nil {
			continue
		}
		if _, err := moveAside(prev); err != nil {
			return fmt.Errorf("the copy kept from an earlier update, %s, cannot be removed: %w", filepath.Base(prev), err)
		}
	}
	return nil
}

// moveAside renames a file that cannot be deleted because it is in use (a
// running program) to a unique name beside it, and returns that name, which
// is deleted now if possible and otherwise at the next restart. Windows
// allows renaming a running program but not deleting or replacing it.
func moveAside(p string) (string, error) {
	out := p + ".old-" + strings.ReplaceAll(time.Now().UTC().Format("20060102T150405.000000000"), ".", "")
	if err := moveFile(p, out); err != nil {
		return "", err
	}
	if os.Remove(out) != nil {
		deleteAtRestart(out)
	}
	return out, nil
}

// deleteAtRestart marks a file for deletion at the next restart, the way
// Windows Installer removes files in use (ADR-0010).
func deleteAtRestart(p string) {
	if u, err := windows.UTF16PtrFromString(p); err == nil {
		_ = windows.MoveFileEx(u, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}
}

// swapIn puts the staged program in place, keeping the current files as
// .previous. Windows allows renaming a running program, so this works while
// control panels and this process still run from it.
func swapIn(l Layout) error {
	if exists(l.Cloudflared()) {
		if err := moveFile(l.Cloudflared(), l.Cloudflared()+prevSuffix); err != nil {
			return err
		}
	}
	if err := moveFile(l.Exe(), l.Exe()+prevSuffix); err != nil {
		return err
	}
	return moveFile(l.Exe()+newSuffix, l.Exe())
}

// restoreFiles puts every .previous file back. It is safe to repeat: a file
// with no .previous beside it is left as it is.
//
// oldHash is the SHA-256 of the binary that was running when the update
// began (the journal's OldHash). A kept binary with another hash is not this
// update's, so nothing is moved: the files stay as they are (S-63).
func restoreFiles(l Layout, oldHash string) error {
	if prev := l.Exe() + prevSuffix; oldHash != "" && exists(prev) {
		h, err := fileHash(prev)
		if err != nil {
			return fmt.Errorf("checking the kept copy: %w", err)
		}
		if !strings.EqualFold(h, oldHash) {
			return errors.New("the kept copy is not the version that was running, so nothing was restored")
		}
	}
	var errs []error
	for _, f := range programFiles(l) {
		prev := f + prevSuffix
		if !exists(prev) {
			continue
		}
		if exists(f) {
			if err := moveFile(f, f+failedSuffix); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		if err := moveFile(prev, f); err != nil {
			errs = append(errs, err)
		}
	}
	for _, f := range programFiles(l) {
		if exists(f + failedSuffix) {
			if os.Remove(f+failedSuffix) != nil {
				deleteAtRestart(f + failedSuffix)
			}
		}
	}
	_ = os.Remove(l.Exe() + newSuffix)
	return errors.Join(errs...)
}

// snapshotConfig copies the settings store (current.json, good and the
// history) to the program folder's rollback folder, which only
// Administrators and SYSTEM may open. A newer release may migrate the
// settings; the previous one must find its own after a rollback.
func snapshotConfig(l Layout) error {
	dst := l.RollbackDir()
	_ = os.RemoveAll(dst)
	if err := winsec.CreateFolderSDDL(dst, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"); err != nil {
		return err
	}
	return copyStorePaths(supervisor.Paths{Root: l.DataRoot}.Config(), dst, false)
}

// maxStoreFile bounds one settings file read by setup.
const maxStoreFile = 16 << 20

// copyStorePaths opens both folders and copies the store between them.
// The config folder belongs to the supervisor's account, which could swap
// any part of it for a junction or a hard link to a file elsewhere, so
// every access goes through winsec.Dir: relative to an open folder handle,
// never through a link (security review of 20 Nov 2026). With prune, history
// revisions in dst that src does not hold are removed (a restore).
func copyStorePaths(src, dst string, prune bool) error {
	from, err := winsec.OpenDir(src)
	if err != nil {
		return err
	}
	defer from.Close() //nolint:errcheck // nothing to do on failure
	to, err := winsec.OpenDir(dst)
	if err != nil {
		return err
	}
	defer to.Close() //nolint:errcheck // nothing to do on failure
	return copyStore(from, to, prune)
}

// copyStore copies current.json, good and history\* from src to dst.
func copyStore(src, dst *winsec.Dir, prune bool) error {
	for _, f := range []string{"current.json", "good"} {
		if err := copyStoreFile(src, dst, f); err != nil {
			return err
		}
	}
	srcHist, err := src.Sub("history", false)
	if errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	defer srcHist.Close() //nolint:errcheck // nothing to do on failure
	dstHist, err := dst.Sub("history", true)
	if err != nil {
		return err
	}
	defer dstHist.Close() //nolint:errcheck // nothing to do on failure
	names, err := srcHist.Names()
	if err != nil {
		return err
	}
	if prune {
		keep := map[string]bool{}
		for _, n := range names {
			keep[n] = true
		}
		have, err := dstHist.Names()
		if err != nil {
			return err
		}
		for _, n := range have {
			if !keep[n] {
				// a folder or anything else Remove refuses stays; the
				// store ignores what it did not write
				_ = dstHist.Remove(n)
			}
		}
	}
	for _, n := range names {
		if err := copyStoreFile(srcHist, dstHist, n); err != nil {
			return err
		}
	}
	return nil
}

// copyStoreFile copies one plain file; a missing one is skipped.
func copyStoreFile(src, dst *winsec.Dir, name string) error {
	b, err := src.ReadFile(name, maxStoreFile)
	if errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	return dst.WriteFile(name, b)
}

// restoreConfig puts the snapshot back. Each file is written afresh in the
// config folder, so it takes that folder's permissions, and history
// revisions the new version added are removed.
func restoreConfig(l Layout) error {
	snap := l.RollbackDir()
	if !exists(snap) {
		return nil
	}
	return copyStorePaths(snap, supervisor.Paths{Root: l.DataRoot}.Config(), true)
}

// stopServices stops the three services, supervisor first, and waits for
// their processes to exit.
func stopServices() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect() //nolint:errcheck // nothing to do on failure
	var pids []uint32
	for _, spec := range services {
		if s, err := m.OpenService(spec.name); err == nil {
			if st, err := s.Query(); err == nil && st.ProcessId != 0 {
				pids = append(pids, st.ProcessId)
			}
			_ = s.Close()
		}
	}
	ok := true
	for _, spec := range services {
		if s, err := m.OpenService(spec.name); err == nil {
			ok = stopAndWait(s) && ok
			_ = s.Close()
		}
	}
	for _, pid := range pids {
		ok = processExited(pid, 10*time.Second) && ok
	}
	return ok
}

// runNewRepair runs the new program's own "setup repair", which unpacks its
// cloudflared and applies its release's service, folder and firewall
// settings. The journal names this process, so the child may run while it
// holds the setup lock.
func runNewRepair(l Layout) error {
	ctx, cancel := context.WithTimeout(context.Background(), finishTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, l.Exe(), "setup", "repair") // #nosec G204 -- the installed program, verified against the signed manifest, with fixed arguments
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "SOIREEHOST_TEST_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	if err := cmd.Run(); err != nil {
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			return fmt.Errorf("exited with code %d", ee.ExitCode())
		}
		return err
	}
	return nil
}

// confirmVersion waits until the supervisor answers status.get with want.
func confirmVersion(l Layout, want string, within time.Duration) error {
	deadline := time.Now().Add(within)
	file := ipc.PipeFilePath(l.DataRoot, ipc.ControlPipeFile)
	sup := winsec.ServiceSID(winsec.SupervisorService)
	got := ""
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := ipc.DialControlFile(ctx, file, sup)
		if err == nil {
			var st ipc.StatusResult
			err = c.Call(ctx, ipc.MethodStatus, nil, &st)
			_ = c.Close()
			if err == nil {
				if st.Version == want {
					cancel()
					return nil
				}
				got = st.Version
			}
		}
		cancel()
		time.Sleep(2 * time.Second)
	}
	if got != "" {
		return fmt.Errorf("the supervisor reports version %s, not %s", got, want)
	}
	return fmt.Errorf("the supervisor did not answer within %s", within)
}

// cleanupBeforeSwap removes what an update leaves before the swap.
func cleanupBeforeSwap(l Layout) {
	_ = os.Remove(l.Exe() + newSuffix)
	finishUpdate(l)
}

// finishUpdate removes the journal and the settings snapshot. The .previous
// pair stays until the next update (S-63).
func finishUpdate(l Layout) {
	_ = os.RemoveAll(l.RollbackDir())
	_ = os.Remove(l.JournalPath())
}

// rollback puts the previous version back after a failure at or after the
// swap. inProcess says this process is the previous version, which then
// repeats its own install steps (unpacking its cloudflared among them);
// otherwise the restored files are started as they are.
func rollback(l Layout, sid string, j Journal, inProcess bool, cause error) error {
	j.Step = StepRollingBack
	_ = writeJournal(l, j)
	stopServices()
	var errs []error
	if err := restoreFiles(l, j.OldHash); err != nil {
		errs = append(errs, err)
	}
	if err := restoreConfig(l); err != nil {
		errs = append(errs, err)
	}
	if inProcess {
		if err := installSteps(l, sid); err != nil {
			errs = append(errs, err)
		}
	}
	finishUpdate(l)
	if err := startSupervisor(); err != nil {
		errs = append(errs, err)
	}
	return rollbackResult(j.To, cause, errs)
}

// recoverUpdate finishes or undoes an update that was interrupted, before
// any other setup action (ADR-0010). rolledBack reports that it put the
// previous version back.
func recoverUpdate(l Layout, sid string) (rolledBack bool, err error) {
	b, err := os.ReadFile(l.JournalPath())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	installed, _ := fileHash(l.Exe())
	j, jerr := DecodeJournal(b)
	var action Recovery
	switch {
	case jerr != nil && (exists(l.Exe()+prevSuffix) || exists(l.Cloudflared()+prevSuffix)):
		// a damaged journal after the swap began: the previous version is
		// the one known to work
		action = RecoverRollback
		j = Journal{To: "an unknown version"}
	case jerr != nil:
		action = RecoverCleanup
	default:
		action = Decide(j, installed)
	}
	self, _ := os.Executable()
	selfHash, _ := fileHash(self)
	switch action {
	case RecoverCleanup:
		stopServices()
		cleanupBeforeSwap(l)
		return false, startSupervisor()
	case RecoverConfirm:
		_ = startSupervisor()
		if confirmVersion(l, j.To, confirmTimeout) == nil {
			finishUpdate(l)
			return false, nil
		}
	}
	inProcess := jerr == nil && selfHash != "" && selfHash == j.OldHash
	if err := rollback(l, sid, j, inProcess, errors.New("an interrupted update was found")); ExitCode(err) != CodeRolledBack {
		return true, err
	}
	return true, nil
}

// childOfUpdater reports whether this process was started by the
// apply-update process the journal names, at the step where it runs the new
// version's repair.
func childOfUpdater(l Layout) bool {
	b, err := os.ReadFile(l.JournalPath())
	if err != nil {
		return false
	}
	j, err := DecodeJournal(b)
	if err != nil || j.Step != StepSwapped {
		return false
	}
	ppid, err := parentPID()
	return err == nil && ppid == uint32(j.PID) // #nosec G115 -- a process id, checked positive by DecodeJournal
}

// parentPID returns this process's parent process id.
func parentPID() (uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap) //nolint:errcheck // nothing to do on failure
	me := windows.GetCurrentProcessId()
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e)) // #nosec G103 G115 -- the size of a fixed Windows structure
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ProcessID == me {
			return e.ParentProcessID, nil
		}
	}
	return 0, errors.New("this process is not in the process list")
}

// checkSignatures applies S-61 to the staged program, open as h at path:
// once this program is Authenticode-signed, the update must be signed by
// the same publisher. A check that cannot run refuses the update.
func checkSignatures(path string, h windows.Handle) error {
	self, err := os.Executable()
	if err != nil {
		return fail(CodeUpdateRefused, err)
	}
	sf, err := os.Open(self) // #nosec G304 -- this program's own file
	if err != nil {
		return fail(CodeUpdateRefused, err)
	}
	defer sf.Close() //nolint:errcheck // read-only
	run, err := winsec.FileSignature(self, windows.Handle(sf.Fd()))
	if err != nil {
		return fail(CodeUpdateRefused, fmt.Errorf("checking this program's signature: %w", err))
	}
	cand, err := winsec.FileSignature(path, h)
	if err != nil {
		return fail(CodeUpdateRefused, fmt.Errorf("checking the update's signature: %w", err))
	}
	// the publisher is the subject with its issuer, so a same-named
	// certificate from another authority does not pass
	return signatureAllows(run.Signed, run.Valid, run.Publisher(), cand.Valid, cand.Publisher())
}

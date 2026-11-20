package supervisor

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
	"github.com/TheAlsaadi/SoireeHost/internal/svcrun"
	"github.com/TheAlsaadi/SoireeHost/internal/update"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// DataRoot returns %ProgramData%\SoireeHost.
func DataRoot() (string, error) {
	loc, err := sitecheck.DefaultLocations()
	if err != nil {
		return "", err
	}
	return filepath.Join(loc.ProgramData, "SoireeHost"), nil
}

// Limits confine the supervisor as the workers are confined (S-21): it
// starts no process of its own (the workers are services, started by the
// service manager), so it may start none. A process it could start would
// outlive the service stop that setup relies on before it touches the
// supervisor's folders (security review of 20 Nov 2026), and the job ends
// with the service. The supervisor's token already holds only
// SeChangeNotifyPrivilege (setup's required-privileges setting).
var Limits = winsec.Limits{MemoryBytes: 1 << 30, ActiveProcesses: 1, NoChildProcesses: true}

// RunService runs the supervisor as the SoireeHost Windows service.
func RunService(version string) error {
	return svcrun.Run(winsec.SupervisorService, true, func(ctx context.Context) error {
		if err := winsec.Confine(Limits); err != nil {
			return err
		}
		if failStartForTest {
			return errors.New("this test build's supervisor refuses to start (updatetestfail)")
		}
		root, err := DataRoot()
		if err != nil {
			return err
		}
		loc, err := sitecheck.DefaultLocations()
		if err != nil {
			return err
		}
		pipes, err := NewPipes()
		if err != nil {
			return err
		}
		s, err := New(Options{
			Paths:     Paths{Root: root},
			Identity:  ServiceIdentity(),
			Pipes:     pipes,
			Services:  svcrun.SCM{},
			Version:   version,
			CheckACLs: true,
			CheckRoot: func(r string) (string, error) { return sitecheck.CheckRoot(r, loc) },
			WorkerCanRead: func(r string) (bool, error) {
				return winsec.GrantsRead(r, winsec.WorkerGroups(winsec.ServiceSID(winsec.WebService))...)
			},
			// a key file that does not parse trusts nothing, so every
			// update is refused (S-60)
			Updates: &UpdateOptions{Keys: trustedKeys()},
		})
		if err != nil {
			return err
		}
		return s.Run(ctx)
	})
}

// trustedKeys returns the compiled-in update keys, or none.
func trustedKeys() update.KeySet {
	ks, err := update.Trusted()
	if err != nil {
		return nil
	}
	return ks
}

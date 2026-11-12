package supervisor

import (
	"context"
	"path/filepath"

	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
	"github.com/TheAlsaadi/SoireeHost/internal/svcrun"
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

// RunService runs the supervisor as the SoireeHost Windows service.
func RunService(version string) error {
	return svcrun.Run(winsec.SupervisorService, true, func(ctx context.Context) error {
		root, err := DataRoot()
		if err != nil {
			return err
		}
		loc, err := sitecheck.DefaultLocations()
		if err != nil {
			return err
		}
		s, err := New(Options{
			Paths:     Paths{Root: root},
			Identity:  ServiceIdentity(),
			Pipes:     DefaultPipes,
			Services:  svcrun.SCM{},
			Version:   version,
			CheckACLs: true,
			CheckRoot: func(r string) (string, error) { return sitecheck.CheckRoot(r, loc) },
			WorkerCanRead: func(r string) (bool, error) {
				return winsec.GrantsRead(r, winsec.WorkerGroups(winsec.ServiceSID(winsec.WebService))...)
			},
		})
		if err != nil {
			return err
		}
		return s.Run(ctx)
	})
}

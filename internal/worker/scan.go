package worker

import (
	"fmt"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
)

// Scan runs the exposure check on a static site folder for the supervisor
// (ADR-0008). The folder is opened with every S-11 check, as for serving,
// and read only through that os.Root.
func Scan(req ipc.ScanRequest) (sitecheck.ExposureReport, error) {
	loc, err := blockedLocations()
	if err != nil {
		return sitecheck.ExposureReport{}, err
	}
	r, err := sitecheck.OpenRoot(req.Root, loc)
	if err != nil {
		return sitecheck.ExposureReport{}, fmt.Errorf("site folder %s: %w", req.Root, err)
	}
	defer r.Close() //nolint:errcheck // read-only
	return sitecheck.ScanExposure(r, sitecheck.Rules{AllowWellKnown: req.AllowWellKnown}, sitecheck.DefaultScanTime), nil
}

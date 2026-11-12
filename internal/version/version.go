// Package version holds the application version, set at link time.
package version

import "regexp"

// Version is replaced at build time with
//
//	-ldflags "-X github.com/TheAlsaadi/SoireeHost/internal/version.Version=1.2.3"
//
// Builds without that flag report a development version.
var Version = "0.0.0-dev"

// semver accepts MAJOR.MINOR.PATCH with an optional pre-release suffix.
// Build metadata (+...) is not used by this project.
var semver = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// Valid reports whether v is a version string this project accepts.
func Valid(v string) bool {
	return semver.MatchString(v)
}

// Current returns the running version, or "0.0.0-invalid" if the link-time
// value is malformed, so a bad build flag can never show arbitrary text.
func Current() string {
	if !Valid(Version) {
		return "0.0.0-invalid"
	}
	return Version
}

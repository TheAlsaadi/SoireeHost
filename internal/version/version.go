// Package version holds the application version, set at link time, and
// compares versions by semantic-version precedence.
package version

import (
	"errors"
	"regexp"
	"strings"
)

// Version is replaced at build time with
//
//	-ldflags "-X github.com/TheAlsaadi/SoireeHost/internal/version.Version=1.2.3"
//
// Builds without that flag report a development version.
var Version = "0.0.0-dev"

// semver accepts MAJOR.MINOR.PATCH with an optional pre-release suffix.
// Build metadata (+...) is not used by this project.
var semver = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// maxLen bounds a version string. Real versions are a few characters; the
// bound keeps comparison cheap on hostile input (a manifest's fields).
const maxLen = 64

// Valid reports whether v is a version string this project accepts. A
// numeric pre-release identifier may not start with 0 (semantic versioning
// 2.0.0, item 9), so every valid version has one precedence order.
func Valid(v string) bool {
	if len(v) > maxLen || !semver.MatchString(v) {
		return false
	}
	_, pre, _ := strings.Cut(v, "-")
	if pre == "" {
		return true
	}
	for id := range strings.SplitSeq(pre, ".") {
		if numeric(id) && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

// Current returns the running version, or "0.0.0-invalid" if the link-time
// value is malformed, so a bad build flag can never show arbitrary text.
func Current() string {
	if !Valid(Version) {
		return "0.0.0-invalid"
	}
	return Version
}

// Release reports whether v is a release version: valid and without a
// pre-release suffix. Development builds ("0.0.0-dev") are not releases.
func Release(v string) bool {
	return Valid(v) && !strings.Contains(v, "-")
}

// Updatable reports whether a build of version v checks for updates: a
// release, or a release candidate "X.Y.Z-rc.N" with X.Y.Z above 0.0.0.
// Candidates are published as pre-releases, which releases/latest skips, so
// they are offered the next full release (owner decision, 21 Nov 2026).
// Development and dry-run builds ("0.0.0-dev", "0.0.0-dryrun.N") are not.
func Updatable(v string) bool {
	if Release(v) {
		return true
	}
	core, pre, ok := strings.Cut(v, "-")
	if !ok || core == "0.0.0" || !Valid(v) {
		return false
	}
	n, rc := strings.CutPrefix(pre, "rc.")
	return rc && numeric(n)
}

// ErrInvalid is returned by Compare for a version that Valid refuses.
var ErrInvalid = errors.New("invalid version")

// Compare returns -1, 0 or +1 as a is lower than, equal to or higher than b
// in semantic-version precedence (2.0.0, item 11): major, minor and patch
// compared as numbers, then a version with a pre-release suffix is lower
// than the same version without one, and pre-release identifiers are
// compared one by one (numbers as numbers and below text, text in ASCII
// order, a shorter list lower when all before are equal).
func Compare(a, b string) (int, error) {
	if !Valid(a) || !Valid(b) {
		return 0, ErrInvalid
	}
	ca, pa, _ := strings.Cut(a, "-")
	cb, pb, _ := strings.Cut(b, "-")
	na, nb := strings.Split(ca, "."), strings.Split(cb, ".")
	for i := range 3 {
		if c := compareNumbers(na[i], nb[i]); c != 0 {
			return c, nil
		}
	}
	switch {
	case pa == "" && pb == "":
		return 0, nil
	case pa == "":
		return 1, nil
	case pb == "":
		return -1, nil
	}
	ia, ib := strings.Split(pa, "."), strings.Split(pb, ".")
	for i := 0; i < len(ia) && i < len(ib); i++ {
		if c := compareIdentifiers(ia[i], ib[i]); c != 0 {
			return c, nil
		}
	}
	switch {
	case len(ia) < len(ib):
		return -1, nil
	case len(ia) > len(ib):
		return 1, nil
	}
	return 0, nil
}

func compareIdentifiers(a, b string) int {
	an, bn := numeric(a), numeric(b)
	switch {
	case an && bn:
		return compareNumbers(a, b)
	case an:
		return -1
	case bn:
		return 1
	}
	return strings.Compare(a, b)
}

// compareNumbers compares two decimal strings without leading zeros, of any
// length, so no conversion can overflow.
func compareNumbers(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func numeric(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

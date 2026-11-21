package version

import (
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"0.0.0-dev", true},
		{"1.2.3", true},
		{"1.0.0-rc.1", true},
		{"10.20.30", true},
		{"", false},
		{"1.2", false},
		{"01.2.3", false},
		{"1.2.3+build", false},
		{"v1.2.3", false},
		{"1.2.3-", false},
		{"1.2.3 <script>", false},
		{"1.2.3\n", false},
	}
	for _, tt := range tests {
		if got := Valid(tt.in); got != tt.want {
			t.Errorf("Valid(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestCurrent(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })

	Version = "1.4.0"
	if got := Current(); got != "1.4.0" {
		t.Errorf("Current() = %q, want 1.4.0", got)
	}

	Version = "<b>bad</b>"
	if got := Current(); got != "0.0.0-invalid" {
		t.Errorf("Current() with malformed version = %q, want 0.0.0-invalid", got)
	}
}

func TestDefaultIsValid(t *testing.T) {
	if !Valid(Version) {
		t.Fatalf("default Version %q is not valid", Version)
	}
}

// versionRune reports whether r may appear in a valid version string.
func versionRune(r rune) bool {
	switch {
	case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '.', r == '-':
		return true
	default:
		return false
	}
}

func FuzzValid(f *testing.F) {
	for _, s := range []string{"0.0.0-dev", "1.2.3", "1.2", "", "1.2.3-a.b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !Valid(s) {
			return
		}
		for _, r := range s {
			if !versionRune(r) {
				t.Fatalf("Valid accepted %q containing %q", s, r)
			}
		}
	})
}

func TestValidPreRelease(t *testing.T) {
	for in, want := range map[string]bool{
		"1.0.0-0":                          true,
		"1.0.0-0a":                         true,
		"1.0.0-01":                         false,
		"1.0.0-rc.01":                      false,
		"1.0.0-rc.0":                       true,
		"1.0.0-x." + "0":                   true,
		"1.0.0-" + strings.Repeat("a", 60): false,
	} {
		if got := Valid(in); got != want {
			t.Errorf("Valid(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestUpdatable: releases and release candidates check for updates;
// development, dry-run and other pre-release builds do not.
func TestUpdatable(t *testing.T) {
	for in, want := range map[string]bool{
		"1.2.3":             true,
		"1.0.0-rc.1":        true,
		"1.0.0-rc.12":       true,
		"0.0.0-rc.1":        false,
		"0.0.0-dev":         false,
		"0.0.0-dryrun.16":   false,
		"1.0.0-beta.1":      false,
		"1.0.0-rc":          false,
		"1.0.0-rc.1.2":      false,
		"1.0.0-rc.x":        false,
		"1.0.0-rc.01":       false,
		"1.0.0-rc.1-dryrun": false,
		"":                  false,
		"0.0.0-invalid":     false,
	} {
		if got := Updatable(in); got != want {
			t.Errorf("Updatable(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestRelease(t *testing.T) {
	for in, want := range map[string]bool{
		"1.2.3": true, "0.0.0-dev": false, "1.0.0-rc.1": false, "": false, "0.0.0-invalid": false,
	} {
		if got := Release(in); got != want {
			t.Errorf("Release(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestCompareOrder checks the precedence example of semantic versioning
// 2.0.0 (item 11) plus numeric fields too long for any integer type.
func TestCompareOrder(t *testing.T) {
	order := []string{
		"0.0.0-dev",
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
		"1.0.1", "1.2.0", "1.10.0", "2.0.0",
		"99999999999999999999999.0.0", "100000000000000000000000.0.0",
	}
	for i, a := range order {
		for j, b := range order {
			got, err := Compare(a, b)
			if err != nil {
				t.Fatalf("Compare(%q, %q): %v", a, b, err)
			}
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got != want {
				t.Errorf("Compare(%q, %q) = %d, want %d", a, b, got, want)
			}
		}
	}
}

func TestCompareRefusesInvalid(t *testing.T) {
	for _, p := range [][2]string{{"1.0", "1.0.0"}, {"1.0.0", "v1.0.0"}, {"1.0.0-01", "1.0.0"}, {"", ""}} {
		if _, err := Compare(p[0], p[1]); err == nil {
			t.Errorf("Compare(%q, %q) accepted an invalid version", p[0], p[1])
		}
	}
}

// FuzzCompare: comparison is reflexive and antisymmetric for every pair of
// valid versions, and never accepts an invalid one.
func FuzzCompare(f *testing.F) {
	f.Add("1.0.0", "1.0.0-rc.1")
	f.Add("1.0.0-alpha.1", "1.0.0-alpha.beta")
	f.Add("0.0.0-dev", "10.0.0")
	f.Fuzz(func(t *testing.T, a, b string) {
		ab, err := Compare(a, b)
		if err != nil {
			if Valid(a) && Valid(b) {
				t.Fatalf("Compare(%q, %q) refused two valid versions", a, b)
			}
			return
		}
		ba, _ := Compare(b, a)
		if ab != -ba {
			t.Fatalf("Compare(%q, %q) = %d but Compare(%q, %q) = %d", a, b, ab, b, a, ba)
		}
		if aa, _ := Compare(a, a); aa != 0 {
			t.Fatalf("Compare(%q, %q) = %d", a, a, aa)
		}
		if ab == 0 && a != b {
			t.Fatalf("Compare(%q, %q) = 0 for different versions", a, b)
		}
	})
}

package version

import "testing"

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

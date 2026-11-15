package waf

import (
	"net/http"
	"strings"
	"testing"
)

func TestNormalisePathKeepsSlashes(t *testing.T) {
	for in, want := range map[string]string{
		"/etc/passwd":        "/etc/passwd",
		"/etc/./passwd":      "/etc/passwd",
		"/a/b/../../etc/x":   "/etc/x",
		"a/b/":               "a/b/",
		".":                  "",
		"/":                  "/",
		"//etc//passwd":      "/etc/passwd",
		"../../../etc/hosts": "../../../etc/hosts",
	} {
		got, _, err := normalisePath(in)
		if err != nil || got != want {
			t.Errorf("normalisePath(%q) = %q, %v; want %q", in, got, err, want)
		}
		if strings.Contains(got, `\`) {
			t.Errorf("normalisePath(%q) holds a backslash: %q", in, got)
		}
	}
}

func TestNormalisePathWin(t *testing.T) {
	for in, want := range map[string]string{ //nolint:gosec // G101: file paths, not credentials
		`\windows\win.ini`:      "/windows/win.ini",
		`c:\windows\win.ini`:    "c:/windows/win.ini",
		"/etc/passwd":           "/etc/passwd",
		"web.config::$DATA":     "web.config",
		"/site/web.config. ":    "/site/web.config",
		`..\..\boot.ini`:        "../../boot.ini",
		"/a/secret.txt:stream":  "/a/secret.txt",
		"/x/ /y":                "/x/y",
		"C:file.txt:hidden:$DA": "C:file.txt",
	} {
		got, _, err := normalisePathWin(in)
		if err != nil || got != want {
			t.Errorf("normalisePathWin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// TestUnixPathsDetectedOnWindows is the regression test for Coraza issue
// 1140: with Coraza's own transformations, rule 930120 missed /etc/passwd on
// Windows.
func TestUnixPathsDetectedOnWindows(t *testing.T) {
	f, _ := testFirewall(t, ModeBlock, 1)
	for _, u := range []string{"/view?file=/etc/passwd", "/view?file=etc/shadow", "/ping?host=127.0.0.1%3Bcat%20/etc/passwd"} {
		if code, _ := serve(f, browserGet(u)); code != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403", u, code)
		}
	}
}

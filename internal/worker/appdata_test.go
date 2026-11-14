package worker

// Regression test from the 12 Nov 2026 skills review (docs/reviews/2026-11-12-skills-review.md).

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
)

func TestAppDataNeverServed(t *testing.T) {
	profile := filepath.Join(testutil.SiteDir(t), "Profiles", "bob")
	writeFile(t, filepath.Join(profile, "NTUSER.DAT"), "hive")
	writeFile(t, filepath.Join(profile, "Documents", "notes.txt"), "NOTES")
	logins := filepath.Join(profile, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "x.default", "logins.json")
	writeFile(t, logins, secretMarker+"-FIREFOX-LOGINS")
	writeFile(t, filepath.Join(profile, "AppData", "Local", "Google", "Chrome", "User Data", "Local State"), secretMarker+"-CHROME-KEY")

	h := startHarness(t, func(c *config.Config) {
		c.Sites = append(c.Sites, config.Site{ID: "bob", Name: "Bob", Enabled: true, Hostnames: []string{"bob.example.com"},
			Type: config.TypeStatic, Static: &config.Static{Root: profile}})
	})
	for _, target := range []string{
		"/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/logins.json",
		"/AppData/Local/Google/Chrome/User%20Data/Local%20State",
	} {
		r := h.get(t, "bob.example.com", target)
		t.Logf("GET %s -> %d %q", target, r.status, r.body)
		if strings.Contains(r.body, secretMarker) {
			t.Errorf("R-09: profile root outside the Users folder served %s", target)
		}
	}
}

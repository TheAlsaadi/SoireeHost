package winsec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
)

func acceptAll(p string) (string, error) { return p, nil }

func daclOf(t *testing.T, p string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

// SE-07: a link or junction is refused before anything is checked or
// changed, and so is a folder the check refuses.
func TestGrantSiteAccessRefusesLinksAndCheckedFolders(t *testing.T) {
	web, sup := ServiceSID(WebService), ServiceSID(SupervisorService)
	base := testutil.SiteDir(t)
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	testutil.Junction(t, link, target)
	called := false
	_, err := GrantSiteAccess(link, web, sup, func(p string) (string, error) { called = true; return p, nil })
	if err == nil || called {
		t.Fatalf("a junction was accepted (check called: %v): %v", called, err)
	}
	if strings.Contains(daclOf(t, target), web) {
		t.Fatal("the junction's target was changed")
	}
	refuse := errors.New("refused by the path rules")
	if _, err := GrantSiteAccess(target, web, sup, func(string) (string, error) { return "", refuse }); !errors.Is(err, refuse) {
		t.Fatalf("a refused folder: %v", err)
	}
	if strings.Contains(daclOf(t, target), web) {
		t.Fatal("a refused folder was changed")
	}
	// the check approving another folder than the one opened
	other := filepath.Join(base, "other")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := GrantSiteAccess(target, web, sup, func(string) (string, error) { return other, nil }); err == nil {
		t.Fatal("a check result naming another folder was accepted")
	}
}

// SE-07: a second grant adds no duplicate entries, and the check sees the
// handle's real path.
func TestGrantSiteAccessIdempotent(t *testing.T) {
	web, sup := ServiceSID(WebService), ServiceSID(SupervisorService)
	dir := testutil.SiteDir(t)
	var seen string
	canon, err := GrantSiteAccess(dir, web, sup, func(p string) (string, error) { seen = p; return p, nil })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(seen, canon) || strings.HasPrefix(seen, `\\?\`) {
		t.Fatalf("check saw %q, returned %q", seen, canon)
	}
	first := daclOf(t, dir)
	if _, err := GrantSiteAccess(dir, web, sup, acceptAll); err != nil {
		t.Fatal(err)
	}
	if again := daclOf(t, dir); again != first || strings.Count(again, web) != 1 || strings.Count(again, sup) != 1 {
		t.Fatalf("second grant changed the folder:\n%s\n%s", first, again)
	}
}

// SE-07: the inherited read entry reaches what is inside the folder, but
// never what a junction inside it points to.
func TestGrantSiteAccessStaysInside(t *testing.T) {
	web, sup := ServiceSID(WebService), ServiceSID(SupervisorService)
	base := testutil.SiteDir(t)
	site := filepath.Join(base, "site")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(site, "sub"), outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(site, "sub", "page.html"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	testutil.Junction(t, filepath.Join(site, "escape"), outside)
	if _, err := GrantSiteAccess(site, web, sup, acceptAll); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(daclOf(t, filepath.Join(site, "sub", "page.html")), web) {
		t.Fatal("a file inside the folder did not inherit the read entry")
	}
	for _, p := range []string{outside, filepath.Join(outside, "secret.txt")} {
		if strings.Contains(daclOf(t, p), web) {
			t.Fatalf("the grant followed a junction to %s", p)
		}
	}
}

package gui

import (
	"errors"
	"testing"
)

type fakeDesktop struct{ opened []string }

func (f *fakeDesktop) OpenURL(u string) error                { f.opened = append(f.opened, u); return nil }
func (f *fakeDesktop) SetClipboard(string) bool              { return true }
func (f *fakeDesktop) ChooseFolder() (string, error)         { return "", nil }
func (f *fakeDesktop) SaveFile(string, string) (bool, error) { return true, nil }
func (f *fakeDesktop) OpenTextFile(int64) (string, error)    { return "", nil }

// S-33: the control panel opens only pages from a closed list and site
// addresses made of a valid hostname, never an address from the UI.
func TestLinksAreClosed(t *testing.T) {
	d := &fakeDesktop{}
	l := NewLocal(d)
	if err := l.OpenKnownLink("project"); err != nil || d.opened[0] != knownLinks["project"] {
		t.Fatal(d.opened, err)
	}
	for _, bad := range []string{"https://evil.example.com", "javascript:alert(1)", ""} {
		if err := l.OpenKnownLink(bad); err == nil {
			t.Errorf("link %q opened", bad)
		}
	}
	if err := l.OpenSiteAddress("https://plain-river-tide.trycloudflare.com"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"http://a.example.com", "https://a.example.com/path?x", "https://user@a.example.com", "file:///C:/Windows", "https://a.example.com\\..\\x", "https://localhost"} {
		if err := l.OpenSiteAddress(bad); err == nil {
			t.Errorf("address %q opened", bad)
		}
	}
	if len(d.opened) != 2 {
		t.Fatalf("opened %v", d.opened)
	}
}

func TestQRCode(t *testing.T) {
	l := NewLocal(&fakeDesktop{})
	q, err := l.QRCode("https://plain-river-tide.trycloudflare.com")
	if err != nil || q.Size < 21 || len(q.Modules) != q.Size || len(q.Modules[0]) != q.Size {
		t.Fatalf("qr: size %d, %v", q.Size, err)
	}
	// the top-left finder pattern is dark at its corner
	if !q.Modules[0][0] || !q.Modules[6][6] || q.Modules[1][1] {
		t.Fatal("finder pattern missing")
	}
	for _, bad := range []string{"javascript:x", "http://a.example.com", "https://" + string(make([]byte, 300))} {
		if _, err := l.QRCode(bad); err == nil {
			t.Errorf("%q encoded", bad)
		}
	}
}

func TestOwnPorts(t *testing.T) {
	for _, p := range []Port{{Port: 8787}, {Port: 8800}, {Port: 20350}, {Port: 3000, Process: "soireehost.exe"}, {Port: 5000, Process: "cloudflared.exe"}} {
		if !ownPort(p) {
			t.Errorf("%+v offered", p)
		}
	}
	for _, p := range []Port{{Port: 3000, Process: "node.exe"}, {Port: 8800, Process: "python.exe"}, {Port: 3000}} {
		if ownPort(p) {
			t.Errorf("%+v hidden", p)
		}
	}
	l := NewLocal(&fakeDesktop{})
	if _, err := l.ListeningPorts(); err != nil {
		t.Fatal(err)
	}
}

// The sign-in entry is refused for a copy that is not installed, so it never
// points at a file in Downloads or a build folder.
func TestSignInNeedsInstalledCopy(t *testing.T) {
	l := NewLocal(&fakeDesktop{})
	if err := l.SetStartAtSignIn(true); !errors.Is(err, errNotInstalled) {
		t.Fatalf("a test binary set the sign-in entry: %v", err)
	}
}

func TestPrepareFolderRefuses(t *testing.T) {
	l := NewLocal(&fakeDesktop{})
	for _, bad := range []string{"", `C:\`, `C:\Windows`} {
		if _, err := l.PrepareFolder(bad); err == nil {
			t.Errorf("%q prepared", bad)
		}
	}
}

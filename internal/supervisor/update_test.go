package supervisor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/update"
)

// fakeGitHub is a local TLS server holding a test certificate for the
// update hosts. The updater's client dials it whatever the host, so the real
// redirect chain (github.com, then release-assets) runs with full TLS
// verification against the test root.
type fakeGitHub struct {
	t        *testing.T
	opts     UpdateOptions
	mu       sync.Mutex
	manifest []byte
	artifact []byte
	// short makes the artifact response end early, with no length header
	short bool
	// manifestRedirect, when set, replaces the manifest's redirect target
	manifestRedirect   string
	hits, artifactHits atomic.Int32
}

var (
	updatePub, updatePriv = updateKey(1)
	updateArtifact        = bytes.Repeat([]byte("MZ-update-test-"), update.MinArtifactSize/15+1)
)

func updateKey(n byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize))
	return priv.Public().(ed25519.PublicKey), priv
}

func trusting(pubs ...ed25519.PublicKey) update.KeySet {
	var ks update.KeySet
	for _, p := range pubs {
		ks = append(ks, update.Key{ID: update.KeyID(p), Public: p})
	}
	return ks
}

// signedManifest signs a manifest for artifact at version v.
func signedManifest(t *testing.T, v string, artifact []byte, priv ed25519.PrivateKey) []byte {
	t.Helper()
	sum := sha256.Sum256(artifact)
	p, err := update.EncodePayload(update.Manifest{
		Product: update.Product, Channel: update.Channel, Version: v, MinFrom: "1.0.0",
		Published: time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC),
		Artifact: update.Artifact{
			Name: update.ArtifactName, URL: update.ReleaseURL + v + "/" + update.ArtifactName,
			Size: int64(len(artifact)), SHA256: hex.EncodeToString(sum[:]),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	env, err := update.Sign(p, priv)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SoireeHost update test"},
		DNSNames:              update.Hosts,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGitHub{t: t, manifest: signedManifest(t, "1.3.0", updateArtifact, updatePriv), artifact: updateArtifact}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	addr := srv.Listener.Addr().String()
	f.opts = UpdateOptions{
		Keys:  trusting(updatePub),
		roots: roots,
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	return f
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Host + r.URL.Path {
	case "github.com/TheAlsaadi/SoireeHost/releases/latest/download/manifest.json":
		to := "https://release-assets.githubusercontent.com/manifest?sig=1"
		if f.manifestRedirect != "" {
			to = f.manifestRedirect
		}
		http.Redirect(w, r, to, http.StatusFound)
	case "release-assets.githubusercontent.com/manifest":
		_, _ = w.Write(f.manifest)
	case "example.com/manifest":
		_, _ = w.Write(f.manifest)
	default:
		if r.Host == "github.com" && strings.HasPrefix(r.URL.Path, "/TheAlsaadi/SoireeHost/releases/download/v") {
			http.Redirect(w, r, "https://release-assets.githubusercontent.com/exe?sig=2", http.StatusFound)
			return
		}
		if r.Host+r.URL.Path == "release-assets.githubusercontent.com/exe" {
			f.artifactHits.Add(1)
			if f.short {
				w.(http.Flusher).Flush() // chunked: no Content-Length
				_, _ = w.Write(f.artifact[:len(f.artifact)/2])
				return
			}
			_, _ = w.Write(f.artifact)
			return
		}
		http.NotFound(w, r)
	}
}

func (f *fakeGitHub) set(fn func(*fakeGitHub)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

type updateRun struct {
	u       *updater
	dir     string
	records []string
	on      atomic.Bool
}

func newTestUpdater(t *testing.T, f *fakeGitHub, running string) *updateRun {
	t.Helper()
	r := &updateRun{dir: t.TempDir()}
	r.on.Store(true)
	var mu sync.Mutex
	r.u = newUpdater(r.dir, running, f.opts, r.on.Load, func(action string, _ map[string]string) {
		mu.Lock()
		r.records = append(r.records, action)
		mu.Unlock()
	})
	return r
}

func (r *updateRun) files(t *testing.T) []string {
	t.Helper()
	es, err := os.ReadDir(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestUpdateStagesVerifiedFile(t *testing.T) {
	f := newFakeGitHub(t)
	r := newTestUpdater(t, f, "1.2.0")
	if err := r.u.check(t.Context()); err != nil {
		t.Fatalf("check: %v", err)
	}
	st := r.u.status()
	if st.State != ipc.UpdateReady || st.Version != "1.3.0" || st.LastCheck.IsZero() {
		t.Fatalf("status = %+v", st)
	}
	got, err := os.ReadFile(filepath.Join(r.dir, stagedExe("1.3.0")))
	if err != nil || !bytes.Equal(got, updateArtifact) {
		t.Fatalf("staged file differs from the release (%v)", err)
	}
	env, _ := os.ReadFile(filepath.Join(r.dir, stagedManifest))
	if !bytes.Equal(env, f.manifest) {
		t.Fatal("staged manifest differs from the one served")
	}
	if fs := r.files(t); len(fs) != 2 {
		t.Fatalf("updates folder holds %v, want the file and its manifest", fs)
	}
	if len(r.records) != 1 || r.records[0] != "update.ready" {
		t.Fatalf("audit records = %v", r.records)
	}
	// a second check finds it staged and downloads nothing
	before := f.artifactHits.Load()
	if err := r.u.check(t.Context()); err != nil || f.artifactHits.Load() != before {
		t.Fatalf("second check: %v, %d downloads", err, f.artifactHits.Load()-before)
	}
}

// TestUpdateRefusesForgedManifest covers S-60 in the supervisor: a manifest
// that does not verify is refused before anything is downloaded.
func TestUpdateRefusesForgedManifest(t *testing.T) {
	_, otherPriv := updateKey(2)
	good := signedManifest(t, "1.3.0", updateArtifact, updatePriv)
	tampered := bytes.Replace(good, []byte(`"key"`), []byte(`"key" `), 1) // still verifies: white space only
	for name, tc := range map[string]struct {
		manifest []byte
		problem  string
	}{
		"untrusted key":      {signedManifest(t, "1.3.0", updateArtifact, otherPriv), "unknown_key"},
		"tampered signature": {bytes.Replace(good, []byte(`"sig": "`), []byte(`"sig": "AAAA`), 1), "bad_signature"},
		"truncated":          {good[:len(good)/2], "malformed"},
		"oversized":          {append(bytes.Repeat([]byte(" "), update.MaxManifestSize), good...), "too_large"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeGitHub(t)
			f.set(func(f *fakeGitHub) { f.manifest = tc.manifest })
			r := newTestUpdater(t, f, "1.2.0")
			if err := r.u.check(t.Context()); err == nil {
				t.Fatal("check accepted the manifest")
			}
			if st := r.u.status(); st.State != ipc.UpdateFailed || st.Problem != tc.problem {
				t.Fatalf("status = %+v, want failed %s", st, tc.problem)
			}
			if n := f.artifactHits.Load(); n != 0 {
				t.Fatalf("downloaded the file %d times for a refused manifest", n)
			}
			if fs := r.files(t); len(fs) != 0 {
				t.Fatalf("updates folder holds %v", fs)
			}
		})
	}
	// white space outside the signed payload changes nothing
	f := newFakeGitHub(t)
	f.set(func(f *fakeGitHub) { f.manifest = tampered })
	if err := newTestUpdater(t, f, "1.2.0").u.check(t.Context()); err != nil {
		t.Fatalf("white space around the envelope: %v", err)
	}
}

// TestUpdateRefusesBadDownload covers S-60 and S-63: a changed or truncated
// file is never staged, and no partial download is left behind.
func TestUpdateRefusesBadDownload(t *testing.T) {
	flipped := bytes.Clone(updateArtifact)
	flipped[1000] ^= 1
	for name, fn := range map[string]func(*fakeGitHub){
		"changed file":           func(f *fakeGitHub) { f.artifact = flipped },
		"truncated, declared":    func(f *fakeGitHub) { f.artifact = updateArtifact[:len(updateArtifact)-10] },
		"truncated, chunked":     func(f *fakeGitHub) { f.short = true },
		"longer than the signed": func(f *fakeGitHub) { f.artifact = append(bytes.Clone(updateArtifact), 'x') },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeGitHub(t)
			f.set(fn)
			r := newTestUpdater(t, f, "1.2.0")
			if err := r.u.check(t.Context()); err == nil {
				t.Fatal("check staged a file that does not match its manifest")
			}
			if st := r.u.status(); st.State != ipc.UpdateFailed || st.Problem != "artifact_mismatch" {
				t.Fatalf("status = %+v", st)
			}
			if fs := r.files(t); len(fs) != 0 {
				t.Fatalf("updates folder holds %v", fs)
			}
		})
	}
}

// TestUpdateRefusesOlderVersions covers S-62: an older or equal release is
// not downloaded, and a newer one already seen is not replaced by an older
// one served later.
func TestUpdateRefusesOlderVersions(t *testing.T) {
	f := newFakeGitHub(t)
	for _, running := range []string{"1.3.0", "1.4.0"} {
		r := newTestUpdater(t, f, running)
		if err := r.u.check(t.Context()); err != nil {
			t.Fatalf("running %s: %v", running, err)
		}
		if st := r.u.status(); st.State != ipc.UpdateIdle || st.Problem != "" {
			t.Fatalf("running %s: status = %+v", running, st)
		}
	}
	if n := f.artifactHits.Load(); n != 0 {
		t.Fatalf("downloaded %d times", n)
	}

	r := newTestUpdater(t, f, "1.2.0")
	if err := r.u.check(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.set(func(f *fakeGitHub) { f.manifest = signedManifest(t, "1.2.5", updateArtifact, updatePriv) })
	if err := r.u.check(t.Context()); err != nil {
		t.Fatal(err)
	}
	if st := r.u.status(); st.State != ipc.UpdateReady || st.Version != "1.3.0" {
		t.Fatalf("an older manifest replaced the staged update: %+v", st)
	}
	if n := f.artifactHits.Load(); n != 1 {
		t.Fatalf("downloaded %d times, want 1", n)
	}
}

// TestUpdateStaysOnGitHub covers S-42: a redirect off the update hosts is
// refused, whatever the target serves.
func TestUpdateStaysOnGitHub(t *testing.T) {
	for _, to := range []string{"https://example.com/manifest", "http://release-assets.githubusercontent.com/manifest", "https://release-assets.githubusercontent.com:8443/manifest"} {
		f := newFakeGitHub(t)
		f.set(func(f *fakeGitHub) { f.manifestRedirect = to })
		r := newTestUpdater(t, f, "1.2.0")
		if err := r.u.check(t.Context()); err == nil {
			t.Fatalf("followed a redirect to %s", to)
		}
		if st := r.u.status(); st.Problem != problemNetwork {
			t.Fatalf("redirect to %s: status = %+v", to, st)
		}
	}
	for raw, want := range map[string]bool{
		update.ManifestURL:                              true,
		"https://GitHub.com/x":                          true,
		"https://objects.githubusercontent.com/x":       true,
		"https://raw.githubusercontent.com/x":           false,
		"https://github.com.evil.example/x":             false,
		"https://user@github.com/x":                     false,
		"https://github.com:443/x":                      false,
		"http://github.com/x":                           false,
		"file:///C:/Windows/System32/drivers/etc/hosts": false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := allowedURL(u); got != want {
			t.Errorf("allowedURL(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestUpdateOffAndDevelopmentBuild(t *testing.T) {
	f := newFakeGitHub(t)
	r := newTestUpdater(t, f, "1.2.0")
	r.on.Store(false)
	if _, err := r.u.checkNow(); !errors.Is(err, errUpdatesOff) {
		t.Fatalf("checkNow while off = %v", err)
	}
	if st := r.u.status(); st.State != ipc.UpdateOff {
		t.Fatalf("status while off = %+v", st)
	}
	dev := newTestUpdater(t, f, "0.0.0-dev")
	if err := dev.u.check(t.Context()); !errors.Is(err, errDevBuild) {
		t.Fatalf("check on a development build = %v", err)
	}
	if _, err := dev.u.checkNow(); !errors.Is(err, errDevBuild) {
		t.Fatalf("checkNow on a development build = %v", err)
	}
	if st := dev.u.status(); st.State != ipc.UpdateOff || st.Problem != problemDevBuild {
		t.Fatalf("development build status = %+v", st)
	}
	if n := f.hits.Load(); n != 0 {
		t.Fatalf("%d requests while off or on a development build (S-42)", n)
	}
}

func TestUpdateCheckNowRateLimited(t *testing.T) {
	r := newTestUpdater(t, newFakeGitHub(t), "1.2.0")
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	r.u.now = func() time.Time { return now }
	if ok, err := r.u.checkNow(); !ok || err != nil {
		t.Fatalf("first checkNow = %v, %v", ok, err)
	}
	now = now.Add(30 * time.Second)
	if ok, _ := r.u.checkNow(); ok {
		t.Fatal("a second check started within a minute")
	}
	now = now.Add(31 * time.Second)
	if ok, _ := r.u.checkNow(); !ok {
		t.Fatal("no check allowed a minute later")
	}
}

// TestUpdateRestore: after a restart a staged update is ready again, and
// everything else in the folder is removed.
func TestUpdateRestore(t *testing.T) {
	f := newFakeGitHub(t)
	r := newTestUpdater(t, f, "1.2.0")
	if err := r.u.check(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, junk := range []string{"soireehost-1.1.0.exe", "soireehost-1.4.0.exe.partial"} {
		if err := os.WriteFile(filepath.Join(r.dir, junk), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	again := newUpdater(r.dir, "1.2.0", f.opts, func() bool { return true }, func(string, map[string]string) {})
	again.restore()
	if st := again.status(); st.State != ipc.UpdateReady || st.Version != "1.3.0" {
		t.Fatalf("after a restart: %+v", st)
	}
	if fs := r.files(t); len(fs) != 2 {
		t.Fatalf("leftovers kept: %v", fs)
	}
	// once 1.3.0 runs, its own staged copy goes
	after := newUpdater(r.dir, "1.3.0", f.opts, func() bool { return true }, func(string, map[string]string) {})
	after.restore()
	if fs := r.files(t); len(fs) != 0 {
		t.Fatalf("the installed version's files were kept: %v", fs)
	}
	// a changed staged file is not offered
	r2 := newTestUpdater(t, f, "1.2.0")
	if err := r2.u.check(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r2.dir, stagedExe("1.3.0")), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	third := newUpdater(r2.dir, "1.2.0", f.opts, func() bool { return true }, func(string, map[string]string) {})
	third.restore()
	if st := third.status(); st.State == ipc.UpdateReady {
		t.Fatal("a changed staged file was offered as ready")
	}
}

// Turning the update check off is a weakening change (S-32, ADR-0004), and
// turning it on is not.
func TestUpdateSetCheckNeedsConfirmation(t *testing.T) {
	h := start(t)
	conf := confirmationOf(t, h.call(ipc.MethodUpdateSetCheck, ipc.UpdateSetCheckParams{Check: false}, nil))
	if !strings.Contains(conf.Sentences[0], "update check off") {
		t.Fatalf("sentences: %v", conf.Sentences)
	}
	var res ipc.ConfigResult
	if err := h.call(ipc.MethodUpdateSetCheck, ipc.UpdateSetCheckParams{Check: false, Confirmation: conf.Token}, &res); err != nil {
		t.Fatal(err)
	}
	if !res.Config.Updates.Off {
		t.Fatal("the check is still on")
	}
	if err := h.call(ipc.MethodUpdateSetCheck, ipc.UpdateSetCheckParams{Check: true}, &res); err != nil {
		t.Fatalf("turning the check on needed more than one call: %v", err)
	}
	if res.Config.Updates.Off {
		t.Fatal("the check is still off")
	}
	// importing settings that turn it off says so
	cfg := config.Default()
	cfg.Updates.Off = true
	conf = confirmationOf(t, h.call(ipc.MethodConfigImport, ipc.ConfigImportParams{Config: cfg}, nil))
	if !strings.Contains(strings.Join(conf.Sentences, " "), "update check off") {
		t.Fatalf("import sentences: %v", conf.Sentences)
	}
	// without an updater (tests, development) status reports it off and
	// "Check now" is refused
	if st := h.status(); st.Update.State != ipc.UpdateOff {
		t.Fatalf("status.update = %+v", st.Update)
	}
	var e *ipc.Error
	if err := h.call(ipc.MethodUpdateCheck, nil, nil); !errors.As(err, &e) || e.Code != ipc.CodeUnavailable {
		t.Fatalf("update.check without an updater = %v", err)
	}
}

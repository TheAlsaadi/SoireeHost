package supervisor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/fsutil"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/update"
	"github.com/TheAlsaadi/SoireeHost/internal/version"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// UpdateOptions configure the update check (ADR-0004). The zero value of
// every field but Keys means the production default.
type UpdateOptions struct {
	// Keys are the trusted update-signing keys (update.Trusted in the
	// service).
	Keys update.KeySet
	// ManifestURL is update.ManifestURL unless a test sets it.
	ManifestURL string
	// FirstDelay, Interval and Jitter time the automatic checks: the first
	// after FirstDelay, then every Interval plus up to Jitter.
	FirstDelay, Interval, Jitter time.Duration

	// roots and dial exist for tests only, which point the client at a
	// local TLS server holding a certificate for the GitHub hosts. They are
	// unexported, so no production caller can change how TLS is verified.
	roots *x509.CertPool
	dial  func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Problem codes besides update.Code's.
const (
	problemNetwork  = "network"
	problemDevBuild = "development_build"
)

// staged file names in the updates folder
const stagedManifest = "manifest.json"

func stagedExe(v string) string { return "soireehost-" + v + ".exe" }

// errors the control handler turns into sentences
var (
	errUpdatesOff = errors.New("update checks are off")
	errDevBuild   = errors.New("development build")
)

// updater checks for, downloads and stages updates (S-60, S-62, S-63). It
// never runs, opens for execution or loads anything it downloads; setup
// verifies the staged file again and installs it (ADR-0010).
type updater struct {
	opts    UpdateOptions
	dir     string
	running string
	client  *http.Client
	enabled func() bool
	record  func(action string, detail map[string]string)
	now     func() time.Time
	kick    chan struct{} // "Check now"

	checkMu sync.Mutex // one check at a time

	mu     sync.Mutex // guards st, newest, staged and lastKick
	st     ipc.UpdateStatus
	newest string // the newest version a verified manifest has offered
	staged string // the version staged and ready to install, if any
	// lastKick is when "Check now" last started a check
	lastKick time.Time
}

func newUpdater(dir, running string, o UpdateOptions, enabled func() bool, record func(string, map[string]string)) *updater {
	if o.ManifestURL == "" {
		o.ManifestURL = update.ManifestURL
	}
	if o.FirstDelay == 0 {
		o.FirstDelay = 10 * time.Minute
	}
	if o.Interval == 0 {
		o.Interval = 24 * time.Hour
	}
	if o.Jitter == 0 {
		o.Jitter = time.Hour
	}
	return &updater{
		opts: o, dir: dir, running: running, client: newUpdateClient(o),
		enabled: enabled, record: record, now: time.Now,
		kick: make(chan struct{}, 1),
		st:   ipc.UpdateStatus{State: ipc.UpdateIdle},
	}
}

// allowedURL is the update connection's whole reach: HTTPS on the default
// port to one of update.Hosts, with no user name (S-42).
func allowedURL(u *url.URL) bool {
	return u.Scheme == "https" && u.User == nil && u.Port() == "" &&
		slices.Contains(update.Hosts, strings.ToLower(u.Hostname()))
}

func newUpdateClient(o UpdateOptions) *http.Client {
	tr := &http.Transport{
		// a service has no proxy settings, and none are read from the
		// environment
		Proxy: nil,
		// normal verification against the Windows root store; never disabled
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.roots},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          2,
		ForceAttemptHTTP2:     true,
	}
	if o.dial != nil {
		tr.DialContext = o.dial
	}
	return &http.Client{
		Transport: tr,
		Timeout:   10 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if !allowedURL(req.URL) {
				return errors.New("redirect to a host outside the update connection")
			}
			return nil
		},
	}
}

// get fetches u, which must be an allowed URL, and returns the open body of
// a 200 response.
func (u *updater) get(ctx context.Context, raw string) (*http.Response, error) {
	parsed, err := url.Parse(raw)
	if err != nil || !allowedURL(parsed) {
		return nil, errors.New("address outside the update connection")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	// a fixed user agent: no version, nothing that identifies the PC (S-42)
	req.Header.Set("User-Agent", "SoireeHost-update-check")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

// status is the update state for status.get.
func (u *updater) status() ipc.UpdateStatus {
	if !version.Release(u.running) {
		return ipc.UpdateStatus{State: ipc.UpdateOff, Problem: problemDevBuild}
	}
	u.mu.Lock()
	st := u.st
	u.mu.Unlock()
	// a staged update stays installable while checks are off
	if !u.enabled() && st.State != ipc.UpdateReady {
		st.State = ipc.UpdateOff
	}
	return st
}

func (u *updater) set(f func(*ipc.UpdateStatus)) {
	u.mu.Lock()
	f(&u.st)
	u.mu.Unlock()
}

// checkNow asks the run loop for a check at once ("Check now"). It returns
// false if one was asked for less than a minute ago.
func (u *updater) checkNow() (bool, error) {
	if !version.Release(u.running) {
		return false, errDevBuild
	}
	if !u.enabled() {
		return false, errUpdatesOff
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	now := u.now()
	if !u.lastKick.IsZero() && now.Sub(u.lastKick) < time.Minute {
		return false, nil
	}
	u.lastKick = now
	select {
	case u.kick <- struct{}{}:
	default:
	}
	return true, nil
}

// run checks after FirstDelay, then every Interval plus jitter, and when
// asked, until ctx ends.
func (u *updater) run(ctx context.Context) {
	u.restore()
	t := time.NewTimer(u.opts.FirstDelay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// #nosec G404 -- timing jitter only, nothing secret depends on it
			t.Reset(u.opts.Interval + time.Duration(rand.Int64N(int64(u.opts.Jitter))))
		case <-u.kick:
		}
		if u.enabled() {
			_ = u.check(ctx)
		}
	}
}

// check runs one update check: manifest, verification, download, staging.
func (u *updater) check(ctx context.Context) error {
	if !version.Release(u.running) {
		return errDevBuild
	}
	u.checkMu.Lock()
	defer u.checkMu.Unlock()
	u.set(func(s *ipc.UpdateStatus) { s.State, s.Problem = ipc.UpdateChecking, "" })
	err := u.checkOnce(ctx)
	u.set(func(s *ipc.UpdateStatus) {
		s.LastCheck = u.now()
		switch {
		case err == nil:
		case errors.Is(err, update.ErrNotNewer):
			s.State, s.Problem = ipc.UpdateIdle, ""
			if u.staged != "" {
				// an update staged earlier stays ready
				s.State, s.Version = ipc.UpdateReady, u.staged
			}
			err = nil
		default:
			s.State = ipc.UpdateFailed
			s.Problem = update.Code(err)
			if s.Problem == "failed" {
				s.Problem = problemNetwork
			}
			if u.staged != "" {
				// a failed check (or a failed download of a still newer
				// version) leaves the update staged earlier intact and
				// installable; Problem still says what went wrong
				s.State, s.Version = ipc.UpdateReady, u.staged
			}
		}
	})
	return err
}

func (u *updater) checkOnce(ctx context.Context) error {
	env, m, err := u.fetchManifest(ctx)
	if err != nil {
		return err
	}
	u.mu.Lock()
	older := false
	if u.newest != "" {
		c, _ := version.Compare(m.Version, u.newest)
		older = c < 0
	}
	if !older {
		u.newest = m.Version
	}
	u.mu.Unlock()
	if older {
		// a valid but older manifest than one already seen: a mirror or an
		// attacker holding updates back. Nothing to install (ADR-0004).
		return update.ErrNotNewer
	}
	if u.stagedMatches(m) {
		if err := fsutil.WriteAtomic(filepath.Join(u.dir, stagedManifest), env); err != nil {
			return err
		}
		u.ready(m.Version)
		return nil
	}
	u.set(func(s *ipc.UpdateStatus) { s.State, s.Version = ipc.UpdateDownloading, m.Version })
	if err := u.download(ctx, m); err != nil {
		return err
	}
	// the manifest is written after the file, so setup never finds a
	// manifest whose file is missing
	if err := fsutil.WriteAtomic(filepath.Join(u.dir, stagedManifest), env); err != nil {
		return err
	}
	u.removeStaged(m.Version)
	u.ready(m.Version)
	u.record("update.ready", map[string]string{"version": m.Version})
	return nil
}

func (u *updater) ready(v string) {
	u.set(func(s *ipc.UpdateStatus) { s.State, s.Version, s.Problem = ipc.UpdateReady, v, "" })
	u.mu.Lock()
	u.staged = v
	u.mu.Unlock()
}

func (u *updater) fetchManifest(ctx context.Context) ([]byte, update.Manifest, error) {
	resp, err := u.get(ctx, u.opts.ManifestURL)
	if err != nil {
		return nil, update.Manifest{}, err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	env, err := io.ReadAll(io.LimitReader(resp.Body, update.MaxManifestSize+1))
	if err != nil {
		return nil, update.Manifest{}, err
	}
	m, err := update.Verify(env, u.opts.Keys, u.running)
	return env, m, err
}

// download streams the artifact into a .partial file while hashing it, and
// renames it into place only if it is exactly the signed file (S-63).
func (u *updater) download(ctx context.Context, m update.Manifest) (err error) {
	partial := filepath.Join(u.dir, stagedExe(m.Version)+".partial")
	_ = os.Remove(partial)
	resp, err := u.get(ctx, m.Artifact.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	if resp.ContentLength >= 0 && resp.ContentLength != m.Artifact.Size {
		return update.ErrArtifactMismatch
	}
	// #nosec G304 -- a fixed name under the updates folder; the version passed version.Valid
	f, err := os.OpenFile(partial, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(partial)
		}
	}()
	cerr := update.CheckFile(io.TeeReader(resp.Body, f), m.Artifact)
	if err := f.Close(); err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	return os.Rename(partial, filepath.Join(u.dir, stagedExe(m.Version)))
}

// stagedMatches reports whether the file for m is already staged intact.
func (u *updater) stagedMatches(m update.Manifest) bool {
	f, err := os.Open(filepath.Join(u.dir, stagedExe(m.Version))) // #nosec G304 -- fixed name under the updates folder
	if err != nil {
		return false
	}
	defer f.Close() //nolint:errcheck // read-only
	return update.CheckFile(f, m.Artifact) == nil
}

// removeStaged deletes every staged executable and partial download except
// version keep's executable.
func (u *updater) removeStaged(keep string) {
	entries, err := os.ReadDir(u.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		if n == stagedManifest || (keep != "" && n == stagedExe(keep)) {
			continue
		}
		if strings.HasPrefix(n, "soireehost-") && (strings.HasSuffix(n, ".exe") || strings.HasSuffix(n, ".partial")) {
			_ = os.Remove(filepath.Join(u.dir, n))
		}
	}
}

// restore runs at start: an update staged before a restart is ready again
// if its manifest still verifies as newer and its file is intact; anything
// else in the folder (older versions, partial downloads, the manifest of
// the version now running) is removed.
func (u *updater) restore() {
	if !version.Release(u.running) {
		return
	}
	mp := filepath.Join(u.dir, stagedManifest)
	env, err := os.ReadFile(mp) // #nosec G304 -- fixed name under the updates folder
	if err == nil && len(env) <= update.MaxManifestSize {
		if m, verr := update.Verify(env, u.opts.Keys, u.running); verr == nil && u.stagedMatches(m) {
			u.removeStaged(m.Version)
			u.mu.Lock()
			u.newest = m.Version
			u.mu.Unlock()
			u.ready(m.Version)
			return
		}
	}
	u.removeStaged("")
	_ = os.Remove(mp)
}

// updateCheck is "Check now": it starts a check in the background and
// returns at once; status.get follows its progress.
func (s *Supervisor) updateCheck(c winsec.Caller) (any, *ipc.Error) {
	if s.upd == nil {
		return nil, ipc.Errorf(ipc.CodeUnavailable, "This build does not check for updates.")
	}
	started, err := s.upd.checkNow()
	switch {
	case errors.Is(err, errDevBuild):
		return nil, ipc.Errorf(ipc.CodeUnavailable, "This is a development build, which does not check for updates.")
	case errors.Is(err, errUpdatesOff):
		return nil, ipc.Errorf(ipc.CodeUnavailable, "Update checks are off. Turn them on in Settings first.")
	case !started:
		return nil, ipc.Errorf(ipc.CodeUnavailable, "SoiréeHost checked for updates less than a minute ago.")
	}
	s.record(c.SID, "update.check", nil)
	return s.upd.status(), nil
}

// updateSetCheck turns the update check on or off; off needs a confirmation
// (S-32).
func (s *Supervisor) updateSetCheck(c winsec.Caller, p *ipc.UpdateSetCheckParams) (any, *ipc.Error) {
	detail := map[string]string{"check": strconv.FormatBool(p.Check)}
	return s.change(c, "update.set_check", detail, func(cfg *config.Config) *ipc.Error {
		next := *cfg
		next.Updates.Off = !p.Check
		var w weakenings
		w.updates(*cfg, next)
		q := *p
		q.Confirmation = ""
		if e := w.check(s.conf, confirmRequest{sid: c.SID, method: ipc.MethodUpdateSetCheck, params: q, token: p.Confirmation}, detail); e != nil {
			return e
		}
		cfg.Updates.Off = !p.Check
		return nil
	})
}

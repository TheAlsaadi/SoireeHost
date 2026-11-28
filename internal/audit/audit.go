// Package audit is the supervisor's append-only, hash-chained audit log
// (S-36). Each entry carries the SHA-256 of the previous one, so editing,
// removing or reordering entries breaks the chain, and Verify reports where.
// Breaks are reported, never repaired.
//
// The chain alone cannot show what happened at its end: a file cut short,
// deleted, or rewritten with every hash recomputed still chains from the
// fixed genesis (SE-13). So before every append the log saves an Anchor
// (the sequence number and hash of the entry it is about to write) in an
// AnchorStore kept apart from the file; the supervisor keeps it
// DPAPI-protected in its secrets folder. Verification checks the file
// against the anchor, and a log whose file disagrees with its anchor chains
// its next entry from the anchor, so the break stays in the file after later
// appends.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"
)

// Entry is one audit record. Actor is a SID and Action a name from the closed
// set of Action values; Append refuses detail keys that name secrets.
type Entry struct {
	Seq    uint64            `json:"seq"`
	Time   time.Time         `json:"time"`
	Actor  string            `json:"actor"`
	Action string            `json:"action"`
	Detail map[string]string `json:"detail,omitempty"`
	Prev   string            `json:"prev"`
	Hash   string            `json:"hash,omitempty"`
}

// genesis is the Prev of the first entry.
const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// MaxLineBytes bounds one entry on disk.
const MaxLineBytes = 64 << 10

// ErrBroken is returned by Open, with a usable Log and the full Report, when
// the log already on disk does not verify. The caller reports it; the log
// keeps working, because refusing to start would let anyone who can damage
// the file stop the supervisor.
var ErrBroken = errors.New("the audit log does not verify")

// Anchor is the newest entry's sequence number and hash, kept outside the
// log file (SE-13). Seq 0 with the genesis hash is an empty log.
type Anchor struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// AnchorStore keeps the anchor where those who can rewrite the log file
// cannot silently rewrite it too. LoadAnchor reports false when there is
// none yet.
type AnchorStore interface {
	LoadAnchor() (Anchor, bool, error)
	SaveAnchor(Anchor) error
}

// hashOf is the SHA-256 of the entry's JSON with Hash empty. encoding/json
// writes struct fields in order and map keys sorted, so it is deterministic.
func hashOf(e Entry) (string, error) {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Log appends to one audit file.
type Log struct {
	mu      sync.Mutex
	path    string
	anchors AnchorStore
	// head is what the next entry chains from: Seq and Hash only
	head Anchor
	now  func() time.Time
}

// Open opens the audit log at path (the file is created by the first
// append), verifies what is already there against the anchor, and returns
// the report. When the report is not OK the error is ErrBroken and the Log
// is still returned, ready to append.
//
// A log with entries but no anchor (the first start after the upgrade that
// added anchors) or with an anchor that cannot be read is anchored to its
// last entry, and Open records that as an audit.anchored entry, so the
// moment the anchor was (re)made stays visible in the log itself.
//
// Open fails only without an anchor store. Everything else it cannot do
// (read the file, save a first anchor, write the audit.anchored entry) is a
// break in the report: the supervisor keeps running and says so.
func Open(path string, anchors AnchorStore) (*Log, Report, error) {
	if anchors == nil {
		return nil, Report{}, errors.New("audit log needs an anchor store")
	}
	a, hasAnchor, aerr := anchors.LoadAnchor()
	var want *Anchor
	if aerr == nil && hasAnchor {
		want = &a
	}
	rep, res, err := verifyFile(path, want)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		rep.Breaks = append(rep.Breaks, Break{Reason: "the audit file could not be read"})
	}
	l := &Log{path: path, anchors: anchors, head: res.last, now: time.Now}
	var reason string
	switch {
	case aerr != nil:
		rep.Breaks = append(rep.Breaks, Break{Reason: "the audit anchor could not be read, so removal of the newest entries cannot be ruled out"})
		reason = "unreadable"
	case !hasAnchor && res.last.Seq > 0:
		reason = "missing"
	case !hasAnchor:
		// a new log: anchor it empty, so deleting it later is reported
		if err := anchors.SaveAnchor(l.head); err != nil {
			rep.Breaks = append(rep.Breaks, Break{Reason: "the audit anchor could not be saved"})
		}
	case !res.anchorMatched:
		// the file was cut short, deleted, rewritten or added to: chain on
		// from the newest entry the supervisor wrote, so the break stays in
		// the file after this start
		l.head = Anchor{Seq: max(a.Seq, res.last.Seq), Hash: a.Hash}
	}
	if reason != "" {
		if _, err := l.Append(System, AuditAnchored, map[string]string{"reason": reason, "from_seq": strconv.FormatUint(res.last.Seq, 10)}); err != nil {
			rep.Breaks = append(rep.Breaks, Break{Reason: "the audit log could not be anchored"})
		}
	}
	if !rep.OK() {
		return l, rep, ErrBroken
	}
	return l, rep, nil
}

// Append adds an entry. The file is opened for append only, so this code
// cannot overwrite earlier entries even by mistake (the folder ACL enforces
// the same for the supervisor's account).
//
// The anchor is saved first, naming the entry about to be written, so an
// entry added to the file by anyone else is always past the anchor and
// reported. When the anchor cannot be saved nothing is written and the
// error is returned. When the write fails after it, the anchor names an
// entry that is not in the file, which Verify reports until the next
// successful append (it reuses the sequence number and moves the anchor).
func (l *Log) Append(actor Actor, action Action, detail map[string]string) (Entry, error) {
	if actor.sid == "" {
		return Entry{}, errors.New("audit entry has no actor")
	}
	if !action.valid() {
		return Entry{}, errors.New("audit entry has an unknown action")
	}
	if err := checkDetail(detail); err != nil {
		return Entry{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Entry{
		Seq:    l.head.Seq + 1,
		Time:   l.now().UTC(),
		Actor:  actor.sid,
		Action: action.String(),
		Detail: detail,
		Prev:   l.head.Hash,
	}
	h, err := hashOf(e)
	if err != nil {
		return Entry{}, err
	}
	e.Hash = h
	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	if len(line) >= MaxLineBytes {
		return Entry{}, errors.New("audit entry too large")
	}
	if err := l.anchors.SaveAnchor(Anchor{Seq: e.Seq, Hash: e.Hash}); err != nil {
		return Entry{}, fmt.Errorf("saving the audit anchor: %w", err)
	}
	f, err := openAppendOnly(l.path)
	if err != nil {
		return Entry{}, fmt.Errorf("opening audit log: %w", err)
	}
	// A crash can leave a partial last line; start on a fresh line so the
	// new entry is still readable (the partial line stays a reported break).
	if needsNewline(l.path) {
		line = append([]byte("\n"), line...)
	}
	_, werr := f.Write(append(line, '\n'))
	serr := f.Sync()
	cerr := f.Close()
	if werr == nil {
		// the line is in the file: the next entry must follow it, or Verify
		// would report a break the program made (review finding GO-8)
		l.head = Anchor{Seq: e.Seq, Hash: e.Hash}
	}
	if err := errors.Join(werr, serr, cerr); err != nil {
		return Entry{}, fmt.Errorf("writing audit log: %w", err)
	}
	return e, nil
}

// Verify checks the log's chain and its agreement with the anchor.
func (l *Log) Verify() (Report, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok, err := l.anchors.LoadAnchor()
	if err != nil {
		return Report{Breaks: []Break{{Reason: "the audit anchor could not be read"}}}, nil
	}
	var want *Anchor
	if ok {
		want = &a
	}
	rep, _, err := verifyFile(l.path, want)
	if errors.Is(err, os.ErrNotExist) {
		return rep, nil
	}
	return rep, err
}

func needsNewline(path string) bool {
	f, err := os.Open(path) // #nosec G304 -- the supervisor's own audit file
	if err != nil {
		return false
	}
	defer f.Close() //nolint:errcheck // read-only
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return false
	}
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, fi.Size()-1); err != nil {
		return false
	}
	return b[0] != '\n'
}

// Break is one place where the chain does not hold. Line 0 means the file as
// a whole (its end, or the file itself).
type Break struct {
	Line   int    `json:"line"`
	Reason string `json:"reason"`
}

// Report is the result of verifying a log.
type Report struct {
	Entries int     `json:"entries"`
	Breaks  []Break `json:"breaks,omitempty"`
}

// OK reports whether the whole chain verified.
func (r Report) OK() bool { return len(r.Breaks) == 0 }

type verifyResult struct {
	last          Anchor // the last entry that verified, or the genesis
	anchorMatched bool   // the anchor's entry is in the file, unchanged
}

// verifyFile walks every line and checks the file against want, when there
// is an anchor. A missing file is reported as removed when the anchor says
// entries were written, and returns os.ErrNotExist.
func verifyFile(path string, want *Anchor) (Report, verifyResult, error) {
	f, err := os.Open(path) // #nosec G304 -- the supervisor's own audit file
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return Report{}, verifyResult{}, err
		}
		rep, res := verifyReader(bytes.NewReader(nil), want)
		if want != nil && want.Seq > 0 {
			rep.Breaks = []Break{{Reason: fmt.Sprintf("the audit file is missing, but %d entries were written (it was deleted or moved)", want.Seq)}}
		}
		return rep, res, err
	}
	defer f.Close() //nolint:errcheck // read-only
	rep, res := verifyReader(f, want)
	return rep, res, nil
}

// verifyReader walks every line. After a break it carries on from the last
// good entry, so one damaged line does not hide later tampering.
func verifyReader(r io.Reader, want *Anchor) (Report, verifyResult) {
	var rep Report
	last := Entry{Hash: genesis}
	matched := want == nil || (want.Seq == 0 && want.Hash == genesis)
	rewritten := false // the anchor's entry is there with another hash
	added := false     // valid entries follow the anchor's entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), MaxLineBytes)
	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var e Entry
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			rep.Breaks = append(rep.Breaks, Break{line, "not a valid entry"})
			continue
		}
		sum, err := hashOf(e)
		switch {
		case err != nil || e.Hash != sum:
			rep.Breaks = append(rep.Breaks, Break{line, "entry was changed after it was written"})
			continue
		case e.Prev != last.Hash:
			rep.Breaks = append(rep.Breaks, Break{line, "entry does not follow the one before it (an entry was removed, added or reordered)"})
		case e.Seq != last.Seq+1:
			rep.Breaks = append(rep.Breaks, Break{line, fmt.Sprintf("sequence jumps from %d to %d", last.Seq, e.Seq)})
		}
		if want != nil && matched && want.Seq < e.Seq && !added {
			// the anchor names the newest entry written (it is saved before
			// each write), so nothing may follow it
			added = true
			matched = false
			rep.Breaks = append(rep.Breaks, Break{line, fmt.Sprintf("entry %d was added after the newest entry the supervisor wrote (%d)", e.Seq, want.Seq)})
		}
		if want != nil && e.Seq == want.Seq {
			if e.Hash == want.Hash && !added {
				matched = true
			} else {
				rewritten = true
				rep.Breaks = append(rep.Breaks, Break{line, fmt.Sprintf("entry %d is not the one that was written (the log was rewritten)", e.Seq)})
			}
		}
		rep.Entries++
		last = e
	}
	if err := sc.Err(); err != nil {
		rep.Breaks = append(rep.Breaks, Break{line + 1, "line too long or unreadable"})
	}
	if !matched && last.Seq < want.Seq {
		rep.Breaks = append(rep.Breaks, Break{0, fmt.Sprintf("the log ends at entry %d, but %d entries were written (entries were removed from the end, or the newest was lost in a crash)", last.Seq, want.Seq)})
	} else if !matched && !rewritten && !added {
		rep.Breaks = append(rep.Breaks, Break{0, fmt.Sprintf("entry %d, the newest one written, is missing or was changed", want.Seq)})
	}
	return rep, verifyResult{last: Anchor{Seq: last.Seq, Hash: last.Hash}, anchorMatched: matched}
}

// List returns up to limit entries with Seq greater than after, oldest first,
// skipping lines that do not parse.
func List(path string, after uint64, limit int) ([]Entry, error) {
	f, err := os.Open(path) // #nosec G304 -- the supervisor's own audit file
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), MaxLineBytes)
	for sc.Scan() && len(out) < limit {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Seq <= after {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

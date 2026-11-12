// Package audit is the supervisor's append-only, hash-chained audit log
// (S-36). Each entry carries the SHA-256 of the previous one, so editing,
// removing or reordering entries breaks the chain, and Verify reports where.
// Breaks are reported, never repaired.
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
	"sync"
	"time"
)

// Entry is one audit record. Detail must never contain a secret value.
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
	mu   sync.Mutex
	path string
	last Entry
	now  func() time.Time
}

// Open opens (creating if needed) the audit log at path, finds the last valid
// entry to chain from, and returns the verification report of what is
// already there.
func Open(path string) (*Log, Report, error) {
	rep, last, err := verifyFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, rep, err
	}
	l := &Log{path: path, last: last, now: time.Now}
	if last.Hash == "" {
		l.last = Entry{Hash: genesis}
	}
	return l, rep, nil
}

// Append adds an entry. The file is opened for append only, so this code
// cannot overwrite earlier entries even by mistake (the folder ACL enforces
// the same for the supervisor's account).
func (l *Log) Append(actor, action string, detail map[string]string) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Entry{
		Seq:    l.last.Seq + 1,
		Time:   l.now().UTC(),
		Actor:  actor,
		Action: action,
		Detail: detail,
		Prev:   l.last.Hash,
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
	if err := errors.Join(werr, serr, cerr); err != nil {
		return Entry{}, fmt.Errorf("writing audit log: %w", err)
	}
	l.last = e
	return e, nil
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

// Break is one place where the chain does not hold.
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

// Verify checks the chain of the log at path.
func Verify(path string) (Report, error) {
	rep, _, err := verifyFile(path)
	return rep, err
}

// verifyFile walks every line. After a break it carries on from the last
// good entry, so one damaged line does not hide later tampering.
func verifyFile(path string) (Report, Entry, error) {
	f, err := os.Open(path) // #nosec G304 -- the supervisor's own audit file
	if err != nil {
		return Report{}, Entry{}, err
	}
	defer f.Close() //nolint:errcheck // read-only
	return verifyReader(f)
}

func verifyReader(r io.Reader) (Report, Entry, error) {
	var rep Report
	last := Entry{Hash: genesis}
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
		want, err := hashOf(e)
		switch {
		case err != nil || e.Hash != want:
			rep.Breaks = append(rep.Breaks, Break{line, "entry was changed after it was written"})
			continue
		case e.Prev != last.Hash:
			rep.Breaks = append(rep.Breaks, Break{line, "entry does not follow the one before it (an entry was removed, added or reordered)"})
		case e.Seq != last.Seq+1:
			rep.Breaks = append(rep.Breaks, Break{line, fmt.Sprintf("sequence jumps from %d to %d", last.Seq, e.Seq)})
		}
		rep.Entries++
		last = e
	}
	if err := sc.Err(); err != nil {
		rep.Breaks = append(rep.Breaks, Break{line + 1, "line too long or unreadable"})
	}
	if last.Seq == 0 {
		last = Entry{}
	}
	return rep, last, nil
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

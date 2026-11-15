package fwevent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// LogName is the firewall log's file name inside the web worker's log
// folder; rotated files are named firewall-<time>.log.
const LogName = "firewall.log"

// LogMessage is the message of every firewall event line.
const LogMessage = "firewall event"

// Reading limits: a line longer than MaxLineBytes is skipped, and at most
// MaxReadBytes are read across all files for one query.
const (
	MaxLineBytes = 16 << 10
	MaxReadBytes = 64 << 20
	MaxPage      = 500
	DefaultPage  = 100
)

// Query selects events: those of one site (all sites if empty), older than
// Before (no bound if zero), at most Limit of them, newest first.
type Query struct {
	Site   string
	Before time.Time
	Limit  int
}

// Page is one answer: events newest first, the number of lines that were not
// valid events, and whether older events may exist beyond this page.
type Page struct {
	Events  []Event
	Skipped int
	More    bool
}

// line is the JSON object Caddy's logger writes for one event.
type line struct {
	Level  string          `json:"level"`
	TS     json.RawMessage `json:"ts"`
	Logger string          `json:"logger"`
	Msg    string          `json:"msg"`
	Event  *Event          `json:"event"`
}

// ParseLine decodes one log line strictly and validates the event in it.
func ParseLine(b []byte) (Event, error) {
	if len(b) > MaxLineBytes {
		return Event{}, errors.New("line too long")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var l line
	if err := dec.Decode(&l); err != nil {
		return Event{}, fmt.Errorf("malformed line: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Event{}, errors.New("data after the event")
	}
	if l.Msg != LogMessage || l.Event == nil {
		return Event{}, errors.New("not a firewall event")
	}
	if err := l.Event.Validate(); err != nil {
		return Event{}, err
	}
	return *l.Event, nil
}

// Read answers q from the firewall log files in dir: firewall.log and its
// rotated files, newest first. Files are read in order of modification time,
// newest first; each holds events in the order they were written.
func Read(dir string, q Query) (Page, error) {
	if q.Limit <= 0 || q.Limit > MaxPage {
		q.Limit = DefaultPage
	}
	files, err := logFiles(dir)
	if err != nil {
		return Page{}, err
	}
	var page Page
	budget := int64(MaxReadBytes)
	for _, f := range files {
		if budget <= 0 {
			page.More = true
			break
		}
		evs, skipped, used, err := readFile(f, q, budget)
		if err != nil {
			return Page{}, err
		}
		budget -= used
		page.Skipped += skipped
		// newest first: this file's events reversed, after the newer files'
		for i := len(evs) - 1; i >= 0; i-- {
			if len(page.Events) == q.Limit {
				page.More = true
				break
			}
			page.Events = append(page.Events, evs[i])
		}
		if len(page.Events) == q.Limit {
			page.More = true
			break
		}
	}
	if page.Events == nil {
		page.Events = []Event{}
	}
	return page, nil
}

// logFiles lists firewall.log and its rotated files, newest first. Links and
// anything that is not a regular file are left out.
func logFiles(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("listing the firewall logs: %w", err)
	}
	type file struct {
		path string
		mod  time.Time
	}
	var out []file
	for _, e := range ents {
		n := e.Name()
		if n != LogName && (!strings.HasPrefix(n, "firewall-") || !strings.HasSuffix(n, ".log")) {
			continue
		}
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, file{filepath.Join(dir, n), info.ModTime()})
	}
	slices.SortStableFunc(out, func(a, b file) int {
		if n := b.mod.Compare(a.mod); n != 0 {
			return n
		}
		// the live file is the newest when times tie
		if filepath.Base(a.path) == LogName {
			return -1
		}
		if filepath.Base(b.path) == LogName {
			return 1
		}
		return strings.Compare(b.path, a.path)
	})
	paths := make([]string, len(out))
	for i, f := range out {
		paths[i] = f.path
	}
	return paths, nil
}

// readFile returns the events in one file that match q, oldest first,
// keeping only the newest q.Limit of them, the number of lines skipped, and
// the bytes read (at most budget).
func readFile(path string, q Query, budget int64) ([]Event, int, int64, error) {
	f, err := os.Open(path) // #nosec G304 -- a file name listed from the supervisor's own view of the web log folder
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, 0, nil // rotated away while listing
	}
	if err != nil {
		return nil, 0, 0, fmt.Errorf("opening a firewall log: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	lr := &io.LimitedReader{R: f, N: budget}
	r := bufio.NewReaderSize(lr, MaxLineBytes+1)
	var evs []Event
	skipped := 0
	for {
		b, tooLong, err := nextLine(r)
		if len(b) > 0 || tooLong {
			if tooLong {
				skipped++
			} else if e, perr := ParseLine(b); perr != nil {
				skipped++
			} else if (q.Site == "" || e.Site == q.Site) && (q.Before.IsZero() || e.Time.Before(q.Before)) {
				evs = append(evs, e)
				if len(evs) > q.Limit {
					evs = evs[1:]
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, 0, 0, fmt.Errorf("reading a firewall log: %w", err)
		}
	}
	return evs, skipped, budget - lr.N, nil
}

// nextLine returns the next line without its newline. A line longer than the
// reader's buffer is consumed and reported as too long.
func nextLine(r *bufio.Reader) ([]byte, bool, error) {
	b, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = r.ReadSlice('\n')
		}
		return nil, true, err
	}
	return bytes.TrimRight(b, "\r\n"), false, err
}

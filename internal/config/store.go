package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HistoryKept is how many earlier revisions the store keeps (plan section 4).
const HistoryKept = 10

// Record is one saved revision of the config.
type Record struct {
	Revision uint64    `json:"revision"`
	SavedAt  time.Time `json:"saved_at"`
	Actor    string    `json:"actor"`
	Summary  string    `json:"summary"`
	Config   Config    `json:"config"`
}

// Store keeps the current config and its history in a folder (S-41):
//
//	current.json        the revision in force
//	history/<rev>.json  earlier revisions, newest HistoryKept kept
//	good                the last revision the web worker loaded
//
// Every write is validated first and lands atomically.
type Store struct {
	mu        sync.Mutex
	dir       string
	now       func() time.Time
	writeFile func(path string, data []byte) error
}

// OpenStore opens the store in dir, creating the history folder if needed.
// writeFile must replace a file atomically (fsutil.WriteAtomic in production).
func OpenStore(dir string, writeFile func(path string, data []byte) error) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "history"), 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir, now: time.Now, writeFile: writeFile}, nil
}

func (s *Store) currentPath() string { return filepath.Join(s.dir, "current.json") }
func (s *Store) historyPath(rev uint64) string {
	return filepath.Join(s.dir, "history", strconv.FormatUint(rev, 10)+".json")
}
func (s *Store) goodPath() string { return filepath.Join(s.dir, "good") }

// ErrNoConfig means no config has been saved yet.
var ErrNoConfig = errors.New("no config saved yet")

// Current returns the revision in force, or ErrNoConfig.
func (s *Store) Current() (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read(s.currentPath())
}

func (s *Store) read(path string) (Record, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- paths are built by the store from fixed names
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, ErrNoConfig
		}
		return Record{}, err
	}
	return decodeRecord(data)
}

// decodeRecord parses a record as strictly as Decode parses a config.
func decodeRecord(data []byte) (Record, error) {
	var env struct {
		Revision uint64          `json:"revision"`
		SavedAt  time.Time       `json:"saved_at"`
		Actor    string          `json:"actor"`
		Summary  string          `json:"summary"`
		Config   json.RawMessage `json:"config"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return Record{}, fmt.Errorf("reading saved config: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Record{}, errors.New("reading saved config: unexpected data after the record")
	}
	cfg, err := Decode(bytes.NewReader(env.Config))
	if err != nil {
		return Record{}, fmt.Errorf("saved config revision %d: %w", env.Revision, err)
	}
	return Record{env.Revision, env.SavedAt, env.Actor, env.Summary, cfg}, nil
}

// Save validates cfg and makes it the new current revision. The revision it
// replaces moves to the history.
func (s *Store) Save(cfg Config, actor, summary string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(cfg, actor, summary)
}

func (s *Store) save(cfg Config, actor, summary string) (Record, error) {
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return Record{}, err
	}
	cur, err := s.read(s.currentPath())
	switch {
	case errors.Is(err, ErrNoConfig):
		cur = Record{}
	case err != nil:
		// a damaged current file is kept in the history folder under its
		// own name rather than overwritten silently; numbering carries on
		// past it so no two configs ever share a revision number
		damagedRev := s.damagedRevision()
		keep := filepath.Join(s.dir, "history", "damaged-"+strconv.FormatInt(s.now().Unix(), 10)+".json")
		if rerr := os.Rename(s.currentPath(), keep); rerr != nil {
			// not saving is better than overwriting the damaged file
			// unkept (review finding GOE-9)
			return Record{}, fmt.Errorf("the saved settings are damaged (%w) and could not be set aside: %w", err, rerr)
		}
		cur = Record{Revision: max(s.newestRevision(), damagedRev)}
	default:
		data, err := os.ReadFile(s.currentPath())
		if err != nil {
			return Record{}, err
		}
		if err := s.writeFile(s.historyPath(cur.Revision), data); err != nil {
			return Record{}, err
		}
	}
	rec := Record{Revision: cur.Revision + 1, SavedAt: s.now().UTC(), Actor: actor, Summary: summary, Config: cfg}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return Record{}, err
	}
	if err := s.writeFile(s.currentPath(), data); err != nil {
		return Record{}, err
	}
	s.prune()
	return rec, nil
}

// History lists saved revisions, newest first, without their configs.
func (s *Store) History() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Record
	if cur, err := s.read(s.currentPath()); err == nil {
		cur.Config = Config{}
		out = append(out, cur)
	}
	for _, rev := range s.historyRevisions() {
		r, err := s.read(s.historyPath(rev))
		if err != nil {
			continue
		}
		r.Config = Config{}
		out = append(out, r)
	}
	return out, nil
}

// Get returns a revision, current or from the history.
func (s *Store) Get(rev uint64) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(rev)
}

func (s *Store) get(rev uint64) (Record, error) {
	if cur, err := s.read(s.currentPath()); err == nil && cur.Revision == rev {
		return cur, nil
	}
	r, err := s.read(s.historyPath(rev))
	if errors.Is(err, ErrNoConfig) {
		return Record{}, fmt.Errorf("revision %d is not kept", rev)
	}
	return r, err
}

// Rollback saves the config of an earlier revision as a new revision. History
// only moves forward, so a rollback can itself be rolled back.
func (s *Store) Rollback(rev uint64, actor string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, err := s.get(rev)
	if err != nil {
		return Record{}, err
	}
	return s.save(old.Config, actor, fmt.Sprintf("Rolled back to revision %d", rev))
}

// MarkGood records that the web worker loaded rev.
func (s *Store) MarkGood(rev uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeFile(s.goodPath(), []byte(strconv.FormatUint(rev, 10)))
}

// LastGood returns the last revision the web worker loaded, or 0.
func (s *Store) LastGood() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.goodPath())
	if err != nil {
		return 0
	}
	rev, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return rev
}

func (s *Store) historyRevisions() []uint64 {
	entries, err := os.ReadDir(filepath.Join(s.dir, "history"))
	if err != nil {
		return nil
	}
	var revs []uint64
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		if rev, err := strconv.ParseUint(name, 10, 64); err == nil {
			revs = append(revs, rev)
		}
	}
	slices.Sort(revs)
	slices.Reverse(revs)
	return revs
}

// damagedRevision reads just the revision number of a current file that
// failed validation, or 0 if even that cannot be read.
func (s *Store) damagedRevision() uint64 {
	data, err := os.ReadFile(s.currentPath())
	if err != nil {
		return 0
	}
	var env struct {
		Revision uint64 `json:"revision"`
	}
	if json.Unmarshal(data, &env) != nil {
		return 0
	}
	return env.Revision
}

func (s *Store) newestRevision() uint64 {
	if revs := s.historyRevisions(); len(revs) > 0 {
		return revs[0]
	}
	return 0
}

// prune keeps the newest HistoryKept history files, and never the one the
// worker last loaded if that is older (it is the rollback target).
func (s *Store) prune() {
	// An unreadable or damaged last-good marker reads as 0, which keeps no
	// extra revision; a failed removal leaves one more history file than
	// needed, which the next prune tries again. Neither stops a save.
	good := uint64(0)
	if b, err := os.ReadFile(s.goodPath()); err == nil {
		if rev, perr := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); perr == nil {
			good = rev
		}
	}
	for i, rev := range s.historyRevisions() {
		if i >= HistoryKept && rev != good {
			_ = os.Remove(s.historyPath(rev))
		}
	}
}

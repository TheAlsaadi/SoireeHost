// Package logread lists and reads the web worker's rotating log files for
// the supervisor: the live file and its rotated copies, newest first, line by
// line, with a cap on line length. Used by fwevent (firewall.log) and
// accesslog (access.log). A compromised worker may write anything into its
// own log folder, so links and anything that is not a regular file are left
// out, and every line is parsed and validated by the caller.
package logread

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Files lists the log called live in dir and its rotated copies
// (<prefix><anything>.log), newest first. A file last written before since
// (when it is not zero) cannot hold anything newer, so it is left out; this
// keeps a poll for new lines from reading the whole history each time.
func Files(dir, live, prefix string, since time.Time) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("listing the logs: %w", err)
	}
	type file struct {
		path string
		mod  time.Time
	}
	var out []file
	for _, e := range ents {
		n := e.Name()
		if n != live && (!strings.HasPrefix(n, prefix) || !strings.HasSuffix(n, ".log")) {
			continue
		}
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if !since.IsZero() && info.ModTime().Before(since) {
			continue
		}
		out = append(out, file{filepath.Join(dir, n), info.ModTime()})
	}
	slices.SortStableFunc(out, func(a, b file) int {
		if n := b.mod.Compare(a.mod); n != 0 {
			return n
		}
		// the live file is the newest when times tie
		if filepath.Base(a.path) == live {
			return -1
		}
		if filepath.Base(b.path) == live {
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

// NextLine returns the next line without its line ending. A line longer than
// the reader's buffer is consumed and reported as too long.
func NextLine(r *bufio.Reader) ([]byte, bool, error) {
	b, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = r.ReadSlice('\n')
		}
		return nil, true, err
	}
	return bytes.TrimRight(b, "\r\n"), false, err
}

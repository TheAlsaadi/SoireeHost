package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Log rotation for cloudflared's output: about LogMaxBytes * (logKeep+1).
const (
	LogMaxBytes = 10 << 20
	logKeep     = 3
	// LogName is the file in the tunnel log folder.
	LogName = "cloudflared.log"
)

// rotatingLog appends lines to one file in the tunnel launcher's own log
// folder and rotates it by size. Lines reach it only after the scrubber.
type rotatingLog struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

func openRotatingLog(dir string, maxBytes int64) (*rotatingLog, error) {
	l := &rotatingLog{path: filepath.Join(dir, LogName), max: maxBytes}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *rotatingLog) open() error {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) // #nosec G304 -- fixed name in the launcher's own log folder
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	l.f, l.size = f, st.Size()
	return nil
}

// writeLine writes prefix, the line and a newline.
func (l *rotatingLog) writeLine(prefix string, line []byte) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return
	}
	if l.size >= l.max {
		l.rotate()
		if l.f == nil {
			return
		}
	}
	n, _ := fmt.Fprintf(l.f, "%s %s\n", prefix, line)
	l.size += int64(n)
}

func (l *rotatingLog) rotate() {
	_ = l.f.Close()
	l.f = nil
	for i := logKeep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", l.path, i), fmt.Sprintf("%s.%d", l.path, i+1))
	}
	_ = os.Rename(l.path, l.path+".1")
	_ = l.open()
}

func (l *rotatingLog) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

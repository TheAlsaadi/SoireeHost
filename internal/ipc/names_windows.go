package ipc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// Pipe names (DR-1). The supervisor creates its three pipes under a new
// random name at every start, so no other account can take a name before the
// supervisor does and keep it from starting: any user may create a named
// pipe, and a fixed, public name could be held while the supervisor
// restarts. The supervisor then writes each name to a small file in its
// config folder that only the pipe's intended client may read (pipe-name
// files). A client reads the name from that file, checks that the supervisor
// owns the file, and dials that exact name, so it never searches the pipe
// namespace and decoys cannot get in its way. Dial still checks the pipe's
// owner before sending anything.
const (
	pipeDir = `\\.\pipe\`

	ControlPipePrefix = "soireehost-control-"
	WebPipePrefix     = "soireehost-web-"
	TunnelPipePrefix  = "soireehost-tunnel-"

	// Pipe-name files, in the config folder.
	ControlPipeFile = "control.pipe"
	WebPipeFile     = "web.pipe"
	TunnelPipeFile  = "tunnel.pipe"

	maxPipeNameFile = 512
)

// NewPipeName returns a full pipe path made of prefix and 128 random bits.
func NewPipeName(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return pipeDir + prefix + hex.EncodeToString(b), nil
}

// DataRoot is %ProgramData%\SoireeHost.
func DataRoot() (string, error) {
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", fmt.Errorf("reading the ProgramData folder: %w", err)
	}
	return filepath.Join(pd, "SoireeHost"), nil
}

// PipeFilePath is the path of a pipe-name file under a data root.
func PipeFilePath(dataRoot, name string) string {
	return filepath.Join(PipeFileFolder(dataRoot, name), name)
}

// PipeFileFolder is the folder that holds one pipe-name file, such as
// config\pipe-web for web.pipe. Each file has a folder of its own, whose
// inheritable permissions admit that pipe's clients (winsec.PipeNameFolderSDDL).
func PipeFileFolder(dataRoot, name string) string {
	return filepath.Join(dataRoot, "config", "pipe-"+strings.TrimSuffix(name, ".pipe"))
}

// ReadPipeName reads a pipe name from a pipe-name file owned by wantOwner and
// checks that it names a SoiréeHost pipe.
func ReadPipeName(file, wantOwner string) (string, error) {
	b, err := winsec.ReadOwnedFile(file, wantOwner, maxPipeNameFile)
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(string(b))
	if !strings.HasPrefix(name, pipeDir+"soireehost-") || strings.ContainsAny(name[len(pipeDir):], `\/`) {
		return "", fmt.Errorf("%s does not hold a SoiréeHost pipe name", file)
	}
	return name, nil
}

// DialFile reads the pipe name from file and connects to it.
func DialFile(ctx context.Context, file, wantOwner string) (net.Conn, error) {
	name, err := ReadPipeName(file, wantOwner)
	if err != nil {
		return nil, err
	}
	return Dial(ctx, name, wantOwner)
}

// dialFileWait retries DialFile until it succeeds or ctx ends, for a worker
// started a moment before the supervisor's pipe or file is ready.
func dialFileWait(ctx context.Context, file, wantOwner string) (net.Conn, error) {
	for {
		conn, err := DialFile(ctx, file, wantOwner)
		if err == nil {
			return conn, nil
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// DialControlFile connects to the supervisor's control pipe, whose name it
// reads from the control pipe-name file.
func DialControlFile(ctx context.Context, file, supervisorSID string) (*Client, error) {
	conn, err := DialFile(ctx, file, supervisorSID)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn}, nil
}

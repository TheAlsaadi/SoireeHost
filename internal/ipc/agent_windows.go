package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
)

// ErrAgentExit is what Load wraps in its error to make RunAgent report the
// failure and then return it, so the worker process ends (S-01: a worker
// whose listener self-check fails must exit).
var ErrAgentExit = errors.New("the worker must exit")

// AgentOptions configure a worker's side of its pipe.
type AgentOptions struct {
	// Pipe is the supervisor's pipe. If it is empty, the agent reads the
	// pipe's name from PipeFile (the supervisor's names are random, DR-1).
	Pipe          string
	PipeFile      string
	SupervisorSID string
	Role          string
	Version       string
	// Load applies one load message (Caddy config or tunnel token).
	Load func(WorkerMsg) error
	// Scan runs the exposure check on a folder (web worker only). A worker
	// without it answers every scan with failed.
	Scan func(ScanRequest) (sitecheck.ExposureReport, error)
	// Stop is called once when the agent ends, for any reason.
	Stop func()
	// DialTimeout bounds the wait for the supervisor's pipe.
	DialTimeout time.Duration
	// Notify carries messages the worker sends on its own (the tunnel
	// launcher's status reports). Each is validated for the role before it
	// is sent.
	Notify <-chan WorkerMsg
}

// maxScans bounds the exposure checks a worker runs at once.
const maxScans = 2

// scanReply runs one exposure check and builds its answer.
func scanReply(scan func(ScanRequest) (sitecheck.ExposureReport, error), m WorkerMsg) WorkerMsg {
	if scan == nil {
		return WorkerMsg{Type: MsgFailed, Revision: m.Revision, Code: FailOther, Reason: "this worker does not check folders"}
	}
	rep, err := scan(*m.Scan)
	if err != nil {
		return WorkerMsg{Type: MsgFailed, Revision: m.Revision, Code: FailScan, Reason: CutReason(err.Error())}
	}
	return WorkerMsg{Type: MsgScanned, Revision: m.Revision, Exposure: &rep}
}

// RunAgent is the whole life of a worker: connect to the supervisor (checking
// that the pipe belongs to the supervisor's account), say hello, apply each
// load, and return when the pipe closes, a stop arrives, or ctx ends. A
// worker exits when this returns, so a dead supervisor takes its workers
// with it (ADR-0001).
func RunAgent(ctx context.Context, o AgentOptions) error {
	if o.DialTimeout == 0 {
		o.DialTimeout = 30 * time.Second
	}
	if o.Stop != nil {
		defer o.Stop()
	}
	// ends the goroutine below that closes the pipe, also when the caller's
	// context never ends
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	dctx, cancel := context.WithTimeout(ctx, o.DialTimeout)
	var conn net.Conn
	var err error
	switch {
	case o.Pipe != "":
		conn, err = Dial(dctx, o.Pipe, o.SupervisorSID)
	case o.PipeFile != "":
		conn, err = dialFileWait(dctx, o.PipeFile, o.SupervisorSID)
	default:
		err = errors.New("no pipe and no pipe-name file given")
	}
	cancel()
	if err != nil {
		return fmt.Errorf("connecting to the supervisor: %w", err)
	}
	wc := NewWorkerConn(conn, o.Role)
	defer wc.Close() //nolint:errcheck // closing is the signal either way
	go func() {
		<-ctx.Done()
		_ = wc.Close()
	}()
	if err := wc.Send(WorkerMsg{Type: MsgHello, Role: o.Role, Version: o.Version}); err != nil {
		return err
	}
	if o.Notify != nil {
		nctx, ncancel := context.WithCancel(ctx)
		defer ncancel()
		go func() {
			for {
				select {
				case <-nctx.Done():
					return
				case m := <-o.Notify:
					// a failed send means the pipe is closing; the receive
					// loop below sees that and returns
					_ = wc.Send(m)
				}
			}
		}()
	}
	scanSlots := make(chan struct{}, maxScans)
	for {
		m, err := wc.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("supervisor pipe: %w", err)
		}
		switch m.Type {
		case MsgStop:
			return nil
		case MsgLoad:
			if lerr := o.Load(m); lerr != nil {
				reason := CutReason(lerr.Error())
				code := FailureCode(lerr, FailConfigRejected)
				if o.Role == RoleTunnel {
					code = FailTunnelRefused
				}
				if err := wc.Send(WorkerMsg{Type: MsgFailed, Revision: m.Revision, Code: code, Reason: reason}); err != nil {
					return err
				}
				if errors.Is(lerr, ErrAgentExit) {
					return lerr
				}
				continue
			}
			if err := wc.Send(WorkerMsg{Type: MsgLoaded, Revision: m.Revision}); err != nil {
				return err
			}
		case MsgScan:
			// a scan can take its full 30 s; it runs beside the receive loop so
			// a load sent meanwhile is not held up past the supervisor's load
			// timeout and undone (pre-merge review, 15 Nov 2026). At most
			// maxScans run at once; more are answered failed at once.
			select {
			case scanSlots <- struct{}{}:
				go func(m WorkerMsg) {
					defer func() { <-scanSlots }()
					// a failed send means the pipe is closing; the loop sees it
					_ = wc.Send(scanReply(o.Scan, m))
				}(m)
			default:
				if err := wc.Send(WorkerMsg{Type: MsgFailed, Revision: m.Revision, Code: FailBusy, Reason: "other folders are being checked; try again"}); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unexpected %s from the supervisor", m.Type)
		}
	}
}

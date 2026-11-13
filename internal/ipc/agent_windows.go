package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

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
	// Stop is called once when the agent ends, for any reason.
	Stop func()
	// DialTimeout bounds the wait for the supervisor's pipe.
	DialTimeout time.Duration
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
	wc := NewWorkerConn(conn)
	defer wc.Close() //nolint:errcheck // closing is the signal either way
	go func() {
		<-ctx.Done()
		_ = wc.Close()
	}()
	if err := wc.Send(WorkerMsg{Type: MsgHello, Role: o.Role, Version: o.Version}); err != nil {
		return err
	}
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
				reason := lerr.Error()
				if len(reason) > MaxReasonLen {
					reason = reason[:MaxReasonLen]
				}
				if err := wc.Send(WorkerMsg{Type: MsgFailed, Revision: m.Revision, Reason: reason}); err != nil {
					return err
				}
				continue
			}
			if err := wc.Send(WorkerMsg{Type: MsgLoaded, Revision: m.Revision}); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected %s from the supervisor", m.Type)
		}
	}
}

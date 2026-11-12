// Package svcrun runs a role as a Windows service and starts and stops the
// worker services with the least rights the service control manager needs.
package svcrun

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

// ErrNotService is returned when a service role is started from a console.
var ErrNotService = errors.New("this role runs as a Windows service; setup installs it")

// The service dispatcher (StartServiceCtrlDispatcher) can be started once
// per process. Caddy, which every role links, starts it from its own init()
// whenever the process runs as a service, with a handler that ends the
// process on Stop. So this package claims the dispatcher first, in its own
// init(): the Go spec (since 1.21) initialises ready packages in import-path
// order, and "github.com/TheAlsaadi/..." sorts before
// "github.com/caddyserver/...", so this init runs before Caddy's, as long as
// this package never imports Caddy. Caddy's later attempt then fails, and
// Caddy ignores that failure. Run hands the claimed dispatcher to the role.
var dispatcher struct {
	isService bool
	err       error // why the dispatcher could not be claimed
	ready     chan struct{}
	req       <-chan svc.ChangeRequest
	status    chan<- svc.Status
	result    chan [2]uint32 // Execute's return values: specific flag, exit code
	stopped   chan error     // svc.Run's own return
}

// claimTimeout bounds how long init waits for the service manager to call
// back; Windows itself allows a service 30 seconds to connect.
const claimTimeout = 20 * time.Second

func init() {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return
	}
	d := &dispatcher
	d.isService = true
	d.ready = make(chan struct{})
	d.result = make(chan [2]uint32, 1)
	d.stopped = make(chan error, 1)
	go func() { d.stopped <- svc.Run("", bridge{}) }()
	select {
	case <-d.ready:
	case err := <-d.stopped:
		d.err = fmt.Errorf("starting the service dispatcher: %w", err)
	case <-time.After(claimTimeout):
		d.err = errors.New("the service manager did not call back in time")
	}
}

// bridge is the handler the dispatcher calls; it passes the service's
// request and status channels to Run and waits for Run's verdict.
type bridge struct{}

func (bridge) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	dispatcher.req, dispatcher.status = req, status
	close(dispatcher.ready)
	r := <-dispatcher.result
	return r[0] != 0, r[1]
}

// Run runs fn as the service name until the service control manager asks it
// to stop (or, with preShutdown, the system is shutting down), then cancels
// fn's context and waits for it to return.
func Run(name string, preShutdown bool, fn func(ctx context.Context) error) error {
	d := &dispatcher
	if !d.isService {
		return ErrNotService
	}
	// A service has no console, so its start and failure are written to the
	// Application event log under its own name (setup registers the source).
	// Messages are error texts and paths, never secret values.
	elog, _ := eventlog.Open(name)
	err := d.err
	if err == nil {
		h := &handler{fn: fn, preShutdown: preShutdown}
		specific, code := h.Execute(nil, d.req, d.status)
		var flag uint32
		if specific {
			flag = 1
		}
		d.result <- [2]uint32{flag, code}
		// let the dispatcher report SERVICE_STOPPED before the process exits
		select {
		case dispErr := <-d.stopped:
			_ = dispErr // the dispatcher's own result; the role's error is what matters
		case <-time.After(10 * time.Second):
		}
		err = h.err
	}
	if elog != nil {
		if err != nil {
			_ = elog.Error(1, name+" stopped with an error: "+err.Error())
		}
		_ = elog.Close()
	}
	return err
}

type handler struct {
	fn          func(ctx context.Context) error
	preShutdown bool
	err         error
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	accepts := svc.AcceptStop | svc.AcceptShutdown
	if h.preShutdown {
		accepts |= svc.AcceptPreShutdown
	}
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.fn(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: accepts}
	for {
		select {
		case err := <-done:
			cancel()
			h.err = err
			status <- svc.Status{State: svc.StopPending}
			if err != nil {
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown, svc.PreShutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 20000}
				cancel()
			}
		}
	}
}

// SCM starts and stops services through the service control manager, asking
// only for the rights it uses: connect to the manager, and start, stop and
// query the service. The worker services' security descriptors grant exactly
// these to the supervisor (S-20).
type SCM struct{}

func openService(name string, access uint32) (windows.Handle, error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, fmt.Errorf("connecting to the service manager: %w", err)
	}
	defer windows.CloseServiceHandle(m) //nolint:errcheck // nothing to do on failure
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	s, err := windows.OpenService(m, n, access)
	if err != nil {
		return 0, fmt.Errorf("opening service %s: %w", name, err)
	}
	return s, nil
}

// Start starts a service. One that is already running is not an error.
func (SCM) Start(name string) error {
	s, err := openService(name, windows.SERVICE_START)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(s) //nolint:errcheck // nothing to do on failure
	if err := windows.StartService(s, 0, nil); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("starting %s: %w", name, err)
	}
	return nil
}

// Stop asks a service to stop and waits up to ten seconds. One that is not
// running is not an error.
func (SCM) Stop(name string) error {
	s, err := openService(name, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(s) //nolint:errcheck // nothing to do on failure
	var st windows.SERVICE_STATUS
	if err := windows.ControlService(s, windows.SERVICE_CONTROL_STOP, &st); err != nil &&
		!errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return fmt.Errorf("stopping %s: %w", name, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for st.CurrentState != windows.SERVICE_STOPPED && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		if err := windows.QueryServiceStatus(s, &st); err != nil {
			return err
		}
	}
	return nil
}

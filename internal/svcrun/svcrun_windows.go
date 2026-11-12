// Package svcrun runs a role as a Windows service and starts and stops the
// worker services with the least rights the service control manager needs.
package svcrun

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

// ErrNotService is returned when a service role is started from a console.
var ErrNotService = errors.New("this role runs as a Windows service; setup installs it")

// Why this package talks to the service manager itself
//
// The service dispatcher (StartServiceCtrlDispatcher) can be started once per
// process. Caddy, which every role links, starts it from its own init()
// through golang.org/x/sys/windows/svc whenever the process runs as a
// service, with a handler that ends the process on Stop. That package keeps
// its handler in one package-level variable, so any later svc.Run call
// replaces the handler of a dispatcher started earlier. So this package does
// not use svc.Run: it runs the service protocol itself with its own
// callbacks, and starts the dispatcher before Caddy can:
//
//   - The Go spec (since 1.21) initialises ready packages in import-path order;
//     "github.com/TheAlsaadi/..." sorts before "github.com/caddyserver/...",
//     and this package never imports Caddy, so this init() runs first.
//   - init() cannot wait for the dispatcher's callback, because the Go runtime
//     holds every callback from a Windows thread until all init functions have
//     returned. It starts the dispatcher in the background and pauses briefly,
//     long enough for it to register with the service manager (a local call
//     that takes milliseconds). Caddy's attempt then fails, and Caddy ignores
//     the failure.
//   - Run, called after start-up, waits for the callback. If something else
//     still claimed the dispatcher, Run reports it and the service exits with
//     an error; the service manager's recovery (or the supervisor, for a
//     worker) starts it again.
type dispatcherState struct {
	isService bool
	ready     chan struct{}  // closed once the control handler is registered
	controls  chan uint32    // stop, shutdown and pre-shutdown requests
	result    chan [2]uint32 // Run's verdict: service-specific flag, exit code
	stopped   chan error     // StartServiceCtrlDispatcher's own return

	mu         sync.Mutex
	handle     windows.Handle
	current    windows.SERVICE_STATUS
	checkpoint uint32
}

var dispatcher dispatcherState

// Timings for claiming the dispatcher (see above).
const (
	registerPause = 250 * time.Millisecond
	claimTimeout  = 30 * time.Second
	stopWaitHint  = 20 * time.Second
)

var (
	// the service name is ignored for a SERVICE_WIN32_OWN_PROCESS service
	emptyName          = &[]uint16{0}[0]
	serviceMainProc    = windows.NewCallback(serviceMain)
	controlHandlerProc = windows.NewCallback(controlHandler)
	serviceTable       = []windows.SERVICE_TABLE_ENTRY{{ServiceName: emptyName, ServiceProc: serviceMainProc}, {}}
)

func init() {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return
	}
	d := &dispatcher
	d.isService = true
	d.ready = make(chan struct{})
	d.controls = make(chan uint32, 8)
	d.result = make(chan [2]uint32, 1)
	d.stopped = make(chan error, 1)
	go func() { d.stopped <- windows.StartServiceCtrlDispatcher(&serviceTable[0]) }()
	time.Sleep(registerPause)
}

// serviceMain is the ServiceMain the dispatcher calls on its own thread. It
// registers the control handler, hands over to Run, and reports the final
// stopped state with Run's exit code.
func serviceMain(_ uint32, _ **uint16) uintptr {
	d := &dispatcher
	h, err := windows.RegisterServiceCtrlHandlerEx(emptyName, controlHandlerProc, 0)
	if err != nil {
		return 0 // Run's claim times out and says so
	}
	d.mu.Lock()
	d.handle = h
	d.mu.Unlock()
	d.setStatus(windows.SERVICE_START_PENDING, 0, 0)
	close(d.ready)
	r := <-d.result
	var win32, specific uint32
	if r[0] != 0 {
		win32, specific = uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR), r[1]
	}
	d.mu.Lock()
	d.current = windows.SERVICE_STATUS{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS,
		CurrentState: windows.SERVICE_STOPPED, Win32ExitCode: win32, ServiceSpecificExitCode: specific}
	_ = windows.SetServiceStatus(d.handle, &d.current)
	d.mu.Unlock()
	return 0
}

// controlHandler is the HandlerEx the service manager calls with controls.
func controlHandler(ctrl, _ uint32, _, _ uintptr) uintptr {
	d := &dispatcher
	switch ctrl {
	case windows.SERVICE_CONTROL_INTERROGATE:
		d.mu.Lock()
		_ = windows.SetServiceStatus(d.handle, &d.current)
		d.mu.Unlock()
	case windows.SERVICE_CONTROL_STOP, windows.SERVICE_CONTROL_SHUTDOWN, windows.SERVICE_CONTROL_PRESHUTDOWN:
		select {
		case d.controls <- ctrl:
		default:
		}
	default:
		return uintptr(windows.ERROR_CALL_NOT_IMPLEMENTED)
	}
	return 0
}

// setStatus reports a state to the service manager.
func (d *dispatcherState) setStatus(state, accepts uint32, waitHint time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if state == windows.SERVICE_START_PENDING || state == windows.SERVICE_STOP_PENDING {
		d.checkpoint++
	} else {
		d.checkpoint = 0
	}
	d.current = windows.SERVICE_STATUS{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		CurrentState:     state,
		ControlsAccepted: accepts,
		CheckPoint:       d.checkpoint,
		WaitHint:         uint32(waitHint / time.Millisecond), // #nosec G115 -- a few seconds
	}
	_ = windows.SetServiceStatus(d.handle, &d.current)
}

// claim waits, after start-up, for the dispatcher to hand over control.
func (d *dispatcherState) claim() error {
	select {
	case <-d.ready:
		return nil
	case err := <-d.stopped:
		return fmt.Errorf("starting the service dispatcher (did another component claim it first?): %w", err)
	case <-time.After(claimTimeout):
		return errors.New("the service manager did not hand over control in time")
	}
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
	err := d.claim()
	if err == nil {
		err = d.serve(preShutdown, fn)
	}
	if elog != nil {
		if err != nil {
			_ = elog.Error(1, name+" stopped with an error: "+err.Error())
		}
		_ = elog.Close()
	}
	return err
}

// serve reports the service running, runs fn until it returns or a stop
// arrives, then lets serviceMain report it stopped.
func (d *dispatcherState) serve(preShutdown bool, fn func(ctx context.Context) error) error {
	accepts := uint32(windows.SERVICE_ACCEPT_STOP | windows.SERVICE_ACCEPT_SHUTDOWN)
	if preShutdown {
		accepts |= windows.SERVICE_ACCEPT_PRESHUTDOWN
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- fn(ctx) }()
	d.setStatus(windows.SERVICE_RUNNING, accepts, 0)
	var err error
loop:
	for {
		select {
		case err = <-done:
			break loop
		case <-d.controls:
			d.setStatus(windows.SERVICE_STOP_PENDING, 0, stopWaitHint)
			cancel()
		}
	}
	var flag, code uint32
	if err != nil {
		flag, code = 1, 1
	}
	d.result <- [2]uint32{flag, code}
	// let serviceMain report SERVICE_STOPPED before the process exits
	select {
	case dispErr := <-d.stopped:
		_ = dispErr // the dispatcher's own result; the role's error is what matters
	case <-time.After(10 * time.Second):
	}
	return err
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

// Package gui is the control-panel role: the Wails window, its tray icon and
// the thin bindings the UI calls. It holds no secrets and opens no network
// port; every action that changes SoiréeHost goes through internal/ipc to
// the supervisor (ADR-0003, ADR-0009).
package gui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/TheAlsaadi/SoireeHost/frontend"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/version"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// AppService is bound to the UI. Keep its methods free of side effects
// and arguments that reach the system; the supervisor does all real work.
type AppService struct{}

// Version returns the running application version.
func (AppService) Version() string {
	return version.Current()
}

// ContentSecurityPolicy is sent with every page and asset the window loads
// (S-33). It matches the meta tag in frontend/index.html, so neither copy is
// the only one: bundled scripts and styles only, no inline script, no remote
// content of any kind, no framing, no form submissions.
const ContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
	"connect-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-src 'none'; frame-ancestors 'none'"

// securityHeaders adds the S-33 headers to every response of the asset
// server.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// Options are the control panel's command-line options.
type Options struct {
	// Tray starts the control panel hidden in the tray (the sign-in entry).
	Tray bool
	// Uninstall opens the uninstall window (the Settings > Apps entry,
	// ADR-0010).
	Uninstall bool
}

// ParseArgs reads the gui role's arguments: --tray and --uninstall, at most
// one of them. Anything else is an error, so nothing is guessed.
func ParseArgs(args []string) (Options, error) {
	var o Options
	for _, a := range args {
		switch a {
		case "--tray":
			o.Tray = true
		case "--uninstall":
			o.Uninstall = true
		default:
			return Options{}, fmt.Errorf("unknown option %q for the control panel", a)
		}
	}
	if o.Tray && o.Uninstall {
		return Options{}, errors.New("--tray and --uninstall cannot be used together")
	}
	return o, nil
}

// controlPipeFile is where the supervisor writes its control pipe's name.
func controlPipeFile() (string, error) {
	root, err := ipc.DataRoot()
	if err != nil {
		return "", err
	}
	return ipc.PipeFilePath(root, ipc.ControlPipeFile), nil
}

// Run opens the control panel and blocks until the user quits it.
func Run(args []string) error {
	opts, err := ParseArgs(args)
	if err != nil {
		return err
	}
	assets, err := frontend.Assets()
	if err != nil {
		return fmt.Errorf("loading UI assets: %w", err)
	}
	file, err := controlPipeFile()
	if err != nil {
		return err
	}
	client := ipc.ControlFileClient(file, winsec.ServiceSID(winsec.SupervisorService))
	defer client.Close() //nolint:errcheck // closing at exit

	ctrl := NewControl(client)
	desk := &wailsDesktop{}
	local := NewLocal(desk)
	host := &systemHost{}
	setup := NewSetup(host, opts.Uninstall)
	// The install, upgrade and uninstall windows are not the control panel:
	// they have their own single-instance lock (otherwise the Apps entry's
	// Uninstall would only bring a running control panel to the front),
	// a smaller window and no tray.
	mode := setup.State().Mode
	panel := mode == ModeInstalled
	instance, width, height, minW, minH := "soireehost.controlpanel.", 1200, 760, 640, 420
	if !panel {
		instance, width, height, minW, minH = "soireehost.setup.", 720, 640, 560, 480
	}

	var win *application.WebviewWindow
	app := application.New(application.Options{
		Name:        "SoiréeHost",
		Description: "Host sites from this PC through Cloudflare Tunnel",
		Services: []application.Service{
			application.NewService(&AppService{}),
			application.NewService(ctrl),
			application.NewService(local),
			application.NewService(setup),
		},
		Assets: application.AssetOptions{
			Handler:        application.AssetFileServerFS(assets),
			Middleware:     securityHeaders,
			DisableLogging: true,
		},
		MarshalError: marshalError,
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: instance + currentUserTag(),
			OnSecondInstanceLaunch: func(application.SecondInstanceData) {
				if win != nil {
					win.Show()
					win.Restore()
					win.Focus()
				}
			},
		},
		Windows: application.WindowsOptions{DisableQuitOnLastWindowClosed: true},
	})
	desk.app = app
	host.quitApp = app.Quit

	win = app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:                      "SoiréeHost",
		Width:                      width,
		Height:                     height,
		MinWidth:                   minW,
		MinHeight:                  minH,
		URL:                        "/",
		Hidden:                     opts.Tray && panel,
		DefaultContextMenuDisabled: true,
		EnableFileDrop:             true,
	})
	desk.win = win

	// Closing the window hides it: sites keep serving either way, and the
	// tray stays (owner decision of 15 Nov 2026).
	// A setup window just closes and quits.
	win.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		if !panel {
			app.Quit()
			return
		}
		e.Cancel()
		win.Hide()
	})
	// A folder dropped on the window starts adding a site (plan section 6).
	// Only the first path is passed on, as text; the UI checks it through
	// PrepareFolder like a chosen folder.
	win.OnWindowEvent(events.Common.WindowFilesDropped, func(e *application.WindowEvent) {
		if files := e.Context().DroppedFiles(); len(files) > 0 {
			app.Event.Emit("folder-dropped", files[0])
		}
	})

	if panel {
		t := newTray(app, win, ctrl)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go t.watch(ctx)
		// a control panel whose SoiréeHost was uninstalled closes, and
		// removes its own sign-in entry (ADR-0010)
		go watchUninstalled(ctx, host, local, app.Quit)
	}

	err = app.Run()
	setup.afterExit()
	return err
}

// currentUserTag keeps the single-instance lock per user, so two people
// signed in at once each get their own control panel.
func currentUserTag() string {
	c, err := winsec.CurrentCaller()
	if err != nil {
		return "user"
	}
	return c.SID
}

// wailsDesktop is the desktop interface over the Wails application.
type wailsDesktop struct {
	mu  sync.Mutex
	app *application.App
	win *application.WebviewWindow
}

var errNoApp = errors.New("the window is not ready")

func (d *wailsDesktop) OpenURL(url string) error {
	if d.app == nil {
		return errNoApp
	}
	return d.app.Browser.OpenURL(url)
}

func (d *wailsDesktop) SetClipboard(text string) bool {
	if d.app == nil {
		return false
	}
	return d.app.Clipboard.SetText(text)
}

func (d *wailsDesktop) ChooseFolder() (string, error) {
	if d.app == nil {
		return "", errNoApp
	}
	dlg := d.app.Dialog.OpenFile().CanChooseDirectories(true).CanChooseFiles(false).
		CanCreateDirectories(true).SetTitle("Choose the folder to publish")
	if d.win != nil {
		dlg = dlg.AttachToWindow(d.win)
	}
	return dlg.PromptForSingleSelection()
}

func (d *wailsDesktop) SaveFile(name, text string) (bool, error) {
	if d.app == nil {
		return false, errNoApp
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	dlg := d.app.Dialog.SaveFile().SetFilename(name).AddFilter("SoiréeHost settings", "*.json")
	if d.win != nil {
		dlg = dlg.AttachToWindow(d.win)
	}
	path, err := dlg.PromptForSingleSelection()
	if err != nil || path == "" {
		return false, err
	}
	// The file is the user's, written with the user's own rights to the
	// place they chose; it holds no secret (S-40).
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return false, &ipc.Error{Code: ipc.CodeUnavailable, Message: "Could not save the file there. Choose another place."}
	}
	return true, nil
}

func (d *wailsDesktop) OpenTextFile(maxBytes int64) (string, error) {
	if d.app == nil {
		return "", errNoApp
	}
	dlg := d.app.Dialog.OpenFile().CanChooseFiles(true).AddFilter("SoiréeHost settings", "*.json").SetTitle("Choose a settings file")
	if d.win != nil {
		dlg = dlg.AttachToWindow(d.win)
	}
	path, err := dlg.PromptForSingleSelection()
	if err != nil || path == "" {
		return "", err
	}
	return readSmallFile(path, maxBytes)
}

// readSmallFile reads at most maxBytes from a file the user chose.
func readSmallFile(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- a file the user picked in the open dialog
	if err != nil {
		return "", &ipc.Error{Code: ipc.CodeInvalid, Message: "Could not open that file."}
	}
	defer f.Close() //nolint:errcheck // read-only
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return "", &ipc.Error{Code: ipc.CodeInvalid, Message: "Could not read that file."}
	}
	if int64(len(b)) > maxBytes {
		return "", &ipc.Error{Code: ipc.CodeInvalid, Message: "That file is too large to be SoiréeHost settings."}
	}
	return string(b), nil
}

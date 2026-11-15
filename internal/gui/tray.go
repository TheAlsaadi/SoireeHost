package gui

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
)

// trayPoll is how often the tray asks the supervisor for its state.
const trayPoll = 5 * time.Second

// tray is the notification-area icon: the status line in plain words, the
// offline switch, and the way back to the window (plan section 6). Quitting
// the control panel never stops a site.
type tray struct {
	app  *application.App
	win  *application.WebviewWindow
	ctrl *Control
	st   *application.SystemTray

	mu      sync.Mutex
	status  *application.MenuItem
	toggle  *application.MenuItem
	offline bool
	known   bool
	icons   map[bool][]byte
}

func newTray(app *application.App, win *application.WebviewWindow, ctrl *Control) *tray {
	t := &tray{app: app, win: win, ctrl: ctrl, icons: map[bool][]byte{true: trayIcon(true), false: trayIcon(false)}}
	menu := app.NewMenu()
	t.status = menu.Add("SoiréeHost: checking…").SetEnabled(false)
	menu.AddSeparator()
	menu.Add("Open SoiréeHost").OnClick(func(*application.Context) { t.showWindow() })
	t.toggle = menu.Add("Take everything offline").OnClick(func(*application.Context) { go t.flipOffline() })
	menu.AddSeparator()
	menu.Add("Quit control panel (sites keep serving)").OnClick(func(*application.Context) { app.Quit() })
	t.st = app.SystemTray.New()
	t.st.SetIcon(t.icons[true])
	t.st.SetTooltip("SoiréeHost")
	t.st.SetMenu(menu)
	t.st.OnClick(func() { t.showWindow() })
	return t
}

func (t *tray) showWindow() {
	t.win.Show()
	t.win.Restore()
	t.win.Focus()
}

// watch keeps the tray in step with the supervisor until ctx ends.
func (t *tray) watch(ctx context.Context) {
	tick := time.NewTicker(trayPoll)
	defer tick.Stop()
	for {
		t.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (t *tray) refresh(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := t.ctrl.Status(cctx)
	line, online := trayLine(st, err)
	t.mu.Lock()
	t.known = err == nil
	t.offline = err == nil && st.Tunnel.Offline
	label := "Take everything offline"
	if t.offline {
		label = "Bring sites back online"
	}
	t.mu.Unlock()
	t.status.SetLabel(line)
	t.toggle.SetLabel(label)
	t.toggle.SetEnabled(err == nil)
	t.st.SetTooltip(line)
	t.st.SetIcon(t.icons[online])
}

// trayLine is the tray's one sentence, and whether sites are online.
func trayLine(st ipc.StatusResult, err error) (string, bool) {
	switch {
	case err != nil:
		return "SoiréeHost: service not answering", false
	case st.Tunnel.Offline:
		return "SoiréeHost: offline (switched off)", false
	case st.Tunnel.RepairNeeded:
		return "SoiréeHost: tunnel needs repair", false
	}
	up := 0
	for _, tv := range st.Tunnel.Tunnels {
		if tv.State == ipc.TunnelConnected {
			up++
		}
	}
	if up == 0 {
		return "SoiréeHost: not online", false
	}
	return fmt.Sprintf("SoiréeHost: online, %d tunnel(s) connected", up), true
}

// flipOffline toggles the offline switch from the tray. Taking sites
// offline is not a weakening change; bringing them back is what the user
// asked for, so neither needs a confirmation (S-32 lists neither).
func (t *tray) flipOffline() {
	t.mu.Lock()
	known, want := t.known, !t.offline
	t.mu.Unlock()
	if !known {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	_, _ = t.ctrl.SetOffline(ctx, want)
	t.refresh(ctx)
}

// trayIcon draws the tray icon: a plum disc when online, a hollow grey ring
// when not, so the state reads by shape as well as colour (plan section 7).
func trayIcon(online bool) []byte {
	const n = 32
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	plum := color.NRGBA{R: 0x6b, G: 0x3a, B: 0x60, A: 0xff}
	grey := color.NRGBA{R: 0x8a, G: 0x8a, B: 0x8a, A: 0xff}
	c := float64(n-1) / 2
	for y := range n {
		for x := range n {
			d := math.Hypot(float64(x)-c, float64(y)-c)
			switch {
			case online && d <= 13:
				img.SetNRGBA(x, y, plum)
			case !online && d <= 13 && d >= 10:
				img.SetNRGBA(x, y, grey)
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img) // encoding an in-memory image cannot fail
	return buf.Bytes()
}

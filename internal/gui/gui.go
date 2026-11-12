// Package gui is the control-panel role: the Wails window and the thin
// bindings the UI calls. It holds no secrets and opens no network port;
// later phases route every action through internal/ipc to the supervisor.
package gui

import (
	"fmt"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/TheAlsaadi/SoireeHost/frontend"
	"github.com/TheAlsaadi/SoireeHost/internal/version"
)

// AppService is bound to the UI. Keep its methods free of side effects
// and arguments that reach the system; the supervisor does all real work.
type AppService struct{}

// Version returns the running application version.
func (AppService) Version() string {
	return version.Current()
}

// Run opens the control-panel window and blocks until it closes.
func Run() error {
	assets, err := frontend.Assets()
	if err != nil {
		return fmt.Errorf("loading UI assets: %w", err)
	}

	app := application.New(application.Options{
		Name:        "SoiréeHost",
		Description: "Host sites from this PC through Cloudflare Tunnel",
		Services: []application.Service{
			application.NewService(&AppService{}),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
	})

	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:     "SoiréeHost",
		Width:     960,
		Height:    600,
		MinWidth:  640,
		MinHeight: 400,
		URL:       "/",
	})

	return app.Run()
}

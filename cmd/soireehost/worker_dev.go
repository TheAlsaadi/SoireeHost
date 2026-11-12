//go:build !production

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
	"github.com/TheAlsaadi/SoireeHost/internal/worker"
)

// runWorker, in development builds only, serves a config file in the
// foreground so the web worker can be tried before the supervisor exists
// (Phase 2). Release builds never read a config path from the command line;
// there the supervisor hands the worker its config over a named pipe.
func runWorker(args []string) int {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfgPath := fs.String("config", "", "config file to serve (development builds only)")
	logDir := fs.String("logs", "soireehost-logs", "folder for access.log and worker.log")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cfgPath == "" || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: soireehost worker -config FILE [-logs DIR]")
		return 2
	}
	if err := serveConfigFile(*cfgPath, *logDir); err != nil {
		fmt.Fprintln(os.Stderr, "soireehost worker:", err)
		return 1
	}
	return 0
}

func serveConfigFile(cfgPath, logDir string) error {
	f, err := os.Open(cfgPath) // #nosec G304 -- development-only flag; the path is the developer's own config file
	if err != nil {
		return err
	}
	cfg, err := config.Decode(f) // Decode enforces config.MaxConfigBytes
	_ = f.Close()
	if err != nil {
		return err
	}
	loc, err := sitecheck.DefaultLocations()
	if err != nil {
		return err
	}
	for i := range cfg.Sites {
		if s := cfg.Sites[i].Static; s != nil {
			canon, err := sitecheck.CheckRoot(s.Root, loc)
			if err != nil {
				return fmt.Errorf("site %q: %w", cfg.Sites[i].ID, err)
			}
			s.Root = canon
		}
	}
	for _, w := range cfg.Warnings() {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	abs, err := filepath.Abs(logDir)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Fprintf(os.Stderr, "serving on http://%s (Ctrl+C to stop); logs in %s\n", cfg.Listen, abs)
	return worker.Run(ctx, cfg, worker.Options{LogDir: abs})
}

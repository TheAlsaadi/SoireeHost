# ADR-0003: UI shell is Wails v3 with Svelte 5

**Status:** Proposed (framework choice already decided by the owner: Svelte)
**Date:** 12 Nov 2026
**Deciders:** Owner

## Context

The control panel is a local desktop window on Windows 11. It must open no network port (S-31, plan section 4), load only bundled content under a strict CSP (S-33), be part of the single `soireehost.exe` (ADR-0002), and look like a native Windows utility (plan section 7). The owner chose Svelte.

## Decision

Use Wails v3.1.0 with WebView2 for the window and tray, and Svelte 5 + TypeScript + Vite for the UI. The control panel role calls the supervisor only through `internal/ipc` over the named pipe; Wails bindings are a thin layer over that client.

## Options considered

### Option A: Wails v3.1.0 (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Low to medium; Go-native bindings, no extra runtime |
| Cost | Free, MIT |
| Maturity | Stable line released 1 Nov 2026; still young |
| Fit | Tray, multi-window, built-in updater with pinned-key verification, single Go binary |

**Pros:** everything in one Go binary; WebView2 is part of Windows 11; assets are served from memory through Wails' asset server, not a TCP port.
**Cons:** new stable line, so documentation and community answers mix v2 and v3. Pin the exact version and work from the official v3 docs.

### Option B: Wails v2.17.1 (fallback)

**Pros:** mature, widely used.
**Cons:** no built-in tray or multi-window support comparable to v3; the updater would have to be written from scratch. Kept as the fallback if a blocking v3 bug appears; the Svelte UI carries over.

### Option C: Electron or Tauri

**Pros:** large ecosystems.
**Cons:** Electron bundles a whole browser and Node runtime, against the "one Go binary" design. Tauri is Rust, a second language and toolchain. Rejected.

## Consequences

- Assets must be embedded with `go:embed` and served by Wails' in-memory asset server only. Verify in Phase 5 that release builds expose no HTTP port and that developer tools are off (S-33).
- The Wails runtime JS package (`@wailsio/runtime`) is pinned to the same version as the Go module.
- Release builds must use `-tags production`. Without it, Wails turns WebView2 developer tools on and lets the `FRONTEND_DEVSERVER_URL` environment variable redirect the window to any URL (checked in the v3.1.0 source: `internal/assetserver/build_dev.go` is `!production`). `build/build.ps1` sets the tag unless `-Dev` is passed.
- Never build with `-tags server`: it turns the app into an HTTP server without a window.
- Bindings are generated with `wails3 generate bindings -ts ./...` and committed under `frontend/bindings/`; CI fails if they drift from the Go code.
- Revisit if Wails v3 shows a blocking bug; fall back to v2.17.x.

## Action items

1. [x] Phase 0: minimal window that shows the app version.
2. [ ] Phase 5: CSP, navigation lock, no dev tools in release builds, and a test that no TCP listener is opened by the GUI role.

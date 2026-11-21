//go:build server || mcp

package main

// Wails v3 opens a TCP listener when built with the server tag (an HTTP
// server for the frontend, host settable by environment variable) or the
// mcp tag (an MCP server). SoiréeHost's control panel must listen on no
// port (S-01, S-04; Phase 7 compliance review, 21 Nov 2026). This file
// compiles only with either tag, and it does not compile, so such a build
// fails here.
var _ = soireehost_builds_must_not_use_the_wails_server_or_mcp_tag_see_S_01

//go:build !no_fs_access

package waf

// Coraza must be built with the no_fs_access tag: without it, request bodies
// over the in-memory limit and every uploaded file are written to temporary
// files, and the web worker may write nowhere but its log folder (ADR-0008).
// This file only compiles without the tag, and it does not compile, so a
// build that forgets the tag fails here instead of quietly writing bodies to
// disk. Build and test with -tags no_fs_access (CI sets it in GOFLAGS).
var _ = build_with_tag_no_fs_access_see_ADR_0008

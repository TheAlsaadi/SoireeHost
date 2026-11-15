package waf

import (
	"path"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
)

// Coraza v3.8.1 implements the normalizePath and normalizePathWin
// transformations with filepath.Clean, which on Windows turns every '/' into
// '\'. Every CRS rule that uses them then misses Unix-style paths: rule
// 930120 does not see "etc/passwd" in "/view?file=/etc/passwd" (Coraza issue
// 1140, open). Registering under the same names replaces Coraza's versions
// (its registry overwrites), so these run instead. They are Coraza's own
// logic with path.Clean, which always uses '/' (ModSecurity semantics:
// normalizePathWin first turns '\' into '/'). Adapted from Coraza
// (Apache-2.0, internal/transformations/normalise_path*.go).
func init() {
	for _, n := range []string{"normalisePath", "normalizePath"} {
		plugins.RegisterTransformation(n, normalisePath)
	}
	for _, n := range []string{"normalisePathWin", "normalizePathWin"} {
		plugins.RegisterTransformation(n, normalisePathWin)
	}
}

func normalisePath(data string) (string, bool, error) {
	if data == "" {
		return data, false, nil
	}
	clean := path.Clean(data)
	if clean == "." {
		return "", true, nil
	}
	if data[len(data)-1] == '/' && clean != "/" {
		clean += "/"
	}
	return clean, data != clean, nil
}

func normalisePathWin(data string) (string, bool, error) {
	if data == "" {
		return data, false, nil
	}
	clean, _, err := normalisePath(strings.ReplaceAll(data, `\`, "/"))
	if err != nil {
		return clean, false, err
	}
	// Windows resolves a stream suffix ("file::$DATA") against the base file
	// and drops trailing dots and spaces from every component
	out := stripTrailingDotsAndSpaces(stripADS(clean))
	return out, data != out, nil
}

// stripADS cuts the last path component at its first ':', leaving a leading
// drive letter alone.
func stripADS(data string) string {
	prefix := ""
	if len(data) >= 2 && data[1] == ':' && isASCIILetter(data[0]) {
		prefix, data = data[:2], data[2:]
	}
	trailing := ""
	if strings.HasSuffix(data, "/") {
		trailing, data = "/", data[:len(data)-1]
	}
	if i := strings.LastIndexByte(data, '/'); i >= 0 {
		if c := strings.IndexByte(data[i+1:], ':'); c >= 0 {
			data = data[:i+1+c]
		}
	} else if c := strings.IndexByte(data, ':'); c >= 0 {
		data = data[:c]
	}
	return prefix + data + trailing
}

// stripTrailingDotsAndSpaces trims trailing '.' and ' ' from every component
// that is not navigation (".", ".."), dropping components that trim to
// nothing, as the Windows file APIs do.
func stripTrailingDotsAndSpaces(data string) string {
	parts := strings.Split(data, "/")
	out := parts[:0]
	for i, seg := range parts {
		if seg == "" || strings.Trim(seg, ".") == "" {
			out = append(out, seg) // empty (leading or trailing '/') or all dots
			continue
		}
		t := strings.TrimRight(seg, ". ")
		if t == "" {
			if i == len(parts)-1 {
				out = append(out, "")
			}
			continue
		}
		out = append(out, t)
	}
	return strings.Join(out, "/")
}

func isASCIILetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

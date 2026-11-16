package waf

import (
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"strings"
)

// multipartBoundary returns the boundary of a multipart/form-data body.
func multipartBoundary(contentType string) (string, bool) {
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mt, "multipart/form-data") {
		return "", false
	}
	b := params["boundary"]
	return b, b != ""
}

// multipartTextOver reports whether a multipart body holds more than
// TextInspectBytes in parts that are not files. A body that cannot be parsed
// counts as over the limit, so its text cannot slip past by confusing the
// count: the firewall's own parser may still read it as fields.
func multipartTextOver(body io.Reader, boundary string) bool {
	mr := multipart.NewReader(body, boundary)
	var text int64
	for {
		p, err := mr.NextRawPart()
		if errors.Is(err, io.EOF) {
			return false
		}
		if err != nil {
			return true
		}
		if isFilePart(p) {
			_ = p.Close()
			continue
		}
		n, err := io.Copy(io.Discard, io.LimitReader(p, TextInspectBytes-text+1))
		_ = p.Close()
		text += n
		if text > TextInspectBytes {
			return true
		}
		if err != nil {
			return true
		}
	}
}

// isFilePart reports whether a part is a file: its Content-Disposition names
// a filename, plain or extended (RFC 5987), as Coraza's multipart processor
// decides.
func isFilePart(p *multipart.Part) bool {
	_, params, err := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
	if err != nil {
		return false
	}
	return params["filename"] != "" || params["filename*"] != ""
}

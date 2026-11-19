package update

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"slices"
)

// object decodes data as one JSON object whose keys are exactly fields: no
// unknown key, no missing key, no key twice, and nothing after the object.
// encoding/json alone would match keys case-insensitively, keep the last of
// two equal keys and ignore unknown ones, any of which could let a payload
// mean something other than what a reviewer reads in it.
func object(data []byte, fields ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, malformed("not a JSON object")
	}
	out := make(map[string]json.RawMessage, len(fields))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, malformed("unreadable key")
		}
		key, ok := tok.(string)
		if !ok || !slices.Contains(fields, key) {
			return nil, malformed("unexpected field")
		}
		if _, dup := out[key]; dup {
			return nil, malformed("field given twice")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, malformed("unreadable value")
		}
		out[key] = raw
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, malformed("unterminated object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, malformed("data after the object")
	}
	for _, f := range fields {
		if _, ok := out[f]; !ok {
			return nil, malformed("missing field")
		}
	}
	return out, nil
}

// text decodes a JSON string value; a number, null or anything else is
// refused.
func text(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", malformed("expected a string")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", malformed("expected a string")
	}
	return s, nil
}

// integer decodes a JSON integer; fractions, exponents and strings are
// refused by encoding/json for an int64 target.
func integer(raw json.RawMessage) (int64, error) {
	var n int64
	if len(raw) == 0 || raw[0] == '"' {
		return 0, malformed("expected a number")
	}
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, malformed("expected a whole number")
	}
	return n, nil
}

// unbase64 decodes standard base64 with padding and accepts only the
// canonical encoding, so one value has one spelling (no line breaks, no
// non-zero trailing bits).
func unbase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, malformed("bad base64")
	}
	return b, nil
}

// Package ipc is SoiréeHost's control and worker protocol over named pipes
// (ADR-0006): length-prefixed JSON frames, a small typed control API, strict
// decoding, and identity checks on both ends of every pipe.
package ipc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxFrame bounds one message.
const MaxFrame = 1 << 20

// ErrFrameTooLarge is returned for a frame over MaxFrame.
var ErrFrameTooLarge = errors.New("message too large")

// WriteFrame writes a 4-byte big-endian length and the payload.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrame {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(len(payload))) // #nosec G115 -- bounded by MaxFrame above
	copy(buf[4:], payload)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one frame. A length over MaxFrame is refused before any of
// the payload is read.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, ErrFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("short message: %w", err)
	}
	return buf, nil
}

// decodeStrict decodes exactly one JSON value into v, refusing unknown
// fields and trailing data.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after the message")
	}
	return nil
}

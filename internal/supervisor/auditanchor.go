package supervisor

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"

	"github.com/TheAlsaadi/SoireeHost/internal/audit"
	"github.com/TheAlsaadi/SoireeHost/internal/secrets"
)

// auditAnchorName is the secret that holds the audit log's anchor (SE-13).
// It is not secret, but the secrets store is the one place the design
// already keeps apart from the audit folder: DPAPI-protected under the
// supervisor's account, in a folder only SYSTEM and the supervisor may
// open, whose permissions the supervisor checks at every start (S-22).
// Rewriting both the log and its anchor so that they agree needs code
// running as the supervisor's account or SYSTEM.
const auditAnchorName = "audit_anchor"

// secretAnchor keeps the audit anchor in the secrets store.
type secretAnchor struct{ s *secrets.Store }

func (a secretAnchor) LoadAnchor() (audit.Anchor, bool, error) {
	b, err := a.s.Get(auditAnchorName)
	if errors.Is(err, os.ErrNotExist) {
		return audit.Anchor{}, false, nil
	}
	if err != nil {
		return audit.Anchor{}, false, err
	}
	var x audit.Anchor
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&x); err != nil {
		return audit.Anchor{}, false, errors.New("the audit anchor is not valid")
	}
	return x, true, nil
}

func (a secretAnchor) SaveAnchor(x audit.Anchor) error {
	b, err := json.Marshal(x)
	if err != nil {
		return err
	}
	return a.s.Set(auditAnchorName, b)
}

// actorOf is the audit actor for a caller's SID. A SID that is not shaped
// like one gives the zero Actor, which Append refuses, so the change is
// treated as not audited.
func actorOf(sid string) audit.Actor {
	a, err := audit.SID(sid)
	if err != nil {
		return audit.Actor{}
	}
	return a
}

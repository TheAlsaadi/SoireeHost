package supervisor

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
)

// maxConfirmationsPerCaller bounds the open confirmation tokens one caller
// may hold; the oldest is dropped first.
const maxConfirmationsPerCaller = 16

// confirmations holds the single-use tokens the supervisor has offered for
// weakening changes (S-32, review finding SE-27). A token is accepted only
// once, before it expires, from the caller it was issued to, for the method
// and parameters it was issued for, and only while the change still weakens
// protection in exactly the way the user was told.
type confirmations struct {
	mu   sync.Mutex
	now  func() time.Time
	open map[string]confirmation // by token
}

type confirmation struct {
	sid     string
	method  string
	digest  [sha256.Size]byte
	expires time.Time
	issued  time.Time
}

func newConfirmations(now func() time.Time) *confirmations {
	if now == nil {
		now = time.Now
	}
	return &confirmations{now: now, open: map[string]confirmation{}}
}

// digestOf hashes what a token is bound to: the call's parameters without
// the token itself, and the sentences describing what it weakens.
func digestOf(params any, sentences []string) ([sha256.Size]byte, error) {
	b, err := json.Marshal(params)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	h := sha256.New()
	h.Write(b)
	h.Write([]byte{0})
	h.Write([]byte(strings.Join(sentences, "\x00")))
	var d [sha256.Size]byte
	copy(d[:], h.Sum(nil))
	return d, nil
}

// issue creates a token for this caller, method and digest.
func (cs *confirmations) issue(sid, method string, digest [sha256.Size]byte, sentences []string) (*ipc.Confirmation, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(raw[:])
	cs.mu.Lock()
	defer cs.mu.Unlock()
	now := cs.now()
	cs.pruneLocked(now)
	// keep at most maxConfirmationsPerCaller open tokens per caller
	var oldest string
	n := 0
	for t, c := range cs.open {
		if c.sid != sid {
			continue
		}
		n++
		if oldest == "" || c.issued.Before(cs.open[oldest].issued) {
			oldest = t
		}
	}
	if n >= maxConfirmationsPerCaller {
		delete(cs.open, oldest)
	}
	exp := now.Add(ipc.ConfirmationTTL)
	cs.open[token] = confirmation{sid: sid, method: method, digest: digest, expires: exp, issued: now}
	return &ipc.Confirmation{Token: token, Sentences: append([]string(nil), sentences...), Expires: exp}, nil
}

// consume accepts token once: it is removed whether or not it matches, so a
// guessed or misused token is never tried twice.
func (cs *confirmations) consume(token, sid, method string, digest [sha256.Size]byte) bool {
	if token == "" {
		return false
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	c, ok := cs.open[token]
	if !ok {
		return false
	}
	delete(cs.open, token)
	if cs.now().After(c.expires) {
		return false
	}
	return c.sid == sid && c.method == method && subtle.ConstantTimeCompare(c.digest[:], digest[:]) == 1
}

func (cs *confirmations) pruneLocked(now time.Time) {
	for t, c := range cs.open {
		if now.After(c.expires) {
			delete(cs.open, t)
		}
	}
}

// confirmRequest is one weakening call waiting for its confirmation: who
// made it, which method, and its parameters with the token field cleared.
type confirmRequest struct {
	sid    string
	method string
	params any
	token  string
}

// check refuses the change unless it carries a valid confirmation token for
// exactly these weakenings; it then offers a new token. With a valid token
// it records the weakenings in the audit detail.
func (w *weakenings) check(cs *confirmations, r confirmRequest, detail map[string]string) *ipc.Error {
	if len(w.tags) == 0 {
		return nil
	}
	digest, err := digestOf(r.params, w.sentences)
	if err != nil {
		return ipc.Errorf(ipc.CodeInternal, "Could not prepare the confirmation.")
	}
	if cs.consume(r.token, r.sid, r.method, digest) {
		detail["weakening"] = strings.Join(w.tags, ",")
		return nil
	}
	conf, err := cs.issue(r.sid, r.method, digest, w.sentences)
	if err != nil {
		return ipc.Errorf(ipc.CodeInternal, "Could not prepare the confirmation.")
	}
	lead := ""
	if r.token != "" {
		lead = "That confirmation has expired or does not match this change. "
	}
	e := ipc.Errorf(ipc.CodeConfirmationRequired, "%s%s Confirm to continue.", lead, strings.Join(w.sentences, " "))
	e.Confirmation = conf
	return e
}

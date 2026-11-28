package audit

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Actor is who made a change: always a Windows SID (SE-15). It is a struct,
// not a string, so an actor and an action cannot be swapped by mistake, and
// the only ways to get one are SID, which checks the shape, and System.
type Actor struct{ sid string }

// System is the local system account, the actor for the supervisor's own
// actions (S-1-5-18, winsec.SIDSystem).
var System = Actor{sid: "S-1-5-18"}

var sidRE = regexp.MustCompile(`^S-1-[0-9]{1,14}(-[0-9]{1,10}){1,15}$`)

// SID returns the actor for a caller's SID, refusing anything that is not
// shaped like one.
func SID(sid string) (Actor, error) {
	if !sidRE.MatchString(sid) {
		return Actor{}, errors.New("audit actor is not a SID")
	}
	return Actor{sid: sid}, nil
}

// String is the SID.
func (a Actor) String() string { return a.sid }

// Action is what was done, from a closed set (SE-15). Entries store its name.
type Action uint8

// The actions the supervisor records. Add new ones at the end and to
// actionNames; never reuse a name for something else.
const (
	actionInvalid Action = iota
	ConfigImport
	ConfigRollback
	ConfigUndone
	ConfigRestored
	ConfigRestoreFailed
	SitePut
	SiteRemove
	SiteSetEnabled
	QuickshareStart
	QuickshareStop
	TunnelSetOffline
	SecretSet
	SecretReplace
	SecretReplaceFailed
	UpdateSetCheck
	UpdateCheck
	UpdateReady
	SupervisorStart
	SupervisorStop
	WorkerRestart
	// AuditAnchored is written by Open when the log had no anchor (the
	// first start after the upgrade that added it) or its anchor could not
	// be read (SE-13).
	AuditAnchored
	actionEnd
)

var actionNames = [actionEnd]string{
	ConfigImport:        "config.import",
	ConfigRollback:      "config.rollback",
	ConfigUndone:        "config.undone",
	ConfigRestored:      "config.restored",
	ConfigRestoreFailed: "config.restore_failed",
	SitePut:             "site.put",
	SiteRemove:          "site.remove",
	SiteSetEnabled:      "site.set_enabled",
	QuickshareStart:     "quickshare.start",
	QuickshareStop:      "quickshare.stop",
	TunnelSetOffline:    "tunnel.set_offline",
	SecretSet:           "secret.set",
	SecretReplace:       "secret.replace",
	SecretReplaceFailed: "secret.replace.failed",
	UpdateSetCheck:      "update.set_check",
	UpdateCheck:         "update.check",
	UpdateReady:         "update.ready",
	SupervisorStart:     "supervisor.start",
	SupervisorStop:      "supervisor.stop",
	WorkerRestart:       "worker.restart",
	AuditAnchored:       "audit.anchored",
}

func (a Action) valid() bool { return a > actionInvalid && a < actionEnd }

// String is the action's name as stored in entries.
func (a Action) String() string {
	if !a.valid() {
		return fmt.Sprintf("audit.Action(%d)", uint8(a))
	}
	return actionNames[a]
}

// MaxDetailKeys bounds one entry's detail.
const MaxDetailKeys = 32

var detailKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// secretWords are refused anywhere in a detail key: an entry is shown to
// every control user and kept for good, so a value under such a key is a
// leak waiting to happen (S-36, SE-15). Matching is on substrings, so
// "api_key", "tunnel_token" and "passwd" are all refused; a harmless key
// that happens to contain one of these has to be renamed.
var secretWords = []string{"token", "passw", "pwd", "secret", "key", "cred", "cookie", "auth", "bearer", "private", "signature"}

// ErrSecretKey is returned for a detail key that names a secret.
var ErrSecretKey = errors.New("audit detail key looks like it holds a secret")

func checkDetail(detail map[string]string) error {
	if len(detail) > MaxDetailKeys {
		return fmt.Errorf("audit detail has more than %d keys", MaxDetailKeys)
	}
	for k := range detail {
		if !detailKeyRE.MatchString(k) {
			return errors.New("audit detail key is not a lower-case name of up to 32 characters")
		}
		for _, w := range secretWords {
			if strings.Contains(k, w) {
				return fmt.Errorf("%w: %q", ErrSecretKey, k)
			}
		}
	}
	return nil
}

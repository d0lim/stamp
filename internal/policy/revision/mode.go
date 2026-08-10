package revision

// mode.go is the operator's choice of which authoring paths may write.
//
// The mode is deployment configuration, not policy data (D21): a policy author
// is outside the trust boundary, so the setting that closes a window has to
// live somewhere an author cannot reach.
//
// It is enforced at the pipeline entrance rather than at either surface. A mode
// that only hid a form would be a mode the form's own HTTP endpoint still
// honoured, and R49 is explicit that this is an API refusal and not a hidden
// button. Putting the check in [Service.Propose] means every route into the
// revision pipeline — the console's submission, the file path's apply, and
// anything either grows later — is covered by one branch.
//
// Two things stay open in every mode, and both are load-bearing. The lock
// action is one: an operator who turned on `file` mode at install time and then
// found the lock screen switched off with the authoring module would be stuck
// in solo-admin governance with no way out except the offline break-glass
// procedure. The unused-token warning is the other, for the same reason — it is
// the thing that tells them they are still there.

import (
	"errors"
	"fmt"

	"github.com/d0lim/stamp/internal/store"
)

// AuthoringMode is which authoring paths an installation accepts writes from
// (R49).
type AuthoringMode string

// The authoring modes.
const (
	// AuthoringBoth is the default, and it is coherent only because origin is
	// per policy (D23): the two paths do not contend over one policy set, they
	// each own the policies they authored.
	AuthoringBoth AuthoringMode = "both"
	// AuthoringFile closes the console's policy authoring. The approval inbox,
	// the audit views, the dry run and the lock stay open.
	AuthoringFile AuthoringMode = "file"
	// AuthoringConsole closes the file path's apply.
	AuthoringConsole AuthoringMode = "console"
)

// ErrAuthoringLocked reports a write from a path this installation has closed.
var ErrAuthoringLocked = errors.New("revision: this authoring path is closed by the operator's authoring mode")

// AuthoringModes returns every mode, in declaration order.
func AuthoringModes() []AuthoringMode {
	return []AuthoringMode{AuthoringBoth, AuthoringFile, AuthoringConsole}
}

// Valid reports whether m is a declared mode.
func (m AuthoringMode) Valid() bool {
	switch m {
	case AuthoringBoth, AuthoringFile, AuthoringConsole:
		return true
	default:
		return false
	}
}

// OrDefault resolves the empty mode to [AuthoringBoth].
func (m AuthoringMode) OrDefault() AuthoringMode {
	if m == "" {
		return AuthoringBoth
	}
	return m
}

// Allows reports whether an authoring origin may submit a revision.
func (m AuthoringMode) Allows(origin store.Origin) bool {
	switch m.OrDefault() {
	case AuthoringFile:
		return origin != store.OriginForm
	case AuthoringConsole:
		return origin != store.OriginFile
	default:
		return true
	}
}

// ParseAuthoringMode reads the mode from its configured spelling.
func ParseAuthoringMode(spec string) (AuthoringMode, error) {
	m := AuthoringMode(spec)
	if spec == "" {
		return AuthoringBoth, nil
	}
	if !m.Valid() {
		return "", fmt.Errorf("revision: authoring mode %q must be one of %v", spec, AuthoringModes())
	}
	return m, nil
}

// AuthoringMode reports the mode this installation runs in, so a surface can
// tell a caller which path owns a policy before they try to edit it.
func (s *Service) AuthoringMode() AuthoringMode { return s.authoring }

// checkAuthoring refuses a write from a closed path.
func (s *Service) checkAuthoring(origin store.Origin) error {
	if s.authoring.Allows(origin) {
		return nil
	}
	return fmt.Errorf("%w: this installation is in %q authoring mode and the %q path is closed",
		ErrAuthoringLocked, s.authoring, origin)
}

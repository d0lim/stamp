// Package runtime holds the role registry that decides which subsystems a
// stamp process runs. A single image serves every deployment topology; the
// --roles flag is the only thing that differs between an all-in-one install
// and a scaled-out one.
package runtime

import (
	"fmt"
	"sort"
	"strings"
)

// Role names a subsystem group that can be switched on independently.
//
// Console serving and the API surface are deliberately separate roles: a
// deployment that scales the API must not be forced to serve static assets
// alongside it, and one that serves the console must not expose the API.
type Role string

// The roles a stamp process can run. Each one gates a distinct subsystem
// group; a component declares which of them activate it.
const (
	RoleCheck    Role = "check"
	RoleDecide   Role = "decide"
	RoleConsumer Role = "consumer"
	RoleAPI      Role = "api"
	RoleConsole  Role = "console"
)

// RoleAll is the spec token that expands to every role. It is not itself a
// Role — nothing may register against it.
const RoleAll = "all"

func knownRoles() []Role {
	return []Role{RoleCheck, RoleDecide, RoleConsumer, RoleAPI, RoleConsole}
}

// Set is a resolved collection of active roles.
type Set map[Role]struct{}

// Has reports whether r is active.
func (s Set) Has(r Role) bool {
	_, ok := s[r]
	return ok
}

// Roles returns the active roles in a stable order, for logging and tests.
func (s Set) Roles() []Role {
	out := make([]Role, 0, len(s))
	for r := range s {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// String renders the set as a comma-separated spec.
func (s Set) String() string {
	rs := s.Roles()
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = string(r)
	}
	return strings.Join(parts, ",")
}

// ParseRoles resolves a --roles spec into a Set.
//
// The spec is a comma-separated list of role names, or the single token "all".
// An unknown name is an error rather than a silent no-op: a typo in a
// deployment manifest that quietly disabled the decide subsystem would be
// discovered only when a decision failed to be created.
func ParseRoles(spec string) (Set, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil, fmt.Errorf("--roles is empty: expected %q or a comma-separated subset of %s",
			RoleAll, joinRoles(knownRoles()))
	}

	if strings.EqualFold(trimmed, RoleAll) {
		set := make(Set, len(knownRoles()))
		for _, r := range knownRoles() {
			set[r] = struct{}{}
		}
		return set, nil
	}

	set := Set{}
	for _, raw := range strings.Split(trimmed, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			return nil, fmt.Errorf("--roles has an empty entry in %q: remove the stray comma", spec)
		}
		if name == RoleAll {
			return nil, fmt.Errorf("--roles %q mixes %q with named roles: use %q alone or list roles explicitly",
				spec, RoleAll, RoleAll)
		}
		role, ok := lookupRole(name)
		if !ok {
			return nil, fmt.Errorf("--roles has unknown role %q: expected %q or a comma-separated subset of %s",
				name, RoleAll, joinRoles(knownRoles()))
		}
		set[role] = struct{}{}
	}
	return set, nil
}

func lookupRole(name string) (Role, bool) {
	for _, r := range knownRoles() {
		if string(r) == name {
			return r, true
		}
	}
	return "", false
}

func joinRoles(rs []Role) string {
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = string(r)
	}
	return strings.Join(parts, ",")
}

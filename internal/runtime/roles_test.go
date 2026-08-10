package runtime

import (
	"strings"
	"testing"
)

func TestParseRolesAllExpandsToEveryRole(t *testing.T) {
	set, err := ParseRoles("all")
	if err != nil {
		t.Fatalf("ParseRoles(all) returned error: %v", err)
	}
	for _, want := range knownRoles() {
		if !set.Has(want) {
			t.Errorf("role %q missing from --roles=all", want)
		}
	}
	if got, want := len(set), len(knownRoles()); got != want {
		t.Errorf("--roles=all activated %d roles, want %d", got, want)
	}
}

func TestParseRolesSubset(t *testing.T) {
	set, err := ParseRoles("check,api")
	if err != nil {
		t.Fatalf("ParseRoles returned error: %v", err)
	}
	if !set.Has(RoleCheck) || !set.Has(RoleAPI) {
		t.Fatalf("expected check and api active, got %s", set)
	}
	if set.Has(RoleDecide) || set.Has(RoleConsole) || set.Has(RoleConsumer) {
		t.Errorf("unrequested role active in %s", set)
	}
}

func TestParseRolesNormalizesWhitespaceAndCase(t *testing.T) {
	set, err := ParseRoles("  Check , DECIDE  ")
	if err != nil {
		t.Fatalf("ParseRoles returned error: %v", err)
	}
	if !set.Has(RoleCheck) || !set.Has(RoleDecide) {
		t.Errorf("expected check and decide active, got %s", set)
	}
}

func TestParseRolesRejectsUnknownRole(t *testing.T) {
	_, err := ParseRoles("check,decid")
	if err == nil {
		t.Fatal("expected an error for an unknown role, got nil")
	}
	// The message must name the offending token and the valid set, or an
	// operator cannot tell a typo from an unsupported feature.
	if !strings.Contains(err.Error(), `"decid"`) {
		t.Errorf("error does not name the unknown role: %v", err)
	}
	for _, want := range []string{"check", "decide", "consumer", "api", "console"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not list valid role %q: %v", want, err)
		}
	}
}

func TestParseRolesRejectsEmptyAndStrayComma(t *testing.T) {
	for _, spec := range []string{"", "   ", "check,,api", "check,"} {
		if _, err := ParseRoles(spec); err == nil {
			t.Errorf("ParseRoles(%q) succeeded, want an error", spec)
		}
	}
}

func TestParseRolesRejectsAllMixedWithNamedRoles(t *testing.T) {
	if _, err := ParseRoles("all,check"); err == nil {
		t.Fatal(`ParseRoles("all,check") succeeded, want an error`)
	}
}

func TestSetStringIsStable(t *testing.T) {
	set, err := ParseRoles("console,api,check")
	if err != nil {
		t.Fatalf("ParseRoles returned error: %v", err)
	}
	if got, want := set.String(), "api,check,console"; got != want {
		t.Errorf("Set.String() = %q, want %q", got, want)
	}
}

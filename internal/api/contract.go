package api

// contract.go is the machine-readable statement of what the console is allowed
// to call.
//
// D19 embeds the console in the binary but refuses to let embedding foreclose
// separation, and the half of that promise a principle cannot keep on its own
// is "the console has no private endpoints". A BFF does not arrive announced —
// it grows one convenient handler at a time, each of which is defensible alone.
// So the set is declared here, exported as JSON the console's own boundary
// check reads, and pinned from two sides:
//
//   - a Go test asserts this list is exactly the set of console-surface routes
//     the composition root actually mounts, so the declaration cannot describe
//     an API that does not exist or omit one that does;
//   - a Node check asserts every request target in console/src is in the JSON,
//     so the console cannot call an endpoint that is not declared here.
//
// Adding a console endpoint therefore means adding it here, which means it is
// part of the public contract by construction. That is the whole mechanism.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ContractVersion identifies the shape of the exported document, not the
// endpoint set. The console refuses a document it does not understand rather
// than guessing at unfamiliar fields.
const ContractVersion = 1

// ContractGroup separates the endpoints served by the API role from the two
// documents the console-serving role hands out.
//
// The distinction is D14's: console serving and the API surface are separate
// roles, so "the console fetches this" covers two different deployments' worth
// of exposure. A GroupServing entry is always same-origin with the bundle; a
// GroupAPI entry is wherever the operator-configured base URL points.
type ContractGroup string

// The two groups.
const (
	// GroupAPI is served by the api and decide roles and reached through the
	// configured API base URL.
	GroupAPI ContractGroup = "api"
	// GroupServing is served by the console role from the same origin as the
	// bundle itself.
	GroupServing ContractGroup = "serving"
)

// ContractEndpoint is one endpoint of the public console contract.
type ContractEndpoint struct {
	// Name matches the [Route] name the composition root mounts.
	Name string `json:"name"`
	// Method is the HTTP method.
	Method string `json:"method"`
	// Path is the path template, with {param} segments as net/http writes
	// them. The console's check substitutes its own interpolations against
	// these before comparing.
	Path string `json:"path"`
	// Auth is the credential the route requires.
	Auth Auth `json:"auth"`
	// Group says which role serves it.
	Group ContractGroup `json:"group"`
}

// Pattern renders the endpoint as the net/http routing pattern it was declared
// from, which is the form the mount table uses.
func (e ContractEndpoint) Pattern() string { return e.Method + " " + e.Path }

// consoleContract is the declaration. Order is the order a reader wants:
// authoring, then approval, then the serving documents.
var consoleContract = []ContractEndpoint{
	{Name: "policy-list", Method: "GET", Path: "/policies", Auth: AuthUser, Group: GroupAPI},
	{Name: "policy-dry-run", Method: "POST", Path: DryRunPath, Auth: AuthUser, Group: GroupAPI},
	{Name: "revision-preview", Method: "POST", Path: "/policies/revisions/preview", Auth: AuthUser, Group: GroupAPI},
	{Name: "revision-submit", Method: "POST", Path: "/policies/revisions", Auth: AuthUser, Group: GroupAPI},
	{Name: "revision-read", Method: "GET", Path: "/policies/revisions/{id}", Auth: AuthUser, Group: GroupAPI},
	{Name: "revision-withdraw", Method: "POST", Path: "/policies/revisions/{id}/withdrawal", Auth: AuthUser, Group: GroupAPI},
	{Name: "governance-read", Method: "GET", Path: "/governance", Auth: AuthUser, Group: GroupAPI},
	{Name: "governance-lock", Method: "POST", Path: "/governance/lock", Auth: AuthUser, Group: GroupAPI},
	{Name: "approval-review", Method: "GET", Path: "/decisions/{id}/challenges/{ordinal}/approval", Auth: AuthUser, Group: GroupAPI},
	{Name: "approval-submit", Method: "POST", Path: "/decisions/{id}/challenges/{ordinal}/approvals", Auth: AuthUser, Group: GroupAPI},
	{Name: "delay-cancel", Method: "POST", Path: "/decisions/{id}/challenges/{ordinal}/cancellation", Auth: AuthUser, Group: GroupAPI},
	{Name: "console-config", Method: "GET", Path: ConsoleConfigPath, Auth: AuthStatic, Group: GroupServing},
}

// ConsoleContract returns the declared public console contract.
func ConsoleContract() []ContractEndpoint {
	out := make([]ContractEndpoint, len(consoleContract))
	copy(out, consoleContract)
	return out
}

// contractDocument is the exported JSON shape.
type contractDocument struct {
	Version   int                `json:"version"`
	Note      string             `json:"note"`
	Endpoints []ContractEndpoint `json:"endpoints"`
}

const contractNote = "Generated from internal/api/contract.go. " +
	"Edit the Go declaration, not this file; internal/api's tests regenerate and verify it."

// ConsoleContractJSON renders the contract as the document the console's
// boundary check reads. Endpoints are sorted so the file is stable under
// reordering of the declaration.
func ConsoleContractJSON() ([]byte, error) {
	endpoints := ConsoleContract()
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Path != endpoints[j].Path {
			return endpoints[i].Path < endpoints[j].Path
		}
		return endpoints[i].Method < endpoints[j].Method
	})
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(contractDocument{
		Version:   ContractVersion,
		Note:      contractNote,
		Endpoints: endpoints,
	}); err != nil {
		return nil, fmt.Errorf("api: encode console contract: %w", err)
	}
	return buf.Bytes(), nil
}

// ContractPatterns returns the declared patterns for one group, sorted.
func ContractPatterns(group ContractGroup) []string {
	var out []string
	for _, e := range consoleContract {
		if e.Group == group {
			out = append(out, e.Pattern())
		}
	}
	sort.Strings(out)
	return out
}

// RoutePatterns renders a route slice as sorted patterns, for tests that
// compare a mounted surface against the declaration.
func RoutePatterns(routes []Route) []string {
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		out = append(out, strings.Join(strings.Fields(r.Pattern), " "))
	}
	sort.Strings(out)
	return out
}

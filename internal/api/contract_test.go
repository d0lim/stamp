package api_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/d0lim/stamp/internal/api"
)

// contractFile is where the exported contract lands. The console's boundary
// check reads it, and the console build has no Go toolchain, so the file is
// tracked rather than generated at build time.
const contractFile = "../../console/contract/public-endpoints.json"

// TestConsoleContractFileIsUpToDate keeps the exported document and the Go
// declaration from drifting.
//
// It rewrites the file on mismatch and then fails, because the failure a
// contributor wants is "your endpoint is now in the contract, review the diff",
// not a hand transcription task.
func TestConsoleContractFileIsUpToDate(t *testing.T) {
	want, err := api.ConsoleContractJSON()
	if err != nil {
		t.Fatalf("render the contract: %v", err)
	}
	got, err := os.ReadFile(contractFile)
	if err == nil && string(got) == string(want) {
		return
	}
	if mkErr := os.MkdirAll(filepath.Dir(contractFile), 0o750); mkErr != nil {
		t.Fatalf("create the contract directory: %v", mkErr)
	}
	if wErr := os.WriteFile(contractFile, want, 0o600); wErr != nil {
		t.Fatalf("write the contract: %v", wErr)
	}
	t.Fatalf("%s was stale and has been rewritten; review the diff and commit it", contractFile)
}

// TestConsoleContractIsMountable is the cheap half of the drift guarantee: the
// declared patterns are patterns net/http will accept, so a typo in the
// declaration is caught here rather than at a mount in a deployment.
func TestConsoleContractIsMountable(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	for _, e := range api.ConsoleContract() {
		if e.Method != strings.ToUpper(e.Method) {
			t.Errorf("%s: method %q is not upper case", e.Name, e.Method)
		}
		if !strings.HasPrefix(e.Path, "/") {
			t.Errorf("%s: path %q is not rooted", e.Name, e.Path)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: pattern %q is not routable: %v", e.Name, e.Pattern(), r)
				}
			}()
			mux.Handle(e.Pattern(), http.NotFoundHandler())
		}()
	}
}

// TestConsoleContractDeclaresOnlyUserOrStaticAuth states the shape of the
// promise: everything the console calls is either an end-user authenticated API
// endpoint or one of the documents the serving role hands out. A workload
// credentialed endpoint in this list would mean the console held a client
// secret, and a public one would mean an unauthenticated console API.
func TestConsoleContractDeclaresOnlyUserOrStaticAuth(t *testing.T) {
	t.Parallel()
	for _, e := range api.ConsoleContract() {
		switch {
		case e.Group == api.GroupAPI && e.Auth != api.AuthUser:
			t.Errorf("%s is an API endpoint with %q auth, want %q", e.Name, e.Auth, api.AuthUser)
		case e.Group == api.GroupServing && e.Auth != api.AuthStatic:
			t.Errorf("%s is a serving document with %q auth, want %q", e.Name, e.Auth, api.AuthStatic)
		case e.Group != api.GroupAPI && e.Group != api.GroupServing:
			t.Errorf("%s declares unknown group %q", e.Name, e.Group)
		}
	}
}

// TestExportedContractIsReadableByTheConsoleCheck asserts the shape the Node
// side depends on, so a change to the Go struct that would silently break the
// boundary check fails here instead.
func TestExportedContractIsReadableByTheConsoleCheck(t *testing.T) {
	t.Parallel()
	raw, err := api.ConsoleContractJSON()
	if err != nil {
		t.Fatalf("render the contract: %v", err)
	}
	var doc struct {
		Version   int `json:"version"`
		Endpoints []struct {
			Name   string `json:"name"`
			Method string `json:"method"`
			Path   string `json:"path"`
			Auth   string `json:"auth"`
			Group  string `json:"group"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode the contract: %v", err)
	}
	if doc.Version != api.ContractVersion {
		t.Errorf("version = %d, want %d", doc.Version, api.ContractVersion)
	}
	if len(doc.Endpoints) != len(api.ConsoleContract()) {
		t.Errorf("the document has %d endpoints, the declaration has %d",
			len(doc.Endpoints), len(api.ConsoleContract()))
	}
	for _, e := range doc.Endpoints {
		if e.Name == "" || e.Method == "" || e.Path == "" || e.Auth == "" || e.Group == "" {
			t.Errorf("endpoint %+v has an empty field", e)
		}
	}
}

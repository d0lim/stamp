package release_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const versionGate = "../../scripts/check-contract-versions.sh"

func runGate(t *testing.T, docsDir string) (string, error) {
	t.Helper()
	args := []string{versionGate}
	if docsDir != "" {
		abs, err := filepath.Abs(docsDir)
		if err != nil {
			t.Fatalf("abs %s: %v", docsDir, err)
		}
		args = append(args, abs)
	}
	cmd := exec.Command("bash", args...) //nolint:gosec // fixed script, test-owned argument
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// R11 over the repository as it stands: the three documents exist, each states
// a semver version, and each version agrees with the constant the code ships.
func TestTheThreeContractsAreDocumentedAndVersioned(t *testing.T) {
	out, err := runGate(t, "")
	if err != nil {
		t.Fatalf("the contract version gate failed on the real docs:\n%s", out)
	}
	for _, name := range []string{"policy-schema", "challenge-interface", "decision-api"} {
		if !strings.Contains(out, name) {
			t.Errorf("the gate reported nothing for %s:\n%s", name, out)
		}
	}
	// The endpoint table is the input routes_test.go compares against the
	// mounted routes, and the release workflow runs this script on its own.
	if !strings.Contains(out, "endpoint rows") {
		t.Errorf("the gate did not report the decision API's endpoint table:\n%s", out)
	}
}

// A gate that has only ever passed is not known to be a gate. Each fixture is a
// way the release is supposed to be blocked.
func TestTheContractVersionGateFails(t *testing.T) {
	cases := map[string]struct {
		dir  string
		want string
	}{
		"a document states no version": {
			dir:  "testdata/contracts-no-version",
			want: "states no version",
		},
		"a document's version drifted from the code": {
			dir: "testdata/contracts-drifted",
			// Not the version itself: the fixture's drift is from whatever
			// constant the code currently ships, and pinning the number here
			// makes a legitimate contract bump look like a broken gate.
			want: "but the code ships",
		},
		"the documents are missing entirely": {
			dir:  "testdata/contracts-missing",
			want: "does not exist",
		},
		"the decision API document has no endpoint table": {
			dir: "testdata/contracts-no-endpoint-table",
			// The structural check next door has nothing to compare without
			// it, and this gate runs alone in the release workflow.
			want: "states no endpoint table",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := runGate(t, tc.dir)
			if err == nil {
				t.Fatalf("the gate passed on %s, which it must not:\n%s", tc.dir, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("the gate failed but did not say why: want %q in\n%s", tc.want, out)
			}
			if !strings.Contains(out, "the release is blocked") {
				t.Errorf("the gate failed without reporting the release blocked:\n%s", out)
			}
		})
	}
}

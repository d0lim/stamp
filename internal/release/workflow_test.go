package release_test

// workflow_test.go pins what .github/workflows/release.yml does with its
// inputs, without running it.
//
// The workflow has never executed. `gh run list --workflow=release.yml` returns
// nothing: no tag has ever been pushed and no manual run has ever been
// dispatched. Inside it, eight steps are gated on a single value,
// needs.gates.outputs.publish. A gated step that does not fire is *skipped*,
// and a job whose steps all skip is green. So the failure this file exists for
// is not a red release. It is a green release that published nothing, noticed
// after the tag was already pushed.
//
// Running the workflow is not on the table: dispatch is unavailable here, and
// `act` would be a different environment with no secrets, so a green run under
// act would prove something about act rather than about GitHub. The gate rule,
// though, is data. It is a shell script sitting in a YAML file. So the rule is
// read out of the real file with a YAML parser and run under bash, once per
// input combination, and the answers are asserted here.
//
// Two properties make that an assertion about the workflow rather than about a
// copy of it:
//
//   - the extraction re-reads .github/workflows/release.yml on every run, so
//     there is no second copy to drift, and
//   - substitution refuses any ${{ }} expression the harness does not model, so
//     a workflow that grows a new input fails here instead of being silently
//     tested with the old one.
//
// The same shape as testdata/mounted-routes.json next door: the generated thing
// going stale is red rather than quiet.

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	releaseWorkflowPath = "../../.github/workflows/release.yml"
	changelogPath       = "../../CHANGELOG.md"

	// The expression every gated step in the workflow is written against.
	publishExpr = "needs.gates.outputs.publish"
)

// --- reading the real workflow --------------------------------------------

type wfStep struct {
	Name string `yaml:"name"`
	ID   string `yaml:"id"`
	Uses string `yaml:"uses"`
	If   string `yaml:"if"`
	Run  string `yaml:"run"`
}

// label is what the step is called in a failure message. A `uses:` step often
// has no name, and "step 4 of image" is not something a reader can act on.
func (s wfStep) label() string {
	switch {
	case s.Name != "":
		return s.Name
	case s.ID != "":
		return "id=" + s.ID
	default:
		return s.Uses
	}
}

type wfJob struct {
	Name  string   `yaml:"name"`
	Steps []wfStep `yaml:"steps"`
}

type workflow struct {
	Jobs map[string]wfJob `yaml:"jobs"`
}

func loadWorkflow(t *testing.T) workflow {
	t.Helper()
	raw, err := os.ReadFile(releaseWorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", releaseWorkflowPath, err)
	}
	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse %s: %v", releaseWorkflowPath, err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatalf("%s declares no jobs", releaseWorkflowPath)
	}
	return wf
}

// jobNames is sorted so that a failure message reads the same way twice. Go's
// map order is not the file's order and there is nothing to gain from either.
func jobNames(wf workflow) []string {
	names := make([]string, 0, len(wf.Jobs))
	for name := range wf.Jobs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// stepNamed returns the body of one step, by the name the workflow gives it.
// Looking it up by name and failing loudly is the point: if the step is renamed
// or removed, the harness stops testing it, and a harness that quietly tests
// nothing is the thing this whole file is about.
func stepNamed(t *testing.T, wf workflow, job, name string) wfStep {
	t.Helper()
	j, ok := wf.Jobs[job]
	if !ok {
		t.Fatalf("%s has no job %q; the harness is out of date with the workflow", releaseWorkflowPath, job)
	}
	for _, s := range j.Steps {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("job %q has no step named %q; the harness is out of date with the workflow", job, name)
	return wfStep{}
}

// --- substituting the expressions a step is written against ----------------

var expressionRE = regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`)

// substitute fills in the ${{ }} expressions of an extracted step body.
//
// An expression with no value here is a failure and not a blank. The harness is
// only worth anything while it models every input the step actually reads; the
// moment the workflow starts reading something the harness does not know about,
// the answers below are about the old workflow.
func substitute(t *testing.T, body string, values map[string]string) string {
	t.Helper()
	var unknown []string
	out := expressionRE.ReplaceAllStringFunc(body, func(match string) string {
		expr := expressionRE.FindStringSubmatch(match)[1]
		v, ok := values[expr]
		if !ok {
			unknown = append(unknown, expr)
			return match
		}
		return v
	})
	if len(unknown) > 0 {
		sort.Strings(unknown)
		t.Fatalf("the workflow step reads %v, which this harness does not model.\n"+
			"Give the expression a value for every combination in this file, or the table below is about a workflow that no longer exists.",
			unknown)
	}
	return out
}

// runStep runs an extracted step body the way GitHub runs it.
//
// GitHub's default shell for `run:` on a Linux runner is `bash -e {0}` — errexit
// on, and neither pipefail nor nounset. Running it under anything stricter would
// pass here and fail there, which is the direction that costs a release.
func runStep(t *testing.T, dir, body string, env map[string]string) (string, error) {
	t.Helper()
	script := filepath.Join(t.TempDir(), "step.sh")
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatalf("write step script: %v", err)
	}
	cmd := exec.Command("bash", "-e", script)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// parseStepOutputs reads a $GITHUB_OUTPUT file, including the heredoc form the
// image reference step uses for its multi-line tag list.
func parseStepOutputs(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test-owned temporary path
	if err != nil {
		t.Fatalf("read $GITHUB_OUTPUT: %v", err)
	}
	defer func() { _ = f.Close() }()

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		name, delim, isHeredoc := strings.Cut(line, "<<")
		if isHeredoc {
			var body []string
			for sc.Scan() {
				if sc.Text() == delim {
					break
				}
				body = append(body, sc.Text())
			}
			out[name] = strings.Join(body, "\n")
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan $GITHUB_OUTPUT: %v", err)
	}
	return out
}

// --- the input combinations ------------------------------------------------

// combination is one way this workflow can start. There are exactly two
// triggers, and the dispatch one takes two inputs, so this is the whole input
// space up to the value of the version string.
type combination struct {
	name string
	// The trigger.
	eventName string
	// GITHUB_REF_NAME: the tag on a push, the branch on a dispatch.
	refName string
	// The workflow_dispatch inputs. Empty on a push, where the `inputs`
	// context does not exist and every ${{ inputs.* }} renders as nothing.
	inputVersion    string
	inputUnreleased string

	// What the gate is expected to answer.
	wantVersion string
	wantPublish string
}

var combinations = []combination{
	{
		name:        "a tag is pushed",
		eventName:   "push",
		refName:     "v1.2.3",
		wantVersion: "1.2.3",
		wantPublish: "true",
	},
	{
		name:            "dispatch with unreleased=true, the input's default",
		eventName:       "workflow_dispatch",
		refName:         "main",
		inputVersion:    "0.1.0",
		inputUnreleased: "true",
		wantVersion:     "0.1.0",
		wantPublish:     "false",
	},
	{
		name:            "dispatch with unreleased=false",
		eventName:       "workflow_dispatch",
		refName:         "main",
		inputVersion:    "0.1.0",
		inputUnreleased: "false",
		wantVersion:     "0.1.0",
		wantPublish:     "false",
	},
	{
		// Nothing in the workflow compares the dispatched version to the
		// chart, the changelog or any tag. The rehearsal will happily build a
		// chart at a version this repository has never shipped. It cannot
		// publish it — publish is false on every dispatch — so the cost is a
		// misleading rehearsal rather than a bad release, and it is pinned
		// here so that stops being a surprise.
		name:            "dispatch with a version the repository does not ship",
		eventName:       "workflow_dispatch",
		refName:         "main",
		inputVersion:    "9.9.9",
		inputUnreleased: "true",
		wantVersion:     "9.9.9",
		wantPublish:     "false",
	},
}

// gateExpressions is what the `resolve the version` step reads, per combination.
func (c combination) gateExpressions() map[string]string {
	return map[string]string{
		"github.event_name": c.eventName,
		"inputs.version":    c.inputVersion,
	}
}

// downstreamExpressions is what a step in the image or artifacts job reads once
// the gate has answered. version and publish come from the gate's real output
// rather than from the combination's expectation, so a step is only ever tested
// against a value the gate can actually produce.
func (c combination) downstreamExpressions(version, publish, imageRef string) map[string]string {
	return map[string]string{
		publishExpr:                   publish,
		"needs.gates.outputs.version": version,
		"needs.image.outputs.ref":     imageRef,
		"inputs.unreleased":           c.inputUnreleased,
	}
}

// resolveGate runs the real `resolve the version` step for one combination and
// returns what it wrote to $GITHUB_OUTPUT.
func resolveGate(t *testing.T, wf workflow, c combination) (version, publish string) {
	t.Helper()
	step := stepNamed(t, wf, "gates", "resolve the version")
	body := substitute(t, step.Run, c.gateExpressions())

	outFile := filepath.Join(t.TempDir(), "github_output")
	if err := os.WriteFile(outFile, nil, 0o600); err != nil {
		t.Fatalf("create $GITHUB_OUTPUT: %v", err)
	}
	out, err := runStep(t, t.TempDir(), body, map[string]string{
		"GITHUB_REF_NAME": c.refName,
		"GITHUB_OUTPUT":   outFile,
	})
	if err != nil {
		t.Fatalf("the gate step failed for %q: %v\n%s", c.name, err, out)
	}
	outputs := parseStepOutputs(t, outFile)
	return outputs["version"], outputs["publish"]
}

// TestTheGateAnswersTheSameThingEveryTime is the rule the other eight steps
// hang off. It has never run on GitHub; it runs here.
func TestTheGateAnswersTheSameThingEveryTime(t *testing.T) {
	wf := loadWorkflow(t)
	for _, c := range combinations {
		t.Run(c.name, func(t *testing.T) {
			version, publish := resolveGate(t, wf, c)
			if version != c.wantVersion {
				t.Errorf("version = %q, want %q", version, c.wantVersion)
			}
			if publish != c.wantPublish {
				t.Errorf("publish = %q, want %q", publish, c.wantPublish)
			}
		})
	}
}

// TestOnlyATagPushCanPublish states the rule in the direction that matters. The
// eight conditionals compare publish to the *string* 'true'; anything else at
// all — "false", "", "True" — skips them. So the interesting property is not
// that a dispatch says false, it is that nothing except a tag push says true.
func TestOnlyATagPushCanPublish(t *testing.T) {
	wf := loadWorkflow(t)
	for _, c := range combinations {
		_, publish := resolveGate(t, wf, c)
		isPush := c.eventName == "push"
		if got := publish == "true"; got != isPush {
			t.Errorf("%s: publish==%q (publishes: %v), but event_name is %q", c.name, publish, got, c.eventName)
		}
	}
}

// --- the eight conditionals ------------------------------------------------

// gatedStep is one step whose `if:` reads the gate's answer.
type gatedStep struct {
	job   string
	label string
	cond  string
}

// The two forms the workflow uses. Anything else is a condition this harness
// cannot evaluate, and an unevaluated condition is a hole in the table.
var (
	publishIsTrue    = publishExpr + " == 'true'"
	publishIsNotTrue = publishExpr + " != 'true'"
)

// gatedSteps enumerates every step in the workflow that carries an `if:`, and
// fails on any condition the harness cannot evaluate.
//
// It deliberately collects *all* conditions rather than only the ones
// mentioning publish. A step gated on something else is not covered by the
// table below, and the table claiming completeness it does not have is exactly
// the failure mode this file was written for.
func gatedSteps(t *testing.T, wf workflow) []gatedStep {
	t.Helper()
	var steps []gatedStep
	for _, job := range jobNames(wf) {
		for _, s := range wf.Jobs[job].Steps {
			if s.If == "" {
				continue
			}
			cond := strings.TrimSpace(s.If)
			if cond != publishIsTrue && cond != publishIsNotTrue {
				t.Fatalf("job %q step %q is gated on %q, which this harness cannot evaluate.\n"+
					"Teach it the new condition, or the combination table silently stops covering this step.",
					job, s.label(), cond)
			}
			steps = append(steps, gatedStep{job: job, label: s.label(), cond: cond})
		}
	}
	if len(steps) == 0 {
		t.Fatalf("%s has no conditional steps at all, which is not what it looked like when this was written", releaseWorkflowPath)
	}
	return steps
}

func (g gatedStep) runsWhen(publish string) bool {
	if g.cond == publishIsTrue {
		return publish == "true"
	}
	return publish != "true"
}

// TestEveryGatedStepRunsUnderSomeInput is the reason this unit exists.
//
// The table is not the finding. The empty cells are. A step that runs under no
// combination is code that has been written, reviewed and merged and can never
// execute; a step that runs under every combination has an `if:` that is not
// doing anything, which means somebody believed there was a case it guarded
// against and there is not. Both are named here rather than counted.
func TestEveryGatedStepRunsUnderSomeInput(t *testing.T) {
	wf := loadWorkflow(t)
	steps := gatedSteps(t, wf)

	publishBy := map[string]string{}
	for _, c := range combinations {
		_, publish := resolveGate(t, wf, c)
		publishBy[c.name] = publish
	}

	var table strings.Builder
	table.WriteString("which gated step runs under which input:\n")
	for _, g := range steps {
		var runsIn, skipsIn []string
		for _, c := range combinations {
			if g.runsWhen(publishBy[c.name]) {
				runsIn = append(runsIn, c.name)
			} else {
				skipsIn = append(skipsIn, c.name)
			}
		}
		fmt.Fprintf(&table, "  %s / %s\n      runs:  %s\n      skips: %s\n",
			g.job, g.label, describe(runsIn), describe(skipsIn))

		if len(runsIn) == 0 {
			t.Errorf("job %q step %q runs under no input this workflow accepts. "+
				"It is unreachable: merged, gated, and dead.", g.job, g.label)
		}
		if len(skipsIn) == 0 {
			t.Errorf("job %q step %q runs under every input, so its `if: %s` guards nothing. "+
				"Either an input is missing from this table or the condition is decoration.",
				g.job, g.label, g.cond)
		}
	}
	t.Log(table.String())
}

func describe(names []string) string {
	if len(names) == 0 {
		return "(nothing)"
	}
	return strings.Join(names, "; ")
}

// --- what each input actually builds ---------------------------------------

// TestTheImageTagsEachInputProduces covers the branch that is not an `if:`: the
// image reference step decides inside the shell whether :latest is part of the
// tag list. A moving tag that a rehearsal could push is worth pinning, because
// nothing about the step's presence in the log would show it.
func TestTheImageTagsEachInputProduces(t *testing.T) {
	wf := loadWorkflow(t)
	step := stepNamed(t, wf, "image", "image reference")

	for _, c := range combinations {
		t.Run(c.name, func(t *testing.T) {
			version, publish := resolveGate(t, wf, c)
			body := substitute(t, step.Run, c.downstreamExpressions(version, publish, ""))

			outFile := filepath.Join(t.TempDir(), "github_output")
			if err := os.WriteFile(outFile, nil, 0o600); err != nil {
				t.Fatalf("create $GITHUB_OUTPUT: %v", err)
			}
			out, err := runStep(t, t.TempDir(), body, map[string]string{
				"REGISTRY":      "ghcr.io",
				"IMAGE_NAME":    "d0lim/stamp",
				"GITHUB_OUTPUT": outFile,
			})
			if err != nil {
				t.Fatalf("the image reference step failed: %v\n%s", err, out)
			}
			outputs := parseStepOutputs(t, outFile)

			wantRef := "ghcr.io/d0lim/stamp:" + version
			if outputs["ref"] != wantRef {
				t.Errorf("ref = %q, want %q", outputs["ref"], wantRef)
			}
			tags := strings.Split(outputs["tags"], "\n")
			hasLatest := false
			for _, tag := range tags {
				if tag == "ghcr.io/d0lim/stamp:latest" {
					hasLatest = true
				}
			}
			if want := publish == "true"; hasLatest != want {
				t.Errorf("tags %v carry :latest = %v, want %v (publish=%q). "+
					"A moving tag must only move on a real release.", tags, hasLatest, want, publish)
			}
		})
	}
}

// artifactArgs runs the real `build the artifacts` step against a stand-in for
// scripts/release-artifacts.sh, and reports the arguments the step would have
// passed it. The script itself needs helm, syft and minutes; the argument list
// is the part that differs per input, and it is the part that decides where the
// release notes come from.
func artifactArgs(t *testing.T, wf workflow, c combination) []string {
	t.Helper()
	step := stepNamed(t, wf, "artifacts", "build the artifacts")
	version, publish := resolveGate(t, wf, c)
	body := substitute(t, step.Run, c.downstreamExpressions(version, publish, "ghcr.io/d0lim/stamp:"+version))

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o750); err != nil {
		t.Fatalf("stub scripts dir: %v", err)
	}
	recorded := filepath.Join(dir, "args.txt")
	stub := "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > " + recorded + "\n"
	if err := os.WriteFile(filepath.Join(dir, "scripts", "release-artifacts.sh"), []byte(stub), 0o700); err != nil { //nolint:gosec // test-owned stub
		t.Fatalf("write stub: %v", err)
	}

	out, err := runStep(t, dir, body, nil)
	if err != nil {
		t.Fatalf("the build step failed for %q: %v\n%s", c.name, err, out)
	}
	raw, err := os.ReadFile(recorded) //nolint:gosec // test-owned temporary path
	if err != nil {
		t.Fatalf("the build step never called release-artifacts.sh for %q:\n%s", c.name, out)
	}
	return strings.Fields(strings.TrimSpace(string(raw)))
}

// TestWhichArtifactArgumentsEachInputProduces pins the third branch of the
// workflow, the one that is neither an `if:` nor visible in the run log: the
// build step chooses between --image, --unreleased and neither.
//
// "Neither" is the interesting one. It means release-artifacts.sh looks for
// `## [<version>]` in CHANGELOG.md and refuses to build if that section is
// absent — and on a tag push, that is the only branch there is.
func TestWhichArtifactArgumentsEachInputProduces(t *testing.T) {
	wf := loadWorkflow(t)
	want := map[string][]string{
		"a tag is pushed": {"--version", "1.2.3", "--image", "ghcr.io/d0lim/stamp:1.2.3"},
		"dispatch with unreleased=true, the input's default":   {"--version", "0.1.0", "--unreleased"},
		"dispatch with unreleased=false":                       {"--version", "0.1.0"},
		"dispatch with a version the repository does not ship": {"--version", "9.9.9", "--unreleased"},
	}
	for _, c := range combinations {
		t.Run(c.name, func(t *testing.T) {
			got := artifactArgs(t, wf, c)
			expected, ok := want[c.name]
			if !ok {
				t.Fatalf("no expectation recorded for combination %q", c.name)
			}
			if strings.Join(got, " ") != strings.Join(expected, " ") {
				t.Errorf("release-artifacts.sh %v, want %v", got, expected)
			}
		})
	}
}

// TestARealReleaseNeverShipsUnreleasedNotes is the durable half of the finding
// above.
//
// A rehearsal may take its notes from `## [Unreleased]`; that is what the input
// is for. A tag push must not, because those notes describe work that has not
// been released and the section is rewritten on the next release — the published
// notes would then describe something else. The workflow gets this right today
// (--unreleased sits in an `elif` the publish branch never reaches), and this
// keeps it that way if the branches are ever reordered.
func TestARealReleaseNeverShipsUnreleasedNotes(t *testing.T) {
	wf := loadWorkflow(t)
	for _, c := range combinations {
		if c.eventName != "push" {
			continue
		}
		args := artifactArgs(t, wf, c)
		for _, a := range args {
			if a == "--unreleased" {
				t.Errorf("%s passes --unreleased, so a published release would carry the notes of unreleased work", c.name)
			}
		}
	}
}

// TestWhichInputsCanReachTheEndOfTheArtifactsJob checks the one thing the
// argument table cannot: whether the section release-artifacts.sh will look for
// actually has content. The script exits 1 on an empty section, and it runs
// before every publishing step in the job, so a missing section is not a missing
// release note — it is the whole artifacts job never getting as far as
// publishing anything.
//
// Only the rehearsal default is asserted. The tag-push heading depends on the
// tag, which is not knowable from here, so it is reported instead: read the log
// before tagging. docs/operations/release.md says the same thing where an
// operator will see it.
func TestWhichInputsCanReachTheEndOfTheArtifactsJob(t *testing.T) {
	wf := loadWorkflow(t)

	var table strings.Builder
	table.WriteString("which CHANGELOG.md section each input needs, and whether it exists:\n")
	for _, c := range combinations {
		// The rule release-artifacts.sh applies: --unreleased reads the
		// Unreleased section, and everything else reads the version's own.
		version, _ := resolveGate(t, wf, c)
		heading := "## [" + version + "]"
		for _, a := range artifactArgs(t, wf, c) {
			if a == "--unreleased" {
				heading = "## [Unreleased]"
			}
		}
		state := "present"
		if strings.TrimSpace(changelogSection(t, heading)) == "" {
			state = "ABSENT — this input fails at `build the artifacts`, before any publishing step"
		}
		fmt.Fprintf(&table, "  %s\n      needs %s: %s\n", c.name, heading, state)

		if c.inputUnreleased == "true" && state != "present" {
			t.Errorf("CHANGELOG.md has nothing under %s, so `make release-dryrun` and every "+
				"dispatch with unreleased=true fail at `build the artifacts` — and that is the "+
				"only path a person can run before tagging", heading)
		}
	}
	t.Log(table.String())
}

// changelogSection applies the rule release-artifacts.sh applies: the heading
// matches at the start of the line, and the section ends at the next `## `.
func changelogSection(t *testing.T, heading string) string {
	t.Helper()
	raw, err := os.ReadFile(changelogPath)
	if err != nil {
		t.Fatalf("read %s: %v", changelogPath, err)
	}
	var body []string
	inside := false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, heading) {
			inside = true
			continue
		}
		if inside && strings.HasPrefix(line, "## ") {
			break
		}
		if inside {
			body = append(body, line)
		}
	}
	return strings.Join(body, "\n")
}

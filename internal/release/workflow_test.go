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
	"crypto/sha256"
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
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	Uses string            `yaml:"uses"`
	If   string            `yaml:"if"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
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

// --- the checks that make a silent no-op impossible ------------------------
//
// Everything above establishes the rule. Nothing above stops the rule from
// being wrong: if publish ever fails to be the string 'true' on a real tag, all
// seven publishing steps skip, skipped is not failed, and the release is green
// and empty.
//
// So each job ends with a step that reads what is actually there — the registry,
// dist/, and the recorded outcome of every gated step — and fails if it does not
// match what publish claimed. Those steps carry no `if:`, which is the property
// asserted first below, because a check gated on the condition it is checking
// skips in precisely the runs where it was needed.

const (
	imageCheckStep     = "the image this run promised exists"
	artifactsCheckStep = "the artifacts this run promised exist"
)

// TestTheChecksAreNotGatedOnWhatTheyCheck is the check on the checks.
//
// It is one line of assertion and it is the reason the other tests in this
// section mean anything. `if: needs.gates.outputs.publish == 'true'` on the
// verification step would make every test below pass and the workflow still ship
// nothing, because the verification would skip alongside the publishing.
func TestTheChecksAreNotGatedOnWhatTheyCheck(t *testing.T) {
	wf := loadWorkflow(t)
	for job, name := range map[string]string{"image": imageCheckStep, "artifacts": artifactsCheckStep} {
		s := stepNamed(t, wf, job, name)
		if s.If != "" {
			t.Errorf("job %q step %q carries `if: %s`. A check gated on the condition it is "+
				"checking skips exactly when the condition is wrong, which is the only run it "+
				"was written for.", job, name, s.If)
		}
		steps := wf.Jobs[job].Steps
		if last := steps[len(steps)-1]; last.Name != name {
			t.Errorf("job %q ends with %q, not with its check %q; anything after the check is unchecked",
				job, last.label(), name)
		}
	}
}

// stepOutcomes is what GitHub would record for each identified step of a job on
// a run with this publish value: a gated step that fires is "success", a gated
// step that does not is "skipped", and an ungated step just runs.
func stepOutcomes(wf workflow, job, publish string) map[string]string {
	out := map[string]string{}
	for _, s := range wf.Jobs[job].Steps {
		if s.ID == "" {
			continue
		}
		g := gatedStep{job: job, label: s.label(), cond: strings.TrimSpace(s.If)}
		switch {
		case s.If == "":
			out[s.ID] = "success"
		case g.runsWhen(publish):
			out[s.ID] = "success"
		default:
			out[s.ID] = "skipped"
		}
	}
	return out
}

// checkEnv renders a check step's `env:` block for a run, so the body is fed the
// values GitHub would feed it rather than values invented here. overrides is how
// a red scenario says "this step skipped even though publish was true".
func checkEnv(t *testing.T, wf workflow, job, name, publish, version string, overrides map[string]string) (wfStep, map[string]string) {
	t.Helper()
	step := stepNamed(t, wf, job, name)

	values := map[string]string{
		publishExpr:                   publish,
		"needs.gates.outputs.version": version,
		"steps.ref.outputs.ref":       "ghcr.io/d0lim/stamp:" + version,
		"github.ref_name":             "v" + version,
		"secrets.GITHUB_TOKEN":        "token",
		"steps.build.outputs.digest":  "",
	}
	if publish == "true" {
		values["steps.build.outputs.digest"] = "sha256:" + strings.Repeat("a", 64)
	}
	for id, outcome := range stepOutcomes(wf, job, publish) {
		values["steps."+id+".outcome"] = outcome
	}
	for k, v := range overrides {
		values[k] = v
	}

	env := map[string]string{}
	for k, expr := range step.Env {
		env[k] = substitute(t, expr, values)
	}
	return step, env
}

// stubTools puts the commands a check reaches for outside the runner on PATH.
// Each one's exit status comes from the environment, so a scenario can say "the
// registry does not have it" without a second stub.
//
// sha256sum is stubbed only where it is missing (macOS ships shasum instead), so
// the checksum verification in the check runs for real rather than against a
// program that always agrees.
func stubTools(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatalf("stub bin: %v", err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil { //nolint:gosec // test-owned stub
			t.Fatalf("write stub %s: %v", name, err)
		}
	}
	for _, tool := range []string{"docker", "helm", "gh"} {
		write(tool, "#!/usr/bin/env bash\nexit \"${"+strings.ToUpper(tool)+"_EXIT:-0}\"\n")
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		write("sha256sum", "#!/usr/bin/env bash\nexec shasum -a 256 \"$@\"\n")
	}
	return bin + string(os.PathListSeparator) + os.Getenv("PATH")
}

// writeDist builds the dist/ directory release-artifacts.sh produces, in the
// two states it can be in when the check runs: signed (a real release) and
// unsigned (a rehearsal).
func writeDist(t *testing.T, dir, version string, signed bool) {
	t.Helper()
	dist := filepath.Join(dir, "dist")
	if err := os.MkdirAll(dist, 0o750); err != nil {
		t.Fatalf("dist: %v", err)
	}
	files := []string{"stamp-" + version + ".tgz", "sbom-source-" + version + ".spdx.json"}
	put := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dist, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	put("RELEASE-NOTES-"+version+".md", "- something changed\n")
	for _, f := range files {
		put(f, "contents of "+f+"\n")
	}

	// The real checksums of the real files, so `sha256sum -c` in the check has
	// something to disagree with.
	var sums strings.Builder
	for _, f := range files {
		raw, err := os.ReadFile(filepath.Join(dist, f)) //nolint:gosec // test-owned temporary path
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(raw), f)
	}
	put("checksums.txt", sums.String())

	manifest := ""
	for _, f := range append(files, "checksums.txt") {
		manifest += "file:" + f + "\n"
	}
	if signed {
		manifest += "image:ghcr.io/d0lim/stamp:" + version + "\n"
		for _, f := range append(files, "checksums.txt") {
			for _, side := range []string{"sig", "pem", "cosign.bundle"} {
				put(f+"."+side, "signature\n")
			}
		}
	}
	put("sign-manifest.txt", manifest)
}

// runCheck runs one of the two verification steps for real, under bash, against
// a fabricated runner.
func runCheck(t *testing.T, wf workflow, job, name, publish, version string, overrides, extraEnv map[string]string, signed bool) (string, error) {
	t.Helper()
	dir := t.TempDir()
	writeDist(t, dir, version, signed)

	step, env := checkEnv(t, wf, job, name, publish, version, overrides)
	env["PATH"] = stubTools(t, dir)
	env["REGISTRY"] = "ghcr.io"
	env["IMAGE_NAME"] = "d0lim/stamp"
	env["CHART_REPO"] = "oci://ghcr.io/d0lim/charts"
	for k, v := range extraEnv {
		env[k] = v
	}
	return runStep(t, dir, substitute(t, step.Run, nil), env)
}

// TestTheChecksPassTheRunsTheyAreMeantToPass is the green half. A guard that
// only ever fails is as useless as one that only ever passes: it would be turned
// off on the first real release.
func TestTheChecksPassTheRunsTheyAreMeantToPass(t *testing.T) {
	wf := loadWorkflow(t)
	for _, tc := range []struct {
		name    string
		job     string
		step    string
		publish string
		signed  bool
	}{
		{"the image job on a real release", "image", imageCheckStep, "true", true},
		{"the image job on a rehearsal", "image", imageCheckStep, "false", false},
		{"the artifacts job on a real release", "artifacts", artifactsCheckStep, "true", true},
		{"the artifacts job on a rehearsal", "artifacts", artifactsCheckStep, "false", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runCheck(t, wf, tc.job, tc.step, tc.publish, "1.2.3", nil, nil, tc.signed)
			if err != nil {
				t.Fatalf("the check failed a run it is supposed to pass: %v\n%s", err, out)
			}
		})
	}
}

// TestTheChecksFailWhenNothingWasPublished is the red half, and it is the whole
// point: every scenario here is a run that is green today and would ship an
// empty release.
//
// The workflow cannot be dispatched from here, so the step body is pulled out of
// the real file and run under bash with the runner fabricated around it. What is
// being proved is the step's own logic, not GitHub's — GitHub's part is that a
// non-zero exit fails a step, which is not in doubt.
func TestTheChecksFailWhenNothingWasPublished(t *testing.T) {
	wf := loadWorkflow(t)
	for _, tc := range []struct {
		name      string
		job       string
		step      string
		publish   string
		signed    bool
		overrides map[string]string
		extraEnv  map[string]string
		want      string
	}{
		{
			// The failure this round exists for: publish said true, the gated
			// step skipped anyway, and every other step was happy.
			name:      "a publishing step skipped on a release",
			job:       "image",
			step:      imageCheckStep,
			publish:   "true",
			signed:    true,
			overrides: map[string]string{"steps.sign.outcome": "skipped"},
			want:      "sign the image by digest",
		},
		{
			name:      "the build pushed nothing, so there is no digest",
			job:       "image",
			step:      imageCheckStep,
			publish:   "true",
			signed:    true,
			overrides: map[string]string{"steps.build.outputs.digest": ""},
			want:      "no digest",
		},
		{
			name:     "the image is not in the registry it was said to be pushed to",
			job:      "image",
			step:     imageCheckStep,
			publish:  "true",
			signed:   true,
			extraEnv: map[string]string{"DOCKER_EXIT": "1"},
			want:     "is not in",
		},
		{
			// The other direction. A rehearsal that signed something has
			// published something, and nobody asked it to.
			name:      "a rehearsal ran a publishing step",
			job:       "image",
			step:      imageCheckStep,
			publish:   "false",
			signed:    false,
			overrides: map[string]string{"steps.sign.outcome": "success"},
			want:      "sign the image by digest",
		},
		{
			name:      "the signing loop skipped on a release",
			job:       "artifacts",
			step:      artifactsCheckStep,
			publish:   "true",
			signed:    true,
			overrides: map[string]string{"steps.sign.outcome": "skipped"},
			want:      "sign every file in the manifest",
		},
		{
			// The signing step reads sign-manifest.txt in a loop. A loop over a
			// manifest it never opened produces no error and no signatures.
			name:    "a release whose artifacts were never signed",
			job:     "artifacts",
			step:    artifactsCheckStep,
			publish: "true",
			signed:  false,
			want:    "unsigned",
		},
		{
			name:     "the chart was never pushed to the registry",
			job:      "artifacts",
			step:     artifactsCheckStep,
			publish:  "true",
			signed:   true,
			extraEnv: map[string]string{"HELM_EXIT": "1"},
			want:     "is not in the registry",
		},
		{
			name:     "there is no GitHub release for the tag",
			job:      "artifacts",
			step:     artifactsCheckStep,
			publish:  "true",
			signed:   true,
			extraEnv: map[string]string{"GH_EXIT": "1"},
			want:     "no GitHub release",
		},
		{
			// The `!= 'true'` branch gets the same treatment as the seven. A
			// rehearsal whose only visible output stopped being produced is a
			// rehearsal nobody can read.
			name:      "a rehearsal wrote no summary",
			job:       "artifacts",
			step:      artifactsCheckStep,
			publish:   "false",
			signed:    false,
			overrides: map[string]string{"steps.rehearsal.outcome": "skipped"},
			want:      "rehearsal summary",
		},
		{
			name:    "a rehearsal signed and named an image",
			job:     "artifacts",
			step:    artifactsCheckStep,
			publish: "false",
			signed:  true,
			want:    "run that publishes nothing",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runCheck(t, wf, tc.job, tc.step, tc.publish, "1.2.3", tc.overrides, tc.extraEnv, tc.signed)
			if err == nil {
				t.Fatalf("the check passed a run that published nothing:\n%s", out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("the check failed without saying what was missing: want %q in\n%s", tc.want, out)
			}
		})
	}
}

// TestTheArtifactCheckReadsTheArtifactsAndNotTheLog covers the half of the check
// that does not depend on any step outcome: dist/ has to hold what the release
// says it holds, on both paths. A run where every step reported success and the
// directory is wrong is still a bad release.
func TestTheArtifactCheckReadsTheArtifactsAndNotTheLog(t *testing.T) {
	wf := loadWorkflow(t)
	for _, tc := range []struct {
		name    string
		publish string
		signed  bool
		break_  func(t *testing.T, dist string)
		want    string
	}{
		{
			name: "the release notes are empty", publish: "false", signed: false,
			break_: func(t *testing.T, dist string) { truncate(t, filepath.Join(dist, "RELEASE-NOTES-1.2.3.md")) },
			want:   "no release notes",
		},
		{
			name: "the chart was never packaged", publish: "false", signed: false,
			break_: func(t *testing.T, dist string) { remove(t, filepath.Join(dist, "stamp-1.2.3.tgz")) },
			want:   "no packaged chart",
		},
		{
			name: "a file changed after its checksum was written", publish: "true", signed: true,
			break_: func(t *testing.T, dist string) {
				if err := os.WriteFile(filepath.Join(dist, "stamp-1.2.3.tgz"), []byte("tampered\n"), 0o600); err != nil {
					t.Fatalf("tamper: %v", err)
				}
			},
			want: "does not match its own checksums",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeDist(t, dir, "1.2.3", tc.signed)
			tc.break_(t, filepath.Join(dir, "dist"))

			step, env := checkEnv(t, wf, "artifacts", artifactsCheckStep, tc.publish, "1.2.3", nil)
			env["PATH"] = stubTools(t, dir)
			env["CHART_REPO"] = "oci://ghcr.io/d0lim/charts"
			out, err := runStep(t, dir, substitute(t, step.Run, nil), env)
			if err == nil {
				t.Fatalf("the check passed on a broken dist/:\n%s", out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("want %q in\n%s", tc.want, out)
			}
		})
	}
}

func truncate(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("truncate %s: %v", path, err)
	}
}

func remove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove %s: %v", path, err)
	}
}

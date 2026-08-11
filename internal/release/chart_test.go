package release_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	allInOneSnapshot = "../../deploy/helm/snapshots/all-in-one.yaml"
	splitSnapshot    = "../../deploy/helm/snapshots/split.yaml"
	// The chart's own message when it refuses to render a release that asks
	// for audit checkpoints and runs no api role. deploy/helm/render.sh writes
	// it, and requires the render to have failed to produce it.
	splitNoAPIRefusal = "../../deploy/helm/snapshots/split-no-api.err.txt"
	// The chart's own message when it refuses a release that configures what
	// only the callback surface can carry and leaves that listener unbound.
	noCallbackRefusal = "../../deploy/helm/snapshots/no-callback.err.txt"
)

// --- the rendered model ---------------------------------------------------

type envVar struct {
	Name      string         `yaml:"name"`
	Value     string         `yaml:"value"`
	ValueFrom map[string]any `yaml:"valueFrom"`
}

type container struct {
	Name  string   `yaml:"name"`
	Image string   `yaml:"image"`
	Args  []string `yaml:"args"`
	Ports []struct {
		Name          string `yaml:"name"`
		ContainerPort int    `yaml:"containerPort"`
	} `yaml:"ports"`
	Env     []envVar `yaml:"env"`
	EnvFrom []struct {
		ConfigMapRef struct {
			Name string `yaml:"name"`
		} `yaml:"configMapRef"`
	} `yaml:"envFrom"`
	VolumeMounts []volumeMount `yaml:"volumeMounts"`
}

type volumeMount struct {
	Name      string `yaml:"name"`
	MountPath string `yaml:"mountPath"`
	SubPath   string `yaml:"subPath"`
	ReadOnly  bool   `yaml:"readOnly"`
}

type volume struct {
	Name   string `yaml:"name"`
	Secret struct {
		SecretName string `yaml:"secretName"`
	} `yaml:"secret"`
	EmptyDir              map[string]any `yaml:"emptyDir"`
	PersistentVolumeClaim map[string]any `yaml:"persistentVolumeClaim"`
}

// writable reports whether a volume is one a process can append to. It is the
// distinction the checkpoint sink turns on: a Secret projection is read-only
// whatever the mount says, and the sink has to be written.
func (v volume) writable() bool {
	return v.Secret.SecretName == "" && (v.EmptyDir != nil || v.PersistentVolumeClaim != nil)
}

type doc struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name   string            `yaml:"name"`
		Labels map[string]string `yaml:"labels"`
	} `yaml:"metadata"`
	Data       map[string]string `yaml:"data"`
	StringData map[string]string `yaml:"stringData"`
	Spec       struct {
		Replicas int `yaml:"replicas"`
		Ports    []struct {
			Name       string `yaml:"name"`
			Port       int    `yaml:"port"`
			TargetPort string `yaml:"targetPort"`
		} `yaml:"ports"`
		Template struct {
			Spec struct {
				Containers []container `yaml:"containers"`
				Volumes    []volume    `yaml:"volumes"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

type manifest struct {
	path string
	raw  []byte
	docs []doc
}

func load(t *testing.T, path string) manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v (run deploy/helm/render.sh)", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var docs []doc
	for {
		var d doc
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if d.Kind == "" {
			continue
		}
		docs = append(docs, d)
	}
	if len(docs) == 0 {
		t.Fatalf("%s rendered no resources", path)
	}
	return manifest{path: path, raw: raw, docs: docs}
}

func (m manifest) byKind(kind string) []doc {
	var out []doc
	for _, d := range m.docs {
		if d.Kind == kind {
			out = append(out, d)
		}
	}
	return out
}

func (m manifest) deployment(t *testing.T, name string) doc {
	t.Helper()
	for _, d := range m.byKind("Deployment") {
		if d.Metadata.Name == name {
			return d
		}
	}
	t.Fatalf("%s has no Deployment named %q; it has %v", m.path, name, names(m.byKind("Deployment")))
	return doc{}
}

func names(docs []doc) []string {
	out := make([]string, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.Metadata.Name)
	}
	sort.Strings(out)
	return out
}

func (d doc) container(t *testing.T) container {
	t.Helper()
	cs := d.Spec.Template.Spec.Containers
	if len(cs) != 1 {
		t.Fatalf("%s has %d containers, want 1", d.Metadata.Name, len(cs))
	}
	return cs[0]
}

func (c container) rolesArg(t *testing.T) string {
	t.Helper()
	for _, a := range c.Args {
		if strings.HasPrefix(a, "--roles=") {
			return strings.TrimPrefix(a, "--roles=")
		}
	}
	t.Fatalf("container args %v carry no --roles", c.Args)
	return ""
}

func (c container) env(name string) (envVar, bool) {
	for _, e := range c.Env {
		if e.Name == name {
			return e, true
		}
	}
	return envVar{}, false
}

// secretRef returns the Secret name and key an environment variable is read
// from, and fails if it is not read from a Secret at all.
func (c container) secretRef(t *testing.T, name string) (string, string) {
	t.Helper()
	e, ok := c.env(name)
	if !ok {
		t.Fatalf("no %s in the rendered environment", name)
	}
	if e.Value != "" {
		t.Fatalf("%s carries a literal value", name)
	}
	ref, ok := e.ValueFrom["secretKeyRef"].(map[string]any)
	if !ok {
		t.Fatalf("%s is not read from a Secret: %v", name, e.ValueFrom)
	}
	secret, _ := ref["name"].(string)
	key, _ := ref["key"].(string)
	return secret, key
}

// addr returns the bound address of one surface. An empty string is a surface
// the tier deliberately does not serve, which is a different rendering from the
// variable being absent.
func (c container) addr(t *testing.T, surface string) string {
	t.Helper()
	name := map[string]string{
		"pep":      "STAMP_PEP_ADDR",
		"console":  "STAMP_CONSOLE_ADDR",
		"callback": "STAMP_CALLBACK_ADDR",
	}[surface]
	e, ok := c.env(name)
	if !ok {
		t.Fatalf("%s is absent: an absent listen address binds the surface to its default, "+
			"so the chart has to render it even when the answer is \"not served\"", name)
	}
	return e.Value
}

// boundSurfaces returns the surfaces a tier actually listens on, sorted.
func boundSurfaces(t *testing.T, c container) []string {
	t.Helper()
	var out []string
	for _, surface := range []string{"pep", "console", "callback"} {
		if c.addr(t, surface) != "" {
			out = append(out, surface)
		}
	}
	sort.Strings(out)
	return out
}

// surfaceDrift reports the ways one tier's bound listeners disagree with the
// listeners its role's routes are mounted on (R39, #46).
//
// The two directions are not the same failure. A route on a surface the tier
// does not bind is unreachable and silent — no router refuses it, because no
// router has heard of it — and that is the one that shipped. A bound surface
// with no route behind it is a listener exposed for nothing.
//
// It takes the binding as an argument rather than reading a manifest so that
// the self-check can hand it planted drift and watch the same code report it.
func surfaceDrift(table mountTable, role string, bound []string) []string {
	isBound := map[string]struct{}{}
	for _, s := range bound {
		isBound[s] = struct{}{}
	}
	served := map[string]struct{}{}
	var problems []string
	for _, surface := range table.surfacesOf(role) {
		served[surface] = struct{}{}
		if _, ok := isBound[surface]; !ok {
			problems = append(problems, fmt.Sprintf(
				"the %s role mounts %v on the %s surface and this tier does not bind it: "+
					"those routes are not refused there, they are unreachable",
				role, table.patternsOn(role, surface), surface))
		}
	}
	for _, surface := range bound {
		if _, ok := served[surface]; !ok {
			problems = append(problems, fmt.Sprintf(
				"this tier binds the %s surface and the %s role mounts no route on it: "+
					"a listener with nothing behind it is exposure with no reason for it",
				surface, role))
		}
	}
	sort.Strings(problems)
	return problems
}

// --- both topologies render ----------------------------------------------

func TestAllInOneRendersOneTierRunningEveryRole(t *testing.T) {
	m := load(t, allInOneSnapshot)

	deployments := m.byKind("Deployment")
	if len(deployments) != 1 {
		t.Fatalf("all-in-one rendered %d Deployments (%v), want 1", len(deployments), names(deployments))
	}
	c := deployments[0].container(t)
	if got := c.rolesArg(t); got != "all" {
		t.Errorf("--roles=%s, want all", got)
	}
	if got := c.addr(t, "pep"); got != ":8080" {
		t.Errorf("PEP address %q, want :8080", got)
	}
	if got := c.addr(t, "console"); got != ":8081" {
		t.Errorf("console address %q, want :8081", got)
	}
	// The callback surface stays down in values.yaml, because it is the one a
	// deployment may have to publish beyond its perimeter. This release asks for
	// it, and has to: it mounts the ingest grants and the external targets, and
	// both of those are spent on routes that live there and nowhere else.
	if got := c.addr(t, "callback"); got != ":8082" {
		t.Errorf("callback address %q, want :8082 — this release mounts the two documents "+
			"whose routes are on that surface", got)
	}
	if len(m.byKind("Service")) != 1 {
		t.Errorf("all-in-one rendered %d Services, want 1", len(m.byKind("Service")))
	}

	// Derived, not written down, and the same derivation the split topology is
	// held to. --roles=all mounts every route this binary has, so every surface
	// any role serves is one this tier has to bind — and mounting is not
	// reachability: internal/api mounts a route on a surface the process does
	// not serve rather than refusing to start, so an unbound listener here is
	// silence rather than a 404.
	table := loadMountTable(t, mountTableFile)
	bound := map[string]struct{}{}
	for _, surface := range boundSurfaces(t, c) {
		bound[surface] = struct{}{}
	}
	for _, surface := range table.surfacesOfEveryRole() {
		if _, ok := bound[surface]; !ok {
			t.Errorf("the all-in-one tier does not bind the %s surface, and running every role "+
				"mounts %v on it: those routes are not refused there, they are unreachable",
				surface, table.pathsOn(surface))
		}
	}
}

func TestSplitRendersOneTierPerRole(t *testing.T) {
	m := load(t, splitSnapshot)

	want := map[string]string{
		"stamp-check":    "check",
		"stamp-decide":   "decide",
		"stamp-consumer": "consumer",
		"stamp-api":      "api",
		"stamp-console":  "console",
	}
	deployments := m.byKind("Deployment")
	if len(deployments) != len(want) {
		t.Fatalf("split rendered %d Deployments (%v), want %d", len(deployments), names(deployments), len(want))
	}
	for name, role := range want {
		c := m.deployment(t, name).container(t)
		if got := c.rolesArg(t); got != role {
			t.Errorf("%s runs --roles=%s, want %s", name, got, role)
		}
	}
	if len(m.byKind("Service")) != len(want) {
		t.Errorf("split rendered %d Services, want one per tier", len(m.byKind("Service")))
	}
}

// The failure this guards against is a "split" topology that renders the
// all-in-one one under five names. Two topologies that differ only in replica
// count are one topology.
func TestSplitIsNotAllInOneUnderFiveNames(t *testing.T) {
	split := load(t, splitSnapshot)

	t.Run("each tier binds exactly the surfaces its role's routes are on", func(t *testing.T) {
		// Derived, not written down. This assertion used to carry a map of tier
		// to surface by hand, and a hand-written expectation is wrong in the
		// same direction as the thing it checks: when the decide tier stopped
		// binding the PEP surface, POST /decisions could not be served at all
		// in a split deployment, and the map said so too (#46).
		//
		// The surfaces a role serves come from the routes its components mount,
		// which is what testdata/mounted-routes.json holds.
		table := loadMountTable(t, mountTableFile)
		for _, d := range split.byKind("Deployment") {
			c := d.container(t)
			role := c.rolesArg(t)
			bound := boundSurfaces(t, c)
			for _, problem := range surfaceDrift(table, role, bound) {
				t.Errorf("%s: %s", d.Metadata.Name, problem)
			}

			// The container ports and the Service ports follow the binding: a
			// port published for a listener that is down is a lie in the API
			// server's own data.
			var published []string
			for _, p := range c.Ports {
				published = append(published, p.Name)
			}
			sort.Strings(published)
			if strings.Join(published, ",") != strings.Join(bound, ",") {
				t.Errorf("%s publishes ports %v but binds %v", d.Metadata.Name, published, bound)
			}
		}
	})

	t.Run("a bound surface is bound at the port the chart's values give it", func(t *testing.T) {
		// The one thing the mount table cannot say: routes name a listener,
		// values.yaml names its port. Ports are asserted separately so that a
		// changed port fails as a changed port.
		ports := map[string]string{"pep": ":8080", "console": ":8081", "callback": ":8082"}
		for _, d := range split.byKind("Deployment") {
			c := d.container(t)
			for _, surface := range boundSurfaces(t, c) {
				if got := c.addr(t, surface); got != ports[surface] {
					t.Errorf("%s binds %s at %q, want %q", d.Metadata.Name, surface, got, ports[surface])
				}
			}
		}
	})

	t.Run("each tier reads its own database credential", func(t *testing.T) {
		seen := map[string]string{}
		for _, d := range split.byKind("Deployment") {
			secret, key := d.container(t).secretRef(t, "STAMP_DSN")
			if key == "" {
				t.Errorf("%s reads STAMP_DSN from Secret %q with no key", d.Metadata.Name, secret)
			}
			if other, dup := seen[secret]; dup {
				t.Errorf("%s and %s share the database Secret %q: per-role privileges are "+
					"carried by the login, so a shared Secret is a shared privilege set",
					d.Metadata.Name, other, secret)
			}
			seen[secret] = d.Metadata.Name
		}
		if len(seen) != 5 {
			t.Errorf("the split topology uses %d database Secrets, want one per tier", len(seen))
		}
	})

	t.Run("exactly one tier migrates and applies grants", func(t *testing.T) {
		var migrating []string
		for _, d := range split.byKind("Deployment") {
			c := d.container(t)
			migrate, ok := c.env("STAMP_DB_MIGRATE")
			if !ok {
				t.Fatalf("%s does not say whether it migrates", d.Metadata.Name)
			}
			grants, _ := c.env("STAMP_DB_APPLY_GRANTS")
			if migrate.Value == "true" {
				migrating = append(migrating, d.Metadata.Name)
			}
			if grants.Value != migrate.Value {
				t.Errorf("%s migrates=%s but applies grants=%s", d.Metadata.Name, migrate.Value, grants.Value)
			}
		}
		if len(migrating) != 1 || migrating[0] != "stamp-api" {
			t.Errorf("tiers running migrations: %v, want only stamp-api — the schema owner is "+
				"the login that holds the admin role", migrating)
		}
	})

	t.Run("the all-in-one tier does all of it", func(t *testing.T) {
		all := load(t, allInOneSnapshot)
		c := all.byKind("Deployment")[0].container(t)
		migrate, _ := c.env("STAMP_DB_MIGRATE")
		if migrate.Value != "true" {
			t.Errorf("the all-in-one tier does not migrate; nothing else would")
		}
	})
}

// TestTheSurfaceDriftCheckFails is the self-check for the derivation above. The
// hand-written map it replaced was green on the day POST /decisions could not
// be served at all, so a derived one that has only ever agreed has not yet
// earned any more belief than the map did.
func TestTheSurfaceDriftCheckFails(t *testing.T) {
	table := loadMountTable(t, mountTableFile)

	t.Run("the binding the P0 shipped", func(t *testing.T) {
		// #46 exactly: a decide tier that binds console and callback and not
		// PEP. Nothing refuses POST /decisions, because no router on that tier
		// was ever told about it, and the split topology serves no decisions.
		problems := surfaceDrift(table, "decide", []string{"callback", "console"})
		if len(problems) == 0 {
			t.Fatal("a decide tier with no PEP listener reported no drift, and that binding " +
				"is the P0 this check exists for")
		}
		joined := strings.Join(problems, "\n  ")
		for _, want := range []string{"pep", "POST /decisions", "unreachable"} {
			if !strings.Contains(joined, want) {
				t.Errorf("the drift was caught but not named: want %q in\n  %s", want, joined)
			}
		}
	})

	t.Run("a listener with nothing behind it", func(t *testing.T) {
		problems := surfaceDrift(table, "check", []string{"console", "pep"})
		if len(problems) == 0 {
			t.Fatal("a check tier listening on the console surface reported no drift")
		}
		if joined := strings.Join(problems, "\n  "); !strings.Contains(joined, "console") {
			t.Errorf("the drift was caught but not named: want the console surface in\n  %s", joined)
		}
	})

	// The control: the same function, the same table, the binding the chart
	// really renders for that tier.
	t.Run("the aligned binding reports nothing", func(t *testing.T) {
		if problems := surfaceDrift(table, "check", []string{"pep"}); len(problems) > 0 {
			t.Fatalf("the check role's real binding reported drift:\n  %s", strings.Join(problems, "\n  "))
		}
	})
}

// R51 and R49 through the chart: console serving and the API surface are
// separate roles, and the authoring mode is an operator setting that has to
// reach the process.
func TestConsoleAndAPISeparateAndAuthoringModeIsRendered(t *testing.T) {
	split := load(t, splitSnapshot)

	api := split.deployment(t, "stamp-api").container(t)
	console := split.deployment(t, "stamp-console").container(t)
	if api.rolesArg(t) == console.rolesArg(t) {
		t.Fatalf("the api and console tiers run the same roles")
	}

	cm := split.byKind("ConfigMap")
	if len(cm) != 1 {
		t.Fatalf("split rendered %d ConfigMaps, want 1", len(cm))
	}
	if got := cm[0].Data["STAMP_AUTHORING_MODE"]; got != "file" {
		t.Errorf("STAMP_AUTHORING_MODE = %q, want the value values-split.yaml sets (file)", got)
	}
	// The console tier serves no API, so the bundle has to be told where the
	// api tier is — and that address may only come from the operator.
	if got := cm[0].Data["STAMP_CONSOLE_API_BASE_URL"]; got == "" {
		t.Errorf("the split topology renders no console API base address")
	}

	all := load(t, allInOneSnapshot)
	allCM := all.byKind("ConfigMap")[0]
	if got := allCM.Data["STAMP_AUTHORING_MODE"]; got != "both" {
		t.Errorf("all-in-one STAMP_AUTHORING_MODE = %q, want both", got)
	}
	// Same origin: the single-container install is exactly the case where the
	// base address is absent.
	if got, ok := allCM.Data["STAMP_CONSOLE_API_BASE_URL"]; ok {
		t.Errorf("all-in-one renders STAMP_CONSOLE_API_BASE_URL = %q; same-origin means absent", got)
	}
}

// --- no plaintext secrets (R42) ------------------------------------------

// credentialNamed matches the settings whose value would be credential
// material. Endpoint and identifier settings that merely contain the word token
// are not in it — STAMP_CONSOLE_OIDC_TOKEN_ENDPOINT is a URL.
//
// _KEY_FILE and _VERIFY_KEYS are here for the audit checkpoint signing key
// (R42). Their values are paths and never keys, and that is exactly what makes
// them worth scanning: the requirement is not "the key is not in this variable"
// but "this variable names a Secret this pod mounts", so a path pointing
// somewhere else — a key written into the image, or into an emptyDir by some
// other means — is caught by the same rule.
var credentialNamed = regexp.MustCompile(
	`(?i)(^STAMP_DSN$|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|_TOKEN$|_KEY_FILE$|_VERIFY_KEYS$)`)

// materialInText matches credential material wherever it appears in a rendered
// document, including in a place the environment scan does not reach.
var materialInText = []struct {
	name string
	re   *regexp.Regexp
}{
	{"a connection string", regexp.MustCompile(`postgres(ql)?://`)},
	{"userinfo with a password", regexp.MustCompile(`://[^/\s"@]+:[^/\s"@]+@`)},
	{"a PEM block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
}

// The one shape a credential-named setting may carry as a literal: the path of
// a file this pod mounts from a Secret. There are two such directories and they
// are both read-only Secret projections — the configuration documents, and the
// audit checkpoint keys.
const (
	documentMount       = "/etc/stamp/documents/"
	checkpointKeyMount  = "/etc/stamp/checkpoint/"
	checkpointSinkMount = "/var/lib/stamp/checkpoints"
)

var secretMounts = []string{documentMount, checkpointKeyMount}

// settingPaths is the file paths one setting's value names. Most of them are one
// path; STAMP_AUDIT_CHECKPOINT_VERIFY_KEYS is "key-id=/path,other-id=/path",
// which is the binary's form and so has to be the scan's.
func settingPaths(value string) []string {
	var out []string
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, path, ok := strings.Cut(entry, "="); ok {
			entry = strings.TrimSpace(path)
		}
		out = append(out, entry)
	}
	return out
}

// underSecretMounts reports whether every path a setting names is inside a
// directory this chart mounts from a Secret.
func underSecretMounts(value string) bool {
	paths := settingPaths(value)
	if len(paths) == 0 {
		return false
	}
	for _, p := range paths {
		var ok bool
		for _, root := range secretMounts {
			if strings.HasPrefix(p, root) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func plaintextSecrets(m manifest) []string {
	var found []string
	report := func(format string, args ...any) {
		found = append(found, fmt.Sprintf(format, args...))
	}

	for _, d := range m.docs {
		switch d.Kind {
		case "Secret":
			// The chart creates none: every credential is a reference to a
			// Secret the operator already manages.
			report("%s renders a Secret (%s), so the chart is a place credentials live",
				m.path, d.Metadata.Name)
		case "ConfigMap":
			for k, v := range d.Data {
				if credentialNamed.MatchString(k) && !underSecretMounts(v) {
					report("ConfigMap %s carries %s as a literal", d.Metadata.Name, k)
				}
			}
		}
		// The mount roots the scan lets a credential-named setting name. A
		// setting whose value is a path is only as good as the mount behind it:
		// "/tmp/key.pem" is a key somebody put in the filesystem by some means
		// this chart cannot see.
		mounted := map[string]bool{}
		for _, c := range d.Spec.Template.Spec.Containers {
			for _, mnt := range c.VolumeMounts {
				mounted[mnt.MountPath] = true
			}
		}
		for _, c := range d.Spec.Template.Spec.Containers {
			for _, e := range c.Env {
				if !credentialNamed.MatchString(e.Name) {
					continue
				}
				if e.Value == "" {
					continue // a reference, or unset
				}
				if !underSecretMounts(e.Value) {
					report("%s carries %s as a literal value", d.Metadata.Name, e.Name)
					continue
				}
				for _, p := range settingPaths(e.Value) {
					if !mounted[p] && !mounted[filepath.Dir(p)] {
						report("%s: %s names %s, which this pod does not mount from a Secret",
							d.Metadata.Name, e.Name, p)
					}
				}
			}
		}
	}

	for _, pattern := range materialInText {
		if loc := pattern.re.FindIndex(m.raw); loc != nil {
			line := 1 + bytes.Count(m.raw[:loc[0]], []byte("\n"))
			report("%s:%d contains %s", m.path, line, pattern.name)
		}
	}
	sort.Strings(found)
	return found
}

func TestRenderedManifestsCarryNoPlaintextSecret(t *testing.T) {
	for _, path := range []string{allInOneSnapshot, splitSnapshot} {
		m := load(t, path)
		if found := plaintextSecrets(m); len(found) > 0 {
			t.Errorf("%s:\n  %s", path, strings.Join(found, "\n  "))
		}
	}
}

// The scan above is worth exactly as much as its ability to fail. This feeds it
// a manifest with the four shapes it is supposed to catch.
func TestPlaintextSecretScanCatchesAPlantedOne(t *testing.T) {
	m := load(t, "testdata/planted-secrets.yaml")
	found := plaintextSecrets(m)
	want := []string{
		"carries STAMP_DSN as a literal value",
		"carries STAMP_MFA_CIBA_CLIENT_SECRET as a literal",
		"renders a Secret",
		"contains a connection string",
		// R42's two: a signing key that reached the manifest as bytes, and a
		// key path that names something this pod does not mount.
		"contains a PEM block",
		"carries STAMP_AUDIT_CHECKPOINT_KEY_FILE as a literal value",
	}
	for _, w := range want {
		var hit bool
		for _, f := range found {
			if strings.Contains(f, w) {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("the scan missed %q; it found:\n  %s", w, strings.Join(found, "\n  "))
		}
	}
}

// Every credential-bearing setting reaches the process by reference, and the
// mounted documents are read-only.
func TestCredentialsArriveByReference(t *testing.T) {
	split := load(t, splitSnapshot)
	for _, d := range split.byKind("Deployment") {
		c := d.container(t)
		if secret, key := c.secretRef(t, "STAMP_DSN"); secret == "" || key == "" {
			t.Errorf("%s: STAMP_DSN references Secret %q key %q", d.Metadata.Name, secret, key)
		}
		if _, ok := c.env("STAMP_MFA_CIBA_CLIENT_SECRET"); ok {
			c.secretRef(t, "STAMP_MFA_CIBA_CLIENT_SECRET")
		}
		volumes := map[string]volume{}
		for _, v := range d.Spec.Template.Spec.Volumes {
			volumes[v.Name] = v
		}
		mounted := map[string]bool{}
		for _, mnt := range c.VolumeMounts {
			mounted[mnt.Name] = true
			// The audit checkpoint sink is the single writable mount, and it
			// has to be one: the file is appended to, and
			// readOnlyRootFilesystem leaves no other path that can be. It is
			// also the only mount that is not a Secret, which is what keeps
			// "writable" and "holds a credential" from ever being the same
			// volume.
			if mnt.MountPath == checkpointSinkMount {
				if mnt.ReadOnly {
					t.Errorf("%s mounts the checkpoint sink read-only; nothing could be written to it",
						d.Metadata.Name)
				}
				if volumes[mnt.Name].Secret.SecretName != "" {
					t.Errorf("%s backs the writable checkpoint sink with a Secret", d.Metadata.Name)
				}
				continue
			}
			if !mnt.ReadOnly {
				t.Errorf("%s mounts %s writable", d.Metadata.Name, mnt.MountPath)
			}
			if !strings.HasPrefix(mnt.MountPath, documentMount) &&
				!strings.HasPrefix(mnt.MountPath, checkpointKeyMount) {
				t.Errorf("%s mounts %s outside %s and %s",
					d.Metadata.Name, mnt.MountPath, documentMount, checkpointKeyMount)
			}
			if volumes[mnt.Name].Secret.SecretName == "" {
				t.Errorf("%s mounts %s read-only from something that is not a Secret",
					d.Metadata.Name, mnt.MountPath)
			}
		}
		for _, v := range d.Spec.Template.Spec.Volumes {
			if v.Secret.SecretName == "" && !v.writable() {
				t.Errorf("%s volume %s is neither a Secret nor a writable volume", d.Metadata.Name, v.Name)
			}
			if !mounted[v.Name] {
				t.Errorf("%s carries volume %s that nothing mounts", d.Metadata.Name, v.Name)
			}
		}
		// The three documents that may hold a credential are named settings,
		// and their values are paths rather than documents. They are per-tier
		// environment rather than ConfigMap entries — two of the three do not
		// reach every tier — so the scan is of the pod, and the ConfigMap is
		// asserted not to carry them at all.
		cm := split.byKind("ConfigMap")[0]
		for _, name := range credentialDocuments {
			if v, ok := c.env(name); ok && !strings.HasPrefix(v.Value, documentMount) {
				t.Errorf("%s on %s = %q, want a path into %s",
					name, d.Metadata.Name, v.Value, documentMount)
			}
			if _, ok := cm.Data[name]; ok {
				t.Errorf("%s is a ConfigMap entry, so every tier reads it; it belongs to the tiers "+
					"that consume it", name)
			}
		}
	}
}

// credentialDocuments are the settings whose document may hold a credential.
var credentialDocuments = []string{
	"STAMP_EXTERNAL_TARGETS", "STAMP_IDP_GROUP_SOURCES", "STAMP_INGEST_CREDENTIALS",
}

// documentEnv is every configuration document setting, with the tiers of the
// split topology that are supposed to read it.
//
// The expectations are written out rather than derived, because deriving them
// from the chart is what let #34 stand: the chart and the test would agree with
// each other and with nothing else. They follow internal/runtime/credentials.go,
// and internal/runtime's own tests hold the binary to the same line.
var documentEnv = map[string][]string{
	// Declarations. Every process loads the policy set at boot and the schema
	// gate refuses a source of a kind no plane in the process answers for, so a
	// tier without these is a tier that cannot start.
	"STAMP_FACT_SOURCES":   {"check", "decide", "consumer", "api", "console"},
	"STAMP_STREAM_SOURCES": {"check", "decide", "consumer", "api", "console"},
	"STAMP_KAFKA_TOPICS":   {"check", "decide", "consumer", "api", "console"},
	// Declarations and a directory credential in one document. It stays
	// everywhere for the reason above; the narrowing for it is inside the
	// binary, where a role that never resolves a group gets a gate that dials
	// nothing.
	"STAMP_IDP_GROUP_SOURCES": {"check", "decide", "consumer", "api", "console"},
	// Credentials only, and they follow their consumer.
	"STAMP_INGEST_CREDENTIALS": {"consumer"},
	"STAMP_EXTERNAL_TARGETS":   {"decide", "api"},
}

// TestACredentialDocumentReachesOnlyTheTiersThatUseIt is #34's acceptance, and
// R42's second clause: a secret is not present where it is not needed.
//
// The check tier is the one the requirement is about. It is the tier a PEP can
// reach, it is scaled to the request rate, and the database side of R39 already
// gives it a login that cannot write a policy — which the filesystem was handing
// back. It holds no webhook signing key, no CIBA client secret and no ingest
// grant here, and the assertions below are two-sided: the tiers that do use one
// have it, so the narrowing cannot be a deployment that does not work.
func TestACredentialDocumentReachesOnlyTheTiersThatUseIt(t *testing.T) {
	split := load(t, splitSnapshot)
	for setting, tiers := range documentEnv {
		t.Run(setting, func(t *testing.T) {
			for _, tier := range []string{"check", "decide", "consumer", "api", "console"} {
				d := split.deployment(t, "stamp-"+tier)
				c := d.container(t)
				want := false
				for _, name := range tiers {
					if name == tier {
						want = true
					}
				}

				e, got := c.env(setting)
				if got != want {
					t.Errorf("the %s tier reads %s = %v, want %v", tier, setting, got, want)
					continue
				}
				if !got {
					// And the document is not mounted either: a variable is not
					// the only way a credential reaches a filesystem.
					for _, mnt := range c.VolumeMounts {
						if strings.Contains(mnt.MountPath, documentBasename(setting)) {
							t.Errorf("the %s tier mounts %s at %s while reading no variable for it",
								tier, setting, mnt.MountPath)
						}
					}
					continue
				}
				if !strings.HasPrefix(e.Value, documentMount) {
					t.Errorf("the %s tier reads %s = %q, want a path into %s",
						tier, setting, e.Value, documentMount)
				}
				mounted := false
				for _, mnt := range c.VolumeMounts {
					if mnt.MountPath == e.Value {
						mounted = true
					}
				}
				if !mounted {
					t.Errorf("the %s tier names %s at %s and mounts nothing there, which is a boot failure",
						tier, setting, e.Value)
				}
			}
		})
	}
}

// TestTheCIBAClientSecretReachesOnlyTheTiersThatIssue is the same rule on the
// one credential that arrives as a variable rather than as a document.
//
// The api role is in the expectation deliberately: applying a revision
// revalidates the decisions still open under it and re-issues a challenge whose
// binding moved, so an api tier without the client would fail at the moment a
// governance change landed.
func TestTheCIBAClientSecretReachesOnlyTheTiersThatIssue(t *testing.T) {
	split := load(t, splitSnapshot)
	issues := map[string]bool{"decide": true, "api": true}
	for _, tier := range []string{"check", "decide", "consumer", "api", "console"} {
		d := split.deployment(t, "stamp-"+tier)
		c := d.container(t)
		_, got := c.env("STAMP_MFA_CIBA_CLIENT_SECRET")
		if got != issues[tier] {
			t.Errorf("the %s tier reads STAMP_MFA_CIBA_CLIENT_SECRET = %v, want %v",
				tier, got, issues[tier])
		}
		if got {
			c.secretRef(t, "STAMP_MFA_CIBA_CLIENT_SECRET")
		}
	}

	// The all-in-one values configure no CIBA client, so this variable is
	// absent there for a reason that has nothing to do with roles. The "runs
	// every role" branch of the helper that gates it is exercised by the other
	// setting that reads the same helper — the external targets, asserted in
	// TestEveryDocumentReachesTheTierThatRunsEveryRole.
}

// TestEveryDocumentReachesTheTierThatRunsEveryRole is the other end of the
// narrowing. One tier running --roles=all consumes everything, so a rule that
// narrowed by tier name rather than by the roles the tier runs would take the
// single-container install's credentials away from it.
func TestEveryDocumentReachesTheTierThatRunsEveryRole(t *testing.T) {
	c := load(t, allInOneSnapshot).deployment(t, "stamp").container(t)
	if got := c.rolesArg(t); got != "all" {
		t.Fatalf("the all-in-one tier runs --roles=%s, want all", got)
	}
	for setting := range documentEnv {
		e, ok := c.env(setting)
		if !ok {
			t.Errorf("the all-in-one tier does not read %s; it runs every role that consumes one", setting)
			continue
		}
		if !strings.HasPrefix(e.Value, documentMount) {
			t.Errorf("%s = %q, want a path into %s", setting, e.Value, documentMount)
		}
	}
}

// documentBasename is the file a setting's document is mounted as, derived from
// the values files both snapshots use.
func documentBasename(setting string) string {
	return map[string]string{
		"STAMP_FACT_SOURCES":       "fact-sources.json",
		"STAMP_STREAM_SOURCES":     "stream-sources.json",
		"STAMP_KAFKA_TOPICS":       "kafka-topics.json",
		"STAMP_IDP_GROUP_SOURCES":  "idp-group-sources.json",
		"STAMP_INGEST_CREDENTIALS": "ingest-credentials.json",
		"STAMP_EXTERNAL_TARGETS":   "external-targets.json",
	}[setting]
}

// --- audit checkpoints (R32 with R42) ------------------------------------

// checkpointEnv are the settings that only appear on a tier that signs.
var checkpointEnv = []string{
	"STAMP_AUDIT_CHECKPOINT_KEY_FILE",
	"STAMP_AUDIT_CHECKPOINT_KEY_ID",
	"STAMP_AUDIT_CHECKPOINT_VERIFY_KEYS",
	"STAMP_AUDIT_CHECKPOINT_SINK_FILE",
	"STAMP_AUDIT_CHECKPOINT_SINK_WEBHOOK",
	"STAMP_AUDIT_CHECKPOINT_INTERVAL",
}

// R42 on the one credential the binary refuses to take as a value. The signing
// key reaches the process as a path into a mounted Secret, and the whole of
// what the manifest knows about the key is its name.
func TestCheckpointSigningKeyIsMountedAndNeverRendered(t *testing.T) {
	for _, tc := range []struct {
		snapshot string
		tier     string
	}{
		{allInOneSnapshot, "stamp"},
		{splitSnapshot, "stamp-api"},
	} {
		t.Run(tc.tier, func(t *testing.T) {
			m := load(t, tc.snapshot)
			d := m.deployment(t, tc.tier)
			c := d.container(t)

			keyFile, ok := c.env("STAMP_AUDIT_CHECKPOINT_KEY_FILE")
			if !ok {
				t.Fatalf("%s records no checkpoints: the chart's values enable them and the "+
					"api-bearing tier is where they are signed", tc.tier)
			}
			if !strings.HasPrefix(keyFile.Value, checkpointKeyMount) {
				t.Errorf("the signing key path is %q, want a path into the mounted Secret at %s",
					keyFile.Value, checkpointKeyMount)
			}
			// The identifier is what makes a rotation a restart rather than an
			// outage, and the binary refuses to boot with a key and no id.
			if id, ok := c.env("STAMP_AUDIT_CHECKPOINT_KEY_ID"); !ok || id.Value == "" {
				t.Errorf("a signing key with no identifier: checkpoints signed under it could not "+
					"survive a rotation (%s)", tc.tier)
			}
			// A sink that can be read back, because that is the only kind
			// `stamp audit verify` can compare the log against.
			sink, ok := c.env("STAMP_AUDIT_CHECKPOINT_SINK_FILE")
			if !ok || sink.Value == "" {
				t.Errorf("%s signs checkpoints into no readable sink", tc.tier)
			}

			// The key arrives as a read-only projection of a Secret the chart
			// does not create, mounted at exactly the path the setting names.
			volumes := map[string]volume{}
			for _, v := range d.Spec.Template.Spec.Volumes {
				volumes[v.Name] = v
			}
			var keyMount *volumeMount
			for i, mnt := range c.VolumeMounts {
				if mnt.MountPath == keyFile.Value {
					keyMount = &c.VolumeMounts[i]
				}
			}
			if keyMount == nil {
				t.Fatalf("%s names a signing key at %s that it does not mount", tc.tier, keyFile.Value)
			}
			if !keyMount.ReadOnly {
				t.Errorf("%s mounts the signing key writable", tc.tier)
			}
			if volumes[keyMount.Name].Secret.SecretName == "" {
				t.Errorf("%s mounts the signing key from something that is not a Secret", tc.tier)
			}

			// And the bytes are nowhere. plaintextSecrets already refuses a PEM
			// block anywhere in the document; this says the same thing about the
			// two encodings a values file could smuggle one in as, so that
			// "there is no field for it" stays a property of the rendering and
			// not only of the chart as it is written today.
			assertNoKeyMaterial(t, m)
		})
	}
}

// keyMaterial are encodings an Ed25519 private key could reach a manifest as.
// The PEM header is the one the binary's loader accepts; the other two are what
// an operator reaches for when a chart offers a field that takes "the key".
var keyMaterial = []struct {
	name string
	re   *regexp.Regexp
}{
	{"a PEM private key block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"a 64-character hex seed", regexp.MustCompile(`(?i)\b[0-9a-f]{64}\b`)},
	{"a base64 Ed25519 PKCS#8 key", regexp.MustCompile(`MC4CAQAwBQYDK2Vw`)},
}

// checksumAnnotation is the one 64-hex string a rendering is allowed to carry:
// the digest of the ConfigMap, which is what makes a settings change roll the
// pods. It is skipped by name rather than by loosening the pattern, so a second
// hex blob appearing anywhere else is still a finding.
const checksumAnnotation = "checksum/config:"

func assertNoKeyMaterial(t *testing.T, m manifest) {
	t.Helper()
	for n, line := range bytes.Split(m.raw, []byte("\n")) {
		if bytes.Contains(line, []byte(checksumAnnotation)) {
			continue
		}
		for _, pattern := range keyMaterial {
			if pattern.re.Match(line) {
				t.Errorf("%s:%d contains %s", m.path, n+1, pattern.name)
			}
		}
	}
}

// The signing key goes to the tier that signs and to no other.
//
// internal/runtime/wiring.go registers the checkpointer under the api role
// alone, so every other tier would hold a key it never uses — and a check tier
// holding the audit signing key can forge the evidence that its own compromise
// would be detected by, which is the opposite of what the per-tier database
// credentials beside it are for.
func TestOnlyTheSigningTierHoldsCheckpointConfiguration(t *testing.T) {
	split := load(t, splitSnapshot)

	for _, d := range split.byKind("Deployment") {
		c := d.container(t)
		signs := d.Metadata.Name == "stamp-api"
		for _, name := range checkpointEnv {
			_, present := c.env(name)
			if present && !signs {
				t.Errorf("%s carries %s: it does not run the api role, so it would hold "+
					"checkpoint configuration it never acts on", d.Metadata.Name, name)
			}
			if !present && signs && name != "STAMP_AUDIT_CHECKPOINT_VERIFY_KEYS" {
				t.Errorf("stamp-api carries no %s", name)
			}
		}
		for _, mnt := range c.VolumeMounts {
			under := strings.HasPrefix(mnt.MountPath, checkpointKeyMount) ||
				strings.HasPrefix(mnt.MountPath, checkpointSinkMount)
			if under && !signs {
				t.Errorf("%s mounts %s, and records no checkpoints", d.Metadata.Name, mnt.MountPath)
			}
		}
	}

	// The all-in-one topology runs every role in one process, so that tier is
	// the signing tier and there is nowhere else for the key to be.
	all := load(t, allInOneSnapshot)
	if got := len(all.byKind("Deployment")); got != 1 {
		t.Fatalf("all-in-one rendered %d Deployments", got)
	}
}

// The chart refuses a release that asks for checkpoints and runs no api role.
//
// Such a release renders valid manifests and produces no tamper evidence at
// all, which is the failure mode a warning does not address: `helm template`
// never prints NOTES.txt, and an operator who wrote a signing key into their
// values has every reason to believe the control is on. The refusal is
// exercised by deploy/helm/render.sh, which requires the render to fail and
// keeps the message here; this asserts what the message has to say.
func TestSplitWithoutAnAPITierIsRefused(t *testing.T) {
	raw, err := os.ReadFile(splitNoAPIRefusal)
	if err != nil {
		t.Fatalf("read %s: %v (run deploy/helm/render.sh)", splitNoAPIRefusal, err)
	}
	msg := strings.TrimSpace(string(raw))
	if msg == "" {
		t.Fatalf("%s is empty: the chart rendered a release it is supposed to refuse, or the "+
			"refusal no longer names itself", splitNoAPIRefusal)
	}
	// The three things the message has to carry: what is wrong, why it is not
	// visible any other way, and both remedies — one of which is legitimate,
	// because a data-plane-only release beside a release that runs api is a
	// real deployment shape.
	for _, want := range []string{
		"api role",
		"records a checkpoint",
		"roles.api.enabled: true",
		"audit.checkpoint.enabled: false",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q:\n  %s", want, msg)
		}
	}
}

// The chart refuses a release that configures what completes on the callback
// surface and binds no callback listener.
//
// This one is worse than a manifest that does not render, because it does
// render. deploy/helm/stamp/values-no-callback.yaml produced a healthy
// all-in-one Deployment with STAMP_CALLBACK_ADDR: "" beside a set
// STAMP_MFA_AUTHORIZATION_ENDPOINT, a mounted external-targets Secret and a
// mounted ingest-grants Secret: the routes were mounted, because --roles=all
// mounts them, on a listener nothing bound. The IdP's redirect arrived at
// nothing, no external verdict could arrive, and the producers held credentials
// for a route that did not answer — and step-up is the path a decision takes by
// default (D26), so that was the primary flow of the default install.
//
// The refusal is exercised by deploy/helm/render.sh, which requires the render
// to fail and keeps the message here; this asserts what the message has to say.
func TestAReleaseThatStrandsTheCallbackSurfaceIsRefused(t *testing.T) {
	raw, err := os.ReadFile(noCallbackRefusal)
	if err != nil {
		t.Fatalf("read %s: %v (run deploy/helm/render.sh)", noCallbackRefusal, err)
	}
	msg := strings.TrimSpace(string(raw))
	if msg == "" {
		t.Fatalf("%s is empty: the chart rendered a release it is supposed to refuse, or the "+
			"refusal no longer names itself", noCallbackRefusal)
	}

	// Each stranded setting is named, so that an operator reads which of their
	// values asked for the listener rather than only that something did — the
	// fixture configures all three, so a refusal that stopped at the first one
	// it found would fail here.
	for _, want := range []string{
		"listeners.callback.enabled is false",
		"mfa.authorizationEndpoint",
		"documents.externalTargets",
		"documents.ingestCredentials",
		// Both ways out, and the second one is legitimate: a deployment that
		// runs none of the three is exactly what the unbound default is for.
		"listeners.callback.enabled: true",
		"callbackBaseUrl",
		"clear the settings named above",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q:\n  %s", want, msg)
		}
	}

	// Derived rather than listed: every path that lives on the callback surface
	// is named in the message. A route added there later is one more thing an
	// unbound listener silently swallows, and this fails until the refusal
	// accounts for it.
	table := loadMountTable(t, mountTableFile)
	for _, path := range table.pathsOn("callback") {
		if path == "/healthz" {
			// Mounted by api.Server on every surface rather than by a role, so
			// it belongs to no feature an operator could have configured.
			continue
		}
		if !strings.Contains(msg, path) {
			t.Errorf("the refusal does not name %s, which is mounted on the callback surface "+
				"and is therefore one of the things this release would have lost:\n  %s", path, msg)
		}
	}
}

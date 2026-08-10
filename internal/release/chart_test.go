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
	VolumeMounts []struct {
		Name      string `yaml:"name"`
		MountPath string `yaml:"mountPath"`
		ReadOnly  bool   `yaml:"readOnly"`
	} `yaml:"volumeMounts"`
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
				Volumes    []struct {
					Name   string `yaml:"name"`
					Secret struct {
						SecretName string `yaml:"secretName"`
					} `yaml:"secret"`
				} `yaml:"volumes"`
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
	// The callback surface is the one a deployment may have to expose beyond
	// its perimeter, so it stays down until asked for.
	if got := c.addr(t, "callback"); got != "" {
		t.Errorf("callback address %q, want it unbound by default", got)
	}
	if len(m.byKind("Service")) != 1 {
		t.Errorf("all-in-one rendered %d Services, want 1", len(m.byKind("Service")))
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

	t.Run("each tier binds only the surfaces its roles serve", func(t *testing.T) {
		// check answers AuthZEN on the PEP surface and nothing else; a check
		// tier reachable on the console surface would be an authoring endpoint
		// on the highest-QPS, least-trusted tier.
		want := map[string]map[string]string{
			"stamp-check":    {"pep": ":8080", "console": "", "callback": ""},
			"stamp-decide":   {"pep": "", "console": ":8081", "callback": ":8082"},
			"stamp-consumer": {"pep": "", "console": "", "callback": ":8082"},
			"stamp-api":      {"pep": "", "console": ":8081", "callback": ""},
			"stamp-console":  {"pep": "", "console": ":8081", "callback": ""},
		}
		for tier, surfaces := range want {
			c := split.deployment(t, tier).container(t)
			for surface, addr := range surfaces {
				if got := c.addr(t, surface); got != addr {
					t.Errorf("%s binds %s at %q, want %q", tier, surface, got, addr)
				}
			}
			// The container ports and the Service ports follow the binding: a
			// port published for a listener that is down is a lie in the API
			// server's own data.
			var published []string
			for _, p := range c.Ports {
				published = append(published, p.Name)
			}
			sort.Strings(published)
			var bound []string
			for surface, addr := range surfaces {
				if addr != "" {
					bound = append(bound, surface)
				}
			}
			sort.Strings(bound)
			if strings.Join(published, ",") != strings.Join(bound, ",") {
				t.Errorf("%s publishes ports %v but binds %v", tier, published, bound)
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
var credentialNamed = regexp.MustCompile(`(?i)(^STAMP_DSN$|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|_TOKEN$)`)

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

// documentMount is the one shape a credential-named setting may carry as a
// literal: the path of a file mounted from a Secret.
const documentMount = "/etc/stamp/documents/"

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
				if credentialNamed.MatchString(k) && !strings.HasPrefix(v, documentMount) {
					report("ConfigMap %s carries %s as a literal", d.Metadata.Name, k)
				}
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
				if strings.HasPrefix(e.Value, documentMount) {
					continue
				}
				report("%s carries %s as a literal value", d.Metadata.Name, e.Name)
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
		mounted := map[string]bool{}
		for _, mnt := range c.VolumeMounts {
			if !mnt.ReadOnly {
				t.Errorf("%s mounts %s writable", d.Metadata.Name, mnt.MountPath)
			}
			if !strings.HasPrefix(mnt.MountPath, documentMount) {
				t.Errorf("%s mounts %s outside %s", d.Metadata.Name, mnt.MountPath, documentMount)
			}
			mounted[mnt.Name] = true
		}
		for _, v := range d.Spec.Template.Spec.Volumes {
			if v.Secret.SecretName == "" {
				t.Errorf("%s volume %s is not a Secret", d.Metadata.Name, v.Name)
			}
			if !mounted[v.Name] {
				t.Errorf("%s carries volume %s that nothing mounts", d.Metadata.Name, v.Name)
			}
		}
		// The three documents that may hold a credential are named settings,
		// and their values are paths rather than documents.
		for _, name := range []string{"STAMP_EXTERNAL_TARGETS", "STAMP_IDP_GROUP_SOURCES", "STAMP_INGEST_CREDENTIALS"} {
			cm := split.byKind("ConfigMap")[0]
			if v, ok := cm.Data[name]; ok && !strings.HasPrefix(v, documentMount) {
				t.Errorf("%s = %q, want a path into %s", name, v, documentMount)
			}
		}
	}
}

package runtime

// consumption_test.go is the check that a setting an operator can write down is
// a setting this process acts on.
//
// # Why this file exists
//
// The same defect has now been found four times, by four different pieces of
// work, and every one of them was found by accident:
//
//   - STAMP_BOOTSTRAP_WARN_INTERVAL was read from the environment into Config
//     and never passed on, so the warning interval was always one hour (found by
//     the M4 integration).
//   - The whole checkpoint subsystem — Checkpointer, NewCheckpointSigner,
//     NewFileSink — had no production caller and no configuration surface at all
//     (found by U18a, issue #24).
//   - AuditWriter.ReloadHead was implemented and tested and has no production
//     caller (issue #17). It still has none; see the note at the bottom.
//   - AuditConfig.AlertThreshold was accepted by the api package and never
//     supplied by the composition root, so the audit loss alert fired on the
//     first lost event and an operator could not move it (issue #31).
//
// Fixing the fourth one does not prevent the fifth. What prevents the fifth is a
// test that fails, and the test below is it.
//
// # Which shape of check this is, and why
//
// The plan left two options open (Open Question 3):
//
//	(a) field-consumption cross-reference — walk Config's fields and confirm
//	    each is referenced at the composition root. Cheap, but "referenced"
//	    is not "honoured".
//	(b) observable difference — require that setting each field to something
//	    other than its default produces a difference something can observe.
//	    A far stronger claim, and far more expensive: it needs an observation
//	    point per field, and this Config has 63 of them.
//
// This file is (a), made as strong as (a) can be made, and TestAuditAlert-
// ThresholdMovesWhenTheAlertFires in wiring_test.go is (b) for the one field
// this unit adds. The reasoning for the split:
//
//   - (a) is exhaustive and (b) is not affordable exhaustively. Exhaustive is
//     the property that matters here, because the failure mode is a field
//     nobody thought about — the four cases above were all found by accident
//     precisely because nobody was looking at that field. A strong check over
//     the fields somebody remembered to cover is a check that cannot catch the
//     next one.
//   - All four historical cases are "no read at all", not "read and
//     discarded". (a) detects the first exactly. It cannot detect the second,
//     and that is stated here rather than hidden: a line that reads a field
//     into a variable the composition root then ignores would pass this test.
//   - The strength (b) buys is bought back partly by the coverage rules below.
//     A read only counts when it happens at the composition root, so the
//     round trip through ConfigFromEnv and Config.validate — reading a field
//     in order to check it, which is what BootstrapWarnInterval had — is not
//     consumption. And a struct read whole never covers its own fields, so
//     `cfg := a.cfg.Console` does not vouch for the nine fields of
//     ConsoleConfig.
//
// A field that cannot pass belongs in exceptedFields with a reason, and the
// reason has to be a fact about the field rather than a note that it fails.
// A name in that list with no argument behind it turns this file into the thing
// that hides the fifth case instead of the thing that finds it.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// runtimePkgPath is this package, which is how the walk below tells a nested
// deployment struct — one whose fields are themselves settings — from a struct
// that belongs to a subsystem and is handed over whole.
const runtimePkgPath = "github.com/d0lim/stamp/internal/runtime"

// configLoaderFile holds the environment reader, the defaulting and the
// validation. Reads there are deliberately not consumption: every one of the
// four cases above read the field somewhere in this file and stopped there.
const configLoaderFile = "config.go"

// exceptedFields are the Config fields the check below cannot require, with the
// reason each one is a fact about the field and not about the check.
//
// It is empty. It is kept, and kept documented, because the next person to reach
// for it should have to write the reason down.
var exceptedFields = map[string]string{}

// TestEveryConfigFieldIsConsumedAtTheCompositionRoot walks Config and requires
// each leaf setting to be read by the assembly, not merely by the loader.
func TestEveryConfigFieldIsConsumedAtTheCompositionRoot(t *testing.T) {
	leaves, typePaths := configLeaves(t)
	if len(leaves) == 0 {
		t.Fatal("the walk over Config found no fields, which means it is walking the wrong thing")
	}

	reads := compositionRootReads(t, leaves, typePaths)
	if len(reads) == 0 {
		t.Fatal("the scan of the composition root found no configuration reads, which means it is " +
			"scanning the wrong files or resolving nothing")
	}

	var missing []string
	for _, leaf := range leaves {
		if why, excepted := exceptedFields[leaf]; excepted {
			if consumedBy(reads, leaf) {
				t.Errorf("Config.%s is listed as an exception (%q) but the composition root does consume it: "+
					"remove the exception", leaf, why)
			}
			continue
		}
		if !consumedBy(reads, leaf) {
			missing = append(missing, leaf)
		}
	}
	for name := range exceptedFields {
		if !containsLeaf(leaves, name) {
			t.Errorf("exceptedFields names %q, which is not a field of Config: a stale exception is an "+
				"exception nobody is checking", name)
		}
	}

	if len(missing) > 0 {
		t.Errorf("%d configuration field(s) are read from the environment and never delivered to a "+
			"subsystem:\n\t%s\n\n"+
			"an operator can write these down and nothing in the process will act on them. wire each one "+
			"through the composition root, or add it to exceptedFields with the reason it cannot be.",
			len(missing), strings.Join(missing, "\n\t"))
	}
}

// TestConfigConsumptionCheckDetectsAnUnwiredField is the check on the check.
//
// The scan is only worth its weight if it fails when a field stops being
// delivered, so this drives the same scan over a composition root with one
// delivery removed and requires the field to be reported. Without it, a scan
// that resolved nothing at all would report every field consumed and this file
// would be decoration.
func TestConfigConsumptionCheckDetectsAnUnwiredField(t *testing.T) {
	leaves, typePaths := configLeaves(t)

	// Each case names a field and the exact source line that delivers it. The
	// line is deleted from the in-memory copy of the file, the scan is rerun,
	// and the field must come back unconsumed.
	cases := []struct {
		field    string
		file     string
		delivery string
	}{
		{
			field:    "AuditCapacity",
			file:     "wiring.go",
			delivery: "Capacity:      cfg.AuditCapacity,",
		},
		{
			field:    "Console.RoleClaim",
			file:     "wiring.go",
			delivery: "RoleClaim:             cfg.RoleClaim,",
		},
		{
			field:    "Checkpoint.Interval",
			file:     "checkpoint.go",
			delivery: "interval:     cfg.Interval,",
		},
	}

	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			if !consumedBy(compositionRootReads(t, leaves, typePaths), tc.field) {
				t.Fatalf("Config.%s is not consumed before the mutation, so this case proves nothing", tc.field)
			}
			reads := compositionRootReads(t, leaves, typePaths, mutation{file: tc.file, remove: tc.delivery})
			if consumedBy(reads, tc.field) {
				t.Fatalf("removing %q from %s left Config.%s reported as consumed: the scan does not "+
					"detect what it claims to", tc.delivery, tc.file, tc.field)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// the walk over Config
// ---------------------------------------------------------------------------

// configLeaves enumerates every setting in Config as a dotted path, and returns
// the path each nested deployment struct type lives at.
//
// A field whose type is another struct declared in this package is not a leaf:
// its fields are settings in their own right and each has to be delivered. A
// field whose type comes from anywhere else is a leaf even when it is a struct,
// because the composition root's job for it is to hand the whole value over —
// what the receiving package then does with the parts is that package's test.
func configLeaves(t *testing.T) (leaves []string, typePaths map[reflect.Type]string) {
	t.Helper()
	typePaths = map[reflect.Type]string{}
	seen := map[reflect.Type]string{}
	var walk func(rt reflect.Type, prefix string)
	walk = func(rt reflect.Type, prefix string) {
		for i := range rt.NumField() {
			f := rt.Field(i)
			if !f.IsExported() {
				continue
			}
			path := f.Name
			if prefix != "" {
				path = prefix + "." + f.Name
			}
			if nested := deploymentStruct(f.Type); nested != nil {
				if at, dup := seen[nested]; dup {
					// Two paths for one type would make the parameter rule in
					// resolveRoots ambiguous, and the ambiguity has to be
					// decided here rather than guessed at there.
					t.Fatalf("%s appears at both %s and %s: the scan resolves a parameter of a "+
						"deployment struct type by its unique path, so this needs a decision",
						nested.Name(), at, path)
				}
				seen[nested] = path
				typePaths[nested] = path
				walk(nested, path)
				continue
			}
			leaves = append(leaves, path)
		}
	}
	walk(reflect.TypeOf(Config{}), "")
	sort.Strings(leaves)
	return leaves, typePaths
}

// deploymentStruct reports the struct type behind a field when that struct is
// declared in this package, unwrapping the pointer, slice, array and map
// containers a configuration surface uses.
func deploymentStruct(rt reflect.Type) reflect.Type {
	for {
		switch rt.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			rt = rt.Elem()
		case reflect.Struct:
			if rt.PkgPath() == runtimePkgPath {
				return rt
			}
			return nil
		default:
			return nil
		}
	}
}

func containsLeaf(leaves []string, name string) bool {
	for _, l := range leaves {
		if l == name {
			return true
		}
	}
	return false
}

// consumedBy reports whether some read at the composition root delivers a leaf.
//
// A read of the leaf itself counts, and so does a read that reaches into it —
// `cfg.Egress.AllowLoopback` delivers Egress, whose own fields belong to the
// fact package. A read of a *shorter* path never counts: leaves are terminal by
// construction, so a shorter path is a nested deployment struct read whole, and
// letting that vouch for its fields is the loophole that would have passed
// three of the four cases this file exists for.
func consumedBy(reads map[string]bool, leaf string) bool {
	if reads[leaf] {
		return true
	}
	for read := range reads {
		if strings.HasPrefix(read, leaf+".") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// the scan of the composition root
// ---------------------------------------------------------------------------

// mutation removes one line from one file before it is parsed, for the check on
// the check.
type mutation struct {
	file   string
	remove string
}

// compositionRootReads returns every configuration path the assembly reads.
//
// The composition root is every non-test file of this package except the
// loader: wiring.go, checkpoint.go, decide.go, registry.go, roles.go,
// snapshot.go. config.go is excluded on purpose — a field read in order to
// default it or validate it has not been delivered anywhere, and treating that
// as consumption is exactly the mistake that let four settings ship unwired.
func compositionRootReads(t *testing.T, leaves []string, typePaths map[reflect.Type]string,
	mutations ...mutation,
) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list the package's files: %v", err)
	}
	typeNames := map[string]string{}
	for rt, path := range typePaths {
		typeNames[rt.Name()] = path
	}

	reads := map[string]bool{}
	scanned := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") || name == configLoaderFile {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(src)
		for _, m := range mutations {
			if m.file != name {
				continue
			}
			if !strings.Contains(text, m.remove) {
				t.Fatalf("the mutation case expects %s to contain %q and it does not: the case has "+
					"drifted from the code it mutates", name, m.remove)
			}
			text = strings.Replace(text, m.remove, "", 1)
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, text, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		collectReads(file, typeNames, leaves, reads)
	}
	if scanned == 0 {
		t.Fatal("no composition-root file was scanned")
	}
	return reads
}

// collectReads walks one file and records the configuration paths it reads.
func collectReads(file *ast.File, typeNames map[string]string, leaves []string, reads map[string]bool) {
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		roots := resolveRoots(fn, typeNames)
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			sel, ok := inner.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if path, ok := resolvePath(sel, roots); ok {
				if isConfigPath(path, leaves) {
					reads[path] = true
				}
			}
			return true
		})
		return true
	})
}

// resolveRoots finds, for one function, the local names that hold a piece of
// the deployment configuration and the path each one sits at.
//
// Three shapes reach configuration into a function body, and all three appear in
// this package:
//
//   - the App's own field, `a.cfg`, and the `cfg` a build step copies out of it;
//   - a parameter typed with a nested deployment struct, which is resolved by
//     that type's unique path in Config — configLeaves refuses to build the
//     table at all if a type has two paths;
//   - a range variable over a slice of them, which is how the pinned issuers are
//     read.
func resolveRoots(fn *ast.FuncDecl, typeNames map[string]string) map[string]string {
	roots := map[string]string{}

	addParams := func(fields *ast.FieldList) {
		if fields == nil {
			return
		}
		for _, field := range fields.List {
			ident, ok := unwrapTypeName(field.Type)
			if !ok {
				continue
			}
			if ident == "Config" {
				for _, name := range field.Names {
					roots[name.Name] = ""
				}
				continue
			}
			if path, ok := typeNames[ident]; ok {
				for _, name := range field.Names {
					roots[name.Name] = path
				}
			}
		}
	}
	addParams(fn.Type.Params)
	addParams(fn.Recv)

	// A second pass over the body picks up the aliases, which are always
	// assignments from something already rooted.
	for range 2 {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch stmt := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range stmt.Lhs {
					name, ok := lhs.(*ast.Ident)
					if !ok || i >= len(stmt.Rhs) {
						continue
					}
					if path, ok := rootedExpr(stmt.Rhs[i], roots); ok {
						roots[name.Name] = path
					}
				}
			case *ast.RangeStmt:
				path, ok := rootedExpr(stmt.X, roots)
				if !ok {
					return true
				}
				if name, ok := stmt.Value.(*ast.Ident); ok && name.Name != "_" {
					roots[name.Name] = path
				}
			}
			return true
		})
	}
	return roots
}

// rootedExpr resolves an expression that yields configuration: a selector on a
// known root, `a.cfg` itself, or a bare identifier that already is one.
func rootedExpr(expr ast.Expr, roots map[string]string) (string, bool) {
	switch e := expr.(type) {
	case *ast.Ident:
		path, ok := roots[e.Name]
		return path, ok
	case *ast.SelectorExpr:
		return resolvePath(e, roots)
	case *ast.CallExpr:
		// `cfg.withDefaults()` returns a Config, and it is the only call in
		// this package that does. Anything else resolves to nothing.
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "withDefaults" {
			return rootedExpr(sel.X, roots)
		}
	}
	return "", false
}

// resolvePath turns a selector chain into a dotted configuration path.
//
// The chain's base is either a name resolveRoots knows or the App's `cfg`
// field, which is written `a.cfg` throughout the package.
func resolvePath(sel *ast.SelectorExpr, roots map[string]string) (string, bool) {
	var parts []string
	cur := ast.Expr(sel)
	for {
		s, ok := cur.(*ast.SelectorExpr)
		if !ok {
			break
		}
		parts = append([]string{s.Sel.Name}, parts...)
		cur = s.X
	}
	ident, ok := cur.(*ast.Ident)
	if !ok {
		return "", false
	}
	// `a.cfg` and `a.cfg.X` — the receiver's own copy of the whole
	// configuration, which is how every build step past the first reaches it.
	if len(parts) > 0 && parts[0] == "cfg" {
		if _, isRoot := roots[ident.Name]; !isRoot {
			return strings.Join(parts[1:], "."), true
		}
	}
	base, ok := roots[ident.Name]
	if !ok {
		return "", false
	}
	if base == "" {
		return strings.Join(parts, "."), true
	}
	return base + "." + strings.Join(parts, "."), true
}

// unwrapTypeName returns the name of a locally declared type behind a
// parameter's type expression.
func unwrapTypeName(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name, true
	case *ast.StarExpr:
		return unwrapTypeName(e.X)
	}
	return "", false
}

// isConfigPath keeps the resolved paths that name a real setting and discards
// the rest — a method call on a nested struct resolves to a chain that ends in
// the method's name, and that is not a field of anything.
func isConfigPath(path string, leaves []string) bool {
	for _, leaf := range leaves {
		if path == leaf || strings.HasPrefix(path, leaf+".") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// what this check does not cover
// ---------------------------------------------------------------------------
//
// Two of the four cases in the header are not Config fields, and no walk over
// Config can reach them: the checkpoint subsystem had no configuration surface
// at all before U18a gave it one, and AuditWriter.ReloadHead is a recovery
// operation with no setting attached — it is still called by nothing but tests,
// which is issue #17, still open.
//
// That is a different sub-class of the same defect — a capability with no
// production caller, rather than a setting with no delivery — and it wants a
// different check: an unused-export pass over internal/, which would report far
// more than four candidates and needs its own triage. It is deliberately not
// attempted here, and it is recorded here so that this file is not mistaken for
// coverage of it.

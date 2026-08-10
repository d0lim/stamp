//go:build m1deps

// Package deps pins the library dependencies M1 will use so they are declared
// once, in the scaffold unit, rather than added piecemeal by sibling branches.
//
// Every M1 unit branches from the scaffold. If each one added its own
// requirement, `go.mod` and `go.sum` would be edited on three sibling branches
// at once and every rebase in the landing stack would hand-resolve a `go.sum`
// conflict. Declaring them here keeps the manifest stable across the stack.
//
// The m1deps build tag keeps these imports out of every real build while still
// counting for `go mod tidy`, which resolves imports across all build
// configurations. Delete an entry only when the plan drops that dependency.
package deps

import (
	// U3 — AST-to-CEL compilation and the evaluation core.
	_ "github.com/google/cel-go/cel"

	// U2 — the policy exchange format, and the proto expression types the
	// cel-go entry point for a programmatically built AST goes through. Both
	// were already in the module graph as indirect requirements; U2 promotes
	// them to direct ones without touching `go.sum`.
	_ "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	_ "gopkg.in/yaml.v3"

	// U4 — Postgres driver and schema migrations.
	_ "github.com/golang-migrate/migrate/v4"
	_ "github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/pgxpool"

	// U4 — Postgres-backed integration tests.
	_ "github.com/testcontainers/testcontainers-go"
	_ "github.com/testcontainers/testcontainers-go/modules/postgres"

	// U8 — OIDC relying party and JWKS verification.
	_ "github.com/coreos/go-oidc/v3/oidc"
)

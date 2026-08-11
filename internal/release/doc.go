// Package release holds the gates a tagged release has to pass, as tests.
//
// Two of them live here rather than in the release workflow, for the same
// reason the console contract check lives in a test: a gate that only runs on a
// tag is a gate that is discovered to be broken at the worst moment.
//
//   - The Helm chart is asserted against its committed snapshots
//     (deploy/helm/snapshots), which deploy/helm/render.sh regenerates and CI
//     diffs. The tests read the snapshots and not the chart, so they run
//     wherever Go runs, with no helm binary in the loop.
//
//   - The three public contract specification documents (R11) are asserted to
//     exist and to declare a semver version that matches the constant the code
//     ships, by running the same script the release workflow runs.
//
// The package has no non-test code on purpose: nothing in the product imports
// it, and it exists so that `go test ./...` covers the packaging.
package release

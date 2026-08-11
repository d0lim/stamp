#!/usr/bin/env bash
# R11: the three public contracts — the policy schema, the challenge interface
# and the decision API — are versioned with semver from the first release, and
# each one's specification document lives in docs/ with its version stated.
#
# This is the release gate for that sentence. It fails when a specification
# document is missing, when it states no semver version, and when the version it
# states has drifted from the constant the code ships — a document that says 1.0
# while the binary says 2.0 is worse than no document, because it is believed.
#
# What it structurally cannot do is notice that a document's *contents* drifted.
# The decision API's major comes from a path constant that does not move when a
# route is added, removed or moved to another listener, so this gate passes a
# document that denies an endpoint the binary serves (#44). That comparison is a
# set difference rather than a string comparison, and it lives in
# internal/release/routes_test.go, against the route table internal/runtime
# renders from the assembled registry.
#
# The one thing this gate owes that check is its input: a decision API document
# with no endpoint table has nothing to compare, so its absence is refused here
# as well as there.
#
# Usage:
#   scripts/check-contract-versions.sh [docs-dir]
#
# docs-dir defaults to docs/contracts. It is an argument so that the gate can be
# pointed at a fixture and watched to fail; a check that has only ever passed is
# not known to be a check.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docs_dir="${1:-${repo_root}/docs/contracts}"

failures=0
fail() {
    printf 'contract versions: %s\n' "$1" >&2
    failures=$((failures + 1))
}

# The version stated in a document's YAML front matter.
stated_version() {
    awk '
        /^---[[:space:]]*$/ { fences++; next }
        fences == 1 && /^version:[[:space:]]/ { print $2; exit }
        fences > 1 { exit }
    ' "$1"
}

# A constant as the Go source spells it.
go_constant() {
    local file="$1" pattern="$2"
    grep -Eo "${pattern}" "${repo_root}/${file}" 2>/dev/null | head -n 1
}

major_of() { printf '%s\n' "${1%%.*}"; }

check_document() {
    local name="$1" want_major="$2" want_exact="$3"
    local path="${docs_dir}/${name}.md"

    if [ ! -f "${path}" ]; then
        fail "${path} does not exist: R11 requires a specification document for this contract"
        return
    fi

    local version
    version="$(stated_version "${path}")"
    if [ -z "${version}" ]; then
        fail "${path} states no version: add a \`version: X.Y.Z\` line to its front matter"
        return
    fi
    if ! printf '%s' "${version}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
        fail "${path} states version '${version}', which is not semver"
        return
    fi

    if [ -n "${want_exact}" ] && [ "${version}" != "${want_exact}" ]; then
        fail "${path} states ${version} but the code ships ${want_exact}"
        return
    fi
    if [ -n "${want_major}" ] && [ "$(major_of "${version}")" != "${want_major}" ]; then
        fail "${path} states ${version}, whose major does not match the ${want_major} the code ships"
        return
    fi

    printf 'contract versions: %-22s %s\n' "${name}" "${version}"
}

# The endpoint table of the decision API document, as rows.
#
# A row is a table line whose first cell holds a backticked pattern, under the
# `## 엔드포인트` heading. It is the same shape internal/release parses, and it is
# counted here so that deleting the table fails the release rather than making
# the check that reads it vacuous.
endpoint_rows() {
    awk '
        /^## / { inside = ($0 ~ /엔드포인트/); next }
        inside && /^\|/ && index($0, "`") > 0 { rows++ }
        END { print rows + 0 }
    ' "$1"
}

check_endpoint_table() {
    local path="${docs_dir}/decision-api.md"
    [ -f "${path}" ] || return

    local rows
    rows="$(endpoint_rows "${path}")"
    if [ "${rows}" -eq 0 ]; then
        fail "${path} states no endpoint table: internal/release compares that table against the \
routes the composition root mounts, and a document with no table is a contract that cannot be checked"
        return
    fi
    printf 'contract versions: %-22s %s endpoint rows\n' "decision-api" "${rows}"
}

# The policy schema's major is the document envelope's: while a policy file says
# `apiVersion: stamp/v1`, the contract is 1.x.
envelope="$(go_constant internal/policy/codec.go 'APIVersion = "stamp/v[0-9]+"')"
if [ -z "${envelope}" ]; then
    fail "internal/policy/codec.go no longer declares APIVersion in the form this gate reads"
    policy_major=""
else
    policy_major="$(printf '%s' "${envelope}" | sed -E 's#.*"stamp/v([0-9]+)".*#\1#')"
fi

# The challenge contract carries its own semver constant, so the document has to
# match it exactly rather than only in the major.
challenge_version="$(go_constant internal/challenge/contract.go 'ContractVersion = "[0-9][^"]*"' \
    | sed -E 's#.*"([^"]+)".*#\1#')"
if [ -z "${challenge_version}" ]; then
    fail "internal/challenge/contract.go no longer declares ContractVersion in the form this gate reads"
fi

# The decision API's major is the one in its own paths.
evaluation="$(go_constant internal/api/authzen.go 'EvaluationPath = "/access/v[0-9]+/[a-z]+"')"
if [ -z "${evaluation}" ]; then
    fail "internal/api/authzen.go no longer declares EvaluationPath in the form this gate reads"
    api_major=""
else
    api_major="$(printf '%s' "${evaluation}" | sed -E 's#.*"/access/v([0-9]+)/.*#\1#')"
fi

check_document policy-schema "${policy_major}" ""
check_document challenge-interface "" "${challenge_version}"
check_document decision-api "${api_major}" ""
check_endpoint_table

if [ "${failures}" -ne 0 ]; then
    printf 'contract versions: %d problem(s); the release is blocked\n' "${failures}" >&2
    exit 1
fi
printf 'contract versions: all three public contracts are documented and versioned\n'

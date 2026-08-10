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

if [ "${failures}" -ne 0 ]; then
    printf 'contract versions: %d problem(s); the release is blocked\n' "${failures}" >&2
    exit 1
fi
printf 'contract versions: all three public contracts are documented and versioned\n'

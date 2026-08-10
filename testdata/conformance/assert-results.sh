#!/usr/bin/env bash
#
# Turn the AuthZEN interop harness's output into a CI gate.
#
# The harness is not a gate on its own: its runner exits 0 whatever it found. A
# run in which every case ERRORed — because the PDP was never reachable —
# exits 0 too, so a job that trusts the exit code is green and empty forever.
# This wrapper reads the console output instead and fails unless it sees
# exactly the expected number of cases and every one of them passed.
#
# Usage: assert-results.sh <results-file> <expected-case-count>

set -euo pipefail

results="${1:?usage: assert-results.sh <results-file> <expected-case-count>}"
expected="${2:?usage: assert-results.sh <results-file> <expected-case-count>}"

if [[ ! -s "${results}" ]]; then
  echo "conformance: ${results} is empty — the harness produced no output at all" >&2
  exit 1
fi

# cli-color emits escape sequences when it thinks it has a terminal. Strip them
# so the verdict tokens are matchable either way.
plain="$(mktemp)"
trap 'rm -f "${plain}"' EXIT
sed -E $'s/\033\\[[0-9;]*[a-zA-Z]//g' "${results}" >"${plain}"

count_of() { grep -c "^$1 " "${plain}" || true; }

passed="$(count_of PASS)"
failed="$(count_of FAIL)"
errored="$(count_of ERROR)"
total=$((passed + failed + errored))

echo "conformance: ${passed} PASS, ${failed} FAIL, ${errored} ERROR (expected ${expected} cases)"

status=0
if [[ "${total}" -eq 0 ]]; then
  echo "conformance: the harness reported no cases — the gate would have been silently empty" >&2
  status=1
fi
if [[ "${total}" -ne "${expected}" ]]; then
  echo "conformance: ran ${total} cases, expected ${expected}" >&2
  echo "conformance: the profile or the pinned fixture set has moved; re-pin before changing this number" >&2
  status=1
fi
if [[ "${failed}" -ne 0 || "${errored}" -ne 0 ]]; then
  echo "conformance: ${failed} failing and ${errored} errored cases:" >&2
  grep -E "^(FAIL|ERROR) " "${plain}" >&2 || true
  status=1
fi

exit "${status}"

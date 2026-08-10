#!/usr/bin/env bash
# Render both topologies into deploy/helm/snapshots/.
#
# The snapshots are committed, and internal/release's tests read them rather
# than the chart: a Go test that shelled out to helm would be skipped wherever
# helm is missing, and a gate that skips is not a gate. The chart and the
# snapshots are held together from the other side instead — CI runs this script
# and fails on `git diff`, exactly as the console contract is pinned.
#
# Usage:
#   deploy/helm/render.sh            # render, using helm or docker
#   deploy/helm/render.sh --check    # render to a temp dir and diff
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="${repo_root}/deploy/helm/snapshots"

check=0
if [ "${1:-}" = "--check" ]; then
    check=1
    out="$(mktemp -d)"
    trap 'rm -rf "${out}"' EXIT
fi

# helm if it is installed, docker otherwise. The image tag is pinned so a
# snapshot diff means the chart changed and not that helm did.
HELM_IMAGE="${HELM_IMAGE:-alpine/helm:3.19.0}"
# `type -P` and not `command -v`: the wrapper below is itself named helm, and
# command -v would find the function and then fail to exec it.
helm_bin="$(type -P helm || true)"
helm() {
    if [ -n "${helm_bin}" ]; then
        "${helm_bin}" "$@"
    elif command -v docker >/dev/null 2>&1; then
        docker run --rm -v "${repo_root}:/repo" -w /repo "${HELM_IMAGE}" "$@"
    else
        echo "render.sh needs helm or docker" >&2
        exit 1
    fi
}

# Paths handed to helm are relative to the repository root, because inside the
# container that is the working directory.
render() {
    local name="$1" values="$2"
    helm template stamp "deploy/helm/stamp" \
        --namespace stamp \
        --values "deploy/helm/stamp/${values}" \
        > "${out}/${name}.yaml"
}

mkdir -p "${out}"
render all-in-one values-all-in-one.yaml
render split values-split.yaml

helm lint "deploy/helm/stamp" --values "deploy/helm/stamp/values-all-in-one.yaml" >/dev/null
helm lint "deploy/helm/stamp" --values "deploy/helm/stamp/values-split.yaml" >/dev/null

if [ "${check}" = "1" ]; then
    for name in all-in-one split; do
        if ! diff -u "${repo_root}/deploy/helm/snapshots/${name}.yaml" "${out}/${name}.yaml"; then
            echo "deploy/helm/snapshots/${name}.yaml is stale: run deploy/helm/render.sh" >&2
            exit 1
        fi
    done
    echo "snapshots are current"
else
    echo "rendered ${out}/all-in-one.yaml and ${out}/split.yaml"
fi

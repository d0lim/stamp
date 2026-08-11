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

# A values file the chart must refuse. The refusal is a rendering outcome like
# any other, so it is pinned like any other: the run has to fail, and the
# chart's own message is written to a snapshot internal/release reads.
#
# Only the text after the sentinel is kept. Everything before it — helm's
# wrapper, the template path, the line number — belongs to helm's version rather
# than to this chart, and pinning it would turn a helm upgrade into a diff in a
# file that is supposed to be about the chart.
render_refusal() {
    local name="$1" values="$2" err
    err="$(mktemp)"
    if helm template stamp "deploy/helm/stamp" \
        --namespace stamp \
        --values "deploy/helm/stamp/${values}" \
        >/dev/null 2>"${err}"; then
        echo "deploy/helm/stamp/${values} rendered successfully; the chart is supposed to refuse it" >&2
        rm -f "${err}"
        exit 1
    fi
    if ! grep -o 'stamp chart: .*' "${err}" > "${out}/${name}.err.txt"; then
        echo "deploy/helm/stamp/${values} failed for a reason that is not the chart's own:" >&2
        cat "${err}" >&2
        rm -f "${err}"
        exit 1
    fi
    rm -f "${err}"
}

mkdir -p "${out}"
render all-in-one values-all-in-one.yaml
render split values-split.yaml
render_refusal split-no-api values-split-no-api.yaml

helm lint "deploy/helm/stamp" --values "deploy/helm/stamp/values-all-in-one.yaml" >/dev/null
helm lint "deploy/helm/stamp" --values "deploy/helm/stamp/values-split.yaml" >/dev/null

if [ "${check}" = "1" ]; then
    for name in all-in-one.yaml split.yaml split-no-api.err.txt; do
        if ! diff -u "${repo_root}/deploy/helm/snapshots/${name}" "${out}/${name}"; then
            echo "deploy/helm/snapshots/${name} is stale: run deploy/helm/render.sh" >&2
            exit 1
        fi
    done
    echo "snapshots are current"
else
    echo "rendered ${out}/all-in-one.yaml, ${out}/split.yaml and ${out}/split-no-api.err.txt"
fi

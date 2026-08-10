#!/usr/bin/env bash
# Build the artifacts a release consists of: the chart, an SBOM, release notes
# taken from CHANGELOG.md, checksums, and the list of files to sign (R29).
#
# The workflow calls this script rather than inlining the steps, so that a
# release can be rehearsed on a laptop with no tag, no registry and no signing
# identity. The one thing that cannot be rehearsed here is the signature itself:
# cosign's keyless flow needs the workflow's OIDC identity, so this script emits
# the manifest of what is to be signed and the workflow signs it.
#
# Usage:
#   scripts/release-artifacts.sh --version 1.2.3
#   scripts/release-artifacts.sh --version 0.1.0 --unreleased      # dry run
#   scripts/release-artifacts.sh --version 1.2.3 --image ghcr.io/d0lim/stamp:1.2.3
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version=""
image=""
unreleased=0
out="${repo_root}/dist"

while [ $# -gt 0 ]; do
    case "$1" in
        --version) version="$2"; shift 2 ;;
        --image) image="$2"; shift 2 ;;
        --unreleased) unreleased=1; shift ;;
        --out) out="$2"; shift 2 ;;
        *) echo "release-artifacts: unknown argument $1" >&2; exit 2 ;;
    esac
done

if [ -z "${version}" ]; then
    echo "release-artifacts: --version is required" >&2
    exit 2
fi
# The tag may say v1.2.3; the chart and the changelog say 1.2.3.
version="${version#v}"
if ! printf '%s' "${version}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
    echo "release-artifacts: ${version} is not a semver version" >&2
    exit 2
fi

helm_bin="$(type -P helm || true)"
helm() {
    if [ -n "${helm_bin}" ]; then
        "${helm_bin}" "$@"
    else
        docker run --rm -v "${repo_root}:/repo" -w /repo "${HELM_IMAGE:-alpine/helm:3.19.0}" "$@"
    fi
}

syft_bin="$(type -P syft || true)"
syft() {
    if [ -n "${syft_bin}" ]; then
        "${syft_bin}" "$@"
    else
        docker run --rm -v "${repo_root}:/repo" -w /repo \
            -v /var/run/docker.sock:/var/run/docker.sock \
            "${SYFT_IMAGE:-anchore/syft:v1.18.1}" "$@"
    fi
}

rm -rf "${out}"
mkdir -p "${out}"
rel_out="${out#"${repo_root}"/}"

# --- release notes --------------------------------------------------------
#
# A tagged release whose version has no changelog section does not ship. The
# entry is the human half of semver and the tag is the machine half; a release
# with only the second one tells nobody what changed.
notes="${out}/RELEASE-NOTES-${version}.md"
if [ "${unreleased}" = "1" ]; then
    heading="## [Unreleased]"
else
    heading="## [${version}]"
fi
# index() and not a regex: the heading contains brackets, and a version heading
# carries a date after them, so neither an exact match nor a naive regex works.
awk -v heading="${heading}" '
    index($0, heading) == 1 { inside = 1; next }
    inside && /^## / { exit }
    inside { print }
' "${repo_root}/CHANGELOG.md" > "${notes}"

if [ ! -s "${notes}" ]; then
    echo "release-artifacts: CHANGELOG.md has no content under ${heading}" >&2
    echo "  add the section before tagging, or pass --unreleased for a dry run" >&2
    exit 1
fi

# --- chart ----------------------------------------------------------------
#
# The chart version and the application version are both the release version:
# a chart pulled at 1.2.3 installs the image tagged 1.2.3.
helm lint "deploy/helm/stamp" --values "deploy/helm/stamp/values-all-in-one.yaml"
helm lint "deploy/helm/stamp" --values "deploy/helm/stamp/values-split.yaml"
helm package "deploy/helm/stamp" \
    --version "${version}" \
    --app-version "${version}" \
    --destination "${rel_out}"

# --- SBOM -----------------------------------------------------------------
#
# Of the image when there is one, and of the source tree otherwise. The second
# form is what a dry run produces, and it is the one that can be built without
# a registry.
if [ -n "${image}" ]; then
    sbom="${rel_out}/sbom-image-${version}.spdx.json"
    syft scan "${image}" -o "spdx-json=${sbom}"
else
    sbom="${rel_out}/sbom-source-${version}.spdx.json"
    syft scan "dir:." --exclude "./console/node_modules" --exclude "./dist" \
        -o "spdx-json=${sbom}"
fi

# --- checksums and the signing manifest -----------------------------------
(
    cd "${out}"
    : > checksums.txt
    for f in *; do
        [ "${f}" = "checksums.txt" ] && continue
        [ "${f}" = "sign-manifest.txt" ] && continue
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "${f}" >> checksums.txt
        else
            shasum -a 256 "${f}" >> checksums.txt
        fi
    done
    # What the workflow signs. The image is signed by digest in the workflow —
    # it is not a file — so it is named here rather than hashed.
    : > sign-manifest.txt
    for f in *.tgz *.spdx.json checksums.txt; do
        [ -e "${f}" ] && printf 'file:%s\n' "${f}" >> sign-manifest.txt
    done
    if [ -n "${image:-}" ]; then
        printf 'image:%s\n' "${image}" >> sign-manifest.txt
    fi
)

echo
echo "release ${version} artifacts in ${out}:"
find "${out}" -maxdepth 1 -mindepth 1 -exec basename {} \; | sort | sed 's/^/  /'
echo
echo "to sign:"
sed 's/^/  /' "${out}/sign-manifest.txt"

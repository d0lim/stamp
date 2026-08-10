# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build
WORKDIR /src

# Dependencies resolve in their own layer so source edits do not re-download
# the module graph on every build.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/stamp ./cmd/stamp

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/stamp /stamp
USER nonroot:nonroot

# The three surfaces are three listeners rather than three path prefixes on
# one: the PEP surface a workload calls, the console surface an operator calls,
# and the callback surface, which is unbound unless a deployment asks for it
# because it is the one a deployment may have to expose beyond its perimeter.
EXPOSE 8080 8081

# Default to the all-in-one topology. A scaled-out deployment overrides this
# with its own --roles value; the image is identical either way.
#
# Everything else — the database, the OIDC issuer, the egress allowlist — comes
# from the environment and has no default, so a container started without them
# fails with a message naming what is missing rather than running on a guess.
ENTRYPOINT ["/stamp"]
CMD ["--roles=all"]

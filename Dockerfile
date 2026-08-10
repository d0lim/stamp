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
EXPOSE 8080

# Default to the all-in-one topology. A scaled-out deployment overrides this
# with its own --roles value; the image is identical either way.
ENTRYPOINT ["/stamp"]
CMD ["--roles=all", "--addr=:8080"]

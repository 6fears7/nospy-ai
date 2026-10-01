# nospy container image. Build with podman and keep the HEALTHCHECK (OCI format drops it):
#   podman build --format docker -t nospy:dev .
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27 AS build
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /nospy ./cmd/nospy

# distroless static: CA certificates for upstream TLS, no shell or package manager, uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
ARG REVISION=unknown
ARG SOURCE=
LABEL org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build /nospy /nospy
EXPOSE 8788
# The image has no shell or curl, so the probe is nospy itself. The chart uses exec probes instead.
HEALTHCHECK --interval=10s --timeout=3s CMD ["/nospy", "healthcheck"]
ENTRYPOINT ["/nospy", "serve"]

# Build the manager binary
FROM golang:1.24-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the Go source (relies on .dockerignore to filter)
COPY . .

# Build with version info
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a \
    -ldflags "-X main.version=${VERSION} -X main.gitCommit=${GIT_COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o manager cmd/main.go

# Download SOPS binary
FROM alpine:3.21 AS sops-downloader
ARG TARGETARCH
ARG SOPS_VERSION=3.9.2

RUN apk add --no-cache curl && \
    ARCH=$(case ${TARGETARCH} in \
        amd64) echo "amd64" ;; \
        arm64) echo "arm64" ;; \
        *) echo "amd64" ;; \
    esac) && \
    curl -fsSL "https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/sops-v${SOPS_VERSION}.linux.${ARCH}" \
        -o /sops && \
    chmod +x /sops

# Final image with SOPS
FROM alpine:3.21
WORKDIR /

# Install ca-certificates for HTTPS and age for potential direct key operations
RUN apk add --no-cache ca-certificates

COPY --from=builder /workspace/manager .
COPY --from=sops-downloader /sops /usr/local/bin/sops

# Run as non-root user
RUN adduser -D -u 65532 nonroot
USER 65532:65532

ENTRYPOINT ["/manager"]

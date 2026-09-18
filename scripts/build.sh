#!/usr/bin/env bash
set -euo pipefail

BINARY_NAME="dnsfuck"
MODULE="github.com/m5rcel-vibecodes/dnsfuck"
VERSION="${VERSION:-1.0.0}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo "dev")}"
BUILD_DATE="${BUILD_DATE:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

LDFLAGS="-s -w -X ${MODULE}/pkg/cli.Version=${VERSION} -X ${MODULE}/pkg/cli.Commit=${COMMIT} -X ${MODULE}/pkg/cli.BuildDate=${BUILD_DATE}"

echo "==> Building cross-platform release binaries for dnsfuck v${VERSION}..."
mkdir -p dist

platforms=(
    "darwin/arm64"
    "darwin/amd64"
    "linux/amd64"
    "linux/arm64"
    "windows/amd64"
    "windows/arm64"
)

for platform in "${platforms[@]}"; do
    os="${platform%/*}"
    arch="${platform#*/}"
    out="dist/${BINARY_NAME}-${os}-${arch}"
    if [ "$os" = "windows" ]; then
        out="${out}.exe"
    fi
    echo "  -> Building for ${os}/${arch}..."
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -ldflags "$LDFLAGS" -o "$out" ./cmd/dnsfuck
done

echo "==> Successfully built all binaries in dist/:"
ls -lh dist/

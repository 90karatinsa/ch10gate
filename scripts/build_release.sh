#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
mkdir -p "${DIST_DIR}"

VERSION="${VERSION:-$(git -C "${ROOT_DIR}" describe --tags --always --dirty 2>/dev/null || echo dev)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE}"

build() {
  local os="$1"
  local arch="$2"
  local output="$3"
  echo "building ${output}"
  GOOS="${os}" GOARCH="${arch}" CGO_ENABLED=0 \
    go build -ldflags "${LDFLAGS}" -o "${output}" "${ROOT_DIR}/cmd/ch10ctl"
}

build linux amd64 "${DIST_DIR}/ch10ctl_${VERSION}_linux_amd64"
build windows amd64 "${DIST_DIR}/ch10ctl_${VERSION}_windows_amd64.exe"

echo "artifacts written to ${DIST_DIR}"

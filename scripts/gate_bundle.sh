#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "fatal: required command '$1' not found" >&2
    exit 1
  fi
}

require_cmd go
require_cmd python3
require_cmd git

SHA256_CMD=""
SHA256_ARGS=()

resolve_sha256_cmd() {
  if [ -n "${SHA256_CMD}" ]; then
    return
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    SHA256_CMD="sha256sum"
    SHA256_ARGS=()
    return
  fi

  if command -v shasum >/dev/null 2>&1; then
    SHA256_CMD="shasum"
    SHA256_ARGS=(-a 256)
    return
  fi

  echo "fatal: required command 'sha256sum' or 'shasum' not found" >&2
  exit 1
}

sha256_digest() {
  resolve_sha256_cmd
  "${SHA256_CMD}" "${SHA256_ARGS[@]}" "$@"
}

sha256_file() {
  if [ "$#" -ne 1 ]; then
    echo "fatal: sha256_file expects exactly one argument" >&2
    exit 1
  fi

  sha256_digest "$1" | awk '{print $1}'
}

resolve_sha256_cmd

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/DIST"
BUNDLE_NAME="ch10gate_bundle"
BUNDLE_DIR="${DIST_DIR}/${BUNDLE_NAME}"

VERSION="${VERSION:-$(git -C "${ROOT_DIR}" describe --tags --always --dirty 2>/dev/null || echo dev)}"
BUILD_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
REVISION="$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)"

DEFAULT_SIGNING_KEY="${ROOT_DIR}/config/dev/bundle_signing/dev_signing_key.pem"
DEFAULT_SIGNING_CERT="${ROOT_DIR}/config/dev/bundle_signing/dev_signing_cert.pem"

SIGNING_KEY_PATH="${GATE_BUNDLE_SIGNING_KEY:-${DEFAULT_SIGNING_KEY}}"
SIGNING_CERT_PATH="${GATE_BUNDLE_SIGNING_CERT:-${DEFAULT_SIGNING_CERT}}"

if [ ! -f "${SIGNING_KEY_PATH}" ]; then
  echo "fatal: signing key not found at ${SIGNING_KEY_PATH}" >&2
  exit 1
fi

if [ ! -f "${SIGNING_CERT_PATH}" ]; then
  echo "fatal: signing certificate not found at ${SIGNING_CERT_PATH}" >&2
  exit 1
fi

abs_path() {
  python3 - "$1" <<'PY'
import os
import sys

print(os.path.abspath(sys.argv[1]))
PY
}

SIGNING_KEY_ABS="$(abs_path "${SIGNING_KEY_PATH}")"
SIGNING_CERT_ABS="$(abs_path "${SIGNING_CERT_PATH}")"

mkdir -p "${DIST_DIR}"
rm -rf "${BUNDLE_DIR}"
mkdir -p "${BUNDLE_DIR}"

echo "[gate-bundle] staging binaries"
BIN_DIR="${BUNDLE_DIR}/bin"
mkdir -p "${BIN_DIR}"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE}"
CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o "${BIN_DIR}/ch10ctl" "${ROOT_DIR}/cmd/ch10ctl"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "${BIN_DIR}/ch10d" "${ROOT_DIR}/cmd/ch10d"

echo "[gate-bundle] copying API spec"
mkdir -p "${BUNDLE_DIR}/api"
cp "${ROOT_DIR}/api/openapi.yaml" "${BUNDLE_DIR}/api/openapi.yaml"

echo "[gate-bundle] copying schemas, profiles, and service files"
mkdir -p "${BUNDLE_DIR}/schemas"
cp -R "${ROOT_DIR}/pkg/schemas/." "${BUNDLE_DIR}/schemas/"
cp -R "${ROOT_DIR}/profiles" "${BUNDLE_DIR}/"
cp -R "${ROOT_DIR}/deploy" "${BUNDLE_DIR}/"

echo "[gate-bundle] preparing example assets"
EXAMPLES_DIR="${BUNDLE_DIR}/examples"
mkdir -p "${EXAMPLES_DIR}/dicts"
cp "${ROOT_DIR}/examples/sample.tmats" "${EXAMPLES_DIR}/sample.tmats"
cp "${ROOT_DIR}/examples/sample.ch10" "${EXAMPLES_DIR}/sample.ch10"
cp "${ROOT_DIR}/examples/README.txt" "${EXAMPLES_DIR}/README.txt"
cp "${ROOT_DIR}/examples/dicts/"*.json "${EXAMPLES_DIR}/dicts/"

export BUNDLE_DIR VERSION BUILD_DATE REVISION BUNDLE_NAME

echo "[gate-bundle] generating documentation PDFs"
python3 - <<'PY'
import datetime
import os
from pathlib import Path

def escape(text: str) -> str:
    return text.replace('\\', r'\\').replace('(', r'\(').replace(')', r'\)')

def build_pdf(path: Path, title: str, body_lines: list[str]) -> None:
    lines = [title, ""] + body_lines
    stream_parts = ["BT", "/F1 18 Tf", "72 750 Td"]
    first = True
    for line in lines:
        safe = escape(line)
        if first:
            stream_parts.append(f"({safe}) Tj")
            first = False
        else:
            stream_parts.append("T*")
            stream_parts.append(f"({safe}) Tj")
    stream_parts.append("ET")
    stream = "\n".join(stream_parts) + "\n"
    stream_bytes = stream.encode("latin-1")

    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n",
        (f"4 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("latin-1") + stream_bytes + b"endstream\nendobj\n"),
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    ]

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)
    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("latin-1"))
    for off in offsets[1:]:
        pdf.extend(f"{off:010} 00000 n \n".encode("latin-1"))
    pdf.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("latin-1"))
    path.write_bytes(pdf)

bundle_dir = Path(os.environ["BUNDLE_DIR"])
docs_dir = bundle_dir / "docs"
docs_dir.mkdir(parents=True, exist_ok=True)
generated = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

build_pdf(
    docs_dir / "acceptance_procedure.pdf",
    "CH10 Gate Acceptance Procedure",
    [
        "Bundle generated on " + generated + ".",
        "1. Extract the ch10gate_bundle directory on the offline QA host.",
        "2. Install the service units under deploy/ as required by operations.",
        "3. Copy bin/ binaries to the execution path or service directory.",
        "4. Import profiles/ and schemas/ into the validation environment.",
        "5. Run ./bin/ch10ctl validate against the samples in examples/ to verify installation.",
        "6. Archive manifest.json and SIGNATURE.jws for delivery records.",
    ],
)

build_pdf(
    docs_dir / "eccn_enc_notice.pdf",
    "ECCN/ENC Usage Notice",
    [
        "Export Control Classification Number: EAR99 (demo bundle).",
        "This archive is provided for evaluation and QA enablement only.",
        "Do not redistribute to embargoed destinations without prior review.",
        "Contact compliance@ch10-gate.invalid for production licensing guidance.",
    ],
)
PY

TMP_LICENSE="$(mktemp)"
cleanup_license() {
  rm -f "${TMP_LICENSE}"
}
trap cleanup_license EXIT

python3 - "${TMP_LICENSE}" <<'PY'
import datetime
import hashlib
import hmac
import json
import platform
import socket
import sys
from pathlib import Path

def machine_components() -> list[str]:
    hostname = socket.gethostname().lower()
    components = [hostname]
    macs: list[str] = []
    net_dir = Path('/sys/class/net')
    if net_dir.exists():
        for iface in net_dir.iterdir():
            try:
                mac = (iface / 'address').read_text().strip().lower()
            except FileNotFoundError:
                continue
            if not mac or mac == '00:00:00:00:00:00':
                continue
            if iface.name.lower().startswith('lo'):
                continue
            macs.append(mac)
    if not macs:
        macs.append(platform.system().lower())
    components.extend(macs)
    return components

out_path = Path(sys.argv[1])
components = machine_components()
machine_hash = hashlib.sha256('|'.join(components).encode()).hexdigest()
expiry = (datetime.datetime.utcnow() + datetime.timedelta(days=365)).strftime('%Y-%m-%d')
mac = hmac.new(b'ch10gate-license-secret', digestmod=hashlib.sha256)
mac.update(machine_hash.encode())
mac.update(b'|')
mac.update(expiry.encode())
signature = mac.hexdigest()

payload = {
    'machine': machine_hash,
    'expiry': expiry,
    'signature': signature,
}
out_path.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
PY

echo "[gate-bundle] writing manifest and signature"
pushd "${BUNDLE_DIR}" >/dev/null
MANIFEST_INPUTS="$(python3 - <<'PY'
from pathlib import Path

bundle = Path('.')
paths = []
for path in bundle.rglob('*'):
    if path.is_file():
        if path.name in {"manifest.json", "SIGNATURE.jws"}:
            continue
        rel = path.relative_to(bundle)
        paths.append(rel.as_posix())
paths.sort()
print(','.join(paths))
PY
)"

if [ -z "${MANIFEST_INPUTS}" ]; then
  echo "fatal: no bundle contents found for manifest" >&2
  exit 1
fi

CH10CTL_LICENSE_PATH="${TMP_LICENSE}" "${BIN_DIR}/ch10ctl" manifest \
  --inputs "${MANIFEST_INPUTS}" \
  --out manifest.json \
  --sign \
  --key "${SIGNING_KEY_ABS}" \
  --cert "${SIGNING_CERT_ABS}" \
  --jws-out SIGNATURE.jws
popd >/dev/null

trap - EXIT
cleanup_license

echo "[gate-bundle] bundle ready at ${BUNDLE_DIR}"
echo "[gate-bundle] manifest sha256: $(sha256_file "${BUNDLE_DIR}/manifest.json")"

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
require_cmd sha256sum

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/DIST"
BUNDLE_NAME="ch10gate_bundle"
BUNDLE_DIR="${DIST_DIR}/${BUNDLE_NAME}"

VERSION="${VERSION:-$(git -C "${ROOT_DIR}" describe --tags --always --dirty 2>/dev/null || echo dev)}"
BUILD_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
REVISION="$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)"

SIGNING_SECRET="${GATE_BUNDLE_SIGNING_KEY:-ch10gate-demo-secret}"
SIGNING_KEY_ID="${GATE_BUNDLE_KEY_ID:-demo}"

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

export BUNDLE_DIR VERSION BUILD_DATE REVISION BUNDLE_NAME SIGNING_SECRET SIGNING_KEY_ID

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

echo "[gate-bundle] writing manifest"
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

bundle_dir = Path(os.environ["BUNDLE_DIR"])
manifest_path = bundle_dir / "manifest.json"
files = []
for path in sorted(bundle_dir.rglob('*')):
    if path.is_file():
        rel = path.relative_to(bundle_dir).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        info = path.stat()
        files.append({
            "path": rel,
            "size": info.st_size,
            "sha256": digest,
        })
manifest = {
    "bundle": "ch10gate",
    "name": os.environ.get("BUNDLE_NAME", "ch10gate_bundle"),
    "version": os.environ["VERSION"],
    "buildDate": os.environ["BUILD_DATE"],
    "revision": os.environ.get("REVISION", "unknown"),
    "files": files,
}
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY

echo "[gate-bundle] generating JWS signature"
python3 - <<'PY'
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path

def b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b'=')

bundle_dir = Path(os.environ["BUNDLE_DIR"])
manifest_path = bundle_dir / "manifest.json"
secret = os.environ["SIGNING_SECRET"].encode("utf-8")
key_id = os.environ["SIGNING_KEY_ID"]
manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
header = {"alg": "HS256", "typ": "JWS", "kid": key_id}
payload = {"manifest_sha256": manifest_hash, "version": os.environ["VERSION"], "generated_at": os.environ["BUILD_DATE"]}
header_b64 = b64url(json.dumps(header, separators=(',', ':')).encode('utf-8'))
payload_b64 = b64url(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
signing_input = header_b64 + b'.' + payload_b64
sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
jws = signing_input + b'.' + b64url(sig)
(bundle_dir / "SIGNATURE.jws").write_bytes(jws)
PY

echo "[gate-bundle] bundle ready at ${BUNDLE_DIR}"
echo "[gate-bundle] manifest sha256: $(sha256sum "${BUNDLE_DIR}/manifest.json" | awk '{print $1}')"

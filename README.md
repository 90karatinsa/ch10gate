# ch10gate (MVP skeleton)

Build:
  go build ./cmd/ch10ctl

Generate deterministic example capture:
  go generate ./examples

Validate example:
  ./ch10ctl validate --in examples/sample.ch10 --tmats examples/sample.tmats \
    --profile 106-15 --rules profiles/106-15/rules.json \
    --out out/diagnostics.jsonl --acceptance out/acceptance_report.json

Profiles and their default rule packs are declared in `profiles/index.json`.
Each entry points at a deterministic `rules.json` bundle and matching
`rules.json.sha256` signature so the daemon can validate that installed packs
are complete.

Manifest:
  ./ch10ctl manifest --inputs examples/sample.ch10,examples/sample.tmats --out out/manifest.json

## Release bundle

Use the gate bundle helper to build a portable delivery tree with binaries,
schemas, service definitions, docs, and sample data:

```
./scripts/gate_bundle.sh
```

Environment knobs:

* `VERSION` — override the git tag/hash embedded in the CLI binaries.
* `GATE_BUNDLE_SIGNING_KEY` — path to the RSA private key used for manifest
  signatures (default:
  `config/dev/bundle_signing/dev_signing_key.pem`).
* `GATE_BUNDLE_SIGNING_CERT` — path to the PEM encoded X.509 certificate that
  corresponds to the signing key (default:
  `config/dev/bundle_signing/dev_signing_cert.pem`).

Artifacts land in `DIST/ch10gate_bundle/`. Distribute that directory as-is for
offline QA installations.

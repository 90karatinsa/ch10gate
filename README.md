# ch10gate (MVP skeleton)

Build:
  go build ./cmd/ch10ctl

Validate example:
  ./ch10ctl validate --in examples/sample.ch10 --tmats examples/sample.tmats \
    --profile 106-15 --rules profiles/106-15/rules-min.json \
    --out out/diagnostics.jsonl --acceptance out/acceptance_report.json

Manifest:
  ./ch10ctl manifest --inputs examples/sample.ch10,examples/sample.tmats --out out/manifest.json

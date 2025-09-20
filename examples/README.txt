The files in this directory provide deterministic sample assets for local
validation and offline demonstrations.

The Chapter 10 capture is generated on demand so that consumers can reproduce it
exactly. To materialize `sample.ch10` (and refresh `sample.tmats`), run:

    go generate ./examples

This invokes the generator at `examples/cmd/generate_samples`, which uses the
`internal/ch10` and `internal/tmats` packages to emit a minimal Chapter 10
capture alongside a matching TMATS document. Both files are built from fixed
timestamps and payloads so their digests remain stable across runs.

The Chapter 10 artifact is intentionally ignored by git; rerun the generator to
recreate it whenever needed. The bundle script (`scripts/gate_bundle.sh`)
invokes the generator automatically and packages the resulting assets along
with the channel dictionaries under `dicts/`.

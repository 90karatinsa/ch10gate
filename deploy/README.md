# Deployment Key Management

The gate bundle release tooling requires an RSA private key and matching X.509
certificate to sign the generated manifest. Production keys **must** be stored in
managed secrets infrastructure (for example an HSM, Vault, or the CI secret
store) and never committed to this repository. The bundle helper
(`scripts/gate_bundle.sh`) now enforces this by requiring the
`GATE_BUNDLE_SIGNING_KEY` and `GATE_BUNDLE_SIGNING_CERT` environment variables to
point at externally provisioned files before it will run.

For day-to-day development we recommend the following workflow:

1. Generate throwaway dev credentials outside of the repository (for example
   using `openssl req -x509` or the helper snippets in integration tests).
2. Store the resulting `*.pem` files in a location managed by your shell profile
   or secret manager, and export the environment variables to point at those
   paths when invoking `scripts/gate_bundle.sh`.
3. Rotate the dev credentials frequently; they are only intended for local smoke
   testing and should never be used for production deliveries.

In CI the smoke jobs create ephemeral signing material at runtime so test
artifacts can be signed without exposing long-lived keys. Production pipelines
should follow the same model and mount the signing key and certificate at
build-time via secure secrets injection.

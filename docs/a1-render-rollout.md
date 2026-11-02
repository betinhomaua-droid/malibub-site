# MALIBUB A1/PAdES production rollout (not yet enabled)

The isolated signer is a foundation, **not** an approved clinical release flow.

## Secure Render configuration

- Keep `MALIBUB_A1_SIGNING_ENABLED` absent or `false` until the complete
  authorization, trust and immutable-storage integration is reviewed.
- Provision the A1 certificate **only as a protected secret file**, not in
  GitHub, the source tree, an environment variable containing base64 bytes,
  or a public upload endpoint. The absolute file path is supplied through
  `MALIBUB_A1_PFX_PATH`.
- Store the PFX password separately as a Render secret environment variable
  `MALIBUB_A1_PFX_PASSWORD`. Limit administrative access and rotate after
  suspected exposure. Never include credentials in logs, traces or tickets.
- Confirm the Render plan supports secret files and the file is readable only
  by the application runtime. If it does not, stop: do not substitute a
  repository file or unencrypted persistent disk.
- Confirm the A1 identity, validity period and signer authorization before
  allowing any clinical signature. Never sign automatically on PDF preview.

## Release prerequisites

1. The responsible radiologist explicitly approves the finalized report.
2. The signed bytes are persisted in private object storage, with immutable
   version reference, SHA-256 digest and audited signer/report association.
3. The exact signed bytes are served to the clinic without regeneration.
4. A configured ICP-Brasil trust store, certificate path, revocation checks
   (OCSP/CRL), and timestamp policy are reviewed and tested with non-patient
   samples. A basic `verify_embedded_signature` result is **not** enough.
5. Failure to sign, validate, or store leaves the report unreleased; never
   fall back to distributing a PDF as if it were digitally signed.
6. End-to-end tests cover authorized signer, unauthorized roles, failed
   password, expired/revoked certificate, retry/idempotency, storage failure,
   and post-signature PDF mutation.

No real certificate, passphrase or patient document is required in GitHub CI.

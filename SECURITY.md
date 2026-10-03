# Security policy

## Reporting

Open a private security advisory on the GitHub repository, or email the
maintainer (see `Cargo.toml` authors). Do not file public issues for
trust-model bypasses — e.g. any path where a non-owner produces a
valid artifact, or a revoked node keeps serving.

## Scope

In scope:

- Forgery: certs, plans, revocations, or serving records that verify
  without the correct key.
- Enrollment bypass: acceptance without valid PoP, expired certs
  admitted, revoked serials/nodes admitted.
- Plan-integrity failures: hash mismatch accepted, non-owner
  signatures accepted, coverage gaps/overlaps accepted.
- Attestation forgery: a node claiming another's shard, records bound
  to foreign plans, unsigned records accepted.
- Determinism breaks: same `(model, members)` producing different
  layouts on different runs — that breaks the no-coordinator property.

Out of scope:

- Owner-key custody — the crate can't protect a key stored on a
  compromised machine.
- Byzantine compute correctness — attestation proves *who*, not
  *that the math was right*.
- Transport confidentiality and node discovery — the wire is the
  integrator's.

## Guidance

- Generate the owner key on the most protected machine you own;
  consider hardware custody for it.
- Reissue certs on a schedule (short `expires_at`) — a long-lived cert
  is a long-lived theft target.
- Rotate member serials on a cadence; serial revocation exists for
  routine rotation, `ban_node` for compromise.
- Verify `SessionAttestation` after every pooled run — the artifact
  is only worth what you check.
- Treat plan epoch as fencing: after any roster change, discard plans
  minted before it.

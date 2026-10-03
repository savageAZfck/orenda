# Threat model

orenda's trust model is the inverse of the cloud's: the owner key is
the only root, members are machines the owner controls, and every
decision the mesh makes is a verifiable artifact. The adversary is
anyone who is not the owner — a rogue node, a network adversary, a
revoked box that won't stay dead, or a foreign federation.

## What it defends against

- **Unowned membership.** Enrollment requires an owner-signed cert
  *and* proof of possession of the node key — a stolen cert file alone
  can't enroll a foreign box, and a foreign owner's cert is rejected
  at the door.
- **Plan forgery.** Every plan is owner-signed and hash-bound to
  model + roster + epoch + layout. A node can't invent an assignment,
  inflate its shard, or graft itself into a plan.
- **Coordinator capture.** There is no coordinator — placement is a
  pure function of signed membership. Compromising "the leader"
  compromises nothing; the same inputs yield the same plan everywhere.
- **Zombie members.** Revocation is owner-signed and total: serial
  revocation kills one cert, node ban kills the machine. Plans naming
  a revoked node fail verification the moment the CRL lands.
- **Credit fraud.** Serving attestations bind `node → shard → plan
  hash` under the node's signature — a node can't claim work done on
  a shard it doesn't own or under a plan that isn't this one.
- **Replayed heartbeats.** Heartbeat messages embed the serial and
  timestamp — a replayed signature only re-proves a moment that
  already passed.

## What it does not defend against

- **Owner key compromise.** Whoever holds the owner key *is* the
  federation — custody (hardware key, airgap, split custody) is the
  operator's burden, not the crate's.
- **Malicious-but-certified nodes.** An owner-certified node that
  computes garbage produces a valid attestation of garbage —
  provenance proves *who* computed, not *correctly*. Pair with
  verifier spot-checks or redundant shards for Byzantine guarantees.
- **Transport security.** orenda signs artifacts; it does not encrypt
  the wire — shard and KV traffic need channel protection the
  integrator provides.
- **Availability.** A mesh of owned boxes can lose members; liveness
  gates planning, but a plan in flight can still lose a node — the
  runtime must re-plan, not this crate.

## Design posture

No silent authority, no unverifiable claims, no coordinator to
capture. Every statement the mesh makes — membership, layout, work —
is a signature someone can check offline.

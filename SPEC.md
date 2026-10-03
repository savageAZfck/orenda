# orenda specification

Federated cognition pooling under an owner-held trust root.

## Trust model

One Ed25519 owner key is the root of all authority. Every artifact —
member certificate, placement plan, revocation — is signed by it or
verifies against it. There is no other authority in the system.

## Artifacts

### MemberCert
`{serial, node, capability{accel, free_bytes, bandwidth_mbps,
tok_per_sec}, issued_at, expires_at, owner, signature}` — the owner
signs the canonical body (all fields minus `signature`). Verifies
under the owner key when unexpired.

### Enrollment proof
`orenda-enroll:<serial>:<node>` signed by the node key the cert names.
`enroll` requires: cert verifies under the owner key, unexpired,
unrevoked, and PoP signature valid. Any failure rejects — enrollment
fails closed.

### Revocation
`{serial, node, ts, owner, signature}` — `serial > 0` revokes that
cert (re-enrollment under a new serial is permitted); `serial == 0`
bans the node — all current and future certs void.

### Plan
`{epoch, model{layers, weights_bytes, kv_bytes_per_token,
context_tokens}, members[], shards[], plan_hash, owner, signature}`.
`plan_hash = sha256(canonical unsigned body)` binds model + roster +
epoch + layout.

### ServedRecord / SessionAttestation
`{plan_hash, node, shard_index, tokens, signature}` — node-signed.
Aggregate verification: plan verifies; every record is node-signed,
bound to the plan hash, and names a shard index whose `node` matches
the signer.

## Deterministic placement

`place(model, members)` is pure:

1. Rank members by `score = free_bytes/1MiB + 64·tok_per_sec +
   1024·accel_bonus` (NE=3, GPU=2, else=1); ties → node id ascending.
2. Allocate `layers` by largest remainder proportional to
   `free_bytes`.
3. Contiguous layer ranges in rank order; the weakest-ranked node
   takes `Role::Draft` (when >1 member), all others `Verify`.
4. `kv_share = free_bytes/total_free`; `weights_share =
   alloc/layers`.

Same inputs → same plan, on every node, no coordinator.

## Plan verification

`plan.verify(fed, at)` requires, in order: owner matches the
federation root; `plan_hash` recomputes; owner signature valid; every
shard node is a member unexpired at `at`; shard layer ranges partition
`[0, model.layers)` contiguously with no gaps or overlaps.

## Epochs and liveness

`fed.epoch` bumps on every roster change (enroll, revoke). Plans carry
the epoch at plan time — a plan remains valid while its named nodes
stay live; the revocation path kills it via the member check.
Heartbeats (`orenda-heartbeat:<serial>:<ts>`) refresh `last_seen`;
`live_members(at, ttl)` gates placement.

## Invariants

- Only the owner key produces valid certs, plans, and revocations.
- Enrollment, plans, and attestations all fail closed.
- A node can never claim a shard that isn't its own — attestation
  binds shard index to node identity.
- Placement needs no network and no leader — it is a function.

## Non-goals

- Transport: orenda defines *who may serve what and how it's proven*,
  not the wire. Carrying shards and KV over your links is the
  integrator's.
- Scheduling/queueing: placement is layout, not a runtime.
- Weight distribution: `manitou` manifests prove each node loaded the
  right bytes; moving them is out of scope.

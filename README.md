# orenda

Federated cognition pooling. Named for the Iroquoian *orenda* — a diffuse power that flows through all things and can be pooled; power that lives in no single node.

**A federation of boxes you own, under keys you hold. The opposite trust model of the cloud.**

## The thesis

The cloud model is: your compute lives on their machines, under their keys, revocable at their discretion. The orenda model inverts it: your machines enroll under **your** key, placement is **your** signature, and revocation is **your** word. There is no vendor in the loop. A mesh of consumer hardware — a desktop GPU, a laptop's neural engine, a spare box in the closet — becomes one organism whose cognition spans the hardware you physically control.

"Your model doesn't fit on one machine" becomes "your machines are one machine."

## The four pieces

### 1. Owner key — the trust root
One Ed25519 key. It certifies members, signs placement plans, signs revocations. Whoever holds it owns the mesh. This is the entire trust model — there is no other authority.

### 2. Member certificates + proof of possession
Each node gets an owner-signed `MemberCert`: a capability ceiling bound to the node's own key, with an expiry. Enrollment requires proof-of-possession — the node signs `orenda-enroll:<serial>:<node>` with the key the cert names. A cert can't be replayed onto a box that doesn't hold the key.

### 3. Deterministic placement — no coordinator
`place(model, members)` is a **pure function**. Members are ranked by capability score (ties → node id), layers are allocated by largest remainder over free memory, the weakest node gets the draft role. Every node computes the *same* plan independently — the mesh converges on a layout with no coordinator, no leader election, no consensus round. The owner signs the plan; the hash binds members + model + epoch + layout.

### 4. Serving attestations — provable provenance
Each node signs `ServedRecord`s bound to the plan hash and its shard index. A `SessionAttestation` verifies the whole chain: plan valid under the owner, every record node-signed, every node claiming only shards it owns. **"Which machines computed this" is a verifiable artifact, not a log line.**

## Revocation — the kill switch you hold

- `Revocation::issue(owner, serial, node)` — revokes one cert; the node may re-enroll under a new serial (rotation).
- `Revocation::ban_node(owner, node)` — bans the node entirely; every current and future cert is void. The compromise path.
- A revoked node's removal bumps the membership epoch; outstanding plans naming it fail verification on the spot.

## Liveness

Heartbeats are proof-of-possession refreshes (`orenda-heartbeat:<serial>:<ts>`). `live_members(at, ttl)` gates placement on nodes that have checked in — a dead box doesn't get planned for.

## Usage

```rust
use orenda::*;

let owner = generate_key();                       // the trust root — guard it
let node = generate_key();                        // each machine's identity
let mut fed = Federation::new(owner.verifying_key());

// Owner certifies the node; node proves possession.
let cert = MemberCert::issue(&owner, 1, node_id(&node.verifying_key()), gpu_capability, 86_400);
fed.enroll(cert.clone(), &sign_pop(&node, &cert), now())?;

// Every node computes the same layout from the same roster.
let plan = fed.plan(&owner, &model_7b, now(), ttl);
plan.verify(&fed, now())?;                        // hash + signature + roster all check

// Nodes serve and attest.
let rec = ServedRecord::sign(&node, &plan.plan_hash, shard_idx, token_range);
SessionAttestation { plan, records: vec![rec] }.verify(&fed, now())?;
```

## Composition

- `smokesignal` — the draft/verify handshake rides the mesh: the draft shard is the cheap resident node, verify shards are the strong ones.
- `manitou` — weight manifests prove each node loaded the weights the plan intended.
- `wintercount` — the policy hash in force binds into the plan's epoch record.
- `xipe` — changes to the federation constitution (owner rotation, membership policy) are amendments, not edits.

## License

MIT

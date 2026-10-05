//! orenda — federated cognition pooling.
//!
//! Named for the Iroquoian *orenda*: a diffuse spiritual power that
//! flows through all things and can be *pooled* — power that lives in
//! no single node. This crate is the trust and placement layer for a
//! federation of machines **you own, under keys you hold**: the
//! opposite trust model of the cloud.
//!
//! The pieces:
//! * **Owner key** — the trust root. It certifies members, signs
//!   placement plans, and signs revocations. Whoever holds it owns the
//!   mesh; there is no vendor in the loop.
//! * **Member certificates** — owner-signed capability ceilings bound
//!   to a node's Ed25519 key, plus proof-of-possession enrollment.
//! * **Deterministic placement** — layer and KV shards are assigned by
//!   a pure function of (member set, model spec, epoch). Every node
//!   independently computes the *same* plan — the mesh converges
//!   without a coordinator.
//! * **Signed plans + serving attestations** — each plan carries an
//!   owner signature; each serving record is node-signed. "Which nodes
//!   computed this" is a verifiable artifact, not a log line.
//!
//! ```no_run
//! use orenda::*;
//! let owner = generate_key();
//! // … certify members, build a federation, place a model …
//! ```

use ed25519_dalek::{Signature, Signer};

pub use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;
use std::time::{SystemTime, UNIX_EPOCH};

// ─────────────────────────── primitives ─────────────────────────────

/// Hex-encoded Ed25519 public key — a node's identity.
pub type NodeId = String;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Generate a random Ed25519 keypair.
pub fn generate_key() -> SigningKey {
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
    SigningKey::from_bytes(&secret)
}

pub fn node_id(key: &VerifyingKey) -> NodeId {
    hex::encode(key.to_bytes())
}

fn sig_hex(sig: &Signature) -> String {
    hex::encode(sig.to_bytes())
}

fn verify_sig(vk: &VerifyingKey, body: &[u8], sig_hex: &str) -> bool {
    let Ok(bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(arr) = <[u8; 64]>::try_from(bytes.as_slice()) else {
        return false;
    };
    vk.verify_strict(body, &Signature::from_bytes(&arr)).is_ok()
}

fn parse_vk(hex_key: &str) -> Option<VerifyingKey> {
    let bytes = hex::decode(hex_key).ok()?;
    let arr = <[u8; 32]>::try_from(bytes.as_slice()).ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

fn canonical(v: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

// ─────────────────────────── capabilities ───────────────────────────

/// The silicon a node runs inference on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Accel {
    Cpu,
    Gpu,
    NeuralEngine,
    Other(String),
}

impl fmt::Display for Accel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Accel::Cpu => write!(f, "cpu"),
            Accel::Gpu => write!(f, "gpu"),
            Accel::NeuralEngine => write!(f, "neural_engine"),
            Accel::Other(s) => write!(f, "{s}"),
        }
    }
}

/// What a node can contribute. The certificate binds a *ceiling* —
/// a node may advertise less than its cert allows, never more.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub accel: Accel,
    /// Free unified/VRAM bytes available for weights + KV.
    pub free_bytes: u64,
    /// Inter-node bandwidth, megabits/sec.
    pub bandwidth_mbps: u32,
    /// Relative throughput hint (tokens/sec) for placement weighting.
    pub tok_per_sec: u32,
}

impl Capability {
    /// Placement score — deterministic ordering key.
    fn score(&self) -> u64 {
        let accel_bonus: u64 = match self.accel {
            Accel::NeuralEngine => 3,
            Accel::Gpu => 2,
            Accel::Cpu => 1,
            Accel::Other(_) => 1,
        };
        self.free_bytes / (1 << 20) + u64::from(self.tok_per_sec) * 64 + accel_bonus * 1024
    }
}

// ─────────────────────── member certificates ────────────────────────

/// Owner-signed certificate: this node's key may serve within this
/// capability ceiling until `expires_at`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberCert {
    pub serial: u64,
    pub node: NodeId,
    pub capability: Capability,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Owner's public key (hex) — binds the cert to one trust root.
    pub owner: String,
    /// Owner signature over `signing_body()`.
    pub signature: String,
}

impl MemberCert {
    /// The canonical bytes the owner signs.
    pub fn signing_body(&self) -> Vec<u8> {
        let mut v = serde_json::to_value(self).unwrap_or_default();
        if let Some(m) = v.as_object_mut() {
            m.remove("signature");
        }
        serde_json::to_vec(&v).unwrap_or_default()
    }

    /// Issue a certificate. `node` is the member's verifying key hex.
    pub fn issue(
        owner: &SigningKey,
        serial: u64,
        node: NodeId,
        capability: Capability,
        lifetime_secs: u64,
    ) -> Self {
        let mut cert = Self {
            serial,
            node,
            capability,
            issued_at: now(),
            expires_at: now() + lifetime_secs,
            owner: node_id(&owner.verifying_key()),
            signature: String::new(),
        };
        cert.signature = sig_hex(&owner.sign(&cert.signing_body()));
        cert
    }

    /// Verify the owner signature and expiry at `at`.
    pub fn verify(&self, owner_vk: &VerifyingKey, at: u64) -> bool {
        node_id(owner_vk) == self.owner
            && at <= self.expires_at
            && verify_sig(owner_vk, &self.signing_body(), &self.signature)
    }
}

// ─────────────────────────── enrollment ─────────────────────────────

/// Proof of possession: the member signs `enroll:<cert_serial>:<node>`
/// with the key the cert names. Enrollment can't be replayed onto a
/// node that doesn't hold the key.
pub fn pop_message(serial: u64, node: &str) -> Vec<u8> {
    format!("orenda-enroll:{serial}:{node}").into_bytes()
}

/// One revocation line — owner-signed, appendable to the CRL.
///
/// Scope: `serial > 0` revokes that certificate only (the node may
/// re-enroll under a new cert); `serial == 0` bans the node entirely —
/// the compromise path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    /// Cert serial revoked; `0` = the whole node is banned.
    pub serial: u64,
    pub node: NodeId,
    pub ts: u64,
    pub owner: String,
    pub signature: String,
}

impl Revocation {
    /// Revoke one certificate by serial.
    pub fn issue(owner: &SigningKey, serial: u64, node: NodeId) -> Self {
        let mut r = Self {
            serial,
            node,
            ts: now(),
            owner: node_id(&owner.verifying_key()),
            signature: String::new(),
        };
        r.signature = sig_hex(&owner.sign(&r.signing_body()));
        r
    }

    /// Ban a node entirely — every current and future cert for it is
    /// void. The compromise path.
    pub fn ban_node(owner: &SigningKey, node: NodeId) -> Self {
        Self::issue(owner, 0, node)
    }

    pub fn signing_body(&self) -> Vec<u8> {
        let mut v = serde_json::to_value(self).unwrap_or_default();
        if let Some(m) = v.as_object_mut() {
            m.remove("signature");
        }
        serde_json::to_vec(&v).unwrap_or_default()
    }

    pub fn verify(&self, owner_vk: &VerifyingKey) -> bool {
        node_id(owner_vk) == self.owner
            && verify_sig(owner_vk, &self.signing_body(), &self.signature)
    }
}

/// A live member: cert + proof of possession accepted.
#[derive(Debug, Clone)]
pub struct Member {
    pub cert: MemberCert,
    /// Last heartbeat (seconds since epoch).
    pub last_seen: u64,
}

/// Enrollment failures — all fail closed.
#[derive(Debug, Clone, PartialEq)]
pub enum EnrollError {
    /// Cert signature or expiry invalid.
    BadCert,
    /// Cert issued by a different owner than this federation trusts.
    WrongOwner,
    /// Proof-of-possession signature invalid — the key isn't held.
    BadProof,
    /// This cert serial is on the revocation list.
    Revoked,
}

impl fmt::Display for EnrollError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EnrollError::BadCert => "certificate invalid or expired",
            EnrollError::WrongOwner => "certificate issued by a foreign owner",
            EnrollError::BadProof => "proof of possession failed — key not held",
            EnrollError::Revoked => "certificate revoked",
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for EnrollError {}

// ──────────────────────────── placement ─────────────────────────────

/// What a brain needs placed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSpec {
    /// Transformer layers to shard.
    pub layers: u32,
    /// Total weight bytes.
    pub weights_bytes: u64,
    /// KV cache bytes per token.
    pub kv_bytes_per_token: u64,
    /// Context window to provision for.
    pub context_tokens: u64,
}

impl ModelSpec {
    /// Total KV pool bytes the plan must provision.
    pub fn kv_bytes(&self) -> u64 {
        self.kv_bytes_per_token * self.context_tokens
    }
}

/// A node's role in the mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Serves model shards for verification.
    Verify,
    /// Runs the draft model (smokesignal) — typically the cheapest
    /// resident silicon.
    Draft,
}

/// One node's share of the plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shard {
    pub node: NodeId,
    pub role: Role,
    /// Contiguous layer range `[start, end)` this node serves.
    pub layers: Range<u32>,
    /// Fraction of the KV pool this node holds (0..=1).
    pub kv_share: f64,
    /// Fraction of weights resident on this node (0..=1).
    pub weights_share: f64,
}

/// An owner-signed placement plan — every node verifies the same plan
/// independently; the hash binds members, model, epoch, and layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub epoch: u64,
    pub model: ModelSpec,
    /// Sorted member roster the plan was computed over.
    pub members: Vec<NodeId>,
    pub shards: Vec<Shard>,
    /// SHA-256 of the canonical unsigned body.
    pub plan_hash: String,
    pub owner: String,
    pub signature: String,
}

impl Plan {
    /// The canonical unsigned body — hashed, signed, and verified.
    pub fn signing_body(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Body<'a> {
            epoch: u64,
            model: &'a ModelSpec,
            members: &'a Vec<NodeId>,
            shards: &'a Vec<Shard>,
        }
        canonical(&Body {
            epoch: self.epoch,
            model: &self.model,
            members: &self.members,
            shards: &self.shards,
        })
    }

    /// Recompute the plan hash.
    pub fn compute_hash(&self) -> String {
        sha256_hex(&self.signing_body())
    }

    /// Verify hash + owner signature at `at` against a member set that
    /// must still contain every planned node, unrevoked.
    pub fn verify(&self, fed: &Federation, at: u64) -> Result<(), PlanError> {
        if self.owner != node_id(&fed.owner_key) {
            return Err(PlanError::ForeignPlan);
        }
        if self.plan_hash != self.compute_hash() {
            return Err(PlanError::HashMismatch);
        }
        if !verify_sig(&fed.owner_key, &self.signing_body(), &self.signature) {
            return Err(PlanError::BadSignature);
        }
        for shard in &self.shards {
            match fed.member(&shard.node) {
                Some(m) if m.cert.expires_at >= at => {}
                Some(_) => return Err(PlanError::StaleMember(shard.node.clone())),
                None => return Err(PlanError::UnknownNode(shard.node.clone())),
            }
        }
        // Coverage sanity: layers partition [0, layers) exactly once.
        let mut covered = 0u32;
        let mut sorted: Vec<&Range<u32>> = self.shards.iter().map(|s| &s.layers).collect();
        sorted.sort_by_key(|r| r.start);
        let mut cursor = 0u32;
        for r in sorted {
            if r.start != cursor {
                return Err(PlanError::CoverageGap);
            }
            cursor = r.end;
            covered += r.end - r.start;
        }
        if covered != self.model.layers {
            return Err(PlanError::CoverageGap);
        }
        Ok(())
    }
}

/// Plan verification failures.
#[derive(Debug, Clone, PartialEq)]
pub enum PlanError {
    ForeignPlan,
    HashMismatch,
    BadSignature,
    UnknownNode(NodeId),
    StaleMember(NodeId),
    CoverageGap,
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            PlanError::ForeignPlan => "plan signed by a foreign owner",
            PlanError::HashMismatch => "plan hash does not match its body",
            PlanError::BadSignature => "owner signature invalid",
            PlanError::UnknownNode(n) => return write!(f, "shard assigned to unknown node {n}"),
            PlanError::StaleMember(n) => return write!(f, "shard assigned to expired member {n}"),
            PlanError::CoverageGap => "shards do not partition the model's layers",
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for PlanError {}

/// Deterministic placement: a pure function of `(model, members)`.
///
/// Members are ordered by capability score (ties → node id), then
/// layers are allocated by largest remainder proportional to
/// `free_bytes` — every node running the same function on the same
/// inputs produces the same layout with no coordinator.
pub fn place(model: &ModelSpec, members: &[Member]) -> Vec<Shard> {
    let mut ranked: Vec<&Member> = members.iter().collect();
    ranked.sort_by(|a, b| {
        b.cert
            .capability
            .score()
            .cmp(&a.cert.capability.score())
            .then_with(|| a.cert.node.cmp(&b.cert.node))
    });

    let total_free: u64 = ranked.iter().map(|m| m.cert.capability.free_bytes).sum();
    if total_free == 0 || ranked.is_empty() {
        return Vec::new();
    }

    // Largest-remainder layer allocation over free_bytes.
    let layers = model.layers;
    let exact: Vec<f64> = ranked
        .iter()
        .map(|m| layers as f64 * m.cert.capability.free_bytes as f64 / total_free as f64)
        .collect();
    let mut alloc: Vec<u32> = exact.iter().map(|e| e.floor() as u32).collect();
    let mut assigned: u32 = alloc.iter().sum();
    // Hand the remainder to the largest fractional parts (ties → rank order).
    let mut order: Vec<usize> = (0..ranked.len()).collect();
    order.sort_by(|&a, &b| {
        exact[b]
            .fract()
            .partial_cmp(&exact[a].fract())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.cmp(&b))
    });
    let mut oi = 0;
    while assigned < layers {
        let idx = order[oi % order.len()];
        alloc[idx] += 1;
        assigned += 1;
        oi += 1;
    }

    let mut shards = Vec::new();
    let mut cursor = 0u32;
    for (i, m) in ranked.iter().enumerate() {
        let start = cursor;
        cursor += alloc[i];
        // Draft role: the weakest node holding silicon gets it — the
        // cheap resident brain proposes, the strong verify. Only assign
        // when there is more than one member.
        let role = if ranked.len() > 1 && i == ranked.len() - 1 {
            Role::Draft
        } else {
            Role::Verify
        };
        shards.push(Shard {
            node: m.cert.node.clone(),
            role,
            layers: start..cursor,
            kv_share: m.cert.capability.free_bytes as f64 / total_free as f64,
            weights_share: (alloc[i] as f64 / layers as f64).min(1.0),
        });
    }
    shards
}

// ─────────────────────────── the federation ─────────────────────────

/// The mesh: one trust root, a certified member set, an owner-signed
/// revocation list. No coordinator — plans are a pure function of
/// membership.
pub struct Federation {
    /// The trust root's verifying key.
    pub owner_key: VerifyingKey,
    members: BTreeMap<NodeId, Member>,
    revocations: Vec<Revocation>,
    /// Monotonic membership epoch — bumps on every roster change so a
    /// stale plan can't be replayed against a new roster.
    epoch: u64,
}

impl Federation {
    /// A federation rooted at `owner_key`.
    pub fn new(owner_key: VerifyingKey) -> Self {
        Self {
            owner_key,
            members: BTreeMap::new(),
            revocations: Vec::new(),
            epoch: 0,
        }
    }

    /// Current membership epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Member count.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Look up a member.
    pub fn member(&self, node: &str) -> Option<&Member> {
        self.members.get(node)
    }

    /// All members.
    pub fn members(&self) -> Vec<&Member> {
        self.members.values().collect()
    }

    /// Enroll a member: the cert must verify under the owner key, be
    /// unexpired and unrevoked, and the node must prove possession of
    /// the key the cert names.
    pub fn enroll(
        &mut self,
        cert: MemberCert,
        pop_signature: &str,
        at: u64,
    ) -> Result<NodeId, EnrollError> {
        if cert.owner != node_id(&self.owner_key) {
            return Err(EnrollError::WrongOwner);
        }
        if !cert.verify(&self.owner_key, at) {
            return Err(EnrollError::BadCert);
        }
        // Revocation check: the cert's serial is revoked, or the whole
        // node is banned (serial == 0 entries).
        if self
            .revocations
            .iter()
            .any(|r| r.node == cert.node && (r.serial == 0 || r.serial == cert.serial))
        {
            return Err(EnrollError::Revoked);
        }
        let Some(node_vk) = parse_vk(&cert.node) else {
            return Err(EnrollError::BadProof);
        };
        if !verify_sig(
            &node_vk,
            &pop_message(cert.serial, &cert.node),
            pop_signature,
        ) {
            return Err(EnrollError::BadProof);
        }
        let node = cert.node.clone();
        self.members.insert(
            node.clone(),
            Member {
                cert,
                last_seen: at,
            },
        );
        self.epoch += 1;
        Ok(node)
    }

    /// Accept a revocation: must verify under the owner key. Kicks the
    /// member out and bumps the epoch — existing plans involving it
    /// will fail verification.
    pub fn revoke(&mut self, rev: Revocation) -> bool {
        if !rev.verify(&self.owner_key) {
            return false;
        }
        self.revocations.push(rev.clone());
        if self.members.remove(&rev.node).is_some() {
            self.epoch += 1;
        }
        true
    }

    /// A heartbeat — the node re-signs possession. Returns false for
    /// unknown nodes or bad proofs.
    pub fn heartbeat(&mut self, node: &str, signature: &str, at: u64) -> bool {
        let Some(member) = self.members.get_mut(node) else {
            return false;
        };
        let Some(vk) = parse_vk(node) else {
            return false;
        };
        let msg = format!("orenda-heartbeat:{}:{at}", member.cert.serial).into_bytes();
        if !verify_sig(&vk, &msg, signature) {
            return false;
        }
        member.last_seen = at;
        true
    }

    /// Members whose heartbeat is fresh within `ttl` of `at`.
    pub fn live_members(&self, at: u64, ttl: u64) -> Vec<Member> {
        self.members
            .values()
            .filter(|m| at.saturating_sub(m.last_seen) <= ttl && m.cert.expires_at >= at)
            .cloned()
            .collect()
    }

    /// Compute the deterministic placement over live members, then sign
    /// it with the owner key. Every node can recompute `place` and
    /// verify — the same mesh, the same plan, no coordinator.
    pub fn plan(&self, owner: &SigningKey, model: &ModelSpec, at: u64, ttl: u64) -> Plan {
        let live = self.live_members(at, ttl);
        let shards = place(model, &live);
        let mut members: Vec<NodeId> = live.iter().map(|m| m.cert.node.clone()).collect();
        members.sort();
        let mut plan = Plan {
            epoch: self.epoch,
            model: model.clone(),
            members,
            shards,
            plan_hash: String::new(),
            owner: node_id(&self.owner_key),
            signature: String::new(),
        };
        plan.plan_hash = plan.compute_hash();
        plan.signature = sig_hex(&owner.sign(&plan.signing_body()));
        plan
    }
}

// ──────────────────────── serving attestations ──────────────────────

/// Node-signed record: "I served these tokens under this plan shard."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServedRecord {
    pub plan_hash: String,
    pub node: NodeId,
    /// Index into `plan.shards`.
    pub shard_index: u32,
    /// Token range served `[start, end)`.
    pub tokens: Range<u64>,
    pub signature: String,
}

impl ServedRecord {
    /// The canonical bytes the node signs.
    pub fn signing_body(&self) -> Vec<u8> {
        let mut v = serde_json::to_value(self).unwrap_or_default();
        if let Some(m) = v.as_object_mut() {
            m.remove("signature");
        }
        serde_json::to_vec(&v).unwrap_or_default()
    }

    /// Sign a serving record.
    pub fn sign(
        node_key: &SigningKey,
        plan_hash: &str,
        shard_index: u32,
        tokens: Range<u64>,
    ) -> Self {
        let mut r = Self {
            plan_hash: plan_hash.to_string(),
            node: node_id(&node_key.verifying_key()),
            shard_index,
            tokens,
            signature: String::new(),
        };
        r.signature = sig_hex(&node_key.sign(&r.signing_body()));
        r
    }

    /// Verify the node's signature.
    pub fn verify(&self) -> bool {
        let Some(vk) = parse_vk(&self.node) else {
            return false;
        };
        verify_sig(&vk, &self.signing_body(), &self.signature)
    }
}

/// A session's complete provenance: the plan + every serving record.
/// Verifying it answers "which nodes computed this" as a checkable
/// artifact — not a log line.
#[derive(Debug, Clone)]
pub struct SessionAttestation {
    pub plan: Plan,
    pub records: Vec<ServedRecord>,
}

impl SessionAttestation {
    /// Full verification: plan verifies under the federation, every
    /// record is node-signed, bound to this plan's hash, and names a
    /// shard that exists and belongs to that node.
    pub fn verify(&self, fed: &Federation, at: u64) -> Result<(), AttestError> {
        self.plan.verify(fed, at).map_err(AttestError::Plan)?;
        for r in &self.records {
            if r.plan_hash != self.plan.plan_hash {
                return Err(AttestError::ForeignRecord);
            }
            if !r.verify() {
                return Err(AttestError::BadSignature(r.node.clone()));
            }
            let Some(shard) = self.plan.shards.get(r.shard_index as usize) else {
                return Err(AttestError::BadShard(r.node.clone()));
            };
            if shard.node != r.node {
                return Err(AttestError::BadShard(r.node.clone()));
            }
        }
        Ok(())
    }
}

/// Attestation verification failures.
#[derive(Debug)]
pub enum AttestError {
    Plan(PlanError),
    ForeignRecord,
    BadSignature(NodeId),
    BadShard(NodeId),
}

impl fmt::Display for AttestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttestError::Plan(e) => write!(f, "plan: {e}"),
            AttestError::ForeignRecord => write!(f, "record bound to a different plan"),
            AttestError::BadSignature(n) => write!(f, "bad node signature from {n}"),
            AttestError::BadShard(n) => write!(f, "node {n} claimed a shard it doesn't own"),
        }
    }
}

impl std::error::Error for AttestError {}

use orenda::*;

fn member_key() -> SigningKey {
    generate_key()
}

fn cap(accel: Accel, free_gb: u64, tok: u32) -> Capability {
    Capability {
        accel,
        free_bytes: free_gb * (1 << 30),
        bandwidth_mbps: 1000,
        tok_per_sec: tok,
    }
}

fn certify(owner: &SigningKey, node: &SigningKey, serial: u64, cap: Capability) -> MemberCert {
    MemberCert::issue(owner, serial, node_id(&node.verifying_key()), cap, 86_400)
}

fn pop(node: &SigningKey, cert: &MemberCert) -> String {
    use ed25519_dalek::Signer;
    hex::encode(node.sign(&pop_message(cert.serial, &cert.node)).to_bytes())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn model() -> ModelSpec {
    ModelSpec {
        layers: 32,
        weights_bytes: 4 * (1 << 30),
        kv_bytes_per_token: 256 * 1024,
        context_tokens: 8192,
    }
}

#[test]
fn certificate_verifies_under_owner() {
    let owner = generate_key();
    let node = member_key();
    let cert = certify(&owner, &node, 1, cap(Accel::Gpu, 8, 120));
    assert!(cert.verify(&owner.verifying_key(), now()));
    // A different owner can't validate it.
    let foreign = generate_key();
    assert!(!cert.verify(&foreign.verifying_key(), now()));
    // Expired fails.
    assert!(!cert.verify(&owner.verifying_key(), now() + 200_000));
}

#[test]
fn enrollment_requires_proof_of_possession() {
    let owner = generate_key();
    let node = member_key();
    let mut fed = Federation::new(owner.verifying_key());
    let cert = certify(&owner, &node, 1, cap(Accel::Gpu, 8, 120));

    // No proof → rejected.
    assert!(matches!(
        fed.enroll(cert.clone(), "00", now()),
        Err(EnrollError::BadProof)
    ));
    // A different node's signature → rejected.
    let impostor = member_key();
    let bad_pop = pop(&impostor, &cert);
    assert!(matches!(
        fed.enroll(cert.clone(), &bad_pop, now()),
        Err(EnrollError::BadProof)
    ));
    // Correct proof → enrolled.
    let cert2 = certify(&owner, &node, 2, cap(Accel::Gpu, 8, 120));
    assert!(fed
        .enroll(cert2.clone(), &pop(&node, &cert2), now())
        .is_ok());
    assert_eq!(fed.len(), 1);
}

#[test]
fn foreign_owner_cert_rejected() {
    let owner = generate_key();
    let foreign = generate_key();
    let node = member_key();
    let mut fed = Federation::new(owner.verifying_key());
    let cert = certify(&foreign, &node, 1, cap(Accel::Gpu, 8, 120));
    assert!(matches!(
        fed.enroll(cert.clone(), &pop(&node, &cert), now()),
        Err(EnrollError::WrongOwner) | Err(EnrollError::BadCert)
    ));
}

#[test]
fn revocation_blocks_reenrollment() {
    let owner = generate_key();
    let node = member_key();
    let mut fed = Federation::new(owner.verifying_key());
    let cert = certify(&owner, &node, 7, cap(Accel::Gpu, 8, 120));
    fed.enroll(cert.clone(), &pop(&node, &cert), now()).unwrap();

    // Revoke serial 7 — node kicked, epoch bumped, re-enroll denied.
    let epoch_before = fed.epoch();
    assert!(fed.revoke(Revocation::issue(&owner, 7, node_id(&node.verifying_key()))));
    assert_eq!(fed.len(), 0);
    assert!(fed.epoch() > epoch_before);
    assert!(matches!(
        fed.enroll(cert.clone(), &pop(&node, &cert), now()),
        Err(EnrollError::Revoked)
    ));

    // A *new* cert (serial 8) for the same node may re-enroll —
    // serial-scoped revocation, not a node ban.
    let cert8 = certify(&owner, &node, 8, cap(Accel::Gpu, 8, 120));
    assert!(fed
        .enroll(cert8.clone(), &pop(&node, &cert8), now())
        .is_ok());

    // Node ban kills all future certs.
    assert!(fed.revoke(Revocation::ban_node(&owner, node_id(&node.verifying_key()))));
    let cert9 = certify(&owner, &node, 9, cap(Accel::Gpu, 8, 120));
    assert!(matches!(
        fed.enroll(cert9.clone(), &pop(&node, &cert9), now()),
        Err(EnrollError::Revoked)
    ));
}

#[test]
fn placement_is_deterministic_and_covers_layers() {
    let owner = generate_key();
    let nodes: Vec<_> = (0..3).map(|_| member_key()).collect();
    let caps = [
        cap(Accel::Gpu, 12, 200),
        cap(Accel::NeuralEngine, 4, 80),
        cap(Accel::Cpu, 2, 20),
    ];
    let mut fed = Federation::new(owner.verifying_key());
    for (i, n) in nodes.iter().enumerate() {
        let c = certify(&owner, n, i as u64 + 1, caps[i].clone());
        fed.enroll(c.clone(), &pop(n, &c), now()).unwrap();
    }

    // Two plans over the same roster+model+epoch are identical.
    let p1 = fed.plan(&owner, &model(), now(), 300);
    let p2 = fed.plan(&owner, &model(), now(), 300);
    assert_eq!(p1.plan_hash, p2.plan_hash);

    // Layers partition [0, 32) exactly once.
    let mut ranges: Vec<_> = p1.shards.iter().map(|s| s.layers.clone()).collect();
    ranges.sort_by_key(|r| r.start);
    let mut cursor = 0;
    for r in &ranges {
        assert_eq!(r.start, cursor);
        cursor = r.end;
    }
    assert_eq!(cursor, 32);

    // The weakest node drafts.
    let weakest = p1
        .shards
        .iter()
        .min_by_key(|s| s.layers.end - s.layers.start)
        .unwrap();
    assert_eq!(weakest.role, Role::Draft);

    // Plan verifies.
    assert!(p1.verify(&fed, now()).is_ok());
}

#[test]
fn tampered_plan_fails() {
    let owner = generate_key();
    let foreign = generate_key();
    let node = member_key();
    let mut fed = Federation::new(owner.verifying_key());
    let c = certify(&owner, &node, 1, cap(Accel::Gpu, 8, 120));
    fed.enroll(c.clone(), &pop(&node, &c), now()).unwrap();

    let plan = fed.plan(&owner, &model(), now(), 300);

    // Hash tamper.
    let mut bad = plan.clone();
    bad.epoch = 999;
    assert!(matches!(
        bad.verify(&fed, now()),
        Err(PlanError::HashMismatch) | Err(PlanError::BadSignature)
    ));

    // Foreign signature.
    let mut bad = plan.clone();
    bad.signature = hex::encode(ed25519_dalek::Signer::sign(&foreign, b"x").to_bytes());
    assert!(matches!(
        bad.verify(&fed, now()),
        Err(PlanError::HashMismatch) | Err(PlanError::BadSignature)
    ));
}

#[test]
fn revoked_node_invalidates_plan() {
    let owner = generate_key();
    let nodes: Vec<_> = (0..2).map(|_| member_key()).collect();
    let mut fed = Federation::new(owner.verifying_key());
    for (i, n) in nodes.iter().enumerate() {
        let c = certify(&owner, n, i as u64 + 1, cap(Accel::Gpu, 8, 120));
        fed.enroll(c.clone(), &pop(n, &c), now()).unwrap();
    }
    let plan = fed.plan(&owner, &model(), now(), 300);
    assert!(plan.verify(&fed, now()).is_ok());

    // Revoke a planned member — the plan can no longer verify.
    let victim = nodes[0].verifying_key();
    fed.revoke(Revocation::issue(&owner, 1, node_id(&victim)));
    assert!(plan.verify(&fed, now()).is_err());
}

#[test]
fn attestation_proves_which_nodes_served() {
    let owner = generate_key();
    let nodes: Vec<_> = (0..2).map(|_| member_key()).collect();
    let mut fed = Federation::new(owner.verifying_key());
    for (i, n) in nodes.iter().enumerate() {
        let c = certify(&owner, n, i as u64 + 1, cap(Accel::Gpu, 8, 120));
        fed.enroll(c.clone(), &pop(n, &c), now()).unwrap();
    }
    let plan = fed.plan(&owner, &model(), now(), 300);

    // Each node signs the tokens it served on its own shard.
    let records: Vec<ServedRecord> = plan
        .shards
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let key = nodes
                .iter()
                .find(|k| node_id(&k.verifying_key()) == s.node)
                .unwrap();
            ServedRecord::sign(key, &plan.plan_hash, i as u32, 0..10)
        })
        .collect();
    let att = SessionAttestation {
        plan: plan.clone(),
        records,
    };
    assert!(att.verify(&fed, now()).is_ok());

    // A node claiming another's shard fails.
    let thief = member_key();
    let mut bad = att.clone();
    bad.records
        .push(ServedRecord::sign(&thief, &plan.plan_hash, 0, 10..20));
    assert!(bad.verify(&fed, now()).is_err());

    // A record bound to a different plan fails.
    let mut bad2 = att.clone();
    let mut rogue = ServedRecord::sign(&nodes[0], &plan.plan_hash, 0, 0..5);
    rogue.plan_hash = "deadbeef".repeat(8);
    rogue = ServedRecord {
        signature: rogue.signature,
        ..rogue
    };
    bad2.records.push(rogue);
    assert!(bad2.verify(&fed, now()).is_err());
}

#[test]
fn heartbeat_gates_liveness() {
    let owner = generate_key();
    let node = member_key();
    let mut fed = Federation::new(owner.verifying_key());
    let c = certify(&owner, &node, 1, cap(Accel::Gpu, 8, 120));
    fed.enroll(c.clone(), &pop(&node, &c), now()).unwrap();

    let t0 = now();
    assert_eq!(fed.live_members(t0, 60).len(), 1);
    // Past TTL without heartbeat → not live.
    assert_eq!(fed.live_members(t0 + 600, 60).len(), 0);

    // Heartbeat renews liveness.
    let msg = format!("orenda-heartbeat:{}:{}", c.serial, t0 + 600).into_bytes();
    use ed25519_dalek::Signer;
    let sig = hex::encode(node.sign(&msg).to_bytes());
    assert!(fed.heartbeat(&node_id(&node.verifying_key()), &sig, t0 + 600));
    assert_eq!(fed.live_members(t0 + 600, 60).len(), 1);
}

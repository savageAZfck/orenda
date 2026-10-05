use ed25519_dalek::Signer;
use orenda::*;

fn pop(node: &SigningKey, cert: &MemberCert) -> String {
    hex::encode(node.sign(&pop_message(cert.serial, &cert.node)).to_bytes())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn cap(accel: Accel, free_gb: u64, tok: u32) -> Capability {
    Capability {
        accel,
        free_bytes: free_gb * (1 << 30),
        bandwidth_mbps: 1_000,
        tok_per_sec: tok,
    }
}

fn main() {
    // One owner key — the trust root of everything that follows.
    let owner = generate_key();
    let mut fed = Federation::new(owner.verifying_key());

    // Three machines I own: a desktop GPU, this laptop's Neural
    // Engine, an old mini in the closet.
    let nodes: Vec<SigningKey> = (0..3).map(|_| generate_key()).collect();
    let names = ["desktop-gpu", "laptop-ane", "closet-cpu"];
    let caps = [
        cap(Accel::Gpu, 12, 200),
        cap(Accel::NeuralEngine, 4, 80),
        cap(Accel::Cpu, 2, 20),
    ];

    println!("enrolling {} machines under my key:", nodes.len());
    for (i, node) in nodes.iter().enumerate() {
        let cert = MemberCert::issue(
            &owner,
            (i + 1) as u64,
            node_id(&node.verifying_key()),
            caps[i].clone(),
            86_400,
        );
        let node = fed
            .enroll(cert.clone(), &pop(node, &cert), now())
            .expect("enroll");
        println!("  {} → {}", names[i], &node[..12]);
    }

    // A 7B brain that doesn't fit on any one of them.
    let model = ModelSpec {
        layers: 32,
        weights_bytes: 4 * (1 << 30),
        kv_bytes_per_token: 256 * 1024,
        context_tokens: 8192,
    };

    // The plan every node independently computes and verifies.
    let plan = fed.plan(&owner, &model, now(), 300);
    println!(
        "\nplan {} — {} shards:",
        &plan.plan_hash[..16],
        plan.shards.len()
    );
    for (i, s) in plan.shards.iter().enumerate() {
        let name = names[nodes
            .iter()
            .position(|k| node_id(&k.verifying_key()) == s.node)
            .unwrap_or(9)];
        println!(
            "  shard {i}: {name:12} layers {:2}..{:2} kv {:.0}% weights {:.0}% [{:?}]",
            s.layers.start,
            s.layers.end,
            s.kv_share * 100.0,
            s.weights_share * 100.0,
            s.role
        );
    }
    plan.verify(&fed, now()).expect("plan verifies");

    // Nodes serve and sign what they did.
    let records: Vec<ServedRecord> = plan
        .shards
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let key = nodes
                .iter()
                .find(|k| node_id(&k.verifying_key()) == s.node)
                .unwrap();
            ServedRecord::sign(key, &plan.plan_hash, i as u32, 0..256)
        })
        .collect();
    let att = SessionAttestation {
        plan: plan.clone(),
        records,
    };
    att.verify(&fed, now()).expect("attestation verifies");
    println!(
        "\nattestation verified: {} nodes served under plan {}",
        att.records.len(),
        &plan.plan_hash[..16]
    );

    // The closet box starts acting strange — ban it.
    let closet_id = node_id(&nodes[2].verifying_key());
    fed.revoke(Revocation::ban_node(&owner, closet_id.clone()));
    println!("banned {}; plans naming it now fail:", &closet_id[..12]);
    assert!(plan.verify(&fed, now()).is_err());
    println!("  {} ✓", plan.verify(&fed, now()).unwrap_err());

    // The mesh re-plans over the survivors — new epoch, new layout.
    let plan2 = fed.plan(&owner, &model, now(), 300);
    println!(
        "re-planned over {} members; new plan {} verifies.",
        plan2.members.len(),
        &plan2.plan_hash[..16]
    );
    plan2.verify(&fed, now()).expect("survivor plan verifies");
}

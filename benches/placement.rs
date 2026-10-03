use ed25519_dalek::Signer;
use orenda::*;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let owner = generate_key();
    let mut fed = Federation::new(owner.verifying_key());
    let t0 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // A 100-node mesh.
    let nodes: Vec<SigningKey> = (0..100).map(|_| generate_key()).collect();
    for (i, node) in nodes.iter().enumerate() {
        let cert = MemberCert::issue(
            &owner,
            i as u64 + 1,
            node_id(&node.verifying_key()),
            Capability {
                accel: Accel::Gpu,
                free_bytes: (8 + i as u64 % 8) * (1 << 30),
                bandwidth_mbps: 1000,
                tok_per_sec: 100 + i as u32,
            },
            86_400,
        );
        let pop = hex::encode(
            node.sign(&pop_message(cert.serial, &cert.node)).to_bytes(),
        );
        fed.enroll(cert, &pop, t0).unwrap();
    }

    let model = ModelSpec {
        layers: 80,
        weights_bytes: 40 * (1 << 30),
        kv_bytes_per_token: 512 * 1024,
        context_tokens: 32_768,
    };

    let t = Instant::now();
    for _ in 0..1_000 {
        black_box(fed.plan(black_box(&owner), black_box(&model), t0, 300));
    }
    println!("plan over 100 nodes: {:?}/op", t.elapsed() / 1_000);
}

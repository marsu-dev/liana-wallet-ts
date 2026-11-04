use liana::descriptors::{LianaDescriptor, PathInfo};
use miniscript::bitcoin::{self, Network};
use std::{env, fs, str::FromStr};

fn main() {
    let input_path = env::args().nth(1).expect("descriptor input path");
    let text = fs::read_to_string(input_path).expect("read descriptor input");
    let candidate = text.trim();
    let liana = LianaDescriptor::from_str(candidate)
        .expect("Liana must accept the exact recovery key-threshold candidate");
    let canonical = liana.to_string();
    assert_eq!(
        canonical.split('#').next(),
        Some(candidate.split('#').next().unwrap())
    );
    assert!(liana.all_xpubs_net_is(Network::Bitcoin));

    let policy = liana.policy();
    assert!(matches!(policy.primary_path(), PathInfo::Multi(3, keys) if keys.len() == 3));
    assert_eq!(
        policy.recovery_paths().keys().copied().collect::<Vec<_>>(),
        vec![26352]
    );
    assert!(matches!(
        policy.recovery_paths().get(&26352),
        Some(PathInfo::Multi(2, keys)) if keys.len() == 3
    ));

    println!("D\t{}", liana);
    println!("P\tprimary\tmulti\t3\t3");
    println!("P\trecovery\t26352\tmulti\t2\t3");

    let secp = bitcoin::secp256k1::Secp256k1::new();
    for (branch, single) in [
        ("receive", liana.receive_descriptor()),
        ("change", liana.change_descriptor()),
    ] {
        for index in 0u32..10 {
            let derived = single.derive(index.into(), &secp);
            let address = derived.address(Network::Bitcoin).to_string();
            let script = derived.script_pubkey();
            let script_hex: String = script
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            println!("V\t{branch}\t{index}\t{address}\t{script_hex}");
        }
    }
}

use liana::descriptors::{LianaDescriptor, PathInfo};
use miniscript::bitcoin::{self, Network};
use std::{fs, str::FromStr};

fn main() {
    let input_path = std::env::args().nth(1).expect("path to combined community descriptor required");
    let source = fs::read_to_string(input_path).expect("read combined descriptor");
    let liana = LianaDescriptor::from_str(source.trim()).expect("valid Liana Signet descriptor");
    assert!(liana.all_xpubs_net_is(Network::Testnet), "Signet descriptors serialize extended keys with testnet versions");
    let policy = liana.policy();
    assert!(matches!(policy.primary_path(), PathInfo::Single(_)));
    assert_eq!(policy.recovery_paths().keys().copied().collect::<Vec<_>>(), vec![36]);
    assert!(matches!(policy.recovery_paths().get(&36), Some(PathInfo::Single(_))));

    let secp = bitcoin::secp256k1::Secp256k1::new();
    for (branch, descriptor) in [
        ("receive", liana.receive_descriptor()),
        ("change", liana.change_descriptor()),
    ] {
        for index in 0u32..=9 {
            let derived = descriptor.derive(index.into(), &secp);
            let script = derived.script_pubkey();
            let script_hex: String = script.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect();
            println!("V\t{branch}\t{index}\t{}\t{script_hex}", derived.address(Network::Signet));
        }
    }
}

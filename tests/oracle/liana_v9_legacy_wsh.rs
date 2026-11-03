use liana::descriptors::{LianaDescriptor, LianaPolicy, PathInfo};
use miniscript::bitcoin::{self, bip32::{Fingerprint, Xpub}, Network};
use miniscript::descriptor::DescriptorPublicKey;
use std::{collections::BTreeMap, str::FromStr};

struct RootKey { fingerprint: Fingerprint, xpub: Xpub }

fn root_keys() -> Vec<RootKey> {
    const ROOTS: &[(&str, &str)] = &[
        ("4ba43603", "xpub661MyMwAqRbcEtUEgdXRTY6dJQG9fRgs7C5QomqETKMYBJVtSGpRqyHSmhWy8snovPd5oWZgQ14zUquxbxu7Z1umuXbN5VDpUL1QobD5xUY"),
        ("8dfc9b34", "xpub661MyMwAqRbcGFeMhhkrJL6Yj3YKQFNZQSM2BAvoMmhdjNKBh43n5v3c4YT5dFtjkirfhqQHMd22br7cHAQXAV8cZdicedZJkNweja4WWBK"),
        ("56c4fac3", "xpub661MyMwAqRbcFNWTmtbxHaYsjddAazfBQ51wm61veSzW3z2N7s1U7M9epMGsedj3unJKhXBY2sxWpQutwrZnpFuWe2vVVvLig8nFT4nmG67"),
    ];
    ROOTS.iter().map(|(fingerprint, xpub)| RootKey {
        fingerprint: Fingerprint::from_str(fingerprint).expect("valid fingerprint"),
        xpub: Xpub::from_str(xpub).expect("valid public xpub"),
    }).collect()
}

fn key(roots: &[RootKey], root: usize, purpose: u32) -> DescriptorPublicKey {
    let key = &roots[root];
    DescriptorPublicKey::from_str(&format!("[{}]{}/{}/<0;1>/*", key.fingerprint, key.xpub, purpose)).expect("valid multipath key")
}

fn multi(roots: &[RootKey], purpose: u32, threshold: usize) -> PathInfo {
    PathInfo::Multi(threshold, (0..3).map(|root| key(roots, root, purpose)).collect())
}

fn emit(case_id: &str, liana: LianaDescriptor, secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) {
    assert!(liana.all_xpubs_net_is(Network::Bitcoin));
    println!("D\t{case_id}\t{}", liana);
    for (branch, single) in [("receive", liana.receive_descriptor()), ("change", liana.change_descriptor())] {
        for index in 0u32..=1 {
            let derived = single.derive(index.into(), secp);
            let script = derived.script_pubkey();
            let script_hex: String = script.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect();
            println!("V\t{case_id}\t{branch}\t{index}\t{}\t{script_hex}", derived.address(Network::Bitcoin));
        }
    }
}

fn main() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let roots = root_keys();
    let single = LianaPolicy::new_legacy(
        PathInfo::Single(key(&roots, 0, 0)),
        BTreeMap::from([(36, PathInfo::Single(key(&roots, 1, 1)))]),
    ).expect("valid legacy single-key policy");
    emit("legacy-single-primary-recovery", LianaDescriptor::new(single), &secp);

    let multisig = LianaPolicy::new_legacy(
        multi(&roots, 0, 2),
        BTreeMap::from([(26352, multi(&roots, 1, 2))]),
    ).expect("valid legacy 2-of-3 policy");
    emit("legacy-2-of-3-primary-recovery", LianaDescriptor::new(multisig), &secp);
}

use liana::descriptors::{LianaDescriptor, LianaPolicy, PathInfo};
use miniscript::bitcoin::{self, bip32::{Fingerprint, Xpriv, Xpub}, Network};
use miniscript::descriptor::DescriptorPublicKey;
use std::{collections::BTreeMap, str::FromStr};

struct RootKey { fingerprint: Fingerprint, xpub: Xpub }

fn root_keys(secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Vec<RootKey> {
    (1u8..=5).map(|n| {
        let seed = [n; 32];
        let xpriv = Xpriv::new_master(Network::Bitcoin, &seed).expect("deterministic test root");
        RootKey { fingerprint: xpriv.fingerprint(secp), xpub: Xpub::from_priv(secp, &xpriv) }
    }).collect()
}

fn key(roots: &[RootKey], root: usize, purpose: u32) -> DescriptorPublicKey {
    let key = &roots[root];
    let text = format!("[{}]{}/{}/<0;1>/*", key.fingerprint, key.xpub, purpose);
    DescriptorPublicKey::from_str(&text).expect("valid multipath descriptor key")
}

fn multi(roots: &[RootKey], purpose: u32, threshold: usize, members: &[usize]) -> PathInfo {
    PathInfo::Multi(threshold, members.iter().map(|i| key(roots, *i, purpose)).collect())
}

fn emit(case_id: &str, policy: &str, liana: LianaDescriptor, secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) {
    assert!(liana.all_xpubs_net_is(Network::Bitcoin));
    let descriptor = liana.to_string();
    println!("D\t{case_id}\t{policy}\t{descriptor}");
    for (branch, single) in [("receive", liana.receive_descriptor()), ("change", liana.change_descriptor())] {
        for index in 0u32..=1 {
            let derived = single.derive(index.into(), secp);
            let address = derived.address(Network::Bitcoin).to_string();
            let script = derived.script_pubkey();
            let script_hex: String = script.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            println!("V\t{case_id}\t{branch}\t{index}\t{address}\t{script_hex}");
        }
    }
}

fn main() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let roots = root_keys(&secp);

    let single_primary = LianaPolicy::new(
        PathInfo::Single(key(&roots, 0, 0)),
        BTreeMap::from([(36, PathInfo::Single(key(&roots, 1, 1)))]),
    ).expect("valid single-primary Liana policy");
    emit("single-primary-recovery", "single-key primary; single-key recovery older(36)", LianaDescriptor::new(single_primary), &secp);

    let one_recovery = LianaPolicy::new(
        multi(&roots, 0, 3, &[0, 1, 2]),
        BTreeMap::from([(26352, multi(&roots, 1, 2, &[0, 1, 2]))]),
    ).expect("valid one-recovery Liana policy");
    emit("multisig-one-recovery", "3-of-3 primary; 2-of-3 recovery older(26352)", LianaDescriptor::new(one_recovery), &secp);

    let multiple_recovery = LianaPolicy::new(
        multi(&roots, 0, 2, &[0, 1, 2]),
        BTreeMap::from([
            (42, PathInfo::Single(key(&roots, 3, 2))),
            (43, multi(&roots, 3, 2, &[0, 1, 2])),
            (1678, multi(&roots, 4, 1, &[0, 1, 2])),
        ]),
    ).expect("valid multiple-recovery Liana policy");
    emit("multisig-multiple-recovery", "2-of-3 primary; recovery older(42) single-key, older(43) 2-of-3, older(1678) 1-of-3", LianaDescriptor::new(multiple_recovery), &secp);
}

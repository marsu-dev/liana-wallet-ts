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
        ("83bfab59", "xpub661MyMwAqRbcGqhD7PpVgkvot7Cm4CE94VkA9q1ht6XeAe4Vd9JjnHRTYYgzqgxAY6cxVd1CMh7GdKasJAms53sRu3GvpTnWuWxTiEf4vjh"),
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

fn key_with_branches(roots: &[RootKey], root: usize, purpose: u32, branches: &str) -> String {
    let key = &roots[root];
    format!("[{}]{}/{}/<{branches}>/*", key.fingerprint, key.xpub, purpose)
}

fn multi(roots: &[RootKey], purpose: u32, threshold: usize) -> PathInfo {
    PathInfo::Multi(threshold, (0..3).map(|root| key(roots, root, purpose)).collect())
}

fn emit(case_id: &str, liana: LianaDescriptor, secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) {
    emit_on_network(case_id, liana, Network::Bitcoin, secp);
}

fn emit_on_network(case_id: &str, liana: LianaDescriptor, network: Network, secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) {
    let xpub_network = if network == Network::Signet { Network::Testnet } else { network };
    assert!(liana.all_xpubs_net_is(xpub_network));
    println!("D\t{case_id}\t{}", liana);
    for (branch, single) in [("receive", liana.receive_descriptor()), ("change", liana.change_descriptor())] {
        for index in 0u32..=1 {
            let derived = single.derive(index.into(), secp);
            let script = derived.script_pubkey();
            let script_hex: String = script.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect();
            println!("V\t{case_id}\t{branch}\t{index}\t{}\t{script_hex}", derived.address(network));
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

    let multiple_recovery = LianaPolicy::new_legacy(
        multi(&roots, 0, 2),
        BTreeMap::from([
            (42, PathInfo::Single(key(&roots, 3, 2))),
            (43, multi(&roots, 3, 2)),
            (1678, multi(&roots, 4, 1)),
        ]),
    ).expect("valid legacy policy with multiple recovery paths");
    emit("legacy-multiple-recovery", LianaDescriptor::new(multiple_recovery), &secp);

    let andor_body = format!("wsh(andor(pk({}),older(42),pk({})))", key(&roots, 0, 0), key(&roots, 1, 1));
    let andor = LianaDescriptor::from_str(&andor_body).expect("valid legacy andor descriptor");
    let inferred_policy = andor.policy();
    match inferred_policy.primary_path() {
        PathInfo::Single(key) => assert!(key.to_string().contains("[8dfc9b34]")),
        _ => panic!("expected the third andor argument to be primary"),
    }
    assert_eq!(inferred_policy.recovery_paths().keys().copied().collect::<Vec<_>>(), vec![42]);
    match inferred_policy.recovery_paths().get(&42).expect("recovery at 42") {
        PathInfo::Single(key) => assert!(key.to_string().contains("[4ba43603]")),
        _ => panic!("expected the first andor argument to be the recovery key"),
    }
    emit("legacy-andor", andor, &secp);

    let liana_v2_body = format!(
        "wsh(or_i(and_v(v:thresh(3,pkh({}),a:pkh({}),a:pkh({})),older(6)),or_d(multi(3,{},{},{}),and_v(v:thresh(2,pkh({}),a:pkh({}),a:pkh({})),older(3)))))",
        key_with_branches(&roots, 0, 0, "4;5"), key_with_branches(&roots, 1, 1, "4;5"), key_with_branches(&roots, 2, 2, "4;5"),
        key_with_branches(&roots, 0, 0, "0;1"), key_with_branches(&roots, 1, 1, "0;1"), key_with_branches(&roots, 2, 2, "0;1"),
        key_with_branches(&roots, 0, 0, "2;3"), key_with_branches(&roots, 1, 1, "2;3"), key_with_branches(&roots, 2, 2, "2;3"),
    );
    let liana_v2 = LianaDescriptor::from_str(&liana_v2_body).expect("valid Liana v2 threshold recovery descriptor");
    let inferred_policy = liana_v2.policy();
    assert!(matches!(inferred_policy.primary_path(), PathInfo::Multi(3, keys) if keys.len() == 3));
    assert_eq!(inferred_policy.recovery_paths().keys().copied().collect::<Vec<_>>(), vec![3, 6]);
    assert!(matches!(inferred_policy.recovery_paths().get(&3), Some(PathInfo::Multi(2, keys)) if keys.len() == 3));
    assert!(matches!(inferred_policy.recovery_paths().get(&6), Some(PathInfo::Multi(3, keys)) if keys.len() == 3));
    emit("legacy-v2-threshold-recoveries", liana_v2, &secp);

    let signet_v2 = LianaDescriptor::from_str(include_str!("liana-v2-signet-descriptor.txt").trim())
        .expect("valid pinned Liana v2 Signet descriptor");
    let inferred_policy = signet_v2.policy();
    assert!(matches!(inferred_policy.primary_path(), PathInfo::Multi(3, keys) if keys.len() == 3));
    assert_eq!(inferred_policy.recovery_paths().keys().copied().collect::<Vec<_>>(), vec![3, 6]);
    assert!(matches!(inferred_policy.recovery_paths().get(&3), Some(PathInfo::Multi(2, keys)) if keys.len() == 3));
    assert!(matches!(inferred_policy.recovery_paths().get(&6), Some(PathInfo::Multi(3, keys)) if keys.len() == 3));
    emit_on_network("signet-v2-bip32-derivs", signet_v2, Network::Signet, &secp);

    let nested_threshold = format!(
        "wsh(or_d(thresh(1,thresh(1,pkh({}),pkh({})),pkh({})),and_v(v:pkh({}),older(36))))",
        key(&roots, 0, 0), key(&roots, 1, 0), key(&roots, 2, 0), key(&roots, 1, 1),
    );
    assert!(LianaDescriptor::from_str(&nested_threshold).is_err(), "nested B-type threshold must fail Miniscript type checking");
}

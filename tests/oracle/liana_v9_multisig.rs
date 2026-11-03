use liana::descriptors::{LianaDescriptor, LianaPolicy, PathInfo};
use miniscript::bitcoin::{self, bip32::{Fingerprint, Xpub}, Network};
use miniscript::descriptor::DescriptorPublicKey;
use std::{collections::BTreeMap, str::FromStr};

struct RootKey { fingerprint: Fingerprint, xpub: Xpub }

fn root_keys() -> Vec<RootKey> {
    // Public-only deterministic test roots; the fixture and generator retain no seed or private key.
    const ROOTS: &[(&str, &str)] = &[
        ("4ba43603", "xpub661MyMwAqRbcEtUEgdXRTY6dJQG9fRgs7C5QomqETKMYBJVtSGpRqyHSmhWy8snovPd5oWZgQ14zUquxbxu7Z1umuXbN5VDpUL1QobD5xUY"),
        ("8dfc9b34", "xpub661MyMwAqRbcGFeMhhkrJL6Yj3YKQFNZQSM2BAvoMmhdjNKBh43n5v3c4YT5dFtjkirfhqQHMd22br7cHAQXAV8cZdicedZJkNweja4WWBK"),
        ("56c4fac3", "xpub661MyMwAqRbcFNWTmtbxHaYsjddAazfBQ51wm61veSzW3z2N7s1U7M9epMGsedj3unJKhXBY2sxWpQutwrZnpFuWe2vVVvLig8nFT4nmG67"),
        ("83bfab59", "xpub661MyMwAqRbcGqhD7PpVgkvot7Cm4CE94VkA9q1ht6XeAe4Vd9JjnHRTYYgzqgxAY6cxVd1CMh7GdKasJAms53sRu3GvpTnWuWxTiEf4vjh"),
    ];
    ROOTS.iter().map(|(fingerprint, xpub)| RootKey {
        fingerprint: Fingerprint::from_str(fingerprint).expect("valid root fingerprint"),
        xpub: Xpub::from_str(xpub).expect("valid public root xpub"),
    }).collect()
}

fn key_with_branches(roots: &[RootKey], root: usize, purpose: u32, branches: (u32, u32)) -> DescriptorPublicKey {
    let key = &roots[root];
    let text = format!("[{}]{}/{}/<{};{}>/*", key.fingerprint, key.xpub, purpose, branches.0, branches.1);
    DescriptorPublicKey::from_str(&text).expect("valid multipath descriptor key")
}

fn key(roots: &[RootKey], root: usize, purpose: u32) -> DescriptorPublicKey {
    key_with_branches(roots, root, purpose, (0, 1))
}

fn multi_with_branches(roots: &[RootKey], purpose: u32, threshold: usize, members: &[usize], branches: (u32, u32)) -> PathInfo {
    PathInfo::Multi(threshold, members.iter().map(|i| key_with_branches(roots, *i, purpose, branches)).collect())
}

fn multi(roots: &[RootKey], purpose: u32, threshold: usize, members: &[usize]) -> PathInfo {
    multi_with_branches(roots, purpose, threshold, members, (0, 1))
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
    let roots = root_keys();

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

    let distinct_branch_values = LianaPolicy::new(
        multi_with_branches(&roots, 0, 3, &[0, 1, 2], (0, 1)),
        BTreeMap::from([(26352, multi_with_branches(&roots, 1, 2, &[0, 1, 2], (2, 3)))]),
    ).expect("valid Liana policy with distinct multipath values");
    emit("multisig-distinct-branch-values", "3-of-3 primary branches <0;1>; 2-of-3 recovery older(26352) branches <2;3>", LianaDescriptor::new(distinct_branch_values), &secp);

    let multiple_recovery = LianaPolicy::new(
        multi(&roots, 0, 2, &[0, 1, 2]),
        BTreeMap::from([
            (42, PathInfo::Single(key(&roots, 3, 2))),
            (43, multi(&roots, 3, 2, &[0, 1, 2])),
            (1678, multi(&roots, 4, 1, &[0, 1, 2])),
        ]),
    ).expect("valid multiple-recovery Liana policy");
    emit("multisig-multiple-recovery", "2-of-3 primary; recovery older(42) single-key, older(43) 2-of-3, older(1678) 1-of-3", LianaDescriptor::new(multiple_recovery), &secp);

    let taproot_multi_a_multiple_recovery = LianaPolicy::new(
        multi(&roots, 0, 2, &[0, 1, 2]),
        BTreeMap::from([
            (42, multi(&roots, 1, 2, &[0, 1, 2])),
            (43, multi(&roots, 2, 3, &[0, 1, 2])),
            (1678, multi(&roots, 3, 1, &[0, 1, 2])),
        ]),
    ).expect("valid Taproot multi_a policy with multiple recovery paths");
    let generated = LianaDescriptor::new(taproot_multi_a_multiple_recovery);
    let reparsed = LianaDescriptor::from_str(&generated.to_string())
        .expect("generated Taproot multi_a descriptor must parse through Liana");
    let inferred = reparsed.policy();
    assert!(matches!(inferred.primary_path(), PathInfo::Multi(2, keys) if keys.len() == 3));
    assert_eq!(inferred.recovery_paths().keys().copied().collect::<Vec<_>>(), vec![42, 43, 1678]);
    assert!(matches!(inferred.recovery_paths().get(&42), Some(PathInfo::Multi(2, keys)) if keys.len() == 3));
    assert!(matches!(inferred.recovery_paths().get(&43), Some(PathInfo::Multi(3, keys)) if keys.len() == 3));
    assert!(matches!(inferred.recovery_paths().get(&1678), Some(PathInfo::Multi(1, keys)) if keys.len() == 3));
    emit(
        "taproot-multi-a-multiple-recovery",
        "2-of-3 primary; multi_a recoveries older(42) 2-of-3, older(43) 3-of-3, older(1678) 1-of-3",
        reparsed,
        &secp,
    );
}

use liana::descriptors::{LianaDescError, LianaDescriptor, LianaPolicyError};
use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
use std::{fs, str::FromStr};

fn main() {
    let input_path = std::env::args()
        .nth(1)
        .expect("path to candidate descriptor required");
    let source = fs::read_to_string(input_path).expect("read candidate descriptor");
    let parsed: Descriptor<DescriptorPublicKey> =
        Descriptor::from_str(source.trim()).expect("candidate must be valid descriptor syntax");
    let candidate = parsed.to_string();
    let error = LianaDescriptor::from_str(&candidate)
        .expect_err("duplicate origin fingerprint within recovery path must be rejected");
    assert!(
        matches!(
            &error,
            LianaDescError::Policy(LianaPolicyError::DuplicateOriginSamePath(_))
        ),
        "expected the pinned duplicate-origin-same-path policy error, got {:?}",
        error
    );
    println!("D\t{candidate}");
    println!("E\tDuplicateOriginSamePath");
}

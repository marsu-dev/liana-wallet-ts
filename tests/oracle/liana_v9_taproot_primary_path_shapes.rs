use liana::descriptors::{LianaDescriptor, PathInfo};
use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
use std::{env, fs, str::FromStr};

fn path_info_tag(path: &PathInfo) -> String {
    match path {
        PathInfo::Single(_) => "Single(1,1)".to_owned(),
        PathInfo::Multi(threshold, keys) => format!("Multi({threshold},{})", keys.len()),
    }
}

fn main() {
    let mut args = env::args().skip(1);
    let id = args.next().expect("case id required");
    let path = args.next().expect("path to checksummed descriptor required");
    let source = fs::read_to_string(path).expect("read descriptor");
    let candidate = source.trim();
    let parsed: Descriptor<DescriptorPublicKey> =
        Descriptor::from_str(candidate).expect("candidate must parse as a generic descriptor");
    let descriptor_body = parsed.to_string();
    match LianaDescriptor::from_str(candidate) {
        Ok(descriptor) => {
            let policy = descriptor.policy();
            let recoveries = policy
                .recovery_paths()
                .iter()
                .map(|(timelock, path)| format!("{timelock}:{}", path_info_tag(path)))
                .collect::<Vec<_>>()
                .join(",");
            println!("{id}\tD\t{descriptor_body}");
            println!(
                "{id}\tA\tprimary={};recovery={recoveries}",
                path_info_tag(policy.primary_path())
            );
        }
        Err(error) => {
            let variant = format!("{error:?}");
            let expected = if variant.contains("IncompatibleDesc") {
                "IncompatibleDesc"
            } else if variant.contains("DuplicateOriginSamePath") {
                "DuplicateOriginSamePath"
            } else if variant.contains("DuplicateKey") {
                "DuplicateKey"
            } else {
                panic!("unexpected pinned Liana error variant: {}", variant)
            };
            println!("{id}\tD\t{descriptor_body}");
            println!("{id}\tR\t{expected}");
        }
    }
}

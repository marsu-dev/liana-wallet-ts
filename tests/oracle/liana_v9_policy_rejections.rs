use liana::descriptors::LianaDescriptor;
use std::str::FromStr;

fn main() {
    let cases = [
        (
            "taproot-recovery-hashlock",
            r#"tr([4ba43603]xpub661MyMwAqRbcEtUEgdXRTY6dJQG9fRgs7C5QomqETKMYBJVtSGpRqyHSmhWy8snovPd5oWZgQ14zUquxbxu7Z1umuXbN5VDpUL1QobD5xUY/0/<0;1>/*,and_v(v:pk([8dfc9b34]xpub661MyMwAqRbcGFeMhhkrJL6Yj3YKQFNZQSM2BAvoMmhdjNKBh43n5v3c4YT5dFtjkirfhqQHMd22br7cHAQXAV8cZdicedZJkNweja4WWBK/1/<0;1>/*),and_v(v:sha256(0000000000000000000000000000000000000000000000000000000000000000),older(42))))#2a0vcw08"#,
        ),
        (
            "taproot-primary-hashlock",
            r#"tr([4ba43603]xpub661MyMwAqRbcEtUEgdXRTY6dJQG9fRgs7C5QomqETKMYBJVtSGpRqyHSmhWy8snovPd5oWZgQ14zUquxbxu7Z1umuXbN5VDpUL1QobD5xUY/0/<0;1>/*,{and_v(v:pk([56c4fac3]xpub661MyMwAqRbcFNWTmtbxHaYsjddAazfBQ51wm61veSzW3z2N7s1U7M9epMGsedj3unJKhXBY2sxWpQutwrZnpFuWe2vVVvLig8nFT4nmG67/0/<0;1>/*),sha256(0000000000000000000000000000000000000000000000000000000000000000)),and_v(v:pk([8dfc9b34]xpub661MyMwAqRbcGFeMhhkrJL6Yj3YKQFNZQSM2BAvoMmhdjNKBh43n5v3c4YT5dFtjkirfhqQHMd22br7cHAQXAV8cZdicedZJkNweja4WWBK/1/<0;1>/*),older(36))})#jad3m2e2"#,
        ),
    ];

    for (id, descriptor) in cases {
        let error = LianaDescriptor::from_str(descriptor)
            .expect_err("pinned Liana unexpectedly accepted a non-Liana recovery policy");
        let message = error.to_string();
        assert_eq!(
            message,
            "Descriptor is not compatible with a Liana spending policy."
        );
        println!("R\t{id}\t{descriptor}\t{message}");
    }
}

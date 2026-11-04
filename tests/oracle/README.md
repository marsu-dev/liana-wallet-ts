# Liana v9 Rust descriptor oracle

The fixture `../fixtures/liana-v9-rust-taproot-multisig.json` was generated from the pinned Liana Rust implementation, not from the TypeScript package. It contains five `LianaPolicy::new` policies: a single-key primary with one single-key recovery path, a 3-of-3 primary with one 2-of-3 recovery leaf, a 3-of-3 primary using `<0;1>` with a 2-of-3 recovery using `<2;3>`, a 2-of-3 primary with three recovery paths, and a 2-of-3 primary with three Taproot `multi_a` recovery paths (`older(42)` 2-of-3, `older(43)` 3-of-3, and `older(1678)` 1-of-3). The final descriptor is reparsed through `LianaDescriptor::from_str`, and Rust asserts the primary/recovery thresholds and timelocks. For each case, Rust produced the descriptor plus receive/change addresses and exact `scriptPubKey` bytes at indices 0 and 1.

## Provenance

- Liana v9.0 commit: `398e622596e7530a328de3027cb2c09905f708c6`
- `Cargo.lock`: Miniscript `11.2.0`
- Rust toolchain: `1.80.0`
- Network: Bitcoin mainnet
- The harness uses only public root fingerprints/xpubs retained in the generated descriptors; no seed or private key is stored in the generator or fixture.

## Reproduce

From the project root, set `REF` to a temporary clone location:

```sh
REF="$HOME/.cache/liana-v9-reference"
git clone --filter=blob:none --no-checkout https://github.com/wizardsardine/liana.git "$REF"
git -C "$REF" fetch --depth 1 origin 398e622596e7530a328de3027cb2c09905f708c6
git -C "$REF" checkout --detach 398e622596e7530a328de3027cb2c09905f708c6
cp tests/oracle/liana_v9_multisig.rs "$REF/liana/examples/oracle_vectors.rs"
(cd "$REF" && cargo run --locked -p liana --example oracle_vectors) > "$REF/vectors.tsv"
python3 tests/oracle/build_liana_v9_fixture.py "$REF/vectors.tsv" "$REF/rebuilt.json"
cmp tests/fixtures/liana-v9-rust-taproot-multisig.json "$REF/rebuilt.json"
```

The Taproot Rust generator calls Liana's `LianaPolicy::new` and `LianaDescriptor::new`, then derives through `receive_descriptor()` and `change_descriptor()`. The converter rejects missing/duplicate rows and requires both indices for both branches and all five Taproot policies. The checked-in TypeScript test compares all twenty Rust Taproot address and `scriptPubKey` pairs exactly.

The five `legacy-*` fixtures cover three policies built with pinned `LianaPolicy::new_legacy` plus two valid legacy descriptors parsed with pinned `LianaDescriptor::from_str`. Coverage includes a single-key primary/recovery, 2-of-3 primary/recovery, a 2-of-3 primary with three recovery paths (single-key, 2-of-3 and 1-of-3), the `andor(pk(recovery),older(42),pk(primary))` form, and a mainnet-instantiated form of the three-recovery threshold policy in the pinned Liana v2 test `liana/src/descriptors/mod.rs::bip32_derivs_pruning` (primary 3-of-3, recoveries older(3) 2-of-3 and older(6) 3-of-3, with distinct multipath values). They record mainnet receive/change addresses and `scriptPubKey`s at indices 0 and 1 (twenty pairs total). The additional `liana-v9-rust-signet-v2-bip32-derivs.json` fixture contains the exact public Signet descriptor from that pinned Liana v2 test and four Rust-derived receive/change outputs at indices 0 and 1. It uses tpubs (the testnet extended-key serialization shared by Signet), and Rust derives the addresses with `Network::Signet`. All fixtures use public xpubs/fingerprints only; no seed or private key is stored.

To reproduce those fixtures from the pinned source clone:

```sh
cp tests/oracle/liana_v9_legacy_wsh.rs "$REF/liana/examples/oracle_wsh_vectors.rs"
cp tests/oracle/liana-v2-signet-descriptor.txt "$REF/liana/examples/liana-v2-signet-descriptor.txt"
(cd "$REF" && cargo run --locked -p liana --example oracle_wsh_vectors) > "$REF/wsh.tsv"
python3 tests/oracle/build_liana_v9_wsh_fixtures.py "$REF/wsh.tsv" "$REF/wsh-fixtures"
cmp tests/fixtures/liana-v9-rust-legacy-wsh.json "$REF/wsh-fixtures/liana-v9-rust-legacy-wsh.json"
cmp tests/fixtures/liana-v9-rust-legacy-wsh-multisig.json "$REF/wsh-fixtures/liana-v9-rust-legacy-wsh-multisig.json"
cmp tests/fixtures/liana-v9-rust-legacy-wsh-multiple-recovery.json "$REF/wsh-fixtures/liana-v9-rust-legacy-wsh-multiple-recovery.json"
cmp tests/fixtures/liana-v9-rust-legacy-wsh-andor.json "$REF/wsh-fixtures/liana-v9-rust-legacy-wsh-andor.json"
cmp tests/fixtures/liana-v9-rust-legacy-wsh-v2-thresholds.json "$REF/wsh-fixtures/liana-v9-rust-legacy-wsh-v2-thresholds.json"
cmp tests/fixtures/liana-v9-rust-signet-v2-bip32-derivs.json "$REF/wsh-fixtures/liana-v9-rust-signet-v2-bip32-derivs.json"
```

The exact Signet single-primary community fixture is also checked against Rust for every receive/change index 0–9 (20 address/script pairs), closing the explicit range in T06/T07. The input builder verifies that the preserved receive/change descriptors differ only by the branch value, then presents their ordered `<0;1>` form to `LianaDescriptor::from_str`; the Rust harness asserts the inferred policy (single-key primary, single-key recovery at 36) and derives via `Network::Signet` while validating tpubs as `Network::Testnet`.

```sh
python3 tests/oracle/build_signet_single_primary_input.py tests/fixtures/liana-v9-signet-single-primary-recovery.json "$REF/signet-single-primary-multipath.txt"
cp tests/oracle/liana_v9_signet_single_primary.rs "$REF/liana/examples/liana_v9_signet_single_primary.rs"
(cd "$REF" && cargo run --locked -p liana --example liana_v9_signet_single_primary -- "$REF/signet-single-primary-multipath.txt") > "$REF/signet-single-primary.tsv"
python3 tests/oracle/build_liana_v9_signet_single_primary_fixture.py tests/fixtures/liana-v9-signet-single-primary-recovery.json "$REF/signet-single-primary-multipath.txt" "$REF/signet-single-primary.tsv" "$REF/signet-single-primary.json"
cmp tests/fixtures/liana-v9-rust-signet-single-primary-recovery.json "$REF/signet-single-primary.json"
```

The checked-in TypeScript test compares all 20 exact Rust outputs against `deriveWalletAddress` using the combined multipath descriptor.

The additional `liana-v9-rust-signet-nonstandard-multipath.json` fixture uses the same public community policy with multipath choices `<7;19>`. Liana Rust parses it and derives receive/change indices 0–9; the TypeScript test compares all 20 address/script pairs. This verifies that the API selects the two ordered values from the descriptor rather than assuming branch numbers 0 and 1.

```sh
python3 tests/oracle/build_signet_single_primary_input.py tests/fixtures/liana-v9-signet-single-primary-recovery.json "$REF/signet-nonstandard-multipath.txt" 7 19
(cd "$REF" && cargo run --locked -p liana --example liana_v9_signet_single_primary -- "$REF/signet-nonstandard-multipath.txt") > "$REF/signet-nonstandard-multipath.tsv"
python3 tests/oracle/build_liana_v9_signet_nonstandard_multipath.py tests/fixtures/liana-v9-signet-single-primary-recovery.json "$REF/signet-nonstandard-multipath.txt" "$REF/signet-nonstandard-multipath.tsv" "$REF/signet-nonstandard-multipath.json"
cmp tests/fixtures/liana-v9-rust-signet-nonstandard-multipath.json "$REF/signet-nonstandard-multipath.json"
```

The `liana-v9-rust-signet-single-key-multi-a.json` fixture is a parser-derived positive case, not a descriptor generated by `LianaPolicy::new`. It changes only the community recovery syntax from `pk(key)` to `multi_a(1,key)`. The Rust harness parses the exact candidate with `LianaDescriptor::from_str`, asserts that the primary and the `older(36)` recovery both normalize to `PathInfo::Single`, then derives receive/change indices 0–9 (20 exact address/script pairs). It contains only public xpubs/fingerprints.

```sh
python3 tests/oracle/build_liana_v9_signet_single_key_multi_a_input.py tests/fixtures/liana-v9-rust-signet-single-primary-recovery.json "$REF/signet-single-key-multi-a.txt"
cp tests/oracle/liana_v9_signet_single_key_multi_a.rs "$REF/liana/examples/liana_v9_signet_single_key_multi_a.rs"
(cd "$REF" && cargo run --locked -p liana --example liana_v9_signet_single_key_multi_a -- "$REF/signet-single-key-multi-a.txt") > "$REF/signet-single-key-multi-a.tsv"
python3 tests/oracle/build_liana_v9_signet_single_key_multi_a_fixture.py tests/fixtures/liana-v9-rust-signet-single-primary-recovery.json "$REF/signet-single-key-multi-a.txt" "$REF/signet-single-key-multi-a.tsv" "$REF/signet-single-key-multi-a.json"
cmp tests/fixtures/liana-v9-rust-signet-single-key-multi-a.json "$REF/signet-single-key-multi-a.json"
```

The negative `liana-v9-rust-signet-duplicate-xpub.json` fixture checks the duplicate identity rule across the spendable internal primary key and recovery signer. It preserves the same xpub and derivation paths but changes the origin fingerprint; the Rust harness first parses the descriptor syntax, then asserts the exact Liana policy error is `DuplicateKey`.

```sh
python3 tests/oracle/build_liana_v9_signet_duplicate_xpub_input.py tests/fixtures/liana-v9-rust-signet-single-primary-recovery.json "$REF/signet-duplicate-xpub.txt"
cp tests/oracle/liana_v9_signet_duplicate_xpub.rs "$REF/liana/examples/liana_v9_signet_duplicate_xpub.rs"
(cd "$REF" && cargo run --locked -p liana --example liana_v9_signet_duplicate_xpub -- "$REF/signet-duplicate-xpub.txt") > "$REF/signet-duplicate-xpub.tsv"
python3 tests/oracle/build_liana_v9_signet_duplicate_xpub_fixture.py tests/fixtures/liana-v9-rust-signet-single-primary-recovery.json "$REF/signet-duplicate-xpub.txt" "$REF/signet-duplicate-xpub.tsv" "$REF/signet-duplicate-xpub.json"
cmp tests/fixtures/liana-v9-rust-signet-duplicate-xpub.json "$REF/signet-duplicate-xpub.json"
```

The parser handles the tested Liana P2WSH `or_d` single-recovery, nested `or_i` multi-recovery, `andor(recovery, older(n), primary)`, and direct key-only `thresh` recovery policies; each recovery uses a key-only policy and a distinct positive decimal timelock. The `andor` and threshold fixtures' primary/recovery mappings are asserted by pinned Rust `LianaDescriptor::from_str`, not inferred from TypeScript. The Rust harness also confirms rejection of the nested B-type threshold candidate exercised by the TypeScript negative test. Coverage includes five mainnet P2WSH shapes and one exact pinned Signet descriptor, not every Miniscript/Liana form or broad network parity. Accepted descriptors include a lossless syntax AST with raw source spans; the AST is not complete Miniscript semantic validation. Other networks and broader grammar parity remain unverified. No general Liana compatibility claim is made.

## Pinned semantic rejection vectors

`tests/fixtures/liana-v9-rust-policy-rejections.json` records two checksummed Taproot descriptors that the pinned Rust `LianaDescriptor::from_str` rejects with `Descriptor is not compatible with a Liana spending policy.` One places a hashlock in a recovery leaf; the other places a hashlocked signer leaf alongside a primary key and a valid recovery. The TypeScript tests require the same descriptors to be rejected. The Rust harness checks the exact error, so malformed descriptor or checksum errors cannot masquerade as semantic-policy rejection.

```sh
cp tests/oracle/liana_v9_policy_rejections.rs "$REF/liana/examples/liana_v9_policy_rejections.rs"
(cd "$REF" && cargo run --locked -p liana --example liana_v9_policy_rejections) > "$REF/policy-rejections.tsv"
python3 tests/oracle/build_liana_v9_policy_rejections.py "$REF/policy-rejections.tsv" "$REF/policy-rejections.json"
cmp tests/fixtures/liana-v9-rust-policy-rejections.json "$REF/policy-rejections.json"
```

These negative cases tighten the tested Taproot subset only; they do not make the TypeScript importer a complete Miniscript semantic analyzer.

## BIP32 CKDpub vector cross-check

`tests/oracle/bip32_v1_public_children.rs` derives the non-hardened branch/index public keys from the [BIP32 Test Vector 1](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) account node `m/0'`, and a test-family-serialized account tpub at `m/48'/1'/0'/2'`, using the same published 16-byte seed. The TypeScript tests pin the full tpub and compressed branch 0/1 index-0 public keys. This covers the account-key serialization and CKDpub checks in the specification; the seed is a published conformance vector, not wallet material.

Reproduce from the pinned Liana source clone:

```sh
cp tests/oracle/bip32_v1_public_children.rs "$REF/liana/examples/bip32_v1_public_children.rs"
(cd "$REF" && cargo run --locked -p liana --example bip32_v1_public_children)
```

Expected output:

```text
tpub\ttpubDEC8p4skY4i7mNjxt9yF3u7my5T6KtGLcvEDcH5rKA6XVtJN4JV3SsHWoePTqsHNh47WBkQ79r77KsUYc2PAmaqqasBJMvidbxiupZpJexg
0\t027b6a7dd645507d775215a9035be06700e1ed8c541da9351b4bd14bd50ab61428
1\t03e10f4f003b36e87c070fcda5201bb5f3f8a4a9537f853e3aaca53a44f166b630
```

## BIP39 normalization vectors

`tests/bip32.test.ts` checks the published English BIP39 vector and the Japanese NFKD vector from [bip32JP test_JP_BIP39.json](https://github.com/bip32JP/bip32JP.github.io/blob/master/test_JP_BIP39.json). The Japanese case exercises an ideographic-space mnemonic, the Japanese wordlist, and a compatibility-form passphrase; its expected seed is a published conformance value, not wallet material.

## Third-party descriptor implementation evaluation

`tests/descriptors-library-parity.test.ts` checks `@bitcoinerlab/descriptors` independently against the pinned Rust fixtures. It expands each ordered multipath tuple by position before passing the descriptor to the library, then compares address and `scriptPubKey` for all 64 Rust vector pairs. This establishes parity for those fixtures only; it does not prove the library accepts every valid Liana policy or replace Liana-specific validation.

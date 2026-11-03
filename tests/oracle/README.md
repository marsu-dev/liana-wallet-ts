# Liana v9 Rust descriptor oracle

The fixture `../fixtures/liana-v9-rust-taproot-multisig.json` was generated from the pinned Liana Rust implementation, not from the TypeScript package. It contains four `LianaPolicy::new` policies: a single-key primary with one single-key recovery path, a 3-of-3 primary with one 2-of-3 recovery leaf, a 3-of-3 primary using `<0;1>` with a 2-of-3 recovery using `<2;3>`, and a 2-of-3 primary with three recovery paths. For each, Rust produced the descriptor plus receive/change addresses and exact `scriptPubKey` bytes at indices 0 and 1.

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

The Taproot Rust generator calls Liana's `LianaPolicy::new` and `LianaDescriptor::new`, then derives through `receive_descriptor()` and `change_descriptor()`. The converter rejects missing/duplicate rows and requires both indices for both branches and all four Taproot policies. The checked-in TypeScript test compares all sixteen Rust Taproot address and `scriptPubKey` pairs exactly.

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

The parser handles the tested Liana P2WSH `or_d` single-recovery, nested `or_i` multi-recovery, `andor(recovery, older(n), primary)`, and direct key-only `thresh` recovery policies; each recovery uses a key-only policy and a distinct positive decimal timelock. The `andor` and threshold fixtures' primary/recovery mappings are asserted by pinned Rust `LianaDescriptor::from_str`, not inferred from TypeScript. Coverage includes five mainnet P2WSH shapes and one exact pinned Signet descriptor, not every Miniscript/Liana form or broad network parity. Accepted descriptors include a lossless syntax AST with raw source spans; the AST is not complete Miniscript semantic validation. Other networks and broader grammar parity remain unverified. No general Liana compatibility claim is made.

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

The Rust generator calls Liana's `LianaPolicy::new` and `LianaDescriptor::new`, then derives through `receive_descriptor()` and `change_descriptor()`. The converter rejects missing/duplicate rows and requires both indices for both branches and all four policies. The checked-in TypeScript test compares all sixteen Rust address and `scriptPubKey` pairs exactly.

The fixtures `tests/fixtures/liana-v9-rust-legacy-wsh.json`, its multisig companion, and `liana-v9-rust-legacy-wsh-multiple-recovery.json` were generated from the pinned Rust implementation with `LianaPolicy::new_legacy`: one single-key primary/recovery policy, one 2-of-3 primary/recovery policy, and one 2-of-3 primary with three recovery paths (single-key, 2-of-3 and 1-of-3). Each records the descriptor plus mainnet receive/change addresses and `scriptPubKey`s for indices 0 and 1 (twelve pairs total). They use only public test xpubs and fingerprints; no seed or private key is stored.

To reproduce those fixtures from the pinned source clone:

```sh
cp tests/oracle/liana_v9_legacy_wsh.rs "$REF/liana/examples/oracle_wsh_vectors.rs"
(cd "$REF" && cargo run --locked -p liana --example oracle_wsh_vectors) > "$REF/wsh.tsv"
python3 tests/oracle/build_liana_v9_wsh_fixtures.py "$REF/wsh.tsv" "$REF/wsh-fixtures"
cmp tests/fixtures/liana-v9-rust-legacy-wsh.json "$REF/wsh-fixtures/liana-v9-rust-legacy-wsh.json"
cmp tests/fixtures/liana-v9-rust-legacy-wsh-multisig.json "$REF/wsh-fixtures/liana-v9-rust-legacy-wsh-multisig.json"
cmp tests/fixtures/liana-v9-rust-legacy-wsh-multiple-recovery.json "$REF/wsh-fixtures/liana-v9-rust-legacy-wsh-multiple-recovery.json"
```

The parser handles the tested Liana P2WSH `or_d` single-recovery and nested `or_i` multi-recovery forms, where each recovery pairs a key-only path with `older(n)`; it checks distinct positive decimal timelocks. Coverage includes one three-recovery policy, not every Miniscript/Liana policy form. Accepted descriptors now include a lossless syntax AST with raw source spans; the AST is not complete Miniscript semantic validation. Other networks and broader grammar parity remain unverified. No general Liana compatibility claim is made.

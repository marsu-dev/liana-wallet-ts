# Compatibility oracle notes

## Pinned Liana source

Use Liana tag `v9.0`, resolved annotated-tag commit `398e622596e7530a328de3027cb2c09905f708c6` (tag object `47c16fe1287573f49bee743bfcfd57bf9ab73387`). The Liana crate declares Miniscript 11.0; its `Cargo.lock` pins `miniscript` 11.2.0. Keep both the tag and lockfile version pinned when producing oracle vectors.

Relevant source locations:

- [`liana/src/descriptors/mod.rs`](https://github.com/wizardsardine/liana/blob/398e622596e7530a328de3027cb2c09905f708c6/liana/src/descriptors/mod.rs): Liana descriptor parsing and script/address derivation.
- [`liana/src/descriptors/analysis.rs`](https://github.com/wizardsardine/liana/blob/398e622596e7530a328de3027cb2c09905f708c6/liana/src/descriptors/analysis.rs): policy analysis and `unspendable_internal_xpub`; `bip341_nums` uses compressed point `0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`. The chain code hashes the ordered public-key encodings encountered by walking TapTree leaves and each Miniscript's `iter_pk()`.
- [`liana/src/descriptors/keys.rs`](https://github.com/wizardsardine/liana/blob/398e622596e7530a328de3027cb2c09905f708c6/liana/src/descriptors/keys.rs): key parsing and derived public-key representation.

## Signet fixture

`tests/fixtures/liana-v9-signet-single-primary-recovery.json` records the full receive/change descriptors and index-0 address vectors from the community gist at <https://gist.github.com/jdlcdl/b17c6b551839adb5b7b7d4ef9574e48e>. The source reports Liana v9.0 and uses Bitcoin Core `deriveaddresses`; it is an independent cross-check for a single-key primary path with a 36-block recovery path. It is **not** a multisig or NUMS oracle, nor an upstream Rust-maintained test vector. Mnemonic/private material from the gist is deliberately excluded.

The fixture includes a receive scriptPubKey recorded by the gist's Bitcoin Core output. Change address is included; add its scriptPubKey and further address indexes only when extracted directly from the full source or independently reproduced by the pinned oracle.

## Validation requirements

- Verify the stored descriptor checksums before using fixtures.
- Regenerate addresses and scriptPubKeys from the pinned Rust oracle; do not treat the community fixture alone as proof of Rust parity.
- Obtain or generate separate multisig-primary vectors, including one and multiple recovery leaves, before claiming the multisig path compatible.

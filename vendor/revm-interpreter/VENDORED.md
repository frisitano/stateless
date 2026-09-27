# Vendored revm-interpreter 43.0.2

`revm-interpreter` 43.0.2 as published on crates.io (bluealloy/revm `6b2e655b`, `crates/interpreter`),
with one change: a `zkvm-u256` feature that makes MUL, DIV, MOD, ADDMOD, MULMOD and EXP call the
`zkvm_u256_*` functions of the zkVM SDK the guest is linked against, on `U256`'s little-endian limbs.
Stack handling and gas are unchanged. See `src/instructions/arithmetic.rs`.

Only the zkVM-agnostic guest crate (`bin/stateless-validator-reth/zkvm`) patches it in, through
`[patch.crates-io]`, and enables the feature. Kept here until the change lives in a revm fork or
upstream; a revm upgrade needs this directory replaced by the new version plus the same change.

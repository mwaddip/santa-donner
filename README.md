# santa-donner

**donner** — the SANTA block-tier conformance runner for
[ergo-node-rust](../ergo-node-rust) (enr). Drives enr's digest-mode block
validation (`DigestValidator::from_state` + `BlockValidator::apply_state`)
against committed `santa-block/v1` vectors, the way blitzen drives sigma-rust.

SANTA mounts this repo as a git submodule at `runners/donner`.

## Contract & spec

- Runner spec: `~/projects/santa/prompts/rust-node-donner-runner.md` (shapes frozen)
- Tier contract: `~/projects/santa/docs/contract/runner-contract-block.md`
- Vectors: `~/projects/santa/vectors/block/v6/` (3 captured + 6 authored, live since santa `2f3dbdd`)

## Shape (per spec §1)

- `runner.json` — capability manifest (`tiers: ["block"]`)
- `santa-run` — entry script: `santa-run <impl-path> <vectors-dir> <out-dir>`
- `mise.toml` — self-provisioning toolchain
- runner crate — path-deps enr's `validation` crate

## Status

Repo created 2026-06-10. Implementation pending.

Open: whether donner v1 declares `cost: true` (requires enr's `validation`
crate to surface block-accumulated cost — currently discarded at
`validation/src/tx_validation.rs:160`) or ships `cost: false` (contract-legal;
the cost dimension goes ungraded, not coal).

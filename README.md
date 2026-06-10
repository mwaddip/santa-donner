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

Implemented 2026-06-10, `cost: true`. Full board against the committed
vectors at santa `2f3dbdd`: captured 3/3 (valid + post_digest + cost),
authored 6/6 — run via `./santa-run <enr-checkout> <vectors-dir> <out-dir>`.

Building donner surfaced (and enr fixed, same day): the missing block-level
maxBlockCost sum check, the missing `exBlockVersion` gate, and a v1-only
`transactions_root` in enr's mining crate (mined v2+ blocks would have been
orphaned). It also exposed a sigma-rust round-trip asymmetry — its serializer
emits `"d": null` for v2 PoW solutions, its deserializer rejects null — which
the runner normalizes around (`normalize_header_json`; drop when upstream
fixes).

## Composition

Per-entry: `enr_chain::verify_pow` (hdrPoW) → `ergo_mining::candidate::
transactions_root` vs header (bsCorrespondsToHeader; the live node gets this
binding from wire modifier-ids, which the runner bypasses) → fresh
`DigestValidator::from_state(parent_digest, H-1, checkpoint=0)` +
`apply_state` (proofs digest, state replay, params incl. version gate) →
`evaluate_scripts` (verdict + block-accumulated cost). Panic-isolated per
entry; `expected` never read.

//! donner — SANTA block-tier conformance runner (`santa-block/v1`).
//!
//! Drives ergo-node-rust's digest-mode block validation against committed
//! vectors: per entry a FRESH `DigestValidator::from_state(parent_digest,
//! height-1, checkpoint=0)`, `apply_state` over wire-serialized sections,
//! then `evaluate_scripts` for the verdict + block-accumulated cost.
//!
//! Invocation (by santa-run): `donner-runner <vectors-dir> <out-dir>`.
//! For each `*.json` vector file, writes `<out-dir>/<same-filename>` with
//! `{ "<entry-name>": <actuals>, ... }`.
//!
//! Totality: the runner never aborts on an entry. A clean rejection is a
//! verdict (`valid: false, error: null`); a decode/setup failure is
//! `error: "errored"`; a caught panic is `error: "panicked"` + note.
//! `expected` is never read — the runner decides, SANTA grades.

mod chain_tier;
mod nipopow;

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::process::ExitCode;

use enr_chain::{ADDigest, Header};
use ergo_validation::{
    serialize_ad_proofs, serialize_block_transactions, serialize_extension, BlockValidator,
    DigestValidator, Parameter, Parameters, Transaction,
};
use serde_json::{json, Value};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: donner-runner <vectors-dir> <out-dir>");
        return ExitCode::FAILURE;
    }
    let vectors_dir = Path::new(&args[1]);
    let out_dir = Path::new(&args[2]);

    let mut entries: Vec<_> = match std::fs::read_dir(vectors_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect(),
        Err(e) => {
            eprintln!("cannot read vectors dir {}: {e}", vectors_dir.display());
            return ExitCode::FAILURE;
        }
    };
    entries.sort();

    let mut hard_failures = 0u32;
    for path in entries {
        let file_name = path.file_name().unwrap().to_string_lossy().into_owned();
        let results = run_vector_file(&path);
        let out_path = out_dir.join(&file_name);
        match serde_json::to_string_pretty(&results)
            .map_err(|e| e.to_string())
            .and_then(|s| std::fs::write(&out_path, s).map_err(|e| e.to_string()))
        {
            Ok(()) => eprintln!("{}: {} entries", file_name, results.len()),
            Err(e) => {
                eprintln!("cannot write {}: {e}", out_path.display());
                hard_failures += 1;
            }
        }
    }

    if hard_failures > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Process one vector file into its actuals map. Never panics, never aborts:
/// file-level decode problems surface as `errored` per recoverable entry.
fn run_vector_file(path: &Path) -> BTreeMap<String, Value> {
    let mut results = BTreeMap::new();

    let vector = match std::fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str::<Value>(&s).map_err(|e| e.to_string()))
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}: unreadable vector file: {e}", path.display());
            return results;
        }
    };
    let schema = vector
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or("santa-block/v1");
    let entries = match vector.get("entries").and_then(Value::as_array) {
        Some(arr) => arr,
        None => {
            eprintln!("{}: no entries[] — emitting empty actuals", path.display());
            return results;
        }
    };
    let is_chain = schema.starts_with("santa-chain/");
    let is_nipopow = schema.starts_with("santa-nipopow/");
    let chain_json = if is_nipopow {
        vector.get("chain").and_then(Value::as_array)
    } else {
        None
    };

    for (idx, entry) in entries.iter().enumerate() {
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("entry-{idx}"));

        // Per-entry panic boundary: one entry never aborts the file. Rayon
        // (inside evaluate_scripts) resumes worker panics at the join point,
        // so this catches those too.
        let actuals = catch_unwind(AssertUnwindSafe(|| {
            if is_chain {
                chain_tier::run_chain_entry(entry)
            } else if is_nipopow {
                let chain = chain_json.expect("nipopow vector missing chain");
                let kind = entry["kind"].as_str().unwrap_or("");
                match kind {
                    "nipopow_interlinks" => nipopow::run_interlinks(chain),
                    "nipopow_prove" => {
                        let m = entry["payload"]["m"].as_u64().expect("missing m") as u32;
                        let k = entry["payload"]["k"].as_u64().expect("missing k") as u32;
                        let hid = entry["payload"]["headerId"].as_str();
                        nipopow::run_prove(chain, m, k, hid)
                    }
                    _ => json!({"error": "not-implemented"}),
                }
            } else {
                run_entry(entry)
            }
        }))
            .unwrap_or_else(|payload| {
                let note = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "panic payload not a string".to_string());
                json!({ "error": "panicked", "note": note })
            });
        results.insert(name, actuals);
    }

    results
}

fn errored(reason: String) -> Value {
    json!({
        "valid": null, "post_digest": null, "cost": null,
        "error": "errored", "reason": reason,
    })
}

fn reject(reason: String) -> Value {
    json!({
        "valid": false, "post_digest": null, "cost": null,
        "error": null, "reason": reason,
    })
}

fn run_entry(entry: &Value) -> Value {
    // ---- decode phase: failures here are setup errors, not verdicts ----
    let input = match decode_entry(entry) {
        Ok(i) => i,
        Err(e) => return errored(e),
    };

    // ---- verdict phase: errors below = the validator DECIDED invalid ----
    // Composition mirrors the node's layering + the JVM oracle recipe:
    // hdrPoW (chain/) → bsCorrespondsToHeader txroot (the wire binding,
    // replayed via mining's Merkle fn) → apply_state (proofs digest, state
    // replay, params) → script eval + block cost.

    if let Err(e) = enr_chain::verify_pow(&input.header) {
        return reject(format!("hdrPoW: {e}"));
    }

    match ergo_mining::candidate::transactions_root(&input.transactions, input.header.version) {
        Ok(root) if root == input.header.transaction_root => {}
        Ok(root) => {
            return reject(format!(
                "bsCorrespondsToHeader: transactionsRoot {} != header {}",
                hex::encode(root.0),
                hex::encode(input.header.transaction_root.0),
            ))
        }
        Err(e) => return reject(format!("bsCorrespondsToHeader: transactionsRoot: {e}")),
    }

    // Epoch-boundary expectations (JVM exBlockVersion + exMatchParameters).
    // The tier hands the PRE-STATE in-force table; at a boundary that handed
    // table IS the trustworthy calculated-params operand — deriving from the
    // block's own extension would be the trusting-self-declared-data class.
    // The ≤10 window carries no epoch vote history, so stepped boundaries are
    // out of v1 scope (the retarget-exclusion class). proposed-update comes
    // from the block's own extension — JVM-exact (its matchParameters60
    // compares same-block operands). v6 vectors are testnet: epoch length 128
    // (JVM TestnetVotingSettings.votingLength; enr chain/src/voting.rs:91 —
    // not pub-exported, hence the literal).
    const TESTNET_VOTING_LENGTH: u32 = 128;
    let (expected_boundary, expected_update) = if input.header.height % TESTNET_VOTING_LENGTH == 0 {
        let fields = match enr_chain::parse_extension_bytes(&input.ext_section) {
            Ok((_hid, fields)) => fields,
            Err(e) => return reject(format!("extension parse: {e}")),
        };
        (
            Some(&input.parameters),
            Some(enr_chain::extract_disabling_rules_from_kv(&fields)),
        )
    } else {
        (None, None)
    };

    let mut validator =
        DigestValidator::from_state(input.parent_digest, input.header.height - 1, 0);

    // enr folded script evaluation INTO apply_state (its `BlockValidator` doc:
    // "parse sections, compute state changes, apply AVL operations, verify
    // digest, evaluate scripts, persist — in that order. After Ok … the block's
    // scripts have been evaluated and passed … there is nothing left owed").
    // `ApplyStateOutcome` no longer carries a `deferred_eval` bundle for the
    // caller to run — the bundle "never leaves the stack frame that built it".
    // So an Ok here already means the scripts passed; the reject arm below is
    // the only verdict branch left.
    if let Err(e) = validator.apply_state(
        &input.header,
        &input.txs_section,
        input.proofs_section.as_deref(),
        &input.ext_section,
        &input.preceding_headers,
        &input.parameters,
        expected_boundary,
        expected_update.as_deref(),
    ) {
        return reject(e.to_string());
    }

    // COST IS NOT REPORTABLE from this path any more, so we emit null rather
    // than a fabricated number. enr discards it deliberately inside the
    // validator ("Cost discarded, not unchecked — the maxBlockCost gate runs
    // inside evaluate_scripts", validation/src/digest.rs), and the only inputs
    // that could recompute it (`ScriptEvalInputs.proof_boxes`) are AVL-extracted
    // during the state replay and never surface. Rebuilding them here would be
    // exactly the parallel reimplementation this runner exists to avoid.
    //
    // Grading degrades cleanly: santa-check's grade_block only grades cost when
    // BOTH sides declare it non-null, so a null actual scores "n/a", never coal
    // — an honest coverage gap, not a false divergence. Restoring the dimension
    // needs enr to surface the cost on ApplyStateOutcome.
    let post_digest = hex::encode(<[u8; 33]>::from(validator.current_digest().clone()));
    json!({
        "valid": true, "post_digest": post_digest, "cost": null, "error": null,
    })
}

struct EntryInput {
    parent_digest: ADDigest,
    header: Header,
    preceding_headers: Vec<Header>,
    parameters: Parameters,
    transactions: Vec<Transaction>,
    txs_section: Vec<u8>,
    proofs_section: Option<Vec<u8>>,
    ext_section: Vec<u8>,
}

/// Strip `"d": null` from a header JSON's powSolutions before handing it to
/// ergo-chain-types serde.
///
/// sigma-rust round-trip asymmetry (rev a4ee7442): the `d` serializer emits
/// JSON `null` for v2 solutions (`pow_distance: None` → `serialize_unit`),
/// but `bigint_from_serde_json_number` only accepts String|Number — null is
/// rejected. The field is `serde(default)`, so an ABSENT key deserializes to
/// `None` correctly. The committed vectors carry the emitted `null` (they came
/// from this serializer via the node API), hence this normalization. Remove
/// when the upstream fix lands.
fn decode_entry(entry: &Value) -> Result<EntryInput, String> {
    let parent_digest = {
        let hex_str = entry
            .get("parent_digest")
            .and_then(Value::as_str)
            .ok_or("parent_digest missing")?;
        let bytes: [u8; 33] = hex::decode(hex_str)
            .map_err(|e| format!("parent_digest hex: {e}"))?
            .try_into()
            .map_err(|_| "parent_digest is not 33 bytes".to_string())?;
        ADDigest::from(bytes)
    };

    let header: Header = {
        let mut h = entry
            .get("block")
            .and_then(|b| b.get("header"))
            .cloned()
            .ok_or("block.header missing")?;
        serde_json::from_value(h).map_err(|e| format!("block.header decode: {e}"))?
    };

    if header.height == 0 {
        return Err("header.height is 0 — no parent state to anchor".to_string());
    }

    let preceding_headers: Vec<Header> = {
        let hs = entry.get("headers").cloned().ok_or("headers missing")?;
        serde_json::from_value(hs).map_err(|e| format!("headers decode: {e}"))?
    };
    if preceding_headers.is_empty() {
        return Err("headers window is empty".to_string());
    }

    let parameters = decode_parameters(entry)?;

    let header_id: [u8; 32] = header.id.0 .0;
    let block = entry.get("block").ok_or("block missing")?;

    let transactions: Vec<Transaction> = serde_json::from_value(
        block
            .get("blockTransactions")
            .and_then(|bt| bt.get("transactions"))
            .cloned()
            .ok_or("block.blockTransactions.transactions missing")?,
    )
    .map_err(|e| format!("transactions decode: {e}"))?;
    let txs_section =
        serialize_block_transactions(&header_id, header.version as u32, &transactions)
            .map_err(|e| format!("blockTransactions serialize: {e}"))?;

    // proofBytes: null or absent means proofless block (consensus reject).
    let proof_bytes_opt: Option<Vec<u8>> =
        match block.get("adProofs").and_then(|p| p.get("proofBytes")) {
            Some(Value::String(s)) if !s.is_empty() => Some(
                hex::decode(s).map_err(|e| format!("proofBytes hex: {e}"))?,
            ),
            _ => None,
        };
    let proofs_section = proof_bytes_opt
        .as_deref()
        .map(|pb| serialize_ad_proofs(&header_id, pb));

    let fields_json = block
        .get("extension")
        .and_then(|x| x.get("fields"))
        .and_then(Value::as_array)
        .ok_or("block.extension.fields missing")?;
    let mut fields: Vec<([u8; 2], Vec<u8>)> = Vec::with_capacity(fields_json.len());
    for (i, kv) in fields_json.iter().enumerate() {
        let key_hex = kv.get(0).and_then(Value::as_str).ok_or(format!("extension field {i}: key"))?;
        let val_hex = kv.get(1).and_then(Value::as_str).ok_or(format!("extension field {i}: value"))?;
        let key: [u8; 2] = hex::decode(key_hex)
            .map_err(|e| format!("extension field {i} key hex: {e}"))?
            .try_into()
            .map_err(|_| format!("extension field {i}: key is not 2 bytes"))?;
        let val = hex::decode(val_hex).map_err(|e| format!("extension field {i} value hex: {e}"))?;
        fields.push((key, val));
    }
    let ext_section = serialize_extension(&header_id, &fields)
        .map_err(|e| format!("extension serialize: {e}"))?;

    Ok(EntryInput {
        parent_digest,
        header,
        preceding_headers,
        parameters,
        transactions,
        txs_section,
        proofs_section,
        ext_section,
    })
}

/// Build `Parameters` from the vector's in-force table (decimal-string id →
/// int). Unknown ids are skipped with a stderr note — the handed table is the
/// epoch's full state; the engine only reads the ids it models.
fn decode_parameters(entry: &Value) -> Result<Parameters, String> {
    let table = entry
        .get("parameters")
        .and_then(|p| p.get("table"))
        .and_then(Value::as_object)
        .ok_or("parameters.table missing")?;

    let mut params = Parameters::default();
    for (id_str, value) in table {
        let id: i32 = id_str.parse().map_err(|_| format!("parameter id '{id_str}'"))?;
        let value = value
            .as_i64()
            .and_then(|v| i32::try_from(v).ok())
            .ok_or(format!("parameter {id_str}: value not an i32"))?;
        match parameter_from_id(id) {
            Some(p) => {
                params.parameters_table.insert(p, value);
            }
            None => eprintln!("parameters.table: skipping unmodeled id {id}"),
        }
    }
    Ok(params)
}

fn parameter_from_id(id: i32) -> Option<Parameter> {
    Some(match id {
        1 => Parameter::StorageFeeFactor,
        2 => Parameter::MinValuePerByte,
        3 => Parameter::MaxBlockSize,
        4 => Parameter::MaxBlockCost,
        5 => Parameter::TokenAccessCost,
        6 => Parameter::InputCost,
        7 => Parameter::DataInputCost,
        8 => Parameter::OutputCost,
        9 => Parameter::SubblocksPerBlock,
        121 => Parameter::SoftForkVotesCollected,
        122 => Parameter::SoftForkStartingHeight,
        123 => Parameter::BlockVersion,
        _ => return None,
    })
}

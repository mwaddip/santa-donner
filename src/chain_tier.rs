//! donner — chain tier (`santa-chain/v1`): retargeting + voting.
//!
//! Calls enr's PURE consensus seams with settings FROM THE ENTRY (contract
//! §5: never `ChainConfig::testnet()`/`mainnet()` presets — the
//! bundled-votingLength bug class). Kind dispatch per entry:
//!
//! - `retargeting`: classic `difficulty::calculate` vs `eip37_calculate`,
//!   arm chosen by the entry's settings (§2: eip37 iff the pair is present
//!   AND `target_height >= eip37_activation_height`; when it governs,
//!   `eip37_epoch_length` replaces `epoch_length` as the calculate arg).
//!   Anchors are handed (ascending) — no selection, no linkage checks
//!   (authored anchors share the donor's id by design).
//! - `voting`: seeded tally over the handed vote stream + the pure boundary
//!   parameter pipeline; emits the full next table + activated update.

use std::collections::HashMap;

use ergo_chain_types::Header;
use ergo_lib::chain::parameters::{Parameter, Parameters};
use serde_json::{json, Value};

use crate::normalize_header_json;

pub fn run_chain_entry(entry: &Value) -> Value {
    match entry.get("kind").and_then(Value::as_str) {
        Some("retargeting") => run_retargeting(entry),
        Some("voting") => run_voting(entry),
        Some(other) => not_implemented(format!("unknown chain kind '{other}'")),
        None => errored("entry has no kind".into()),
    }
}

fn errored(reason: String) -> Value {
    json!({ "nbits": null, "parameters": null, "activated_update": null,
            "error": "errored", "reason": reason })
}

fn not_implemented(_note: String) -> Value {
    json!({ "nbits": null, "parameters": null, "activated_update": null,
            "error": "not-implemented" })
}

// ---------------------------------------------------------------- retargeting

fn run_retargeting(entry: &Value) -> Value {
    let s = match entry.get("settings").and_then(Value::as_object) {
        Some(s) => s,
        None => return errored("settings missing".into()),
    };
    let get_u64 = |k: &str| s.get(k).and_then(Value::as_u64);
    let (epoch_length, block_interval_ms, initial_nbits) = match (
        get_u64("epoch_length"),
        get_u64("block_interval_ms"),
        get_u64("initial_nbits"),
    ) {
        (Some(e), Some(b), Some(i)) => (e as u32, b, i as u32),
        _ => return errored("retargeting settings incomplete".into()),
    };

    let target_height = match entry
        .get("payload")
        .and_then(|p| p.get("target_height"))
        .and_then(Value::as_u64)
    {
        Some(t) => t as u32,
        None => return errored("payload.target_height missing".into()),
    };

    let headers: Vec<Header> = {
        let mut hs = match entry.get("payload").and_then(|p| p.get("anchor_headers")) {
            Some(h) => h.clone(),
            None => return errored("payload.anchor_headers missing".into()),
        };
        if let Some(arr) = hs.as_array_mut() {
            arr.iter_mut().for_each(normalize_header_json);
        }
        match serde_json::from_value(hs) {
            Ok(v) => v,
            Err(e) => return errored(format!("anchor_headers decode: {e}")),
        }
    };
    let refs: Vec<&Header> = headers.iter().collect();

    // §2 arm dispatch — entry-settings-driven, eip37_epoch_length replaces
    // epoch_length throughout when the eip37 arm governs.
    let eip37 = match (get_u64("eip37_activation_height"), get_u64("eip37_epoch_length")) {
        (Some(act), Some(len)) if target_height as u64 >= act => Some(len as u32),
        _ => None,
    };

    let result = match eip37 {
        Some(eip37_len) => enr_chain::difficulty::eip37_calculate(
            &refs,
            eip37_len,
            block_interval_ms,
            initial_nbits,
        ),
        None => enr_chain::difficulty::calculate(
            &refs,
            epoch_length,
            block_interval_ms,
            initial_nbits,
        ),
    };

    match result {
        Ok(nbits) => json!({ "nbits": nbits, "error": null }),
        Err(e) => errored(format!("difficulty: {e}")),
    }
}

// -------------------------------------------------------------------- voting

fn run_voting(entry: &Value) -> Value {
    let s = match entry.get("settings").and_then(Value::as_object) {
        Some(s) => s,
        None => return errored("settings missing".into()),
    };
    let get_u32 = |k: &str| s.get(k).and_then(Value::as_u64).map(|v| v as u32);
    let voting = match (
        get_u32("voting_length"),
        get_u32("soft_fork_epochs"),
        get_u32("activation_epochs"),
        get_u32("version2_activation_height"),
    ) {
        (Some(vl), Some(sfe), Some(ae), Some(v2)) => enr_chain::voting::VotingConfig {
            voting_length: vl,
            soft_fork_epochs: sfe,
            activation_epochs: ae,
            version2_activation_height: v2,
        },
        _ => return errored("voting settings incomplete".into()),
    };

    let p = match entry.get("payload") {
        Some(p) => p,
        None => return errored("payload missing".into()),
    };
    let boundary_height = match p.get("boundary_height").and_then(Value::as_u64) {
        Some(h) => h as u32,
        None => return errored("payload.boundary_height missing".into()),
    };

    // vote_stream: [{height, votes: "<6 hex>"}] -> (height, [u8;3]) window
    let window: Vec<(u32, [u8; 3])> = {
        let arr = match p.get("vote_stream").and_then(Value::as_array) {
            Some(a) => a,
            None => return errored("payload.vote_stream missing".into()),
        };
        let mut out = Vec::with_capacity(arr.len());
        for (i, e) in arr.iter().enumerate() {
            let h = match e.get("height").and_then(Value::as_u64) {
                Some(h) => h as u32,
                None => return errored(format!("vote_stream[{i}].height missing")),
            };
            let v = match e.get("votes").and_then(Value::as_str).map(hex::decode) {
                Some(Ok(b)) if b.len() == 3 => [b[0], b[1], b[2]],
                _ => return errored(format!("vote_stream[{i}].votes malformed")),
            };
            out.push((h, v));
        }
        out
    };

    let current = match decode_table(p.get("current_parameters").and_then(|c| c.get("table"))) {
        Ok(t) => t,
        Err(e) => return errored(e),
    };

    let boundary_fork_vote = match p.get("boundary_votes").and_then(Value::as_str).map(hex::decode)
    {
        Some(Ok(b)) if b.len() == 3 => b.contains(&120u8),
        _ => return errored("payload.boundary_votes malformed".into()),
    };

    let proposed_update = match p.get("proposed_update").and_then(Value::as_str).map(hex::decode) {
        Some(Ok(b)) => b,
        _ => return errored("payload.proposed_update malformed".into()),
    };

    let tally =
        enr_chain::voting::tally_votes_seeded(&window, boundary_height, voting.voting_length);

    match enr_chain::voting::compute_boundary_parameters(
        &voting,
        boundary_height,
        &current,
        &tally,
        boundary_fork_vote,
        &proposed_update,
    ) {
        Ok((params, activated)) => {
            let table: std::collections::BTreeMap<String, i32> = params
                .parameters_table
                .iter()
                .filter_map(|(p, &v)| parameter_to_id(p).map(|id| (id.to_string(), v)))
                .collect();
            json!({
                "parameters": { "table": table },
                "activated_update": hex::encode(activated),
                "error": null,
            })
        }
        Err(e) => errored(format!("boundary parameters: {e}")),
    }
}

fn decode_table(table: Option<&Value>) -> Result<Parameters, String> {
    let table = table.and_then(Value::as_object).ok_or("current_parameters.table missing")?;
    let mut params = Parameters::default();
    params.parameters_table.clear();
    for (id_str, value) in table {
        let id: i32 = id_str.parse().map_err(|_| format!("parameter id '{id_str}'"))?;
        let value = value
            .as_i64()
            .and_then(|v| i32::try_from(v).ok())
            .ok_or(format!("parameter {id_str}: value not an i32"))?;
        match crate::parameter_from_id(id) {
            Some(p) => {
                params.parameters_table.insert(p, value);
            }
            None => return Err(format!("unmodeled parameter id {id}")),
        }
    }
    Ok(params)
}

fn parameter_to_id(p: &Parameter) -> Option<i32> {
    Some(match p {
        Parameter::StorageFeeFactor => 1,
        Parameter::MinValuePerByte => 2,
        Parameter::MaxBlockSize => 3,
        Parameter::MaxBlockCost => 4,
        Parameter::TokenAccessCost => 5,
        Parameter::InputCost => 6,
        Parameter::DataInputCost => 7,
        Parameter::OutputCost => 8,
        Parameter::SubblocksPerBlock => 9,
        Parameter::SoftForkVotesCollected => 121,
        Parameter::SoftForkStartingHeight => 122,
        Parameter::BlockVersion => 123,
        _ => return None,
    })
}

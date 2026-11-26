use ergo_chain_types::{ExtensionCandidate, Header};
use ergo_nipopow::{NipopowAlgos, PoPowHeader};
use serde_json::{json, Value};
use sigma_ser::ScorexSerializable;

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
        .collect()
}

fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn block_id_hex(id: &ergo_chain_types::BlockId) -> String {
    bytes_to_hex(id.0.as_ref())
}

fn parse_chain(chain_json: &[Value]) -> Vec<PoPowHeader> {
    let headers: Vec<Header> = chain_json
        .iter()
        .map(|h| {
            let hex = h["headerHex"].as_str().expect("missing headerHex");
            Header::scorex_parse_bytes(&hex_to_bytes(hex)).expect("header parse failed")
        })
        .collect();

    let mut popow = Vec::with_capacity(headers.len());

    let genesis_il = vec![headers[0].id];
    let genesis_ext =
        ExtensionCandidate::new(NipopowAlgos::pack_interlinks(genesis_il.clone()))
            .expect("genesis ext");
    let genesis_proof =
        NipopowAlgos::proof_for_interlink_vector(&genesis_ext).expect("genesis proof");
    popow.push(PoPowHeader {
        header: headers[0].clone(),
        interlinks: genesis_il,
        interlinks_proof: genesis_proof,
    });

    for i in 1..headers.len() {
        let prev = &popow[i - 1];
        let il = NipopowAlgos::update_interlinks(prev.header.clone(), prev.interlinks.clone())
            .expect("update_interlinks");
        let ext = ExtensionCandidate::new(NipopowAlgos::pack_interlinks(il.clone()))
            .expect("ext");
        let proof = NipopowAlgos::proof_for_interlink_vector(&ext).expect("proof");
        popow.push(PoPowHeader {
            header: headers[i].clone(),
            interlinks: il,
            interlinks_proof: proof,
        });
    }
    popow
}

pub fn run_interlinks(chain_json: &[Value]) -> Value {
    let popow = parse_chain(chain_json);
    let il: Vec<Value> = popow
        .iter()
        .map(|ph| {
            Value::Array(ph.interlinks.iter().map(|id| json!(block_id_hex(id))).collect())
        })
        .collect();
    json!({ "interlinks": il, "error": null })
}

pub fn run_prove(chain_json: &[Value], m: u32, k: u32, header_id: Option<&str>) -> Value {
    let popow = parse_chain(chain_json);
    let chain = if let Some(hid) = header_id {
        let hid_lower = hid.to_lowercase();
        let idx = popow
            .iter()
            .position(|ph| block_id_hex(&ph.header.id) == hid_lower)
            .expect("headerId not found");
        popow[..idx + k as usize + 1].to_vec()
    } else {
        popow
    };

    let algos = NipopowAlgos::default();
    let proof = algos.prove(&chain, k, m).expect("prove failed");
    // `proofHex` is ergo's `NipopowProofSerializer.toBytes`, which ends with the proof's `continuous` flag
    // (`NipopowProof.scala:208`). The flag is not computed by the prover: it encodes an input, and this tier fixes it
    // at `continuous = false` (runner-contract-nipopow §2, §5). sigma-rust's `NipopowProof` has no field for it, so
    // the runner writes the 0 — as the blitzen runners have since santa-blitzen `6ba7773` (2026-09-30).
    let mut proof_bytes = proof.scorex_serialize_bytes().expect("serialize");
    proof_bytes.push(0);
    json!({ "proofHex": bytes_to_hex(&proof_bytes), "error": null })
}


#[cfg(test)]
mod tests {
    use super::*;

    /// SANTA's `NipopowProve.jvm-chain-32` (copied into `tests/fixtures/`): every prove entry answers the reference's
    /// `proofHex`, byte for byte, its final `continuous` byte included.
    #[test]
    fn prove_entries_answer_the_reference_bytes() {
        let doc: Value =
            serde_json::from_str(include_str!("../tests/fixtures/nipopow-chain-32.json")).expect("fixture");
        let chain = doc["chain"].as_array().expect("chain");
        let mut n = 0;
        for e in doc["entries"].as_array().expect("entries").iter().filter(|e| e["kind"] == "nipopow_prove") {
            let p = &e["payload"];
            let got = run_prove(chain, p["m"].as_u64().unwrap() as u32, p["k"].as_u64().unwrap() as u32,
                p["headerId"].as_str());
            assert_eq!(got["proofHex"], e["expected"]["proofHex"], "{}", e["name"]);
            n += 1;
        }
        assert_eq!(n, 4, "the fixture's four prove entries");
    }
}

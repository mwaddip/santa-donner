//! Dump all UTXO AVL tree entries from a donner state.redb as JSON.
//!
//! Reads the tree at the current (latest) version and walks every leaf,
//! skipping sentinel leaves.  The output is the `initial_entries` payload
//! for `POST /avl-proof` plus a `meta` block with block height and tree
//! digest so the caller knows what state they're working with.
//!
//! Usage:
//!   dump-avl-tree <state-redb-path>
//!
//! Output (stdout):
//!   {
//!     "meta": { "block_height": 28473, "tree_digest": "hex..." },
//!     "key_length": 32,
//!     "value_length": null,
//!     "entries": [ { "key": "hex...", "value": "hex..." }, ... ]
//!   }
//!
//! The node MUST be stopped — redb holds an exclusive lock.

use std::path::PathBuf;
use std::process;

use enr_state::{AVLTreeParams, CacheSize, RedbAVLStorage};
use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
use ergo_avltree_rust::batch_node::{AVLTree, Node};
use ergo_avltree_rust::versioned_avl_storage::VersionedAVLStorage;
use serde_json::json;

/// Collect all (key, value) pairs from the tree via recursive DFS,
/// skipping sentinel leaves (negative-infinity [0u8;32] and positive-infinity [0xFF;32]).
fn collect_entries(tree: &AVLTree, node_id: &ergo_avltree_rust::batch_node::NodeId,
                    out: &mut Vec<(Vec<u8>, Vec<u8>)>) {
    let node = node_id.borrow().clone();
    match node {
        Node::Internal(_internal) => {
            let left = tree.left(node_id);
            let right = tree.right(node_id);
            collect_entries(tree, &left, out);
            collect_entries(tree, &right, out);
        }
        Node::Leaf(_leaf) => {
            let key = tree.key(node_id);
            let neg_inf = vec![0u8; tree.key_length];
            let pos_inf = vec![0xFFu8; tree.key_length];
            if key == neg_inf || key == pos_inf {
                return; // sentinel — not a real UTXO entry
            }
            let value = tree.value(node_id);
            out.push((key.to_vec(), value.to_vec()));
        }
        Node::LabelOnly(_) => {
            // Should not appear in a fully-resolved tree loaded from storage.
            // The root was unpacked; internal nodes are resolved by left()/right().
            eprintln!("warning: LabelOnly node during traversal — tree may be incomplete");
        }
    }
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: dump-avl-tree <state-redb-path>");
        process::exit(1);
    });

    let db_path = PathBuf::from(&path);
    if !db_path.exists() {
        eprintln!("error: {path} does not exist");
        process::exit(1);
    }

    // ── open storage ──────────────────────────────────────────────────
    let tree_params = AVLTreeParams {
        key_length: 32,
        value_length: None, // Ergo UTXO tree: variable-length box bytes
    };
    let storage = RedbAVLStorage::open(
        &db_path,
        tree_params,
        0, // keep_versions — don't care for read-only dump
        CacheSize::Bytes(64 * 1024 * 1024),
    )
    .unwrap_or_else(|e| {
        eprintln!("error opening {path}: {e}");
        process::exit(1);
    });

    let block_height = storage.block_height();
    let (root_label, tree_height) = storage.root_state().unwrap_or_else(|| {
        eprintln!("error: no root state in database (empty/uninitialised?)");
        process::exit(1);
    });

    let root_bytes = storage
        .get_node(&root_label)
        .unwrap_or_else(|e| {
            eprintln!("error reading root node: {e}");
            process::exit(1);
        })
        .unwrap_or_else(|| {
            eprintln!("error: root node not found in database");
            process::exit(1);
        });

    // ── build in-memory tree ──────────────────────────────────────────
    let resolver = storage.resolver();
    let mut tree = AVLTree::with_resolver(resolver, 32, None);
    let root_node = tree.unpack(&root_bytes);
    tree.root = Some(root_node);
    tree.height = tree_height;

    let prover = BatchAVLProver::new(tree, false);
    prover.base.tree.reset(); // clear is_new flags on unpacked nodes

    let root_id = prover.base.tree.root.clone().unwrap();
    let digest = prover.digest().expect("prover has no digest");

    // ── walk the tree ─────────────────────────────────────────────────
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    collect_entries(&prover.base.tree, &root_id, &mut entries);

    // ── output ────────────────────────────────────────────────────────
    let entry_json: Vec<serde_json::Value> = entries
        .iter()
        .map(|(k, v)| {
            json!({
                "key": hex::encode(k),
                "value": hex::encode(v),
            })
        })
        .collect();

    // ── version info ────────────────────────────────────────────────────
    let version_count = storage.rollback_versions().count();
    let current_version = storage.version().map(|v| hex::encode(v.as_ref()));

    let output = json!({
        "meta": {
            "block_height": block_height,
            "tree_digest": hex::encode(digest.as_ref()),
            "version_count": version_count,
            "current_version_digest": current_version,
        },
        "key_length": 32,
        "value_length": serde_json::Value::Null,
        "entries": entry_json,
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

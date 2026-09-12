use ipsa_scp_verifier::history::{ArchivedEnvelope, ScpHistoryEntry};
use ipsa_scp_verifier::network::Network;
use ipsa_scp_verifier::sweep::{merge_slot, sweep, Options, Outcome};

const CHECKPOINT: u32 = 4_290_047;
const FIRST: u32 = 4_289_984;

fn archive_dir() -> String {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/archive/testnet")
        .display()
        .to_string()
}

fn options(from: u32, to: u32) -> Options {
    Options {
        network: Network::Testnet,
        archives: vec![archive_dir()],
        from,
        to,
        next_slot: false,
        results: false,
        trust_root_xdr: None,
        jsonl: None,
    }
}

#[tokio::test]
async fn a_whole_checkpoint_sweeps_offline_from_a_local_archive() {
    let rows = sweep(&options(FIRST, CHECKPOINT))
        .await
        .expect("sweep runs");

    assert_eq!(rows.len(), 64, "one row per ledger in the checkpoint");
    assert!(
        rows.iter().all(|r| r.outcome == Outcome::Verified),
        "every ledger in this checkpoint should verify, got {:?}",
        rows.iter()
            .filter(|r| r.outcome != Outcome::Verified)
            .map(|r| (r.ledger, r.outcome.tag(), r.reason.clone()))
            .collect::<Vec<_>>()
    );
    assert!(rows.iter().all(|r| r.externalize >= 3));
    assert!(rows.iter().all(|r| r.conflicts == 0));
}

#[tokio::test]
async fn a_ledger_outside_the_mirrored_checkpoint_is_missing_evidence_not_a_finding() {
    let rows = sweep(&options(FIRST - 1, FIRST - 1))
        .await
        .expect("sweep runs");

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, Outcome::NoScpEvidence);
    assert!(
        !rows[0].outcome.is_finding(),
        "an archive gap must never count as a verifier finding"
    );
}

#[tokio::test]
async fn every_row_carries_the_protocol_version_it_ran_under() {
    let rows = sweep(&options(FIRST, FIRST + 3)).await.expect("sweep runs");

    assert!(rows.iter().all(|r| r.protocol.is_some()));
}

fn envelope(node: u8, kind: i32, value: &[u8]) -> ArchivedEnvelope {
    let node_id = [node; 32];
    let mut statement = vec![0, 0, 0, 0];
    statement.extend_from_slice(&node_id);
    statement.extend_from_slice(&7u64.to_be_bytes());
    statement.extend_from_slice(&2i32.to_be_bytes());
    statement.extend_from_slice(&1u32.to_be_bytes());
    statement.extend_from_slice(&(value.len() as u32).to_be_bytes());
    statement.extend_from_slice(value);
    while statement.len() % 4 != 0 {
        statement.push(0);
    }
    statement.extend_from_slice(&1u32.to_be_bytes());
    statement.extend_from_slice(&[0u8; 32]);

    let mut envelope_xdr = statement.clone();
    envelope_xdr.extend_from_slice(&64u32.to_be_bytes());
    envelope_xdr.extend_from_slice(&[0u8; 64]);

    ArchivedEnvelope {
        node_id,
        slot_index: 7,
        statement_type: kind,
        statement_xdr: statement,
        signature: vec![0u8; 64],
        envelope_xdr,
    }
}

fn entry(envelopes: Vec<ArchivedEnvelope>) -> ScpHistoryEntry {
    ScpHistoryEntry {
        ledger_seq: 7,
        quorum_sets_xdr: vec![vec![1, 2, 3]],
        envelopes,
    }
}

#[test]
fn merging_archives_unions_signers_by_node() {
    let a = entry(vec![envelope(1, 2, b"value-a")]);
    let b = entry(vec![envelope(2, 2, b"value-a")]);

    let merged = merge_slot(&[&a, &b]).expect("merge");

    assert_eq!(merged.externalize_xdr.len(), 2);
    assert_eq!(merged.total_envelopes, 2);
    assert!(merged.conflicting_nodes.is_empty());
}

#[test]
fn the_same_envelope_from_two_archives_counts_once() {
    let a = entry(vec![envelope(1, 2, b"value-a")]);
    let b = entry(vec![envelope(1, 2, b"value-a")]);

    let merged = merge_slot(&[&a, &b]).expect("merge");

    assert_eq!(
        merged.externalize_xdr.len(),
        1,
        "a node that appears in both archives must not be counted twice"
    );
}

#[test]
fn a_node_pledging_two_values_is_dropped_and_reported() {
    let a = entry(vec![envelope(1, 2, b"value-a"), envelope(2, 2, b"value-a")]);
    let b = entry(vec![envelope(1, 2, b"value-b")]);

    let merged = merge_slot(&[&a, &b]).expect("merge");

    assert_eq!(merged.conflicting_nodes.len(), 1);
    assert_eq!(merged.conflicting_nodes[0], hex::encode([1u8; 32]));
    assert_eq!(
        merged.externalize_xdr.len(),
        1,
        "the conflicting node is removed rather than resolved by archive order"
    );
}

#[test]
fn non_externalize_envelopes_are_counted_but_not_used() {
    let a = entry(vec![envelope(1, 2, b"value-a"), envelope(3, 1, b"value-a")]);

    let merged = merge_slot(&[&a]).expect("merge");

    assert_eq!(merged.total_envelopes, 2);
    assert_eq!(merged.externalize_xdr.len(), 1);
}

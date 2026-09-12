use ipsa_scp_verifier::steps;
use ipsa_scp_verifier::sweep::Checkpoint;

fn checkpoint_with(headers: &[(u32, Vec<u8>)]) -> Checkpoint {
    let mut cp = Checkpoint::default();
    for (seq, xdr) in headers {
        cp.headers.insert(
            *seq,
            ipsa_scp_verifier::history::HeaderHistoryEntry {
                recorded_hash: [0u8; 32],
                ledger_seq: *seq,
                header_xdr: xdr.clone(),
            },
        );
    }
    cp
}

#[test]
fn the_parent_hash_is_the_hash_of_the_preceding_header() {
    let parent_xdr = vec![1u8, 2, 3, 4];
    let cp = checkpoint_with(&[(41, parent_xdr.clone()), (42, vec![9u8; 8])]);

    let expected = steps::verify_ledger_hash(&parent_xdr, None).unwrap();

    assert_eq!(cp.parent_hash(42), Some(expected));
}

#[test]
fn a_ledger_whose_predecessor_is_absent_has_no_parent_hash() {
    let cp = checkpoint_with(&[(42, vec![9u8; 8])]);

    assert_eq!(cp.parent_hash(42), None);
}

#[test]
fn ledger_zero_has_no_parent_to_check() {
    let cp = checkpoint_with(&[(0, vec![9u8; 8])]);

    assert_eq!(cp.parent_hash(0), None);
}

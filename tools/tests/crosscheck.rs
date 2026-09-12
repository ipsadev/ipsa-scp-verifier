use std::collections::BTreeMap;
use tools::crosscheck::*;

#[test]
fn checkpoints_round_up_to_the_next_boundary() {
    assert_eq!(checkpoint_for(63907880), 63907903);
    assert_eq!(checkpoint_for(63), 63);
    assert_eq!(checkpoint_for(64), 127);
    assert_eq!(checkpoint_for(0), 63);
}

#[test]
fn sha256_matches_a_known_vector() {
    assert_eq!(
        hex::encode(sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn network_id_is_the_hash_of_the_passphrase() {
    assert_eq!(
        hex::encode(sha256(MAINNET.passphrase.as_bytes())),
        "7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979"
    );
}

fn qset(threshold: u32, validators: Vec<NodeId>, inner: Vec<QuorumSet>) -> QuorumSet {
    QuorumSet {
        threshold,
        validators,
        inner,
        raw: Vec::new(),
    }
}

#[test]
fn a_threshold_counts_validators_then_inner_sets() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    let set = qset(2, vec![a, b], Vec::new());
    assert!(is_quorum_slice(&set, &[a, b]));
    assert!(!is_quorum_slice(&set, &[a]));
}

#[test]
fn a_signer_whose_own_set_is_unsatisfied_is_discarded() {
    let a = [1u8; 32];
    let stranger = [9u8; 32];
    let mut qset_of = BTreeMap::new();
    qset_of.insert(a, qset(1, vec![stranger], Vec::new()));

    let (ok, survivors) = is_quorum(&qset(1, vec![a], Vec::new()), &[a], &qset_of);
    assert!(!ok);
    assert!(survivors.is_empty());
}

#[test]
fn frames_split_on_the_length_prefix() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(0x8000_0003u32).to_be_bytes());
    buf.extend_from_slice(b"abc");
    buf.extend_from_slice(&3u32.to_be_bytes());
    buf.extend_from_slice(b"xyz");

    let out = frames(&buf).unwrap();
    assert_eq!(out, vec![b"abc".as_slice(), b"xyz".as_slice()]);
}

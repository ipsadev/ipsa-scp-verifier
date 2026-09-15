use ipsa_scp_verifier::error::VerifyError;
use ipsa_scp_verifier::steps::*;
use sha2::{Digest, Sha256};

#[test]
fn signing_payload_is_network_then_type_then_statement() {
    let net = [0xabu8; 32];
    let raw = externalize_envelope_xdr(152);
    let env = validate_externalize(&raw, 4_160_279).expect("valid");

    let p = env.signing_payload(&net);

    assert_eq!(&p[..32], &net);
    assert_eq!(&p[32..36], &[0, 0, 0, 1]);
    assert_eq!(&p[36..], &env.statement_bytes[..]);
    assert_eq!(p.len(), 32 + 4 + env.statement_bytes.len());
}

fn externalize_envelope_xdr(value_len: usize) -> Vec<u8> {
    envelope_xdr_signed_by(&[0xaau8; 32], value_len)
}

fn envelope_xdr_signed_by(node_id: &[u8; 32], value_len: usize) -> Vec<u8> {
    let mut out = 0u32.to_be_bytes().to_vec();
    out.extend_from_slice(node_id);
    out.extend_from_slice(&4_160_279u64.to_be_bytes());
    out.extend_from_slice(&2i32.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&(value_len as u32).to_be_bytes());
    out.extend_from_slice(&vec![0x11u8; value_len]);
    out.extend_from_slice(&vec![0u8; (4 - (value_len % 4)) % 4]);
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&[0xbbu8; 32]);
    out.extend_from_slice(&64u32.to_be_bytes());
    out.extend_from_slice(&[0xccu8; 64]);
    out
}

#[test]
fn an_empty_commit_value_is_refused() {
    let raw = externalize_envelope_xdr(0);

    assert!(matches!(
        validate_externalize(&raw, 4_160_279),
        Err(VerifyError::EmptyCommitValue { .. })
    ));
}

#[test]
fn a_well_formed_envelope_passes_validation() {
    let raw = externalize_envelope_xdr(152);
    let env = validate_externalize(&raw, 4_160_279).expect("valid");

    assert_eq!(env.slot_index, 4_160_279);
    assert_eq!(env.externalize().unwrap().commit.value.len(), 152);
}

#[test]
fn a_public_key_that_is_not_a_curve_point_is_refused() {
    let mut node_id = [0u8; 32];
    node_id[31] = 0x7f;

    let raw = envelope_xdr_signed_by(&node_id, 152);
    let env = validate_externalize(&raw, 4_160_279).expect("valid");

    assert!(matches!(
        verify_envelope_signature(&env, &[0u8; 32]),
        Err(VerifyError::InvalidPublicKey { .. })
    ));
}

#[test]
fn a_signature_that_does_not_verify_is_refused() {
    let raw = externalize_envelope_xdr(152);
    let env = validate_externalize(&raw, 4_160_279).expect("valid");

    assert!(matches!(
        verify_envelope_signature(&env, &[0u8; 32]),
        Err(VerifyError::InvalidSignature { .. })
    ));
}

#[test]
fn ledger_hash_is_sha256_of_the_header_alone() {
    let header = b"not-a-real-header";
    let want: [u8; 32] = Sha256::digest(header).into();
    assert_eq!(verify_ledger_hash(header, None).unwrap(), want);
    assert_eq!(verify_ledger_hash(header, Some(want)).unwrap(), want);
    assert!(matches!(
        verify_ledger_hash(header, Some([0u8; 32])),
        Err(VerifyError::LedgerHashMismatch { .. })
    ));
}

fn qc(threshold: u32, validators: &[[u8; 32]]) -> QuorumConfig {
    let mut raw = threshold.to_be_bytes().to_vec();
    raw.extend_from_slice(&(validators.len() as u32).to_be_bytes());
    for v in validators {
        raw.extend_from_slice(&0u32.to_be_bytes());
        raw.extend_from_slice(v);
    }
    raw.extend_from_slice(&0u32.to_be_bytes());
    QuorumConfig::from_xdr(&raw).expect("sane trust root")
}

fn signer_set(
    ids: &[[u8; 32]],
    among: &[[u8; 32]],
    threshold: u32,
) -> Vec<([u8; 32], ipsa_scp_verifier::scp::quorum::QuorumSet)> {
    ids.iter()
        .map(|id| {
            (
                *id,
                ipsa_scp_verifier::scp::quorum::QuorumSet {
                    threshold,
                    validators: among.to_vec(),
                    inner_sets: Vec::new(),
                },
            )
        })
        .collect()
}

fn envelope_with(node_id: [u8; 32], value: &[u8]) -> ipsa_scp_verifier::scp::envelope::Envelope {
    ipsa_scp_verifier::scp::envelope::Envelope {
        node_id,
        slot_index: 1,
        statement: ipsa_scp_verifier::scp::envelope::Statement::Externalize(
            ipsa_scp_verifier::scp::envelope::Externalize {
                commit: ipsa_scp_verifier::scp::envelope::Ballot {
                    counter: 1,
                    value: value.to_vec(),
                },
                highest_confirmed_ballot_counter: 1,
                commit_quorum_set_hash: [0u8; 32],
            },
        ),
        signature: [0u8; 64],
        statement_bytes: Vec::new(),
    }
}

#[test]
fn a_lone_dissenter_is_discarded_rather_than_stalling_the_verifier() {
    let all = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let signers = signer_set(&all, &all, 2);
    let envelopes = [
        envelope_with(all[0], b"agreed"),
        envelope_with(all[1], b"agreed"),
        envelope_with(all[2], b"rogue"),
    ];

    let out = verify_externalized_quorum(&qc(2, &all), &signers, &envelopes)
        .expect("the honest majority is still a quorum");

    assert_eq!(out.value, b"agreed".to_vec());
    assert_eq!(out.supporters.len(), 2);
    assert_eq!(out.discarded, vec![all[2]]);
}

#[test]
fn a_dissenter_is_never_counted_toward_the_value_it_rejected() {
    let all = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let signers = signer_set(&all, &all, 3);
    let envelopes = [
        envelope_with(all[0], b"agreed"),
        envelope_with(all[1], b"agreed"),
        envelope_with(all[2], b"rogue"),
    ];

    assert!(matches!(
        verify_externalized_quorum(&qc(3, &all), &signers, &envelopes),
        Err(VerifyError::InsufficientQuorum { .. })
    ));
}

#[test]
fn two_quorum_backed_values_are_reported_as_fork_evidence() {
    let a = [[1u8; 32], [2u8; 32]];
    let b = [[3u8; 32], [4u8; 32]];

    let split_root = QuorumConfig {
        local: ipsa_scp_verifier::scp::quorum::QuorumSet {
            threshold: 1,
            validators: Vec::new(),
            inner_sets: vec![
                ipsa_scp_verifier::scp::quorum::QuorumSet {
                    threshold: 2,
                    validators: a.to_vec(),
                    inner_sets: Vec::new(),
                },
                ipsa_scp_verifier::scp::quorum::QuorumSet {
                    threshold: 2,
                    validators: b.to_vec(),
                    inner_sets: Vec::new(),
                },
            ],
        },
        raw: Vec::new(),
    };

    let mut signers = signer_set(&a, &a, 2);
    signers.extend(signer_set(&b, &b, 2));
    let envelopes = [
        envelope_with(a[0], b"left"),
        envelope_with(a[1], b"left"),
        envelope_with(b[0], b"right"),
        envelope_with(b[1], b"right"),
    ];

    assert!(matches!(
        verify_externalized_quorum(&split_root, &signers, &envelopes),
        Err(VerifyError::ForkedQuorums { .. })
    ));
}

#[test]
fn a_sane_trust_root_cannot_produce_two_quorum_backed_values() {
    let all = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let signers = signer_set(&all, &all, 2);
    let envelopes = [
        envelope_with(all[0], b"left"),
        envelope_with(all[1], b"right"),
        envelope_with(all[2], b"other"),
    ];

    assert!(matches!(
        verify_externalized_quorum(&qc(2, &all), &signers, &envelopes),
        Err(VerifyError::InsufficientQuorum { .. })
    ));
}

use crate::scp::envelope::{Ballot, Envelope, Externalize, Statement};

use crate::error::VerifyError;
use crate::steps::{
    authenticate_evidence, index_quorum_sets, validate_externalize, verify_externalized_quorum,
    verify_externalized_value, verify_header, verify_ledger_hash, verify_next_slot_binding,
    verify_quorum_set_hashes, verify_result_set, verify_scp_header, HeaderInput, QuorumConfig,
};

pub struct NextSlotEvidence<'a> {
    pub envelopes_xdr: &'a [Vec<u8>],
    pub tx_set_xdr: &'a [u8],
}

pub struct Case {
    pub name: &'static str,
    pub step: &'static str,
    pub expected: &'static str,
    pub outcome: Outcome,
}

pub enum Outcome {
    Rejected(String),
    WrongError(String),
    Accepted,
}

const STATEMENT_TYPE_OFFSET: usize = 44;

fn resolve_quorum_sets(
    input: &HeaderInput,
    quorum_sets_xdr: &[Vec<u8>],
) -> Result<Vec<(crate::scp::quorum::NodeId, crate::scp::quorum::QuorumSet)>, VerifyError> {
    let envelopes = input
        .envelopes_xdr
        .iter()
        .map(|raw| validate_externalize(raw, input.slot))
        .collect::<Result<Vec<_>, _>>()?;
    let preimages = index_quorum_sets(quorum_sets_xdr)?;

    verify_quorum_set_hashes(&envelopes, &preimages)
}

fn as_confirm(envelope_xdr: &[u8]) -> Vec<u8> {
    let value_offset = STATEMENT_TYPE_OFFSET + 8;
    let value_len = u32::from_be_bytes(
        envelope_xdr[value_offset..value_offset + 4]
            .try_into()
            .expect("four bytes"),
    ) as usize;
    let padded = value_len + (4 - (value_len % 4)) % 4;
    let highest_offset = value_offset + 4 + padded;
    let mut out = envelope_xdr[..STATEMENT_TYPE_OFFSET].to_vec();

    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&envelope_xdr[STATEMENT_TYPE_OFFSET + 4..highest_offset]);
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&envelope_xdr[highest_offset + 4..]);

    out
}

fn flip_last(bytes: &mut [u8]) {
    if let Some(b) = bytes.last_mut() {
        *b ^= 0x01;
    }
}

fn check(
    name: &'static str,
    step: &'static str,
    expected: &'static str,
    result: Result<(), VerifyError>,
    matches: impl Fn(&VerifyError) -> bool,
) -> Case {
    let outcome = match result {
        Ok(()) => Outcome::Accepted,
        Err(error) if matches(&error) => Outcome::Rejected(error.to_string()),
        Err(error) => Outcome::WrongError(error.to_string()),
    };

    Case {
        name,
        step,
        expected,
        outcome,
    }
}

pub fn run_suite(
    input: &HeaderInput,
    config: &QuorumConfig,
    next: Option<NextSlotEvidence<'_>>,
) -> Vec<Case> {
    let mut cases = Vec::new();

    cases.push(check(
        "tampered signature",
        "envelope signatures",
        "InvalidSignature",
        {
            let mut bad = input.clone();

            flip_last(&mut bad.envelopes_xdr[0]);
            verify_header(&bad, config).map(|_| ())
        },
        |error| matches!(error, VerifyError::InvalidSignature { .. }),
    ));
    cases.push(check(
        "wrong network id",
        "envelope signatures",
        "InvalidSignature",
        {
            let mut bad = input.clone();

            bad.network_id[0] ^= 0x01;
            verify_header(&bad, config).map(|_| ())
        },
        |error| matches!(error, VerifyError::InvalidSignature { .. }),
    ));
    cases.push(check(
        "tampered statement (ballot counter)",
        "statement validation",
        "InsaneStatement",
        {
            let mut bad = input.clone();
            let statement_offset = STATEMENT_TYPE_OFFSET + 4;

            bad.envelopes_xdr[0][statement_offset] ^= 0x01;
            verify_header(&bad, config).map(|_| ())
        },
        |error| matches!(error, VerifyError::InsaneStatement { .. }),
    ));
    cases.push(check(
        "tampered statement (highest confirmed ballot counter)",
        "envelope signatures",
        "InvalidSignature",
        {
            let mut bad = input.clone();
            let value_offset = STATEMENT_TYPE_OFFSET + 8;
            let value_len = u32::from_be_bytes(
                bad.envelopes_xdr[0][value_offset..value_offset + 4]
                    .try_into()
                    .expect("four bytes"),
            ) as usize;
            let highest_offset = value_offset + 4 + value_len;

            bad.envelopes_xdr[0][highest_offset] ^= 0x01;
            verify_header(&bad, config).map(|_| ())
        },
        |error| matches!(error, VerifyError::InvalidSignature { .. }),
    ));
    cases.push(check(
        "non-EXTERNALIZE statement",
        "statement validation",
        "NotExternalize",
        validate_externalize(&as_confirm(&input.envelopes_xdr[0]), input.slot).map(|_| ()),
        |error| matches!(error, VerifyError::NotExternalize { .. }),
    ));
    cases.push(check(
        "wrong slot",
        "statement validation",
        "SlotMismatch",
        {
            let mut bad = input.clone();

            bad.slot += 1;
            verify_header(&bad, config).map(|_| ())
        },
        |error| matches!(error, VerifyError::SlotMismatch { .. }),
    ));
    cases.push(check(
        "duplicate signer",
        "statement validation",
        "DuplicateSigner",
        {
            let mut bad = input.clone();
            let first = bad.envelopes_xdr[0].clone();

            bad.envelopes_xdr.push(first);
            verify_header(&bad, config).map(|_| ())
        },
        |error| matches!(error, VerifyError::DuplicateSigner { .. }),
    ));
    cases.push(check(
        "missing quorum-set preimage",
        "quorum-set authentication",
        "QuorumSetPreimageMissing",
        resolve_quorum_sets(input, &[]).map(|_| ()),
        |error| matches!(error, VerifyError::QuorumSetPreimageMissing { .. }),
    ));
    cases.push(check(
        "quorum-set preimage that hashes to something else",
        "quorum-set authentication",
        "QuorumSetPreimageMissing",
        resolve_quorum_sets(input, &[minimal_quorum_set_xdr(&[0x11u8; 32])]).map(|_| ()),
        |error| matches!(error, VerifyError::QuorumSetPreimageMissing { .. }),
    ));
    cases.push(check(
        "a forged CONFIRM statement",
        "envelope signatures",
        "InvalidSignature",
        authenticate_evidence(
            &input.network_id,
            input.slot,
            &[as_confirm(&input.envelopes_xdr[0])],
            &input.quorum_sets_xdr,
        )
        .map(|_| ()),
        |error| matches!(error, VerifyError::InvalidSignature { .. }),
    ));
    cases.push(check(
        "malformed nested quorum set",
        "quorum-set authentication",
        "MalformedXdr",
        index_quorum_sets(&[over_nested_quorum_set_xdr()]).map(|_| ()),
        |error| matches!(error, VerifyError::MalformedXdr { .. }),
    ));
    cases.push(check(
        "quorum set with a zero threshold",
        "quorum-set authentication",
        "InsaneQuorumSet",
        {
            let mut zero = minimal_quorum_set_xdr(&[0x22u8; 32]);

            zero[0..4].copy_from_slice(&0u32.to_be_bytes());
            index_quorum_sets(&[zero]).map(|_| ())
        },
        |error| matches!(error, VerifyError::InsaneQuorumSet { .. }),
    ));
    cases.push(check(
        "signers outside the configured trust root",
        "quorum check",
        "InsufficientQuorum",
        {
            let stranger = QuorumConfig::from_xdr(&three_of_three_strangers())
                .expect("stranger trust root is sane");

            verify_header(input, &stranger).map(|_| ())
        },
        |error| matches!(error, VerifyError::InsufficientQuorum { .. }),
    ));
    cases.push(check(
        "a single signer is not a quorum",
        "quorum check",
        "InsufficientQuorum",
        {
            let mut bad = input.clone();

            bad.envelopes_xdr.truncate(1);
            verify_header(&bad, config).map(|_| ())
        },
        |error| matches!(error, VerifyError::InsufficientQuorum { .. }),
    ));
    cases.push(check(
        "no envelopes at all",
        "quorum check",
        "NoEnvelopes",
        {
            let mut bad = input.clone();

            bad.envelopes_xdr.clear();
            verify_header(&bad, config).map(|_| ())
        },
        |error| matches!(error, VerifyError::NoEnvelopes),
    ));
    cases.push(check(
        "conflicting commit.value",
        "value agreement",
        "ConflictingValues",
        verify_externalized_value(&[
            synthetic_envelope([1u8; 32], b"value-a".to_vec()),
            synthetic_envelope([2u8; 32], b"value-b".to_vec()),
        ])
        .map(|_| ()),
        |error| matches!(error, VerifyError::ConflictingValues { .. }),
    ));
    cases.push(check(
        "every signer pledges a different value",
        "quorum check",
        "InsufficientQuorum",
        no_value_is_quorum_backed(input, config),
        |error| matches!(error, VerifyError::InsufficientQuorum { .. }),
    ));
    cases.push(check(
        "commit.value != header.scpValue",
        "ledger binding",
        "ValueNotInHeader",
        {
            let mut bad = input.clone();

            bad.ledger_header_xdr[75] ^= 0x01;
            verify_header(&bad, config).map(|_| ())
        },
        |error| matches!(error, VerifyError::ValueNotInHeader { .. }),
    ));
    cases.push(check(
        "header for another ledger",
        "ledger binding",
        "LedgerSeqMismatch",
        verify_scp_header(&input.ledger_header_xdr, input.slot + 1, &[]).map(|_| ()),
        |error| matches!(error, VerifyError::LedgerSeqMismatch { .. }),
    ));
    cases.push(check(
        "truncated LedgerHeader XDR",
        "ledger binding",
        "MalformedXdr",
        {
            let mut bad = input.clone();

            bad.ledger_header_xdr.truncate(40);
            verify_header(&bad, config).map(|_| ())
        },
        |error| matches!(error, VerifyError::MalformedXdr { .. }),
    ));
    cases.push(check(
        "header names another predecessor",
        "ledger binding",
        "PreviousLedgerMismatch",
        {
            let mut bad = input.clone();

            bad.trusted_previous_hash = Some([0xffu8; 32]);
            verify_header(&bad, config).map(|_| ())
        },
        |error| matches!(error, VerifyError::PreviousLedgerMismatch { .. }),
    ));
    cases.push(check(
        "wrong recorded ledger hash",
        "ledger binding",
        "LedgerHashMismatch",
        verify_ledger_hash(&input.ledger_header_xdr, Some([0xffu8; 32])).map(|_| ()),
        |error| matches!(error, VerifyError::LedgerHashMismatch { .. }),
    ));
    cases.extend(next_slot_cases(input, next));
    cases.extend(result_set_cases(input, config));
    cases
}

fn result_set_cases(input: &HeaderInput, config: &QuorumConfig) -> Vec<Case> {
    if input.result_pairs_xdr.is_empty() {
        return Vec::new();
    }

    let Ok(verified) = verify_header(input, config) else {
        return Vec::new();
    };

    let expected = verified.tx_set_result_hash;
    let mut tampered = input.result_pairs_xdr.clone();

    flip_last(&mut tampered[0]);
    let mut dropped = input.result_pairs_xdr.clone();

    dropped.pop();
    let mut reordered = input.result_pairs_xdr.clone();

    if reordered.len() >= 2 {
        reordered.swap(0, 1);
    }

    let mut cases = vec![
        check(
            "tampered result pair",
            "result-set binding",
            "ResultSetMismatch",
            verify_result_set(&tampered, &expected),
            |error| matches!(error, VerifyError::ResultSetMismatch { .. }),
        ),
        check(
            "a result pair removed",
            "result-set binding",
            "ResultSetMismatch",
            verify_result_set(&dropped, &expected),
            |error| matches!(error, VerifyError::ResultSetMismatch { .. }),
        ),
    ];

    if input.result_pairs_xdr.len() >= 2 {
        cases.push(check(
            "result pairs reordered",
            "result-set binding",
            "ResultSetMismatch",
            verify_result_set(&reordered, &expected),
            |error| matches!(error, VerifyError::ResultSetMismatch { .. }),
        ));
    }

    cases
}

fn next_slot_cases(input: &HeaderInput, next: Option<NextSlotEvidence<'_>>) -> Vec<Case> {
    let Some(next) = next else {
        return Vec::new();
    };

    let Ok(ledger_hash) = verify_ledger_hash(&input.ledger_header_xdr, None) else {
        return Vec::new();
    };

    let decoded = next
        .envelopes_xdr
        .iter()
        .map(|raw| validate_externalize(raw, input.slot + 1))
        .collect::<Result<Vec<_>, _>>();
    let Ok(envelopes) = decoded else {
        return Vec::new();
    };

    let Ok(value) = verify_externalized_value(&envelopes) else {
        return Vec::new();
    };

    let mut tampered = next.tx_set_xdr.to_vec();

    flip_last(&mut tampered);
    vec![
        check(
            "tampered next-slot tx set",
            "next-slot binding",
            "TxSetHashMismatch",
            verify_next_slot_binding(&value, &tampered, &ledger_hash),
            |error| matches!(error, VerifyError::TxSetHashMismatch { .. }),
        ),
        check(
            "next-slot tx set names another predecessor",
            "next-slot binding",
            "LedgerNotPrevious",
            verify_next_slot_binding(&value, next.tx_set_xdr, &[0xffu8; 32]),
            |error| matches!(error, VerifyError::LedgerNotPrevious { .. }),
        ),
    ]
}

fn no_value_is_quorum_backed(
    input: &HeaderInput,
    config: &QuorumConfig,
) -> Result<(), VerifyError> {
    let envelopes = input
        .envelopes_xdr
        .iter()
        .map(|raw| validate_externalize(raw, input.slot))
        .collect::<Result<Vec<_>, _>>()?;
    let preimages = index_quorum_sets(&input.quorum_sets_xdr)?;
    let signers = verify_quorum_set_hashes(&envelopes, &preimages)?;
    let mut mutated = envelopes;

    for (index, envelope) in mutated.iter_mut().enumerate() {
        if let Statement::Externalize(e) = &mut envelope.statement {
            e.commit.value = format!("value-{index}").into_bytes();
        }
    }

    verify_externalized_quorum(config, &signers, &mutated).map(|_| ())
}

fn synthetic_envelope(node_id: [u8; 32], value: Vec<u8>) -> Envelope {
    Envelope {
        node_id,
        slot_index: 1,
        statement: Statement::Externalize(Externalize {
            commit: Ballot { counter: 1, value },
            highest_confirmed_ballot_counter: 1,
            commit_quorum_set_hash: [0u8; 32],
        }),
        signature: [0u8; 64],
        statement_bytes: Vec::new(),
    }
}

fn minimal_quorum_set_xdr(validator: &[u8; 32]) -> Vec<u8> {
    let mut output = 1u32.to_be_bytes().to_vec();

    output.extend_from_slice(&1u32.to_be_bytes());
    output.extend_from_slice(&0u32.to_be_bytes());
    output.extend_from_slice(validator);
    output.extend_from_slice(&0u32.to_be_bytes());
    output
}

fn three_of_three_strangers() -> Vec<u8> {
    let mut output = 3u32.to_be_bytes().to_vec();

    output.extend_from_slice(&3u32.to_be_bytes());

    for seed in [0xa1u8, 0xa2, 0xa3] {
        output.extend_from_slice(&0u32.to_be_bytes());
        output.extend_from_slice(&[seed; 32]);
    }

    output.extend_from_slice(&0u32.to_be_bytes());
    output
}

fn over_nested_quorum_set_xdr() -> Vec<u8> {
    let mut nested = minimal_quorum_set_xdr(&[0x33u8; 32]);

    for _ in 0..8 {
        let mut outer = 1u32.to_be_bytes().to_vec();

        outer.extend_from_slice(&0u32.to_be_bytes());
        outer.extend_from_slice(&1u32.to_be_bytes());
        outer.extend_from_slice(&nested);
        nested = outer;
    }

    nested
}

use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::scp::ballot::{authenticate, confirmed_value, verify_signature, Authenticated};
use crate::scp::envelope::{Envelope, Externalize};
use crate::scp::error::ScpError;
use crate::scp::ledger::{tx_set_hash_of_value, LedgerHeader};
use crate::scp::quorum::{is_quorum, NodeId, QuorumSet};
use crate::scp::results;
use crate::scp::txset;

use crate::error::VerifyError;

type Result<T> = core::result::Result<T, VerifyError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLedger {
    pub slot: u64,
    pub ledger_hash: [u8; 32],
    pub close_time: u64,
    pub tx_set_result_hash: [u8; 32],
    pub bucket_list_hash: [u8; 32],
    pub previous_ledger_hash: [u8; 32],
}

#[derive(Clone, Debug, Default)]
pub struct HeaderInput {
    pub slot: u64,
    pub network_id: [u8; 32],
    pub ledger_header_xdr: Vec<u8>,
    pub envelopes_xdr: Vec<Vec<u8>>,
    pub quorum_sets_xdr: Vec<Vec<u8>>,
    pub recorded_ledger_hash: Option<[u8; 32]>,
    pub result_pairs_xdr: Vec<Vec<u8>>,
    pub trusted_previous_hash: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct QuorumConfig {
    pub local: QuorumSet,
    pub raw: Vec<u8>,
}

impl QuorumConfig {
    pub fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(&self.raw).into()
    }
}

impl QuorumConfig {
    pub fn from_xdr(bytes: &[u8]) -> Result<Self> {
        let local = QuorumSet::decode(bytes).map_err(|error| VerifyError::MalformedXdr {
            what: "local quorum set".into(),
            detail: error.to_string(),
        })?;

        local
            .check_sane(true)
            .map_err(|error| VerifyError::InsaneQuorumSet {
                detail: error.to_string(),
            })?;

        Ok(Self {
            local,
            raw: bytes.to_vec(),
        })
    }
}

pub fn verify_envelope_signature(envelope: &Envelope, network_id: &[u8; 32]) -> Result<()> {
    let node_id = &envelope.node_id;

    VerifyingKey::from_bytes(node_id).map_err(|_| VerifyError::InvalidPublicKey {
        node_id: hex::encode(node_id),
    })?;

    let preimage = envelope.signing_payload(network_id);

    if verify_signature(node_id, &preimage, &envelope.signature) {
        return Ok(());
    }

    Err(VerifyError::InvalidSignature {
        node_id: hex::encode(node_id),
    })
}

fn from_scp(error: ScpError, signers: usize) -> VerifyError {
    match &error {
        ScpError::UnauthenticatedEnvelope { node } => VerifyError::InvalidSignature {
            node_id: node.clone(),
        },
        ScpError::EnvelopeSlotMismatch { expected, found } => VerifyError::SlotMismatch {
            expected: *expected,
            found: *found,
        },
        ScpError::CommitCounterZero
        | ScpError::BallotCounterZero
        | ScpError::EmptyCommitValue
        | ScpError::MalformedPrepare
        | ScpError::MalformedConfirm
        | ScpError::HighestConfirmedBelowCommit { .. } => VerifyError::InsaneStatement {
            detail: error.to_string(),
        },
        ScpError::NominationStatement | ScpError::NotExternalize => VerifyError::NotExternalize {
            detail: error.to_string(),
        },
        ScpError::NoConfirmedCommit => VerifyError::InsufficientQuorum { signers },
        ScpError::ForkedConfirmCommit => VerifyError::ForkedQuorums { values: 2 },
        _ => VerifyError::MalformedXdr {
            what: "SCP evidence".into(),
            detail: error.to_string(),
        },
    }
}

pub fn authenticate_evidence(
    network_id: &[u8; 32],
    slot: u64,
    envelopes_xdr: &[Vec<u8>],
    quorum_sets_xdr: &[Vec<u8>],
) -> Result<Vec<Authenticated>> {
    if envelopes_xdr.is_empty() {
        return Err(VerifyError::NoEnvelopes);
    }

    authenticate(network_id, slot, envelopes_xdr, quorum_sets_xdr)
        .map_err(|e| from_scp(e, envelopes_xdr.len()))
}

pub fn reject_repeated_signers(evidence: &[Authenticated]) -> Result<()> {
    for (index, item) in evidence.iter().enumerate() {
        if let Some(first) = evidence[..index]
            .iter()
            .position(|held| held.node_id() == item.node_id())
        {
            return Err(VerifyError::DuplicateSigner {
                node_id: hex::encode(item.node_id()),
                first,
                second: index,
            });
        }
    }

    Ok(())
}

pub fn confirm_commit(config: &QuorumConfig, evidence: &[Authenticated]) -> Result<Externalized> {
    let value =
        confirmed_value(&config.local, evidence).map_err(|e| from_scp(e, evidence.len()))?;
    let (supporters, discarded) = evidence
        .iter()
        .map(|item| (item.node_id(), item.statement().value() == value))
        .fold((Vec::new(), Vec::new()), |mut acc, (node, agreed)| {
            if agreed {
                acc.0.push(node);
            } else {
                acc.1.push(node);
            }

            acc
        });

    Ok(Externalized {
        value,
        supporters,
        discarded,
    })
}

fn externalize_of(envelope: &Envelope) -> Result<&Externalize> {
    envelope
        .statement
        .as_externalize()
        .ok_or_else(|| VerifyError::NotExternalize {
            detail: "statement is not EXTERNALIZE".into(),
        })
}

fn node_id_of(envelope_xdr: &[u8]) -> String {
    hex::encode(envelope_xdr.get(4..36).unwrap_or_default())
}

pub fn validate_externalize(envelope_xdr: &[u8], expected_slot: u64) -> Result<Envelope> {
    let envelope = Envelope::decode(envelope_xdr).map_err(|error| {
        let detail = error.to_string();

        match error {
            ScpError::EmptyCommitValue => VerifyError::EmptyCommitValue {
                node_id: node_id_of(envelope_xdr),
            },
            ScpError::CommitCounterZero | ScpError::HighestConfirmedBelowCommit { .. } => {
                VerifyError::InsaneStatement { detail }
            }
            ScpError::NotExternalize | ScpError::NominationStatement => {
                VerifyError::NotExternalize { detail }
            }
            ScpError::BallotCounterZero
            | ScpError::MalformedPrepare
            | ScpError::MalformedConfirm => VerifyError::InsaneStatement { detail },
            _ => VerifyError::MalformedXdr {
                what: "SCP envelope".into(),
                detail,
            },
        }
    })?;

    if envelope.statement.as_externalize().is_none() {
        return Err(VerifyError::NotExternalize {
            detail: "statement is not EXTERNALIZE".into(),
        });
    }

    if envelope.slot_index != expected_slot {
        return Err(VerifyError::SlotMismatch {
            expected: expected_slot,
            found: envelope.slot_index,
        });
    }

    Ok(envelope)
}

pub fn reject_duplicate_signers(envelopes: &[Envelope]) -> Result<()> {
    let mut seen: BTreeMap<NodeId, usize> = BTreeMap::new();

    for (index, envelope) in envelopes.iter().enumerate() {
        if let Some(first) = seen.insert(envelope.node_id, index) {
            return Err(VerifyError::DuplicateSigner {
                node_id: hex::encode(envelope.node_id),
                first,
                second: index,
            });
        }
    }

    Ok(())
}

pub fn index_quorum_sets(raw: &[Vec<u8>]) -> Result<BTreeMap<[u8; 32], QuorumSet>> {
    let mut output = BTreeMap::new();

    for bytes in raw {
        let quorum_set = QuorumSet::decode(bytes).map_err(|error| VerifyError::MalformedXdr {
            what: "quorum set".into(),
            detail: error.to_string(),
        })?;

        quorum_set
            .check_sane(false)
            .map_err(|error| VerifyError::InsaneQuorumSet {
                detail: error.to_string(),
            })?;
        output.insert(Sha256::digest(bytes).into(), quorum_set);
    }

    Ok(output)
}

pub fn verify_quorum_set_hashes(
    envelopes: &[Envelope],
    preimages: &BTreeMap<[u8; 32], QuorumSet>,
) -> Result<Vec<(NodeId, QuorumSet)>> {
    let mut output = Vec::with_capacity(envelopes.len());

    for envelope in envelopes {
        let hash = externalize_of(envelope)?.commit_quorum_set_hash;
        let quorum_set =
            preimages
                .get(&hash)
                .ok_or_else(|| VerifyError::QuorumSetPreimageMissing {
                    node_id: hex::encode(envelope.node_id),
                    hash: hex::encode(hash),
                })?;

        output.push((envelope.node_id, quorum_set.clone()));
    }

    Ok(output)
}

pub fn verify_quorum(
    config: &QuorumConfig,
    signers: &[(NodeId, QuorumSet)],
) -> Result<Vec<NodeId>> {
    if signers.is_empty() {
        return Err(VerifyError::NoEnvelopes);
    }

    if !is_quorum(&config.local, signers) {
        return Err(VerifyError::InsufficientQuorum {
            signers: signers.len(),
        });
    }

    Ok(signers.iter().map(|(id, _)| *id).collect())
}

struct ValueGroup {
    value: Vec<u8>,
    members: Vec<(NodeId, QuorumSet)>,
}

pub struct Externalized {
    pub value: Vec<u8>,
    pub supporters: Vec<NodeId>,
    pub discarded: Vec<NodeId>,
}

pub fn verify_externalized_quorum(
    config: &QuorumConfig,
    signers: &[(NodeId, QuorumSet)],
    envelopes: &[Envelope],
) -> Result<Externalized> {
    if signers.is_empty() || envelopes.is_empty() {
        return Err(VerifyError::NoEnvelopes);
    }

    let mut groups: Vec<ValueGroup> = Vec::new();

    for (signer, envelope) in signers.iter().zip(envelopes.iter()) {
        let value = &externalize_of(envelope)?.commit.value;

        match groups.iter_mut().find(|group| group.value == *value) {
            Some(group) => group.members.push(signer.clone()),
            None => groups.push(ValueGroup {
                value: value.clone(),
                members: vec![signer.clone()],
            }),
        }
    }

    let mut backed: Option<&ValueGroup> = None;

    for group in &groups {
        if is_quorum(&config.local, &group.members) {
            if backed.is_some() {
                return Err(VerifyError::ForkedQuorums {
                    values: groups.len(),
                });
            }

            backed = Some(group);
        }
    }

    let Some(group) = backed else {
        return Err(VerifyError::InsufficientQuorum {
            signers: signers.len(),
        });
    };

    let supporters: Vec<NodeId> = group.members.iter().map(|(id, _)| *id).collect();
    let discarded = signers
        .iter()
        .map(|(id, _)| *id)
        .filter(|node_id| !supporters.contains(node_id))
        .collect();

    Ok(Externalized {
        value: group.value.clone(),
        supporters,
        discarded,
    })
}

pub fn verify_externalized_value(envelopes: &[Envelope]) -> Result<Vec<u8>> {
    let mut iter = envelopes.iter();
    let first = externalize_of(iter.next().ok_or(VerifyError::NoEnvelopes)?)?
        .commit
        .value
        .clone();

    for envelope in iter {
        if externalize_of(envelope)?.commit.value != first {
            return Err(VerifyError::ConflictingValues {
                node_id: hex::encode(envelope.node_id),
            });
        }
    }

    Ok(first)
}

pub fn verify_scp_header(
    ledger_header_xdr: &[u8],
    slot: u64,
    externalized_value: &[u8],
) -> Result<LedgerHeader> {
    let header =
        LedgerHeader::decode(ledger_header_xdr).map_err(|error| VerifyError::MalformedXdr {
            what: "ledger header".into(),
            detail: error.to_string(),
        })?;

    if header.ledger_seq as u64 != slot {
        return Err(VerifyError::LedgerSeqMismatch {
            expected: slot,
            found: header.ledger_seq as u64,
        });
    }

    if header.scp_value_bytes != externalized_value {
        return Err(VerifyError::ValueNotInHeader {
            value_len: externalized_value.len(),
            header_value_len: header.scp_value_bytes.len(),
        });
    }

    Ok(header)
}

pub fn verify_ledger_hash(
    ledger_header_xdr: &[u8],
    expected: Option<[u8; 32]>,
) -> Result<[u8; 32]> {
    let computed: [u8; 32] = Sha256::digest(ledger_header_xdr).into();

    if let Some(expected) = expected {
        if computed != expected {
            return Err(VerifyError::LedgerHashMismatch {
                expected: hex::encode(expected),
                computed: hex::encode(computed),
            });
        }
    }

    Ok(computed)
}

pub fn verify_next_slot_binding(
    next_value: &[u8],
    next_tx_set_xdr: &[u8],
    ledger_hash: &[u8; 32],
) -> Result<()> {
    let want = tx_set_hash_of_value(next_value).map_err(|error| VerifyError::MalformedXdr {
        what: "next slot StellarValue".into(),
        detail: error.to_string(),
    })?;
    let got = txset::hash(next_tx_set_xdr);

    if got != want {
        return Err(VerifyError::TxSetHashMismatch {
            expected: hex::encode(want),
            computed: hex::encode(got),
        });
    }

    let prev = txset::previous_ledger_hash(next_tx_set_xdr).map_err(|error| {
        VerifyError::MalformedXdr {
            what: "generalized tx set".into(),
            detail: error.to_string(),
        }
    })?;

    if &prev != ledger_hash {
        return Err(VerifyError::LedgerNotPrevious {
            expected: hex::encode(ledger_hash),
            found: hex::encode(prev),
        });
    }

    Ok(())
}

pub fn verify_previous_ledger(
    header_previous_hash: &[u8; 32],
    trusted_previous_hash: Option<[u8; 32]>,
) -> Result<()> {
    let Some(trusted) = trusted_previous_hash else {
        return Ok(());
    };

    if header_previous_hash != &trusted {
        return Err(VerifyError::PreviousLedgerMismatch {
            expected: hex::encode(trusted),
            found: hex::encode(header_previous_hash),
        });
    }

    Ok(())
}

pub fn verify_result_set(
    result_pairs_xdr: &[Vec<u8>],
    tx_set_result_hash: &[u8; 32],
) -> Result<()> {
    results::verify_result_set_hash(result_pairs_xdr, tx_set_result_hash).map_err(|_| {
        let mut hasher = Sha256::new();

        hasher.update((result_pairs_xdr.len() as u32).to_be_bytes());

        for pair in result_pairs_xdr {
            hasher.update(pair);
        }

        VerifyError::ResultSetMismatch {
            pairs: result_pairs_xdr.len(),
            expected: hex::encode(tx_set_result_hash),
            computed: hex::encode(hasher.finalize()),
        }
    })
}

pub fn verify_header(input: &HeaderInput, config: &QuorumConfig) -> Result<VerifiedLedger> {
    if input.envelopes_xdr.is_empty() {
        return Err(VerifyError::NoEnvelopes);
    }

    let evidence = authenticate_evidence(
        &input.network_id,
        input.slot,
        &input.envelopes_xdr,
        &input.quorum_sets_xdr,
    )?;
    reject_repeated_signers(&evidence)?;
    let value = confirm_commit(config, &evidence)?.value;
    let header = verify_scp_header(&input.ledger_header_xdr, input.slot, &value)?;
    let ledger_hash = verify_ledger_hash(&input.ledger_header_xdr, input.recorded_ledger_hash)?;

    verify_previous_ledger(&header.previous_ledger_hash, input.trusted_previous_hash)?;

    Ok(VerifiedLedger {
        slot: input.slot,
        ledger_hash,
        close_time: header.close_time,
        tx_set_result_hash: header.tx_set_result_hash,
        bucket_list_hash: header.bucket_list_hash,
        previous_ledger_hash: header.previous_ledger_hash,
    })
}

pub fn describe_quorum_set(quorum_set: &QuorumSet) -> String {
    let entries = quorum_set.validators.len() + quorum_set.inner_sets.len();

    format!(
        "threshold {} of {} entries ({} validator(s), {} inner set(s))",
        quorum_set.threshold,
        entries,
        quorum_set.validators.len(),
        quorum_set.inner_sets.len()
    )
}

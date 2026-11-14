use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    error::VerifyError,
    steps::{self, Authentication, HeaderInput, QuorumConfig},
};

const CORE_STEP: usize = 0;
const CORE_FULL: &str = "core acceptance (authenticated end to end)";
const CORE_VALUE_BOUND: &str = "core acceptance (value-bound only)";
const CORE_REJECTED: &str = "core acceptance";

#[derive(Debug, Clone, Serialize)]
pub struct StepResult {
    pub step: usize,
    pub name: &'static str,
    pub passed: bool,
    pub skipped: bool,
    pub detail: String,
    pub error: Option<String>,
    pub verdict: Option<crate::error::Verdict>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub ledger: u64,
    pub verified: bool,
    pub scp_verified: bool,
    pub header_authenticated: bool,
    pub results_verified: bool,
    pub strict_check_failed: bool,
    pub verdict: crate::error::Verdict,
    pub anchored: bool,
    pub next_slot_unavailable: Option<String>,
    pub signers: usize,
    pub ledger_hash: Option<String>,
    pub mutation: Option<String>,
    pub steps: Vec<StepResult>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct QuorumSetView {
    pub threshold: u32,
    pub validators: Vec<String>,
    pub inner_sets: Vec<Self>,
}

impl QuorumSetView {
    fn of(set: &stellar_consensus_verifier::primitives::scp::quorum::QuorumSet) -> Self {
        Self {
            threshold: set.threshold,
            validators: set
                .validators
                .iter()
                .map(crate::strkey::account_id)
                .collect(),
            inner_sets: set.inner_sets.iter().map(Self::of).collect(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Evidence {
    pub network_id: String,
    pub envelopes: usize,
    pub quorum_set_preimages: usize,
    pub result_pairs: usize,
    pub next_slot_evidence: bool,
    pub signers: Vec<String>,
    pub supporters: Vec<String>,
    pub discarded: Vec<String>,
    pub trust_root: Option<QuorumSetView>,
    pub trust_root_fingerprint: String,
    pub externalized_value: Option<String>,
}

pub struct NextSlot<'a> {
    pub envelopes_xdr: &'a [Vec<u8>],
    pub quorum_sets_xdr: &'a [Vec<u8>],
    pub tx_set_xdr: &'a [u8],
}

pub const MUTATIONS: [(&str, &str); 15] = [
    ("tampered-signature", "envelope signatures"),
    ("wrong-network", "envelope signatures"),
    ("wrong-slot", "envelope signatures"),
    ("duplicate-signer", "statement validation"),
    ("wrong-statement-type", "envelope signatures"),
    ("missing-quorum-set", "quorum-set authentication"),
    ("tampered-quorum-set", "quorum-set authentication"),
    ("zero-threshold-quorum-set", "quorum-set authentication"),
    ("foreign-trust-root", "quorum check"),
    ("single-signer", "quorum check"),
    ("no-envelopes", "quorum check"),
    ("wrong-scp-value", "ledger binding"),
    ("tampered-ledger-header", "ledger binding"),
    ("tampered-result-pairs", "result-set binding"),
    ("malicious-archive", "next-slot binding"),
];

/// Whether core's `verify_update` itself must reject a mutation.
///
/// The ones that return `false` are not attacks on consensus or the header:
/// core accepts them because a valid quorum still externalized the ledger (it
/// uses a singleton quorum set for EXTERNALIZE, skips non-EXTERNALIZE
/// statements, and keeps only the latest statement per node), or because the
/// result set is not part of `verify_update` at all. ipsa's strict diagnostic
/// and the result-set step catch those instead.
pub fn core_must_reject(mutation: &str) -> bool {
    !matches!(
        mutation,
        "duplicate-signer"
            | "wrong-statement-type"
            | "missing-quorum-set"
            | "tampered-quorum-set"
            | "zero-threshold-quorum-set"
            | "tampered-result-pairs"
    )
}

const STATEMENT_TYPE_OFFSET: usize = 44;
const SCP_VALUE_OFFSET: usize = 75;

pub struct Mutated {
    pub input: HeaderInput,
    pub config: Option<QuorumConfig>,
}

fn strangers_quorum_set() -> Vec<u8> {
    let mut output = 3u32.to_be_bytes().to_vec();

    output.extend_from_slice(&3u32.to_be_bytes());

    for seed in [0xa1u8, 0xa2, 0xa3] {
        output.extend_from_slice(&0u32.to_be_bytes());
        output.extend_from_slice(&[seed; 32]);
    }

    output.extend_from_slice(&0u32.to_be_bytes());
    output
}

fn zero_threshold_quorum_set() -> Vec<u8> {
    let mut output = 0u32.to_be_bytes().to_vec();

    output.extend_from_slice(&1u32.to_be_bytes());
    output.extend_from_slice(&0u32.to_be_bytes());
    output.extend_from_slice(&[0x33u8; 32]);
    output.extend_from_slice(&0u32.to_be_bytes());
    output
}

fn flip_last(bytes: &mut [u8], what: &str) -> Result<(), String> {
    match bytes.last_mut() {
        Some(byte) => {
            *byte ^= 0x01;

            Ok(())
        }
        None => Err(format!(
            "{what} is empty, so there is nothing to tamper with"
        )),
    }
}

fn flip_at(bytes: &mut [u8], offset: usize, what: &str) -> Result<(), String> {
    match bytes.get_mut(offset) {
        Some(byte) => {
            *byte ^= 0x01;

            Ok(())
        }
        None => Err(format!(
            "{what} is {} bytes, too short to reach offset {offset}",
            bytes.len()
        )),
    }
}

pub fn apply_mutation(name: &str, input: &HeaderInput) -> Result<Mutated, String> {
    let mut output = input.clone();
    let mut config = None;

    match name {
        "tampered-signature" => {
            let first = output
                .envelopes_xdr
                .first_mut()
                .ok_or_else(|| "no envelopes to tamper with".to_string())?;

            if let Some(byte) = first.last_mut() {
                *byte ^= 0x01;
            }
        }
        "wrong-network" => output.network_id[0] ^= 0x01,
        "wrong-slot" => output.slot += 1,
        "duplicate-signer" => {
            let first = output
                .envelopes_xdr
                .first()
                .cloned()
                .ok_or_else(|| "no envelopes to duplicate".to_string())?;

            output.envelopes_xdr.push(first);
        }
        "wrong-statement-type" => {
            let first = output
                .envelopes_xdr
                .first_mut()
                .ok_or_else(|| "no envelopes to tamper with".to_string())?;

            flip_at(first, STATEMENT_TYPE_OFFSET + 3, "the envelope")?;
        }
        "missing-quorum-set" => output.quorum_sets_xdr.clear(),
        "tampered-quorum-set" => {
            let first = output
                .quorum_sets_xdr
                .first_mut()
                .ok_or_else(|| "no quorum set preimage to tamper with".to_string())?;

            flip_last(first, "the quorum set preimage")?;
        }
        "zero-threshold-quorum-set" => output.quorum_sets_xdr = vec![zero_threshold_quorum_set()],
        "foreign-trust-root" => {
            config = Some(
                QuorumConfig::from_xdr(&strangers_quorum_set())
                    .map_err(|error| format!("building a stranger trust root: {error}"))?,
            );
        }
        "single-signer" => {
            if output.envelopes_xdr.is_empty() {
                return Err("no envelopes to truncate".to_string());
            }

            output.envelopes_xdr.truncate(1);
        }
        "no-envelopes" => output.envelopes_xdr.clear(),
        "wrong-scp-value" => flip_at(
            &mut output.ledger_header_xdr,
            SCP_VALUE_OFFSET,
            "the ledger header",
        )?,
        "tampered-ledger-header" => flip_last(&mut output.ledger_header_xdr, "the ledger header")?,
        "malicious-archive" => {
            let header =
                stellar_consensus_verifier::primitives::stellar::header::LedgerHeader::decode(
                    &output.ledger_header_xdr,
                )
                .map_err(|error| format!("decoding the ledger header: {error}"))?;
            let position = output
                .ledger_header_xdr
                .windows(32)
                .position(|window| window == &header.bucket_list_hash[..])
                .ok_or_else(|| "bucketListHash not found in the header bytes".to_string())?;

            output.ledger_header_xdr[position] ^= 0x01;
            output.recorded_ledger_hash = Some(Sha256::digest(&output.ledger_header_xdr).into());
        }
        "tampered-result-pairs" => {
            let first = output
                .result_pairs_xdr
                .first_mut()
                .ok_or_else(|| "this ledger carries no transaction results".to_string())?;

            flip_last(first, "the result pair")?;
        }
        other => return Err(format!("unknown mutation: {other}")),
    }

    Ok(Mutated {
        input: output,
        config,
    })
}

fn ok(step: usize, name: &'static str, detail: String) -> StepResult {
    StepResult {
        step,
        name,
        passed: true,
        skipped: false,
        detail,
        error: None,
        verdict: None,
    }
}

fn failed(step: usize, name: &'static str, error: &VerifyError) -> StepResult {
    StepResult {
        step,
        name,
        passed: false,
        skipped: false,
        detail: String::new(),
        error: Some(error.to_string()),
        verdict: Some(error.verdict()),
    }
}

fn skipped(step: usize, name: &'static str, detail: &str) -> StepResult {
    StepResult {
        step,
        name,
        passed: false,
        skipped: true,
        detail: detail.to_string(),
        error: None,
        verdict: None,
    }
}

pub fn evaluate(
    input: &HeaderInput,
    config: &QuorumConfig,
    next: Option<NextSlot<'_>>,
    mutation: Option<String>,
) -> Report {
    let mut steps_out = Vec::new();
    let mut report = |r: StepResult| steps_out.push(r);
    let mut evidence = Evidence {
        network_id: hex::encode(input.network_id),
        envelopes: input.envelopes_xdr.len(),
        quorum_set_preimages: input.quorum_sets_xdr.len(),
        result_pairs: input.result_pairs_xdr.len(),
        next_slot_evidence: next.is_some(),
        trust_root: Some(QuorumSetView::of(&config.local)),
        trust_root_fingerprint: hex::encode(config.fingerprint()),
        ..Evidence::default()
    };

    let next_evidence = next
        .as_ref()
        .filter(|n| !n.tx_set_xdr.is_empty())
        .map(|n| (n.envelopes_xdr, n.quorum_sets_xdr, n.tx_set_xdr));

    match steps::authenticate_core(input, config, next_evidence) {
        Ok((_, Authentication::Full)) => report(ok(
            CORE_STEP,
            CORE_FULL,
            "verify_update authenticated the header end to end".into(),
        )),
        Ok((_, Authentication::ValueBound)) => report(ok(
            CORE_STEP,
            CORE_VALUE_BOUND,
            "verify_header value-bound the header; no slot N+1 evidence".into(),
        )),
        Err(error) => report(failed(CORE_STEP, CORE_REJECTED, &error)),
    }

    let mut envelopes = Vec::with_capacity(input.envelopes_xdr.len());

    for raw in &input.envelopes_xdr {
        match steps::validate_externalize(raw, input.slot) {
            Ok(envelope) => envelopes.push(envelope),
            Err(error) => {
                report(failed(1, "envelope signatures", &error));

                return finish(input, mutation, steps_out, 0, None, evidence);
            }
        }
    }

    for envelope in &envelopes {
        if let Err(error) = steps::verify_envelope_signature(envelope, &input.network_id) {
            report(failed(1, "envelope signatures", &error));

            return finish(input, mutation, steps_out, 0, None, evidence);
        }
    }

    evidence.signers = envelopes
        .iter()
        .map(|envelope| crate::strkey::account_id(&envelope.node_id))
        .collect();
    report(ok(
        1,
        "envelope signatures",
        format!("{} signature(s) verified", envelopes.len()),
    ));

    if let Err(error) = steps::reject_duplicate_signers(&envelopes) {
        report(failed(2, "statement validation", &error));

        return finish(input, mutation, steps_out, 0, None, evidence);
    }

    report(ok(
        2,
        "statement validation",
        format!(
            "{} distinct signer(s), all EXTERNALIZE for slot {}",
            envelopes.len(),
            input.slot
        ),
    ));
    let preimages = match steps::index_quorum_sets(&input.quorum_sets_xdr) {
        Ok(p) => p,
        Err(error) => {
            report(failed(3, "quorum-set authentication", &error));

            return finish(input, mutation, steps_out, 0, None, evidence);
        }
    };

    let signers = match steps::verify_quorum_set_hashes(&envelopes, &preimages) {
        Ok(s) => s,
        Err(error) => {
            report(failed(3, "quorum-set authentication", &error));

            return finish(input, mutation, steps_out, 0, None, evidence);
        }
    };

    report(ok(
        3,
        "quorum-set authentication",
        format!(
            "{} preimage(s) matched their committed hash",
            preimages.len()
        ),
    ));
    let externalized = match steps::verify_externalized_quorum(&config.local, &signers, &envelopes)
    {
        Ok(externalized) => externalized,
        Err(error) => {
            report(failed(4, "quorum check", &error));

            return finish(input, mutation, steps_out, 0, None, evidence);
        }
    };

    evidence.supporters = externalized
        .supporters
        .iter()
        .map(crate::strkey::account_id)
        .collect();
    evidence.discarded = externalized
        .discarded
        .iter()
        .map(crate::strkey::account_id)
        .collect();
    evidence.externalized_value = Some(hex::encode(&externalized.value));
    report(ok(
        4,
        "quorum check",
        format!(
            "{} signer(s) form a quorum for the trust root, {} discarded (verify_externalized_quorum: each signer's own published quorum set ratifies)",
            externalized.supporters.len(),
            externalized.discarded.len()
        ),
    ));
    report(ok(
        5,
        "value agreement",
        format!("one agreed value, {} bytes", externalized.value.len()),
    ));
    let header =
        match steps::verify_scp_header(&input.ledger_header_xdr, input.slot, &externalized.value) {
            Ok(h) => h,
            Err(error) => {
                report(failed(6, "ledger binding", &error));

                return finish(
                    input,
                    mutation,
                    steps_out,
                    externalized.supporters.len(),
                    None,
                    evidence,
                );
            }
        };

    let ledger_hash =
        match steps::verify_ledger_hash(&input.ledger_header_xdr, input.recorded_ledger_hash) {
            Ok(h) => h,
            Err(error) => {
                report(failed(6, "ledger binding", &error));

                return finish(
                    input,
                    mutation,
                    steps_out,
                    externalized.supporters.len(),
                    None,
                    evidence,
                );
            }
        };

    if let Err(error) =
        steps::verify_previous_ledger(&header.previous_ledger_hash, input.trusted_previous_hash)
    {
        report(failed(6, "ledger binding", &error));

        return finish(
            input,
            mutation,
            steps_out,
            externalized.supporters.len(),
            None,
            evidence,
        );
    }

    let parent_link = match input.trusted_previous_hash {
        Some(_) => "parent link verified against the ledger hash you trust at N-1",
        None => {
            "parent link NOT checked: no trusted N-1 hash was supplied, so this shows the \
             trust root signed this ledger, not that it is on the chain you already trust"
        }
    };

    report(ok(
        6,
        "ledger binding",
        format!(
            "sha256(header) = {}; {parent_link}",
            hex::encode(ledger_hash)
        ),
    ));

    match (next, input.slot.checked_add(1)) {
        (Some(n), Some(next_slot)) if !n.tx_set_xdr.is_empty() => {
            let next_input = HeaderInput {
                slot: next_slot,
                network_id: input.network_id,
                envelopes_xdr: n.envelopes_xdr.to_vec(),
                quorum_sets_xdr: n.quorum_sets_xdr.to_vec(),
                ..HeaderInput::default()
            };

            match next_envelopes(&next_input, config) {
                Ok(next_value) => {
                    match steps::verify_next_slot_binding(&next_value, n.tx_set_xdr, &ledger_hash) {
                        Ok(()) => report(ok(
                            7,
                            "next-slot binding",
                            format!("slot {next_slot} names this ledger as predecessor"),
                        )),
                        Err(error) => report(failed(7, "next-slot binding", &error)),
                    }
                }
                Err(error) => report(failed(7, "next-slot binding", &error)),
            }
        }
        _ => report(skipped(
            7,
            "next-slot binding",
            "no slot N+1 evidence supplied",
        )),
    }

    if input.result_pairs_xdr.is_empty() {
        report(skipped(
            8,
            "result-set binding",
            "transaction results were not supplied, so txSetResultHash is not checked",
        ));
    } else {
        match steps::verify_result_set(&input.result_pairs_xdr, &header.tx_set_result_hash) {
            Ok(()) => report(ok(
                8,
                "result-set binding",
                format!("{} result pair(s) hashed", input.result_pairs_xdr.len()),
            )),
            Err(error) => report(failed(8, "result-set binding", &error)),
        }
    }

    let supporters = externalized.supporters.len();

    finish(
        input,
        mutation,
        steps_out,
        supporters,
        Some(ledger_hash),
        evidence,
    )
}

fn next_envelopes(input: &HeaderInput, config: &QuorumConfig) -> Result<Vec<u8>, VerifyError> {
    let mut envelopes = Vec::with_capacity(input.envelopes_xdr.len());

    for raw in &input.envelopes_xdr {
        let envelope = steps::validate_externalize(raw, input.slot)?;

        steps::verify_envelope_signature(&envelope, &input.network_id)?;

        envelopes.push(envelope);
    }

    steps::reject_duplicate_signers(&envelopes)?;
    let preimages = steps::index_quorum_sets(&input.quorum_sets_xdr)?;
    let signers = steps::verify_quorum_set_hashes(&envelopes, &preimages)?;

    steps::verify_externalized_quorum(&config.local, &signers, &envelopes)
        .map(|externalized| externalized.value)
}

fn finish(
    input: &HeaderInput,
    mutation: Option<String>,
    steps_out: Vec<StepResult>,
    signers: usize,
    ledger_hash: Option<[u8; 32]>,
    evidence: Evidence,
) -> Report {
    let passed = |step: usize| steps_out.iter().any(|s| s.step == step && s.passed);

    let core_accepted = steps_out.iter().any(|s| s.step == CORE_STEP && s.passed);
    let core_full = steps_out
        .iter()
        .any(|s| s.step == CORE_STEP && s.passed && s.name == CORE_FULL);

    let reimplementation_failed = steps_out
        .iter()
        .any(|s| s.step >= 1 && !s.passed && !s.skipped);

    let scp_verified = core_accepted;
    let header_authenticated = core_full;
    let results_verified = passed(8);
    let strict_check_failed = core_accepted && reimplementation_failed;
    let anchored = input.trusted_previous_hash.is_some() && core_full;

    let failure_verdict = steps_out.iter().find_map(|step| step.verdict);
    let verified = core_full && !reimplementation_failed;

    let verdict = if let Some(reported) = failure_verdict {
        reported
    } else if core_full && anchored {
        crate::error::Verdict::Verified
    } else if core_full {
        crate::error::Verdict::VerifiedUnanchored
    } else {
        crate::error::Verdict::VerifiedPartial
    };

    Report {
        ledger: input.slot,
        verified,
        scp_verified,
        header_authenticated,
        results_verified,
        strict_check_failed,
        verdict,
        anchored,
        next_slot_unavailable: None,
        signers,
        ledger_hash: ledger_hash.map(hex::encode),
        mutation,
        steps: steps_out,
        evidence,
    }
}

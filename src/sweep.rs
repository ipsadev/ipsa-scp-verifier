use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use crate::error::{Error, Result};
use sha2::{Digest, Sha256};

use crate::archive::{self, checkpoint_for, next_checkpoint, CHECKPOINT_FREQUENCY};
use crate::error::{Verdict, VerifyError};
use crate::history::{self, ArchivedEnvelope, HeaderHistoryEntry, ScpHistoryEntry};
use crate::network::Network;
use crate::report;
use crate::scp::envelope::Envelope;
use crate::steps::{self, HeaderInput, QuorumConfig};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    Verified,
    LegacyTxSet,
    NoScpEvidence,
    IncompleteEvidence,
    SubQuorumEvidence,
    InsaneHistoricalQset,
    InvalidEvidence,
    Disagreement,
}

impl Outcome {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::LegacyTxSet => "legacy-txset",
            Self::NoScpEvidence => "no-scp-evidence",
            Self::IncompleteEvidence => "incomplete-evidence",
            Self::SubQuorumEvidence => "sub-quorum-evidence",
            Self::InsaneHistoricalQset => "insane-historical-qset",
            Self::InvalidEvidence => "invalid-evidence",
            Self::Disagreement => "disagreement",
        }
    }

    pub fn is_finding(self) -> bool {
        self == Self::Disagreement
    }

    fn of(error: &VerifyError) -> Self {
        match error {
            VerifyError::InsaneQuorumSet { .. } => Self::InsaneHistoricalQset,
            VerifyError::NoEnvelopes | VerifyError::InsufficientQuorum { .. } => {
                Self::SubQuorumEvidence
            }
            VerifyError::QuorumSetPreimageMissing { .. } => Self::IncompleteEvidence,
            other if other.verdict() == Verdict::InvalidEvidence => Self::InvalidEvidence,
            _ => Self::Disagreement,
        }
    }
}

pub struct Options {
    pub network: Network,
    pub archives: Vec<String>,
    pub from: u32,
    pub to: u32,
    pub next_slot: bool,
    pub results: bool,
    pub trust_root_xdr: Option<Vec<u8>>,
    pub jsonl: Option<PathBuf>,
}

pub struct Row {
    pub ledger: u32,
    pub outcome: Outcome,
    pub protocol: Option<u32>,
    pub archives: usize,
    pub envelopes: usize,
    pub externalize: usize,
    pub conflicts: usize,
    pub reason: Option<String>,
}

impl Row {
    fn to_json(&self) -> String {
        serde_json::json!({
            "ledger": self.ledger,
            "outcome": self.outcome.tag(),
            "archives": self.archives,
            "envelopes": self.envelopes,
            "externalize": self.externalize,
            "conflicts": self.conflicts,
            "protocol": self.protocol,
            "reason": self.reason,
        })
        .to_string()
    }
}

pub struct MergedSlot {
    pub quorum_sets_xdr: Vec<Vec<u8>>,
    pub externalize_xdr: Vec<Vec<u8>>,
    pub total_envelopes: usize,
    pub conflicting_nodes: Vec<String>,
    pub sources: usize,
}

pub fn merge_slot(per_archive: &[&ScpHistoryEntry]) -> Result<MergedSlot> {
    let mut quorum_sets_xdr: Vec<Vec<u8>> = Vec::new();
    let mut by_node: BTreeMap<[u8; 32], (Vec<u8>, Vec<u8>)> = BTreeMap::new();
    let mut conflicting: BTreeMap<[u8; 32], ()> = BTreeMap::new();
    let mut total = 0usize;

    for entry in per_archive {
        for quorum_set in &entry.quorum_sets_xdr {
            if !quorum_sets_xdr.contains(quorum_set) {
                quorum_sets_xdr.push(quorum_set.clone());
            }
        }

        total += entry.envelopes.len();

        for env in entry
            .envelopes
            .iter()
            .filter(|envelope| envelope.is_externalize())
        {
            let value = commit_value(env)?;

            match by_node.get(&env.node_id) {
                None => {
                    by_node.insert(env.node_id, (value, env.envelope_xdr.clone()));
                }
                Some((seen, _)) if *seen == value => {}
                Some(_) => {
                    conflicting.insert(env.node_id, ());
                }
            }
        }
    }

    for node in conflicting.keys() {
        by_node.remove(node);
    }

    Ok(MergedSlot {
        quorum_sets_xdr,
        externalize_xdr: by_node.into_values().map(|(_, xdr)| xdr).collect(),
        total_envelopes: total,
        conflicting_nodes: conflicting.keys().map(hex::encode).collect(),
        sources: per_archive.len(),
    })
}

fn commit_value(env: &ArchivedEnvelope) -> Result<Vec<u8>> {
    Envelope::decode(&env.envelope_xdr)
        .map(|envelope| envelope.statement.value().to_vec())
        .map_err(|error| Error::ArchivedEnvelopeUndecodable {
            node: hex::encode(env.node_id),
            detail: error.to_string(),
        })
}

#[derive(Default)]
pub struct Checkpoint {
    pub slots: BTreeMap<u32, MergedSlot>,
    pub headers: BTreeMap<u32, HeaderHistoryEntry>,
    pub results: BTreeMap<u32, Vec<Vec<u8>>>,
    pub tx_sets: BTreeMap<u32, Option<Vec<u8>>>,
}

impl Checkpoint {
    pub fn parent_hash(&self, ledger: u32) -> Option<[u8; 32]> {
        let parent = self.headers.get(&ledger.checked_sub(1)?)?;

        crate::steps::verify_ledger_hash(&parent.header_xdr, None).ok()
    }
}

pub async fn load_checkpoint(
    checkpoint: u32,
    options: &Options,
    want_tx_sets: bool,
) -> Result<Checkpoint> {
    let mut per_archive: Vec<Vec<ScpHistoryEntry>> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let fetched = futures::future::join_all(
        options
            .archives
            .iter()
            .map(|base| archive::fetch(base, "scp", checkpoint)),
    )
    .await;

    for (base, outcome) in options.archives.iter().zip(fetched) {
        match outcome {
            Ok(raw) => per_archive.push(
                archive::frames(&raw)?
                    .into_iter()
                    .map(history::read_scp_history_entry)
                    .collect::<Result<Vec<_>>>()?,
            ),
            Err(error) => errors.push(format!("{base}: {error}")),
        }
    }

    if per_archive.is_empty() {
        return Err(Error::NoArchiveServedCheckpoint {
            checkpoint,
            detail: errors.join("; "),
        });
    }

    if !errors.is_empty() {
        report::warn(&format!(
            "checkpoint {checkpoint}: {} of {} archives did not serve scp - {}",
            errors.len(),
            options.archives.len(),
            errors.join("; ")
        ));
    }

    let mut ledgers: Vec<u32> = Vec::new();

    for entries in &per_archive {
        for entry in entries {
            if !ledgers.contains(&entry.ledger_seq) {
                ledgers.push(entry.ledger_seq);
            }
        }
    }

    let mut slots = BTreeMap::new();

    for seq in ledgers {
        let found: Vec<&ScpHistoryEntry> = per_archive
            .iter()
            .filter_map(|entries| entries.iter().find(|entry| entry.ledger_seq == seq))
            .collect();

        slots.insert(seq, merge_slot(&found)?);
    }

    let primary = &options.archives[0];
    let (ledger_raw, results_raw, tx_raw) = futures::future::join3(
        archive::fetch(primary, "ledger", checkpoint),
        async {
            match options.results {
                true => Some(archive::fetch(primary, "results", checkpoint).await),
                false => None,
            }
        },
        async {
            match want_tx_sets {
                true => Some(archive::fetch(primary, "transactions", checkpoint).await),
                false => None,
            }
        },
    )
    .await;
    let ledger_raw = ledger_raw?;
    let headers = archive::frames(&ledger_raw)?
        .into_iter()
        .map(history::read_header_history_entry)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .map(|header| (header.ledger_seq, header))
        .collect();
    let results = if let Some(raw) = results_raw {
        let raw = raw?;

        archive::frames(&raw)?
            .into_iter()
            .map(history::read_result_record)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|entry| (entry.ledger_seq, entry.result_pairs))
            .collect()
    } else {
        BTreeMap::new()
    };

    let tx_sets = if let Some(raw) = tx_raw {
        let raw = raw?;

        archive::frames(&raw)?
            .into_iter()
            .map(history::read_tx_history_entry)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|entry| (entry.ledger_seq, entry.generalized_xdr))
            .collect()
    } else {
        BTreeMap::new()
    };

    Ok(Checkpoint {
        slots,
        headers,
        results,
        tx_sets,
    })
}

fn protocol_of(header: &HeaderHistoryEntry) -> Option<u32> {
    header
        .header_xdr
        .get(0..4)
        .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn row(ledger: u32, outcome: Outcome, reason: Option<String>) -> Row {
    Row {
        ledger,
        outcome,
        protocol: None,
        archives: 0,
        envelopes: 0,
        externalize: 0,
        conflicts: 0,
        reason,
    }
}

async fn verify_one(
    ledger: u32,
    options: &Options,
    config: &QuorumConfig,
    at: &Checkpoint,
    next: &Checkpoint,
) -> Row {
    let Some(slot) = at.slots.get(&ledger) else {
        return row(
            ledger,
            Outcome::NoScpEvidence,
            Some("no SCP messages archived for this ledger".into()),
        );
    };

    let Some(header) = at.headers.get(&ledger) else {
        return row(
            ledger,
            Outcome::IncompleteEvidence,
            Some("no ledger header archived".into()),
        );
    };

    let mut out = Row {
        ledger,
        outcome: Outcome::Verified,
        protocol: protocol_of(header),
        archives: slot.sources,
        envelopes: slot.total_envelopes,
        externalize: slot.externalize_xdr.len(),
        conflicts: slot.conflicting_nodes.len(),
        reason: None,
    };

    if !slot.conflicting_nodes.is_empty() {
        out.outcome = Outcome::Disagreement;
        out.reason = Some(format!(
            "{} node(s) published two EXTERNALIZE statements with different values: {}",
            slot.conflicting_nodes.len(),
            slot.conflicting_nodes.join(", ")
        ));

        return out;
    }

    let input = HeaderInput {
        slot: ledger as u64,
        network_id: options.network.id(),
        ledger_header_xdr: header.header_xdr.clone(),
        envelopes_xdr: slot.externalize_xdr.clone(),
        quorum_sets_xdr: slot.quorum_sets_xdr.clone(),
        recorded_ledger_hash: Some(header.recorded_hash),
        result_pairs_xdr: at.results.get(&ledger).cloned().unwrap_or_default(),
        trusted_previous_hash: at.parent_hash(ledger),
    };

    let verified = match steps::verify_ledger(&input, config) {
        Ok(v) => v,
        Err(error) => {
            out.outcome = Outcome::of(&error);
            out.reason = Some(error.to_string());

            return out;
        }
    };

    if options.results {
        if let Err(error) =
            steps::verify_result_set(&input.result_pairs_xdr, &verified.tx_set_result_hash)
        {
            out.outcome = Outcome::Disagreement;
            out.reason = Some(error.to_string());

            return out;
        }
    }

    if !options.next_slot {
        return out;
    }

    let Some(following) = ledger.checked_add(1) else {
        out.outcome = Outcome::IncompleteEvidence;
        out.reason = Some("there is no slot after the last ledger sequence".into());

        return out;
    };

    let source = if checkpoint_for(following) == checkpoint_for(ledger) {
        at
    } else {
        next
    };

    let Some(next_slot) = source.slots.get(&following) else {
        out.outcome = Outcome::IncompleteEvidence;
        out.reason = Some(format!("no SCP messages archived for slot {following}"));

        return out;
    };

    let tx_set = match source.tx_sets.get(&following) {
        Some(Some(xdr)) => xdr.clone(),
        Some(None) => {
            out.outcome = Outcome::LegacyTxSet;
            out.reason = Some(format!(
                "slot {following} has a legacy tx set; the binding needs a generalized one"
            ));

            return out;
        }
        None => {
            out.outcome = Outcome::IncompleteEvidence;
            out.reason = Some(format!("no tx set archived for slot {following}"));

            return out;
        }
    };

    let next_input = HeaderInput {
        slot: following as u64,
        network_id: options.network.id(),
        ledger_header_xdr: Vec::new(),
        envelopes_xdr: next_slot.externalize_xdr.clone(),
        quorum_sets_xdr: next_slot.quorum_sets_xdr.clone(),
        recorded_ledger_hash: None,
        result_pairs_xdr: Vec::new(),
        trusted_previous_hash: None,
    };

    let next_value = match externalized_value(&next_input, config) {
        Ok(v) => v,
        Err(error) => {
            out.outcome = Outcome::of(&error);
            out.reason = Some(format!("slot {following}: {error}"));

            return out;
        }
    };

    if let Err(error) = steps::verify_next_slot_binding(&next_value, &tx_set, &verified.ledger_hash)
    {
        out.outcome = Outcome::Disagreement;
        out.reason = Some(error.to_string());
    }

    out
}

fn externalized_value(
    input: &HeaderInput,
    config: &QuorumConfig,
) -> core::result::Result<Vec<u8>, VerifyError> {
    let envelopes = input
        .envelopes_xdr
        .iter()
        .map(|raw| steps::validate_externalize(raw, input.slot))
        .collect::<core::result::Result<Vec<_>, _>>()?;

    steps::reject_duplicate_signers(&envelopes)?;

    for env in &envelopes {
        steps::verify_envelope_signature(env, &input.network_id)?;
    }

    let preimages = steps::index_quorum_sets(&input.quorum_sets_xdr)?;
    let signers = steps::verify_quorum_set_hashes(&envelopes, &preimages)?;

    steps::verify_externalized_quorum(config, &signers, &envelopes)
        .map(|externalized| externalized.value)
}

pub struct ScanRow {
    pub checkpoint: u32,
    pub archives: usize,
    pub distinct: usize,
    pub ledgers: usize,
    pub conflicts: Vec<u32>,
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub async fn scan_checkpoint(checkpoint: u32, options: &Options) -> Result<ScanRow> {
    let mut seen: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    let mut reached = 0usize;
    let fetched = futures::future::join_all(
        options
            .archives
            .iter()
            .map(|base| archive::fetch(base, "scp", checkpoint)),
    )
    .await;

    for outcome in fetched {
        let Ok(raw) = outcome else {
            continue;
        };

        reached += 1;
        let digested = digest(&raw);

        if !seen.iter().any(|(seen_digest, _)| *seen_digest == digested) {
            seen.push((digested, raw));
        }
    }

    if seen.is_empty() {
        return Err(Error::NoArchiveForCheckpoint { checkpoint });
    }

    let mut per_archive: Vec<Vec<ScpHistoryEntry>> = Vec::new();

    for (_, raw) in &seen {
        per_archive.push(
            archive::frames(raw)?
                .into_iter()
                .map(history::read_scp_history_entry)
                .collect::<Result<Vec<_>>>()?,
        );
    }

    let mut ledgers: Vec<u32> = Vec::new();

    for entries in &per_archive {
        for entry in entries {
            if !ledgers.contains(&entry.ledger_seq) {
                ledgers.push(entry.ledger_seq);
            }
        }
    }

    let mut conflicts = Vec::new();

    for seq in &ledgers {
        let found: Vec<&ScpHistoryEntry> = per_archive
            .iter()
            .filter_map(|entries| entries.iter().find(|entry| entry.ledger_seq == *seq))
            .collect();

        if !merge_slot(&found)?.conflicting_nodes.is_empty() {
            conflicts.push(*seq);
        }
    }

    Ok(ScanRow {
        checkpoint,
        archives: reached,
        distinct: seen.len(),
        ledgers: ledgers.len(),
        conflicts,
    })
}

pub async fn scan(options: &Options) -> Result<()> {
    report::banner("scan");
    report::explain(
        "over a range of history, did any validator externalize two different values for one slot?",
        "no signatures are verified and no headers are read; this only looks for equivocation, \
         which is the only outcome that would be a finding rather than a property of the archives",
    );

    for base in &options.archives {
        report::detail(&format!("archive: {base}"));
    }

    let first = archive::checkpoint_for(options.from);
    let last = archive::checkpoint_for(options.to);
    let mut checkpoints = 0usize;
    let mut ledgers = 0usize;
    let mut independent = 0usize;
    let mut mirrored = 0usize;
    let mut findings: Vec<u32> = Vec::new();
    let mut checkpoint = first;

    while checkpoint <= last {
        match scan_checkpoint(checkpoint, options).await {
            Ok(row) => {
                checkpoints += 1;
                ledgers += row.ledgers;

                if row.distinct > 1 {
                    independent += 1;
                } else {
                    mirrored += 1;
                }

                if row.conflicts.is_empty() {
                    report::detail(&format!(
                        "checkpoint {checkpoint}: {} ledger(s), {} of {} archive(s) distinct",
                        row.ledgers, row.distinct, row.archives
                    ));
                } else {
                    for sequence_number in &row.conflicts {
                        report::warn(&format!(
                            "ledger {sequence_number} - DISAGREEMENT: a node externalized two different values"
                        ));
                    }

                    findings.extend(row.conflicts);
                }
            }
            Err(error) => report::warn(&format!("checkpoint {checkpoint}: {error:#}")),
        }

        match next_checkpoint(checkpoint) {
            Some(following) => checkpoint = following,
            None => break,
        }
    }

    report::banner("scan summary");
    report::detail(&format!("{checkpoints} checkpoint(s), {ledgers} ledger(s)"));
    report::detail(&format!(
        "{independent} checkpoint(s) had archives that differ; {mirrored} served identical bytes"
    ));

    if mirrored > 0 {
        report::warn(&format!(
            "{mirrored} checkpoint(s) served byte-identical files from every archive. Identical \
             archives are one witness, not several, so equivocation there is undetectable by \
             comparison"
        ));
    }

    if findings.is_empty() {
        report::ok("no disagreement: no node externalized two different values for one slot");
    } else {
        report::fail(&format!("{} ledger(s) with disagreement", findings.len()));
    }

    Ok(())
}

pub async fn run(options: &Options) -> Result<()> {
    let rows = sweep(options).await?;

    summarize(options, &rows).await
}

pub async fn sweep(options: &Options) -> Result<Vec<Row>> {
    if options.to < options.from {
        return Err(Error::RangeInverted {
            from: options.from,
            to: options.to,
        });
    }

    let config = QuorumConfig::from_xdr(
        options
            .trust_root_xdr
            .as_deref()
            .ok_or(Error::NoTrustRoot)?,
    )?;

    report::banner(&format!(
        "sweep - {} ledgers {}..{}",
        options.network.label(),
        options.from,
        options.to
    ));
    report::explain(
        "over a range of history, where does verification stop, and why?",
        "every ledger is classified; only 'disagreement' is a verifier finding, everything else is \
         a property of the archives",
    );

    for base in &options.archives {
        report::detail(&format!("archive: {base}"));
    }

    report::detail(&format!(
        "steps 1-6 always; step 7 {}, step 8 {}",
        if options.next_slot { "on" } else { "off" },
        if options.results { "on" } else { "off" }
    ));
    report::detail(&format!(
        "{} ledger(s) across {} checkpoint(s) of {CHECKPOINT_FREQUENCY}",
        u64::from(options.to - options.from) + 1,
        checkpoint_for(options.to) / CHECKPOINT_FREQUENCY
            - checkpoint_for(options.from) / CHECKPOINT_FREQUENCY
            + 1
    ));
    let mut sink = match &options.jsonl {
        Some(path) => Some(
            std::fs::File::create(path).map_err(|error| Error::FileCreate {
                path: path.display().to_string(),
                detail: error.to_string(),
            })?,
        ),
        None => None,
    };

    let mut rows: Vec<Row> = Vec::new();
    let mut cached: Option<(u32, Checkpoint)> = None;
    let mut ledger = options.from;

    while ledger <= options.to {
        let checkpoint = checkpoint_for(ledger);

        report::step(&format!(
            "checkpoint {checkpoint} - ledgers {}..{}",
            ledger,
            options.to.min(checkpoint)
        ));
        let at = match take_checkpoint(&mut cached, checkpoint, options, options.next_slot).await {
            Ok(c) => c,
            Err(error) => {
                report::warn(&format!("checkpoint {checkpoint} unavailable: {error:#}"));

                for seq in ledger..=options.to.min(checkpoint) {
                    let r = row(
                        seq,
                        Outcome::NoScpEvidence,
                        Some(format!("checkpoint {checkpoint} unavailable: {error}")),
                    );

                    record(&mut rows, &mut sink, r)?;
                }

                match checkpoint.checked_add(1) {
                    Some(following) => ledger = following,
                    None => break,
                }

                continue;
            }
        };

        let last = options.to.min(checkpoint);
        let spans = options.next_slot && last == checkpoint;
        let following_checkpoint = next_checkpoint(checkpoint).filter(|_| spans);
        let next = match following_checkpoint {
            Some(following) => match load_checkpoint(following, options, true).await {
                Ok(c) => Some((following, c)),
                Err(error) => {
                    report::warn(&format!(
                        "checkpoint {following} unavailable, so the last ledger of {checkpoint} cannot bind forward: {error:#}"
                    ));

                    None
                }
            },
            None => None,
        };

        let empty = Checkpoint {
            slots: BTreeMap::new(),
            headers: BTreeMap::new(),
            results: BTreeMap::new(),
            tx_sets: BTreeMap::new(),
        };

        for seq in ledger..=last {
            let following = next.as_ref().map_or(&empty, |(_, loaded)| loaded);
            let r = verify_one(seq, options, &config, &at, following).await;

            record(&mut rows, &mut sink, r)?;
        }

        cached = next;

        match checkpoint.checked_add(1) {
            Some(following) => ledger = following,
            None => break,
        }
    }

    Ok(rows)
}

async fn summarize(options: &Options, rows: &[Row]) -> Result<()> {
    let mut counts: BTreeMap<Outcome, usize> = BTreeMap::new();

    for row in rows {
        *counts.entry(row.outcome).or_default() += 1;
    }

    let findings: Vec<&Row> = rows.iter().filter(|row| row.outcome.is_finding()).collect();

    report::step("sweep summary");
    let total: usize = counts.values().sum();

    for (outcome, count) in &counts {
        let share = count * 100 / total.max(1);

        report::ok(&format!("{:<24} {count:>7}  ({share}%)", outcome.tag()));
    }

    if let Some(path) = &options.jsonl {
        report::detail(&format!(
            "one JSON object per ledger written to {}",
            path.display()
        ));
    }

    if findings.is_empty() {
        report::hint(
            "no disagreement - every ledger either verified or lacked the evidence to try",
        );

        return Ok(());
    }

    report::fail(&format!(
        "{} ledger(s) disagreed with the archived header",
        findings.len()
    ));

    for finding in findings.iter().take(20) {
        report::item(&format!(
            "ledger {} - {}",
            finding.ledger,
            finding.reason.as_deref().unwrap_or("no reason recorded")
        ));
    }

    Err(Error::Disagreements {
        count: findings.len(),
    })
}

async fn take_checkpoint(
    cached: &mut Option<(u32, Checkpoint)>,
    checkpoint: u32,
    options: &Options,
    want_tx_sets: bool,
) -> Result<Checkpoint> {
    if let Some((have, _)) = cached {
        if *have == checkpoint {
            if let Some((_, loaded)) = cached.take() {
                return Ok(loaded);
            }
        }
    }

    load_checkpoint(checkpoint, options, want_tx_sets).await
}

fn record(rows: &mut Vec<Row>, sink: &mut Option<std::fs::File>, row: Row) -> Result<()> {
    if let Some(file) = sink {
        writeln!(file, "{}", row.to_json()).map_err(|error| Error::JsonlWrite {
            detail: error.to_string(),
        })?;
    }

    match row.outcome {
        Outcome::Verified => report::ok(&format!(
            "ledger {} - verified ({} signer(s) from {} archive(s))",
            row.ledger, row.externalize, row.archives
        )),
        Outcome::Disagreement => report::fail(&format!(
            "ledger {} - {}",
            row.ledger,
            row.reason.as_deref().unwrap_or("disagreement")
        )),
        other => report::warn(&format!(
            "ledger {} - {}: {}",
            row.ledger,
            other.tag(),
            row.reason.as_deref().unwrap_or("no reason recorded")
        )),
    }

    rows.push(row);

    Ok(())
}

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use sha2::{Digest, Sha256};

use crate::archive;
use crate::history;
use crate::network::Network;
use crate::report;

const TX_SET_HASH_OFFSET: usize = 36;
const TX_SET_HASH_END: usize = 68;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub struct Options {
    pub network: Network,
    pub archives: Vec<String>,
    pub from: u32,
    pub to: u32,
}

#[derive(Default)]
pub struct Totals {
    pub checkpoints: usize,
    pub headers: usize,
    pub matched: usize,
    pub mismatched: Vec<u32>,
    pub absent: usize,
    pub legacy: usize,
    pub sentinel: usize,
    pub unreadable: usize,
}

pub async fn audit_checkpoint(checkpoint: u32, base: &str, totals: &mut Totals) -> Result<()> {
    let ledger_raw = archive::fetch(base, "ledger", checkpoint).await?;
    let headers: Vec<_> = archive::frames(&ledger_raw)?
        .into_iter()
        .map(history::read_header_history_entry)
        .collect::<Result<Vec<_>>>()?;
    let tx_raw = archive::fetch(base, "transactions", checkpoint).await?;
    let mut sets: BTreeMap<u32, Option<Vec<u8>>> = BTreeMap::new();

    for frame in archive::frames(&tx_raw)? {
        let record = history::read_tx_history_entry(frame)?;

        sets.insert(record.ledger_seq, record.generalized_xdr);
    }

    for header in &headers {
        totals.headers += 1;
        let Some(want) = header
            .header_xdr
            .get(TX_SET_HASH_OFFSET..TX_SET_HASH_END)
            .map(hex::encode)
        else {
            totals.unreadable += 1;
            continue;
        };

        if want == ZERO_HASH {
            totals.sentinel += 1;
            continue;
        }

        match sets.get(&header.ledger_seq) {
            Some(Some(xdr)) => {
                if hex::encode(Sha256::digest(xdr)) == want {
                    totals.matched += 1;
                } else {
                    report::warn(&format!(
                        "ledger {} - TX SET HASH MISMATCH: header says {want}, archived set hashes to {}",
                        header.ledger_seq,
                        hex::encode(Sha256::digest(xdr))
                    ));
                    totals.mismatched.push(header.ledger_seq);
                }
            }
            Some(None) => totals.legacy += 1,
            None => totals.absent += 1,
        }
    }

    Ok(())
}

pub async fn run(options: &Options) -> Result<()> {
    report::banner("audit");
    report::explain(
        "does every archived transaction set hash to the txSetHash its ledger header names?",
        "this is an archive-integrity question, not a consensus one: it compares two files the \
         archive publishes against each other, and says nothing about what validators agreed",
    );
    let base = options
        .archives
        .first()
        .cloned()
        .unwrap_or_else(|| options.network.archive_base().to_string());

    if options.archives.len() > 1 {
        report::warn("--audit reads only the first --archive; the others are ignored");
    }

    report::detail(&format!("archive: {base}"));
    let first = archive::checkpoint_for(options.from);
    let last = archive::checkpoint_for(options.to);
    let mut totals = Totals::default();
    let mut checkpoint = first;

    while checkpoint <= last {
        match audit_checkpoint(checkpoint, &base, &mut totals).await {
            Ok(()) => totals.checkpoints += 1,
            Err(error) => report::warn(&format!("checkpoint {checkpoint}: {error:#}")),
        }

        match archive::next_checkpoint(checkpoint) {
            Some(following) => checkpoint = following,
            None => break,
        }
    }

    report::banner("audit summary");
    report::detail(&format!(
        "{} checkpoint(s), {} header(s)",
        totals.checkpoints, totals.headers
    ));
    report::ok(&format!("{} txSetHash matched", totals.matched));

    if totals.absent > 0 {
        report::detail(&format!(
            "{} ledger(s) had no archived transaction set. A ledger with no transactions has no \
             transaction set, so this is expected rather than damage",
            totals.absent
        ));
    }

    if totals.legacy > 0 {
        report::detail(&format!(
            "{} ledger(s) used a legacy transaction set, whose txSetHash is not a plain hash of \
             the archived bytes, so they were not checked",
            totals.legacy
        ));
    }

    if totals.sentinel > 0 {
        report::detail(&format!(
            "{} ledger(s) carry an all-zero txSetHash, which is a sentinel and not the hash of \
             anything",
            totals.sentinel
        ));
    }

    if totals.mismatched.is_empty() {
        report::ok("no transaction set disagreed with the hash its header names");
    } else {
        report::fail(&format!(
            "{} ledger(s) where the archived transaction set does not hash to its header's \
             txSetHash",
            totals.mismatched.len()
        ));

        return Err(Error::AuditMismatches {
            count: totals.mismatched.len(),
        });
    }

    Ok(())
}

use std::collections::BTreeMap;

use clap::Parser;
use ipsa_scp_verifier::error::{Error, Result};

use ipsa_scp_verifier::archive::{self, checkpoint_for};
use ipsa_scp_verifier::audit;
use ipsa_scp_verifier::fixture::{self, Fixture, NextSlot};
use ipsa_scp_verifier::history::{self, ScpHistoryEntry};
use ipsa_scp_verifier::negative::{self, Outcome};
use ipsa_scp_verifier::network::Network;
use ipsa_scp_verifier::rawdump;
use ipsa_scp_verifier::report;
use ipsa_scp_verifier::scp::envelope::Envelope;
use ipsa_scp_verifier::scp::ledger::tx_set_hash_of_value;
use ipsa_scp_verifier::scp::quorum::QuorumSet;
use ipsa_scp_verifier::serve;
use ipsa_scp_verifier::steps::{self, HeaderInput, QuorumConfig, VerifiedLedger};
use ipsa_scp_verifier::strkey;
use ipsa_scp_verifier::sweep;

const TOTAL_STEPS: usize = 8;

#[derive(Parser, Debug)]
#[command(
    name = "scp-verify",
    version,
    about = "Independently verify Stellar SCP consensus for a single ledger",
    long_about = "Verifies, against the public Stellar history archives, that a quorum of \
validators externalized a given ledger and that a specific LedgerHeader is the one they \
agreed on. Every check runs locally against signed SCP envelopes - no Horizon or RPC \
provider is trusted for evidence."
)]
struct Cli {
    #[arg(
        long,
        value_name = "SEQ",
        help = "Ledger sequence to verify, e.g. 63907880 on mainnet"
    )]
    ledger: Option<u32>,
    #[arg(
        long,
        value_name = "PORT",
        conflicts_with_all = ["ledger", "fixture", "range"],
        help = "Serve per-step verification over HTTP on this port instead of verifying once"
    )]
    serve: Option<u16>,
    #[arg(
        long,
        value_name = "ORIGIN",
        requires = "serve",
        help = "Browser origin allowed to call the server. Repeat to allow several"
    )]
    cors_origin: Vec<String>,
    #[arg(
        long,
        default_value = "mainnet",
        help = "Which network's history archive to read: mainnet or testnet"
    )]
    network: String,
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "ledger",
        help = "Verify a frozen test vector instead of fetching the archives"
    )]
    fixture: Option<std::path::PathBuf>,
    #[arg(
        long,
        value_name = "PATH",
        help = "Write the verified data out as a reusable test vector"
    )]
    export: Option<std::path::PathBuf>,
    #[arg(
        long,
        value_name = "HEX",
        help = "Hex-encoded SCPQuorumSet to evaluate the quorum against; defaults to the set the signers themselves pledge"
    )]
    trust_root: Option<String>,
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        help = "Run step 7, binding the header through slot N+1's tx set"
    )]
    next_slot: bool,
    #[arg(
        long,
        value_name = "HEX",
        help = "Hex-encoded hash of the ledger you already trust at N-1; the header must name it as its predecessor"
    )]
    trusted_previous: Option<String>,
    #[arg(
        long,
        value_name = "FROM..TO",
        conflicts_with_all = ["ledger", "fixture", "export", "negative"],
        help = "Verify every ledger in a range, classifying each one instead of stopping at the first failure"
    )]
    range: Option<String>,
    #[arg(
        long,
        requires = "range",
        help = "Only look for equivocation over the range: hash the archives, parse the ones that differ, verify nothing"
    )]
    scan: bool,
    #[arg(
        long,
        requires = "range",
        conflicts_with = "scan",
        help = "Check archive integrity over the range: does every archived transaction set hash to the txSetHash its header names"
    )]
    audit: bool,
    #[arg(
        long,
        value_name = "BASE",
        help = "History archive to read: a base URL, or a local directory. Repeat to merge several archives"
    )]
    archive: Vec<String>,
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        help = "Run step 8, hashing the archived transaction results"
    )]
    results: bool,
    #[arg(
        long,
        value_name = "PATH",
        requires = "range",
        help = "Write one JSON object per swept ledger to this file"
    )]
    jsonl: Option<std::path::PathBuf>,
    #[arg(long, help = "Run the single-mutation negative suite after verifying")]
    negative: bool,
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        help = "Print one line per signer and per validator instead of just totals"
    )]
    list_signers: bool,
    #[arg(
        long,
        value_enum,
        default_value_t = RawMode::Sample,
        help = "How much of the ledger's raw XDR to dump, field by field: off, sample (first item of each kind), or all"
    )]
    raw: RawMode,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, clap::ValueEnum)]
enum RawMode {
    Off,
    Sample,
    All,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        report::fail(&format!("{error:#}"));
        std::process::exit(1);
    }
}

async fn run(args: Cli) -> Result<()> {
    let network = Network::parse(&args.network)?;

    report::banner(&format!("scp-verify - {}", network.label()));
    report::detail(&format!("network passphrase: {:?}", network.passphrase()));
    report::detail(&format!(
        "network id = sha256(passphrase) = {}",
        hex::encode(network.id())
    ));
    report::detail("every SCP signature is made over a preimage starting with that id");

    if let Some(port) = args.serve {
        return serve::run(serve::Options {
            port,
            network,
            archives: archives(&args, network),
            archives_pinned: !args.archive.is_empty(),
            origins: cors_origins(&args),
        })
        .await;
    }

    if let Some(spec) = &args.range {
        let (from, to) = parse_range(spec)?;
        let trust_root_xdr = match &args.trust_root {
            Some(hexed) => Some(fixture::unhex(hexed)?),
            None => None,
        };

        let options = sweep::Options {
            network,
            archives: archives(&args, network),
            from,
            to,
            next_slot: args.next_slot,
            results: args.results,
            trust_root_xdr,
            jsonl: args.jsonl.clone(),
        };

        if args.audit {
            return audit::run(&audit::Options {
                network,
                archives: options.archives.clone(),
                from,
                to,
            })
            .await;
        }

        return if args.scan {
            sweep::scan(&options).await
        } else {
            sweep::run(&options).await
        };
    }

    let (mut input, next, source) = match (&args.fixture, args.ledger) {
        (Some(path), _) => {
            report::step("loading a frozen test vector");
            report::explain(
                "where is the evidence coming from?",
                "a JSON fixture of raw, hex-encoded archive bytes - never decoded structs",
            );
            let fixture = Fixture::load(path)?;
            let (input, next) = fixture.to_input()?;

            report::ok(&format!("read {}", path.display()));
            report::detail(&format!(
                "recorded as {} ledger {}, {} envelope(s), {} quorum-set preimage(s), next slot {}",
                if fixture.network.is_empty() {
                    "-"
                } else {
                    &fixture.network
                },
                fixture.ledger_seq,
                fixture.envelopes_xdr.len(),
                fixture.quorum_sets_xdr.len(),
                if next.is_some() { "included" } else { "absent" }
            ));

            if !fixture.network.is_empty() && fixture.network != network.label() {
                report::warn(&format!(
                    "the fixture says {} but --network says {} - signatures will fail if that is wrong",
                    fixture.network,
                    network.label()
                ));
            }

            (input, next, format!("fixture {}", path.display()))
        }

        (None, Some(ledger)) => {
            let (input, next) = from_archive(
                &archives(&args, network),
                network,
                ledger,
                args.next_slot,
                args.results,
            )
            .await?;

            (input, next, format!("{} history archive", network.label()))
        }

        (None, None) => return Err(Error::NoLedgerSelected),
    };

    if let Some(hexed) = &args.trusted_previous {
        input.trusted_previous_hash =
            Some(
                fixture::unhex32(hexed).map_err(|error| Error::TrustedPrevious {
                    detail: error.to_string(),
                })?,
            );
    }

    report::banner(&format!(
        "verify - {} ledger {}",
        network.label(),
        input.slot
    ));
    report::detail(&format!("evidence source: {source}"));
    report::detail(&format!(
        "network id:      {}",
        hex::encode(input.network_id)
    ));
    plan(next.is_some());
    let config = trust_root(&args, &input)?;

    dump_raw_items(&input, next.as_ref(), args.raw);
    let verified = verify_and_report(&input, &config, next.as_ref(), args.list_signers)?;

    if let Some(path) = &args.export {
        report::step("exporting a test vector");
        report::explain(
            "can this run be replayed offline?",
            "write the same raw bytes back out as JSON, so --fixture reproduces it with no network",
        );
        to_fixture(network, &input, &verified, next.as_ref()).save(path)?;
        report::ok(&format!("wrote test vector to {}", path.display()));
    }

    if args.negative {
        run_negative(&input, &config, next.as_ref())?;
    }

    Ok(())
}

fn plan(has_next_slot: bool) {
    report::explain(
        "did a quorum of validators agree on this ledger, and is this LedgerHeader the one they agreed on?",
        "eight steps, in this order because each one's premise is the previous one's conclusion",
    );
    report::item(
        "step 1  envelope signatures        - each statement really came from the node it names",
    );
    report::item(
        "step 2  statement validation       - all EXTERNALIZE, right slot, no repeated signer",
    );
    report::item(
        "step 3  quorum-set authentication  - the quorum set a node pledges is the one it signed",
    );
    report::item(
        "step 4  quorum check               - the signers backing one value form a quorum for the trust root",
    );
    report::item(
        "step 5  value agreement            - that value is one value, byte for byte, counters ignored",
    );
    report::item("step 6  ledger binding             - that value is this header's scpValue; hash the header");
    report::item(if has_next_slot {
        "step 7  next-slot binding          - slot N+1's tx set points back at this ledger hash"
    } else {
        "step 7  next-slot binding          - skipped, no slot N+1 evidence available"
    });
    report::item(
        "step 8  result-set binding        - the archived results hash to header.txSetResultHash",
    );
}

fn parse_range(spec: &str) -> Result<(u32, u32)> {
    let (from, to) = spec.split_once("..").ok_or_else(|| Error::RangeMalformed {
        specification: spec.to_string(),
    })?;
    let to = to.strip_prefix('=').unwrap_or(to);

    Ok((
        from.trim()
            .parse::<u32>()
            .map_err(|error| Error::RangeBound {
                end: format!("start {from:?}"),
                detail: error.to_string(),
            })?,
        to.trim()
            .parse::<u32>()
            .map_err(|error| Error::RangeBound {
                end: format!("end {to:?}"),
                detail: error.to_string(),
            })?,
    ))
}

fn cors_origins(args: &Cli) -> Vec<String> {
    if !args.cors_origin.is_empty() {
        return args.cors_origin.clone();
    }

    std::env::var("SCP_VERIFY_CORS_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|origin| origin.trim().to_string())
        .filter(|origin| !origin.is_empty())
        .collect()
}

fn archives(args: &Cli, network: Network) -> Vec<String> {
    if args.archive.is_empty() {
        vec![network.archive_base().to_string()]
    } else {
        args.archive.clone()
    }
}

async fn from_archive(
    bases: &[String],
    network: Network,
    ledger: u32,
    want_next: bool,
    want_results: bool,
) -> Result<(HeaderInput, Option<NextSlot>)> {
    let base = bases[0].as_str();
    let checkpoint = checkpoint_for(ledger);

    report::step("fetching evidence from the history archive");
    report::explain(
        "where is the evidence coming from, and who has to be trusted for it?",
        "gzipped XDR published by the network itself; nothing in it is trusted - it is all checked below",
    );
    report::detail(&format!(
        "ledger {ledger} lives in checkpoint {checkpoint} ({checkpoint:#010x}); archives publish one file per 64 ledgers"
    ));
    report::detail(&format!("archive base: {base}"));
    check_published(base, ledger, checkpoint).await?;
    let scp_raw = fetch_logged(
        base,
        "scp",
        checkpoint,
        "SCP envelopes + quorum-set preimages",
    )
    .await?;
    let ledger_raw = fetch_logged(
        base,
        "ledger",
        checkpoint,
        "LedgerHeaders + their recorded hashes",
    )
    .await?;
    let result_pairs = if want_results {
        let results_raw =
            fetch_logged(base, "results", checkpoint, "TransactionResultSets").await?;
        let pairs = archive::frames(&results_raw)?
            .into_iter()
            .map(history::read_result_record)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .find(|entry| entry.ledger_seq == ledger)
            .map(|entry| entry.result_pairs)
            .unwrap_or_default();

        report::detail(&format!(
            "{} transaction result pair(s) archived for ledger {ledger}",
            pairs.len()
        ));
        pairs
    } else {
        report::detail("--results false: step 8 will be skipped, the results file is not fetched");
        Vec::new()
    };

    let scp = index_scp(&scp_raw)?;

    report::detail(&format!(
        "{} slot(s) of SCP messages in that checkpoint",
        scp.len()
    ));
    let entry = scp
        .iter()
        .find(|entry| entry.ledger_seq == ledger)
        .ok_or(Error::NoScpMessages { ledger })?;

    report::ok(&format!(
        "ledger {ledger}: {} envelope(s), {} quorum-set preimage(s)",
        entry.envelopes.len(),
        entry.quorum_sets_xdr.len()
    ));
    let archived_headers = archive::frames(&ledger_raw)?
        .into_iter()
        .map(history::read_header_history_entry)
        .collect::<Result<Vec<_>>>()?;
    let parent_hash = ledger.checked_sub(1).and_then(|parent| {
        archived_headers
            .iter()
            .find(|header| header.ledger_seq == parent)
            .and_then(|header| steps::verify_ledger_hash(&header.header_xdr, None).ok())
    });
    let header_entry = archived_headers
        .into_iter()
        .find(|header| header.ledger_seq == ledger)
        .ok_or(Error::NoLedgerHeader { ledger })?;

    report::ok(&format!(
        "ledger {ledger}: header of {} bytes, archive records its hash as {}",
        header_entry.header_xdr.len(),
        hex::encode(header_entry.recorded_hash)
    ));
    report::detail("that recorded hash is a claim, not evidence - step 6 recomputes it");
    let (externalize, other) = split_by_type(entry);

    report::ok(&format!(
        "keeping {} EXTERNALIZE envelope(s)",
        externalize.len()
    ));

    if !other.is_empty() {
        report::detail(&format!(
            "ignoring {} non-EXTERNALIZE envelope(s) - only a decided value binds a ledger: {}",
            other.len(),
            other.join(", ")
        ));
    }

    check_decoder_parity(entry)?;
    report::ok(&format!(
        "two independent XDR readers agree on the signed byte range of all {} envelope(s)",
        externalize.len()
    ));
    report::detail(
        "the archive reader handles all four statement types, the vendored client decoder only \
         EXTERNALIZE; a disagreement here would surface later as an unexplained signature failure",
    );
    let input = HeaderInput {
        slot: ledger as u64,
        network_id: network.id(),
        ledger_header_xdr: header_entry.header_xdr.clone(),
        envelopes_xdr: externalize,
        quorum_sets_xdr: entry.quorum_sets_xdr.clone(),
        recorded_ledger_hash: Some(header_entry.recorded_hash),
        result_pairs_xdr: result_pairs,
        trusted_previous_hash: parent_hash,
    };

    let next = if want_next {
        report::step("fetching slot N+1, for the next-slot binding");
        report::explain(
            "what else is needed to authenticate the parts of the header SCP does not sign?",
            "slot N+1's envelopes and the tx set they name",
        );

        match next_slot(base, ledger, &scp).await {
            Ok(n) => {
                report::ok(&format!(
                    "ledger {}: {} EXTERNALIZE envelope(s), tx set of {} bytes",
                    ledger + 1,
                    n.envelopes_xdr.len(),
                    n.tx_set_xdr.len()
                ));

                Some(n)
            }
            Err(error) => {
                report::warn(&format!("next-slot binding unavailable: {error:#}"));
                report::detail("step 7 will be skipped; the run still verifies steps 1-6");

                None
            }
        }
    } else {
        report::detail("--next-slot false: step 7 will be skipped");

        None
    };

    Ok((input, next))
}

async fn check_published(base: &str, ledger: u32, checkpoint: u32) -> Result<()> {
    report::item(&format!("GET {}", archive::history_url(base)));
    let latest = match archive::latest_ledger(base).await {
        Ok(l) => l,
        Err(error) => {
            report::warn(&format!(
                "could not read the archive's current ledger: {error:#}"
            ));
            report::detail(
                "continuing anyway; if the checkpoint is not published yet the next fetch will 404",
            );

            return Ok(());
        }
    };

    report::ok(&format!(
        "the archive is published through ledger {latest}, its most recent closed checkpoint"
    ));

    if checkpoint > latest {
        return Err(Error::LedgerNotArchivedYet {
            ledger,
            checkpoint,
            latest,
            frequency: archive::CHECKPOINT_FREQUENCY,
        });
    }

    report::detail(&format!(
        "checkpoint {checkpoint} is published; ledger {ledger} is {} ledger(s) behind the archive head",
        latest.saturating_sub(ledger)
    ));

    Ok(())
}

async fn fetch_logged(base: &str, category: &str, checkpoint: u32, what: &str) -> Result<Vec<u8>> {
    let url = archive::url(base, category, checkpoint);

    report::item(&format!("GET {url}"));
    let raw = archive::fetch(base, category, checkpoint).await?;

    report::ok(&format!(
        "{category}: {} KiB of XDR after gunzip - {what}",
        raw.len() / 1024
    ));

    Ok(raw)
}

async fn next_slot(base: &str, ledger: u32, scp: &[ScpHistoryEntry]) -> Result<NextSlot> {
    let next = ledger + 1;
    let entry = match scp.iter().find(|entry| entry.ledger_seq == next) {
        Some(error) => error.clone(),
        None => {
            report::detail(&format!(
                "slot {next} starts the next checkpoint, fetching that one too"
            ));
            let raw = fetch_logged(
                base,
                "scp",
                checkpoint_for(next),
                "SCP envelopes for the following checkpoint",
            )
            .await?;

            index_scp(&raw)?
                .into_iter()
                .find(|entry| entry.ledger_seq == next)
                .ok_or(Error::NoScpMessages { ledger: next })?
        }
    };

    let tx_raw = fetch_logged(
        base,
        "transactions",
        checkpoint_for(next),
        "the tx set slot N+1 committed to",
    )
    .await?;
    let tx_set_xdr = archive::frames(&tx_raw)?
        .into_iter()
        .map(history::read_tx_history_entry)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .find(|entry| entry.ledger_seq == next)
        .ok_or(Error::NoTxSet { ledger: next })?
        .generalized_xdr
        .ok_or(Error::LegacyTxSet { ledger: next })?;
    let (externalize, _) = split_by_type(&entry);

    Ok(NextSlot {
        envelopes_xdr: externalize,
        quorum_sets_xdr: entry.quorum_sets_xdr,
        tx_set_xdr,
    })
}

fn check_decoder_parity(entry: &ScpHistoryEntry) -> Result<()> {
    for archived in entry
        .envelopes
        .iter()
        .filter(|envelope| envelope.is_externalize())
    {
        let node = hex::encode(archived.node_id);
        let decoded = Envelope::decode(&archived.envelope_xdr).map_err(|error| {
            Error::DecoderRejectedEnvelope {
                node: node.clone(),
                detail: error.to_string(),
            }
        })?;

        if decoded.node_id != archived.node_id {
            return Err(Error::DecoderDisagreement {
                field: "nodeID".to_string(),
                node,
            });
        }

        if decoded.slot_index != archived.slot_index {
            return Err(Error::DecoderDisagreement {
                field: "slotIndex".to_string(),
                node,
            });
        }

        if decoded.signature.as_slice() != archived.signature.as_slice() {
            return Err(Error::DecoderDisagreement {
                field: "the signature bytes".to_string(),
                node,
            });
        }

        if decoded.statement_bytes != archived.statement_xdr {
            return Err(Error::DecoderStatementRange {
                node,
                archive: archived.statement_xdr.len(),
                decoder: decoded.statement_bytes.len(),
            });
        }
    }

    Ok(())
}

fn index_scp(raw: &[u8]) -> Result<Vec<ScpHistoryEntry>> {
    archive::frames(raw)?
        .into_iter()
        .map(history::read_scp_history_entry)
        .collect()
}

fn split_by_type(entry: &ScpHistoryEntry) -> (Vec<Vec<u8>>, Vec<String>) {
    let mut keep = Vec::new();
    let mut other = Vec::new();

    for env in &entry.envelopes {
        if env.is_externalize() {
            keep.push(env.envelope_xdr.clone());
        } else {
            other.push(history::statement_type_name(env.statement_type).to_string());
        }
    }

    (keep, other)
}

fn to_fixture(
    network: Network,
    input: &HeaderInput,
    v: &VerifiedLedger,
    next: Option<&NextSlot>,
) -> Fixture {
    Fixture {
        network: network.label().to_string(),
        ledger_seq: input.slot,
        network_id: hex::encode(input.network_id),
        ledger_hash: hex::encode(v.ledger_hash),
        close_time: v.close_time,
        tx_set_result_hash: hex::encode(v.tx_set_result_hash),
        bucket_list_hash: hex::encode(v.bucket_list_hash),
        ledger_header_xdr: hex::encode(&input.ledger_header_xdr),
        quorum_sets_xdr: input.quorum_sets_xdr.iter().map(hex::encode).collect(),
        envelopes_xdr: input.envelopes_xdr.iter().map(hex::encode).collect(),
        next_envelopes_xdr: next
            .map(|slot| slot.envelopes_xdr.iter().map(hex::encode).collect())
            .unwrap_or_default(),
        next_tx_set_xdr: next
            .map(|slot| hex::encode(&slot.tx_set_xdr))
            .unwrap_or_default(),
    }
}

fn trust_root(args: &Cli, input: &HeaderInput) -> Result<QuorumConfig> {
    report::step("choosing the trust root");
    report::explain(
        "which validators does this run consider authoritative?",
        "an SCPQuorumSet, checked with stellar-core's isQuorumSetSane(_, true) - threshold at \
         least the v-blocking size",
    );

    if let Some(hexed) = &args.trust_root {
        let raw = fixture::unhex(hexed)?;
        let config = QuorumConfig::from_xdr(&raw)?;

        report::ok(&format!(
            "using --trust-root ({} bytes of SCPQuorumSet XDR)",
            raw.len()
        ));
        report::detail(&format!(
            "fingerprint (sha256 of the quorum-set XDR): {}",
            hex::encode(config.fingerprint())
        ));
        report::detail("the quorum check below therefore means something about *your* assumptions");

        return Ok(config);
    }

    let first = input.quorum_sets_xdr.first().ok_or(Error::NoTrustRoot)?;
    let config = QuorumConfig::from_xdr(first)?;

    report::ok("no --trust-root given: defaulting to the set the signers themselves pledge");
    report::detail(&format!(
        "fingerprint (sha256 of the quorum-set XDR): {}",
        hex::encode(config.fingerprint())
    ));
    report::detail("that fingerprint is the value an operator pins in a relayer config");
    report::warn(
        "that default is self-referential - it validates the archive data and the quorum \
         arithmetic, not the trust decision",
    );
    report::detail("pass --trust-root <hex SCPQuorumSet> to evaluate against your own set");

    Ok(config)
}

fn print_quorum_set(quorum_set: &QuorumSet, depth: usize, list_validators: bool) {
    report::nested_item(&steps::describe_quorum_set(quorum_set), depth);

    if list_validators {
        for validator in &quorum_set.validators {
            report::nested_item(&strkey::account_id(validator), depth + 1);
        }
    }

    for inner in &quorum_set.inner_sets {
        print_quorum_set(inner, depth + 1, list_validators);
    }
}

fn dump_raw_items(input: &HeaderInput, next: Option<&NextSlot>, mode: RawMode) {
    if mode == RawMode::Off {
        return;
    }

    let all = mode == RawMode::All;

    report::step("raw items");
    report::explain(
        "what do these items actually look like on the wire?",
        "every item below is the exact XDR that gets hashed and signature-checked, walked field \
         by field - offsets and lengths are byte counts into that item",
    );
    report::detail(match all {
        true => "--raw all: every item in full",
        false => "--raw sample: the first item of each kind (use --raw all for every item, --raw off for none)",
    });
    report::ok(&format!(
        "LedgerHeader - {} bytes, sha256 {}",
        input.ledger_header_xdr.len(),
        hex_digest(&input.ledger_header_xdr)
    ));
    rawdump::ledger_header(&input.ledger_header_xdr);
    let envelopes = if all {
        &input.envelopes_xdr[..]
    } else {
        &input.envelopes_xdr[..input.envelopes_xdr.len().min(1)]
    };

    for (index, raw) in envelopes.iter().enumerate() {
        report::ok(&format!(
            "SCPEnvelope {}/{} - {} bytes, sha256 {}",
            index + 1,
            input.envelopes_xdr.len(),
            raw.len(),
            hex_digest(raw)
        ));
        rawdump::envelope(raw, all);
    }

    let qsets = if all {
        &input.quorum_sets_xdr[..]
    } else {
        &input.quorum_sets_xdr[..input.quorum_sets_xdr.len().min(1)]
    };

    for (index, raw) in qsets.iter().enumerate() {
        report::ok(&format!(
            "SCPQuorumSet {}/{} - {} bytes, sha256 {} (this hash is what commitQuorumSetHash names)",
            index + 1,
            input.quorum_sets_xdr.len(),
            raw.len(),
            hex_digest(raw)
        ));
        rawdump::quorum_set(raw);
    }

    if let Some(n) = next {
        report::ok(&format!(
            "GeneralizedTransactionSet for slot {} - {} bytes, sha256 {}",
            input.slot + 1,
            n.tx_set_xdr.len(),
            hex_digest(&n.tx_set_xdr)
        ));
        rawdump::tx_set(&n.tx_set_xdr, all);

        if all {
            rawdump::hex_block(&n.tx_set_xdr, usize::MAX);
        }
    }
}

fn verify_and_report(
    input: &HeaderInput,
    config: &QuorumConfig,
    next: Option<&NextSlot>,
    list_signers: bool,
) -> Result<VerifiedLedger> {
    report::step("inputs");
    report::explain(
        "what exactly is being verified?",
        "raw bytes only - envelopes, quorum-set preimages, and one LedgerHeader",
    );
    report::ok(&format!(
        "{} EXTERNALIZE envelope(s), {} byte(s) total",
        input.envelopes_xdr.len(),
        input.envelopes_xdr.iter().map(Vec::len).sum::<usize>()
    ));
    report::ok(&format!(
        "{} quorum-set preimage(s)",
        input.quorum_sets_xdr.len()
    ));
    report::ok(&format!(
        "1 LedgerHeader, {} bytes",
        input.ledger_header_xdr.len()
    ));
    report::ok("trust root, as a tree:");
    print_quorum_set(&config.local, 0, list_signers);
    report::numbered_step(1, TOTAL_STEPS, "envelope signatures");
    report::explain(
        "did each of these statements really come from the validator it names?",
        "Ed25519 verify_strict over  networkID ‖ xdr(ENVELOPE_TYPE_SCP) ‖ raw SCPStatement bytes",
    );
    let envelopes = input
        .envelopes_xdr
        .iter()
        .map(|raw| steps::validate_externalize(raw, input.slot))
        .collect::<core::result::Result<Vec<_>, _>>()?;

    report::detail(
        "the statement bytes are passed through verbatim - re-encoding a decoded struct would \
         change the preimage and fail every signature",
    );

    for (index, env) in envelopes.iter().enumerate() {
        steps::verify_envelope_signature(
            &env.node_id,
            &env.statement_bytes,
            &env.signature,
            &input.network_id,
        )?;

        if list_signers {
            report::item(&format!(
                "{:>2}. {}  signature ok  (statement {} bytes, ballot counter {})",
                index + 1,
                strkey::account_id(&env.node_id),
                env.statement_bytes.len(),
                env.statement.working_ballot().counter
            ));
        }
    }

    report::ok(&format!(
        "{}/{} Ed25519 signatures valid",
        envelopes.len(),
        envelopes.len()
    ));
    report::detail(
        "verify_strict rejects small-order and non-canonical points, matching the libsodium \
         rules stellar-core signs under",
    );
    report::numbered_step(2, TOTAL_STEPS, "statement validation");
    report::explain(
        "is every statement an EXTERNALIZE for exactly this slot, from a distinct node?",
        "reject any other statement type, any other slotIndex, and any repeated nodeID",
    );
    steps::reject_duplicate_signers(&envelopes)?;
    report::ok(&format!(
        "all {} statements are EXTERNALIZE for slot {}",
        envelopes.len(),
        input.slot
    ));
    report::ok(&format!("{} distinct signers, no replays", envelopes.len()));
    report::detail(
        "without the duplicate check, one node's envelope replayed N times would look like N \
         signers and could fake a quorum",
    );
    report::numbered_step(3, TOTAL_STEPS, "quorum-set authentication");
    report::explain(
        "is the quorum set each node pledges the one it actually signed?",
        "sha256(SCPQuorumSet preimage) must equal that node's commitQuorumSetHash",
    );
    let preimages = steps::index_quorum_sets(&input.quorum_sets_xdr)?;
    let signers = steps::verify_quorum_set_hashes(&envelopes, &preimages)?;

    for (hash, count) in tally_quorum_set_hashes(&envelopes) {
        let shape = preimages
            .get(&hash)
            .map(steps::describe_quorum_set)
            .unwrap_or_else(|| "?".into());

        report::item(&format!(
            "{}… pledged by {count} signer(s) - {shape}",
            &hex::encode(hash)[..16]
        ));
    }

    report::ok(&format!(
        "every commitQuorumSetHash resolves to a supplied preimage ({} distinct set(s))",
        preimages.len()
    ));
    report::detail(
        "each advertised set also passes stellar-core's isQuorumSetSane: sane threshold, \
         1..=1000 validators, no duplicates",
    );
    report::numbered_step(4, TOTAL_STEPS, "quorum check");
    report::explain(
        "do these signers form a quorum for the configured trust root?",
        "stellar-core's LocalNode::isQuorum - drop signers whose own quorum set is not satisfied \
         by the survivors, repeat to a fixed point, then ask whether the trust root has a slice \
         among what is left",
    );
    let externalized = steps::verify_externalized_quorum(config, &signers, &envelopes)?;

    report::ok(&format!(
        "isQuorum = true for the {} signer(s) against the trust root",
        signers.len()
    ));
    report::detail(
        "whitepaper §3 def. 3: a set is a quorum iff it is non-empty and contains a quorum slice \
         for each of its members",
    );
    report::detail(
        "this is not a signature count - signers you do not trust are not a quorum for you, no \
         matter how many of them there are",
    );
    report::numbered_step(5, TOTAL_STEPS, "value agreement");
    report::explain(
        "did every signer commit to the same value, byte for byte?",
        "compare commit.value across all envelopes; ballot counters are deliberately ignored",
    );
    let value = externalized.value.clone();

    if !externalized.discarded.is_empty() {
        report::warn(&format!(
            "{} signer(s) pledged a different value and were discarded - the quorum is over the {} that agree",
            externalized.discarded.len(),
            externalized.supporters.len(),
        ));

        for node_id in &externalized.discarded {
            report::nested_item(&strkey::account_id(node_id), 1);
        }
    }

    report::ok(&format!(
        "one agreed commit.value, {} bytes, identical across all {} signers",
        value.len(),
        envelopes.len()
    ));
    report::detail(&format!("sha256(value) = {}", hex_digest(&value)));
    report::detail(&format!(
        "the value is a StellarValue(txSetHash, closeTime, upgrades); its txSetHash is {}",
        tx_set_hash_of_value(&value)
            .map(hex::encode)
            .unwrap_or_else(|_| "unreadable".into())
    ));
    report::detail(&format!(
        "ballot counters seen: {} - nodes legitimately reach EXTERNALIZE on different counters, \
         so requiring equality would reject valid ledgers",
        describe_counters(&envelopes)
    ));
    report::numbered_step(6, TOTAL_STEPS, "ledger binding");
    report::explain(
        "is this LedgerHeader the header for the value they agreed on?",
        "header.ledgerSeq must equal the slot and header.scpValue must be byte-identical to the \
         agreed value; then ledger_hash = sha256(raw LedgerHeader XDR)",
    );
    let verified = steps::verify_header(input, config)?;

    report::ok(&format!("header.ledgerSeq = {}", verified.slot));
    report::ok(&format!(
        "header.scpValue is byte-identical to the agreed value ({} bytes)",
        value.len()
    ));
    report::ok(&format!(
        "sha256(LedgerHeader) = {}",
        hex::encode(verified.ledger_hash)
    ));

    if input.recorded_ledger_hash.is_some() {
        report::detail("matches the hash the archive recorded for this ledger");
    } else {
        report::detail("no recorded hash was supplied, so there was nothing to compare against");
    }

    report::detail(
        "hashed the header alone - a LedgerHeaderHistoryEntry wrapper would hash to nothing",
    );
    report::field("closeTime", &verified.close_time.to_string());
    report::field(
        "previousLedgerHash",
        &hex::encode(verified.previous_ledger_hash),
    );

    match input.trusted_previous_hash {
        Some(_) => {
            report::ok("the header names the ledger you already trust at N-1 as its predecessor")
        }
        None => report::detail(
            "the predecessor is not in this checkpoint and no --trusted-previous was given, so \
             the parent link is unchecked; this ledger is verified as externalized, not as \
             connected to a chain you already trust",
        ),
    }

    report::field("bucketListHash", &hex::encode(verified.bucket_list_hash));
    report::field("txSetResultHash", &hex::encode(verified.tx_set_result_hash));
    report::detail(
        "SCP signed only (txSetHash, closeTime, upgrades) - bucketListHash and txSetResultHash \
         are NOT covered by anything above; step 7 is what binds them",
    );
    report::numbered_step(7, TOTAL_STEPS, "next-slot binding");
    report::explain(
        "does the next ledger point back at this exact header?",
        "re-run steps 1-5 on slot N+1, then check sha256(its tx set) == the txSetHash it \
         externalized, and that tx set's previousLedgerHash == this ledger hash",
    );

    match next {
        Some(n) => {
            let next_slot = input.slot + 1;
            let next_envelopes = n
                .envelopes_xdr
                .iter()
                .map(|raw| steps::validate_externalize(raw, next_slot))
                .collect::<core::result::Result<Vec<_>, _>>()?;

            for env in &next_envelopes {
                steps::verify_envelope_signature(
                    &env.node_id,
                    &env.statement_bytes,
                    &env.signature,
                    &input.network_id,
                )?;
            }

            report::ok(&format!(
                "slot {next_slot}: {}/{} signatures valid, all EXTERNALIZE for that slot",
                next_envelopes.len(),
                next_envelopes.len()
            ));
            steps::reject_duplicate_signers(&next_envelopes)?;
            let next_preimages = steps::index_quorum_sets(&n.quorum_sets_xdr)?;
            let next_signers = steps::verify_quorum_set_hashes(&next_envelopes, &next_preimages)?;
            let next_externalized =
                steps::verify_externalized_quorum(config, &next_signers, &next_envelopes)?;

            report::ok(&format!(
                "slot {next_slot}: quorum-set hashes resolve and isQuorum = true ({} signers)",
                next_signers.len()
            ));
            let next_value = next_externalized.value.clone();

            report::ok(&format!(
                "slot {next_slot}: one agreed commit.value, {} bytes",
                next_value.len()
            ));

            if let Ok(want) = tx_set_hash_of_value(&next_value) {
                report::detail(&format!("it names txSetHash {}", hex::encode(want)));
            }

            steps::verify_next_slot_binding(&next_value, &n.tx_set_xdr, &verified.ledger_hash)?;
            report::ok(&format!(
                "the archived tx set ({} bytes) hashes to that txSetHash",
                n.tx_set_xdr.len()
            ));
            report::ok(&format!(
                "and its previousLedgerHash == {} - this ledger",
                hex::encode(verified.ledger_hash)
            ));
            report::detail(
                "this is what authenticates bucketListHash and txSetResultHash, which slot N's \
                 SCP value does not cover",
            );
            report::detail(
                "caveat: it leans on a stellar-core Herder rule (validators check \
                 txSet.previousLedgerHash == LCL.hash before voting), not on the whitepaper",
            );
        }
        None => {
            report::warn("skipped - no slot N+1 evidence");
            report::detail(
                "without it, bucketListHash and txSetResultHash are unauthenticated: SCP commits \
                 only to (txSetHash, closeTime, upgrades)",
            );
        }
    }

    report::numbered_step(8, TOTAL_STEPS, "result-set binding");
    report::explain(
        "do the archived transaction results match what this header committed to?",
        "sha256(be32(count) ‖ each raw TransactionResultPair) == header.txSetResultHash",
    );
    let results_checked = !input.result_pairs_xdr.is_empty();

    if !results_checked {
        report::warn("skipped - no result pairs supplied (fixtures do not carry them)");
    } else {
        steps::verify_result_set(&input.result_pairs_xdr, &verified.tx_set_result_hash)?;
        report::ok(&format!(
            "{} result pair(s) hash to txSetResultHash {}",
            input.result_pairs_xdr.len(),
            hex::encode(verified.tx_set_result_hash),
        ));
        report::detail(
            "txSetResultHash is not covered by the SCP value - step 7 is what authenticates the \
             header field this was compared against",
        );
        report::detail(
            "the IBC light client continues from here: pick the router's result pair, check its \
             success preimage, and read the ibc_root event that carries the SMT root. Those need \
             transaction meta, which the history archives do not publish.",
        );
    }

    report::hint(match (next.is_some(), results_checked) {
        (true, true) => "VERIFIED - all 8 steps passed",
        (true, false) => "VERIFIED - steps 1-7 passed, step 8 skipped",
        (false, true) => "VERIFIED - steps 1-6 and 8 passed, step 7 skipped",
        (false, false) => "VERIFIED - steps 1-6 passed, steps 7 and 8 skipped",
    });
    report::field("slot", &verified.slot.to_string());
    report::field("ledgerHash", &hex::encode(verified.ledger_hash));
    report::field("closeTime", &verified.close_time.to_string());
    report::field("signers", &format!("{} validators", signers.len()));
    report::detail(
        "trust: the quorum was evaluated against the configured trust root only. Safety \
         additionally assumes quorum intersection despite ill-behaved nodes - in SDF's Ivy model \
         the assumed property qi_intertwined, which is scoped to intertwined nodes, weaker than \
         the whitepaper's intact. No light client can check it for itself.",
    );
    report::detail(
        "and you are not a node: the safety theorem quantifies over nodes running SCP. This run \
         evaluated the predicate after the fact against a configured set; that you are \
         intertwined with the network under that set is an assumption, not a result.",
    );

    Ok(verified)
}

fn tally_quorum_set_hashes(envelopes: &[Envelope]) -> Vec<([u8; 32], usize)> {
    let mut counts: BTreeMap<[u8; 32], usize> = BTreeMap::new();

    for env in envelopes {
        *counts.entry(env.statement.quorum_set_hash()).or_default() += 1;
    }

    counts.into_iter().collect()
}

fn describe_counters(envelopes: &[Envelope]) -> String {
    let mut counts: BTreeMap<u32, usize> = BTreeMap::new();

    for env in envelopes {
        *counts
            .entry(env.statement.working_ballot().counter)
            .or_default() += 1;
    }

    counts
        .into_iter()
        .map(|(counter, n)| format!("{counter} (×{n})"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn hex_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    hex::encode(Sha256::digest(bytes))
}

fn run_negative(input: &HeaderInput, config: &QuorumConfig, next: Option<&NextSlot>) -> Result<()> {
    report::step("negative suite - one mutation per case");
    report::explain(
        "does the verifier fail closed, and for the right reason?",
        "take the real data just verified, change exactly one field per case, and require a \
         specific error variant - never merely 'an error occurred'",
    );
    let cases = negative::run_suite(
        input,
        config,
        next.map(|slot| negative::NextSlotEvidence {
            envelopes_xdr: &slot.envelopes_xdr,
            tx_set_xdr: &slot.tx_set_xdr,
        }),
    );

    if next.is_none() {
        report::warn("no slot N+1 evidence: the step 7 cases are not in this run");
    }

    let mut failed = 0usize;

    for case in &cases {
        match &case.outcome {
            Outcome::Rejected(msg) => {
                report::ok(&format!("{} [{}] - {}", case.name, case.step, msg));
            }
            Outcome::WrongError(msg) => {
                failed += 1;
                report::fail(&format!(
                    "{} [{}] - expected {}, got: {msg}",
                    case.name, case.step, case.expected
                ));
            }
            Outcome::Accepted => {
                failed += 1;
                report::fail(&format!(
                    "{} [{}] - ACCEPTED, expected {}",
                    case.name, case.step, case.expected
                ));
            }
        }
    }

    if failed > 0 {
        return Err(Error::NegativeCasesPassed {
            failed,
            total: cases.len(),
        });
    }

    report::ok(&format!(
        "{}/{} cases failed closed with the expected error",
        cases.len(),
        cases.len()
    ));

    Ok(())
}

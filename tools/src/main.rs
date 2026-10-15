use tools::{crosscheck, sync};

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use sync::{Mode, Outcome};

const EXIT_DRIFTED: u8 = 1;
const EXIT_NO_TARGET: u8 = 2;

#[derive(Parser)]
#[command(
    name = "tools",
    about = "Repository tasks for ipsa-scp-verifier: the vendored-copy sync check and the independent cross-check"
)]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

#[derive(Subcommand)]
enum Task {
    #[command(about = "Diff (or regenerate) a vendored copy of this verifier's sources")]
    VerifySync {
        #[arg(long, help = "Rewrite the target from this crate instead of diffing")]
        write: bool,
        #[arg(
            long,
            value_name = "PATH",
            help = "The directory holding the vendored copy"
        )]
        target: PathBuf,
    },

    #[command(
        about = "Verify a ledger with an independent implementation - separate XDR reader, ring instead of sha2/ed25519-dalek"
    )]
    ChainCheck {
        #[arg(long, default_value = "testnet")]
        network: String,
        #[arg(long, value_name = "SEQ")]
        ledger: u32,
        #[arg(
            long,
            value_name = "HEX",
            help = "Hex-encoded SCPQuorumSet you trust; the quorum is evaluated against it"
        )]
        trust_root: String,
        #[arg(long, value_name = "PATH", help = "Write a JSON test vector")]
        export: Option<PathBuf>,
    },
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the tools crate lives one level below the repository root")
        .to_path_buf()
}

fn report(label: &str, outcome: &Outcome) -> u8 {
    for name in &outcome.missing {
        eprintln!("MISSING: {name}");
    }
    for drift in &outcome.drifted {
        eprintln!("DRIFTED: {drift}");
    }

    if !outcome.written.is_empty() {
        for path in &outcome.written {
            println!("wrote {}", path.display());
        }
        return 0;
    }

    if outcome.is_clean() {
        println!("{label} is in sync");
        return 0;
    }

    eprintln!("\n{label} has drifted.");
    EXIT_DRIFTED
}

fn run(cli: Cli) -> Result<u8> {
    let root = repo_root();

    match cli.task {
        Task::VerifySync { write, target } => {
            if !target.is_dir() {
                eprintln!("target directory not found: {}", target.display());
                return Ok(EXIT_NO_TARGET);
            }

            let mode = if write { Mode::Write } else { Mode::Check };
            let outcome = sync::verify(mode, &root, target)?;
            Ok(report("the vendored copy", &outcome))
        }
        Task::ChainCheck {
            network,
            ledger,
            trust_root,
            export,
        } => {
            let net = crosscheck::network(&network)?;
            let raw = hex::decode(trust_root.trim()).context("--trust-root is not hex")?;
            let trust_root = crosscheck::parse_quorum_set(&raw).context("--trust-root")?;

            crosscheck::run(&net, ledger, &trust_root, export.as_deref())?;
            Ok(0)
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

use tools::{crosscheck, sync};

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

use sync::{Mode, Outcome};

const EXIT_DRIFTED: u8 = 1;
const EXIT_NO_TARGET: u8 = 2;

#[derive(Parser)]
#[command(
    name = "tools",
    about = "Repository tasks for scp-verifier: sync checks and the independent cross-check"
)]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

#[derive(Subcommand)]
enum Task {
    #[command(about = "Diff (or regenerate) the copy of this verifier in the ipsa CLI")]
    VerifySync {
        #[arg(long, help = "Rewrite the target from this crate instead of diffing")]
        write: bool,
        #[arg(long, value_name = "PATH", help = "The ipsa cli/src/verify directory")]
        target: Option<PathBuf>,
    },

    #[command(
        about = "Verify a ledger with an independent implementation - separate XDR reader, ring instead of sha2/ed25519-dalek"
    )]
    ChainCheck {
        #[arg(long, default_value = "testnet")]
        network: String,
        #[arg(long, value_name = "SEQ")]
        ledger: u32,
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
            let mode = if write { Mode::Write } else { Mode::Check };
            let outcome = sync::verify(mode, &root, target)?;
            Ok(report("the ipsa verify copy", &outcome))
        }
        Task::ChainCheck {
            network,
            ledger,
            export,
        } => {
            let net = crosscheck::network(&network)?;
            crosscheck::run(&net, ledger, export.as_deref())?;
            Ok(0)
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            if error.to_string().contains("not found") {
                return ExitCode::from(EXIT_NO_TARGET);
            }
            ExitCode::FAILURE
        }
    }
}

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

pub const VERIFY_FILES: [&str; 7] = [
    "error.rs",
    "fixture.rs",
    "negative.rs",
    "network.rs",
    "steps.rs",
    "strkey.rs",
    "rawdump.rs",
];

pub const VERIFY_RULES: [(&str, &str); 6] = [
    ("use crate::scp::", "use stellar_consensus_verifier::"),
    ("use crate::error::", "use super::error::"),
    ("use crate::steps::", "use super::steps::"),
    ("use crate::strkey", "use super::strkey"),
    ("use crate::report;", "use crate::logger;"),
    ("report::", "logger::"),
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Check,
    Write,
}

pub struct Outcome {
    pub drifted: Vec<String>,
    pub missing: Vec<String>,
    pub written: Vec<PathBuf>,
}

impl Outcome {
    pub fn is_clean(&self) -> bool {
        self.drifted.is_empty() && self.missing.is_empty()
    }
}

pub fn substitute(text: &str, rules: &[(&str, &str)]) -> String {
    let mut out = text.to_string();
    for (from, to) in rules {
        out = out.replace(from, to);
    }
    out
}

fn rustfmt(text: &str) -> Result<String> {
    let mut child = Command::new("rustfmt")
        .args(["--edition", "2021", "--quiet", "--emit", "stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("running rustfmt - is it installed?")?;

    child
        .stdin
        .take()
        .context("rustfmt has no stdin")?
        .write_all(text.as_bytes())?;

    let output = child.wait_with_output()?;

    if !output.status.success() {
        bail!("rustfmt rejected the substituted source");
    }

    String::from_utf8(output.stdout).context("rustfmt wrote something other than UTF-8")
}

pub fn first_difference(expected: &str, actual: &str) -> Option<String> {
    if expected == actual {
        return None;
    }

    let want: Vec<&str> = expected.lines().collect();
    let got: Vec<&str> = actual.lines().collect();
    let at = want
        .iter()
        .zip(got.iter())
        .position(|(a, b)| a != b)
        .unwrap_or(want.len().min(got.len()));

    let from = at.saturating_sub(2);
    let mut report = format!("  first difference at line {}\n", at + 1);
    for (label, lines) in [("expected", &want), ("actual", &got)] {
        for (i, line) in lines.iter().enumerate().skip(from).take(5) {
            let marker = if i == at { ">" } else { " " };
            report.push_str(&format!("  {marker} {label} {:>4}| {line}\n", i + 1));
        }
    }
    Some(report)
}

fn run(
    mode: Mode,
    source_dir: &Path,
    target_dir: &Path,
    files: &[&str],
    rules: &[(&str, &str)],
    format: bool,
) -> Result<Outcome> {
    if !target_dir.is_dir() {
        bail!("target directory not found: {}", target_dir.display());
    }

    let mut outcome = Outcome {
        drifted: Vec::new(),
        missing: Vec::new(),
        written: Vec::new(),
    };

    for name in files {
        let source = source_dir.join(name);
        let target = target_dir.join(name);

        let raw = std::fs::read_to_string(&source)
            .with_context(|| format!("reading {}", source.display()))?;
        let mut candidate = substitute(&raw, rules);
        if format {
            candidate = rustfmt(&candidate)?;
        }

        match mode {
            Mode::Write => {
                std::fs::write(&target, &candidate)
                    .with_context(|| format!("writing {}", target.display()))?;
                outcome.written.push(target);
            }
            Mode::Check => {
                let Ok(existing) = std::fs::read_to_string(&target) else {
                    outcome.missing.push((*name).to_string());
                    continue;
                };
                if let Some(diff) = first_difference(&candidate, &existing) {
                    outcome.drifted.push(format!("{name}\n{diff}"));
                }
            }
        }
    }

    Ok(outcome)
}

pub fn verify(mode: Mode, root: &Path, target: PathBuf) -> Result<Outcome> {
    run(
        mode,
        &root.join("src"),
        &target,
        &VERIFY_FILES,
        &VERIFY_RULES,
        true,
    )
}

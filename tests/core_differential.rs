use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use ipsa_scp_verifier::scp::quorum::{is_quorum, is_quorum_slice, NodeId, QuorumSet};

const DEFAULT_CASES: usize = 2_000;
const MAX_NODES: usize = 8;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }

    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }
}

fn node(i: usize) -> NodeId {
    [i as u8; 32]
}

fn subset(rng: &mut Rng, nodes: &[NodeId], min: usize) -> Vec<NodeId> {
    loop {
        let picked: Vec<NodeId> = nodes.iter().copied().filter(|_| rng.chance(2)).collect();
        if picked.len() >= min {
            return picked;
        }
    }
}

fn random_qset(rng: &mut Rng, nodes: &[NodeId], depth: u32) -> QuorumSet {
    let validators = subset(rng, nodes, 1);
    let inner_count = if depth < 2 { rng.below(3) } else { 0 };
    let inner_sets: Vec<QuorumSet> = (0..inner_count)
        .map(|_| random_qset(rng, nodes, depth + 1))
        .collect();
    let entries = validators.len() + inner_sets.len();
    QuorumSet {
        threshold: rng.range(1, entries) as u32,
        validators,
        inner_sets,
    }
}

fn encode_qset(qset: &QuorumSet, out: &mut Vec<u8>) {
    out.extend_from_slice(&qset.threshold.to_be_bytes());
    out.extend_from_slice(&(qset.validators.len() as u32).to_be_bytes());
    for v in &qset.validators {
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(v);
    }
    out.extend_from_slice(&(qset.inner_sets.len() as u32).to_be_bytes());
    for inner in &qset.inner_sets {
        encode_qset(inner, out);
    }
}

fn qset_hex(qset: &QuorumSet) -> String {
    let mut out = Vec::new();
    encode_qset(qset, &mut out);
    hex::encode(out)
}

struct Oracle {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Oracle {
    fn start(path: &str) -> Option<Self> {
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .ok()?;
        let stdin = child.stdin.take()?;
        let stdout = BufReader::new(child.stdout.take()?);
        Some(Self {
            child,
            stdin,
            stdout,
        })
    }

    fn ask(&mut self, line: &str) -> bool {
        writeln!(self.stdin, "{line}").expect("write to the core oracle");
        self.stdin.flush().expect("flush to the core oracle");
        let mut answer = String::new();
        self.stdout
            .read_line(&mut answer)
            .expect("read from the core oracle");
        match answer.trim() {
            "1" => true,
            "0" => false,
            other => panic!("core oracle said {other:?} for {line:?}"),
        }
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn oracle() -> Option<Oracle> {
    let path = std::env::var("CORE_ORACLE").ok()?;
    match Oracle::start(&path) {
        Some(o) => Some(o),
        None => panic!("CORE_ORACLE is set to {path:?} but it would not start"),
    }
}

fn cases() -> usize {
    std::env::var("CORE_DIFF_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CASES)
}

const PROGRESS_EVERY: usize = 100_000;

fn progress(name: &str, seed: u64, total: usize) {
    if seed as usize % PROGRESS_EVERY == 0 {
        eprintln!("{name}: {seed}/{total} cases agreed so far");
    }
}

fn require_mix(name: &str, trues: usize, total: usize) {
    let share = trues * 100 / total.max(1);
    assert!(
        (5..=95).contains(&share),
        "{name}: {share}% of cases answered true - the generator has degenerated and agreement \
         with stellar-core no longer means anything"
    );
}

fn skipped() {
    eprintln!(
        "skipping: CORE_ORACLE is not set. Build core-oracle/ against a stellar-core tree, then \
         run CORE_ORACLE=core-oracle/oracle cargo test --release --test core_differential"
    );
}

#[test]
fn is_quorum_agrees_with_stellar_core() {
    let Some(mut oracle) = oracle() else {
        return skipped();
    };

    let total = cases();
    let mut trues = 0usize;
    for seed in 1..=total as u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let count = rng.range(3, MAX_NODES);
        let nodes: Vec<NodeId> = (1..=count).map(node).collect();
        let local = random_qset(&mut rng, &nodes, 0);
        let chosen: Vec<NodeId> = nodes.iter().copied().filter(|_| !rng.chance(3)).collect();
        let signers: Vec<(NodeId, QuorumSet)> = chosen
            .into_iter()
            .map(|id| {
                let qset = random_qset(&mut rng, &nodes, 0);
                (id, qset)
            })
            .collect();

        let mut line = format!("quorum {}", qset_hex(&local));
        for (id, qset) in &signers {
            line.push_str(&format!(" {}:{}", hex::encode(id), qset_hex(qset)));
        }

        let theirs = oracle.ask(&line);
        let ours = is_quorum(&local, &signers);

        assert_eq!(
            ours, theirs,
            "seed {seed}: we say {ours}, stellar-core says {theirs}\n{line}"
        );
        trues += usize::from(theirs);
        progress("is_quorum", seed, total);
    }
    require_mix("is_quorum", trues, total);
    eprintln!("{total} quorum cases agreed with stellar-core ({trues} of them a quorum)");
}

#[test]
fn is_quorum_slice_agrees_with_stellar_core() {
    let Some(mut oracle) = oracle() else {
        return skipped();
    };

    let total = cases();
    let mut trues = 0usize;
    for seed in 1..=total as u64 {
        let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d) | 1);
        let count = rng.range(3, MAX_NODES);
        let nodes: Vec<NodeId> = (1..=count).map(node).collect();
        let qset = random_qset(&mut rng, &nodes, 0);
        let present: Vec<NodeId> = nodes.iter().copied().filter(|_| rng.chance(2)).collect();

        let mut line = format!("slice {}", qset_hex(&qset));
        for id in &present {
            line.push(' ');
            line.push_str(&hex::encode(id));
        }

        let theirs = oracle.ask(&line);
        let ours = is_quorum_slice(&qset, &present);

        assert_eq!(
            ours, theirs,
            "seed {seed}: we say {ours}, stellar-core says {theirs}\n{line}"
        );
        trues += usize::from(theirs);
        progress("is_quorum_slice", seed, total);
    }
    require_mix("is_quorum_slice", trues, total);
    eprintln!("{total} slice cases agreed with stellar-core ({trues} of them a slice)");
}

#[test]
fn quorum_set_sanity_agrees_with_stellar_core() {
    let Some(mut oracle) = oracle() else {
        return skipped();
    };

    let total = cases();
    let mut trues = 0usize;
    for seed in 1..=total as u64 {
        let mut rng = Rng(seed.wrapping_mul(0xd1b5_4a32_d192_ed03) | 1);
        let count = rng.range(1, MAX_NODES);
        let nodes: Vec<NodeId> = (1..=count).map(node).collect();
        let mut qset = random_qset(&mut rng, &nodes, 0);

        if rng.chance(4) {
            qset.threshold = rng.below(4) as u32;
        }
        if rng.chance(6) && !qset.validators.is_empty() {
            let dup = qset.validators[0];
            qset.validators.push(dup);
        }

        for extra in [false, true] {
            let flag = u8::from(extra);
            let line = format!("sane {} {flag}", qset_hex(&qset));
            let theirs = oracle.ask(&line);
            let ours = qset.check_sane(extra).is_ok();

            assert_eq!(
                ours, theirs,
                "seed {seed} extra={extra}: we say {ours}, stellar-core says {theirs}\n{line}"
            );
            trues += usize::from(theirs);
        }
        progress("isQuorumSetSane", seed, total);
    }
    require_mix("isQuorumSetSane", trues, total * 2);
    eprintln!("{total} sanity cases agreed with stellar-core ({trues} of them sane)");
}

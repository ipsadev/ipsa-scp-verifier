use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use base64::Engine as _;
use ring::{digest, signature};

const CHECKPOINT_FREQUENCY: u32 = 64;
const ENVELOPE_TYPE_SCP: [u8; 4] = [0, 0, 0, 1];

const SCP_ST_EXTERNALIZE: i32 = 2;
const SCP_ST_CONFIRM: i32 = 1;
const SCP_ST_PREPARE: i32 = 0;

pub type NodeId = [u8; 32];

pub struct Network {
    pub label: &'static str,
    pub base: &'static str,
    pub passphrase: &'static str,
}

pub const TESTNET: Network = Network {
    label: "testnet",
    base: "https://history.stellar.org/prd/core-testnet/core_testnet_001",
    passphrase: "Test SDF Network ; September 2015",
};

pub const MAINNET: Network = Network {
    label: "mainnet",
    base: "https://history.stellar.org/prd/core-live/core_live_001",
    passphrase: "Public Global Stellar Network ; September 2015",
};

pub fn network(name: &str) -> Result<Network> {
    match name {
        "testnet" | "test" => Ok(TESTNET),
        "mainnet" | "public" | "pubnet" => Ok(MAINNET),
        other => bail!("unknown network {other}"),
    }
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, bytes).as_ref());
    out
}

fn ed25519_verify(key: &[u8], message: &[u8], sig: &[u8]) -> bool {
    signature::UnparsedPublicKey::new(&signature::ED25519, key)
        .verify(message, sig)
        .is_ok()
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.buf.len())
            .with_context(|| format!("truncated XDR: wanted {n} bytes at {}", self.pos))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn fixed(&mut self, n: usize) -> Result<&'a [u8]> {
        let out = self.take(n)?;
        let pad = (4 - (n % 4)) % 4;
        if pad > 0 {
            self.take(pad)?;
        }
        Ok(out)
    }

    fn fixed32(&mut self) -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.fixed(32)?);
        Ok(out)
    }

    fn var(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.fixed(n)
    }

    fn count(&mut self) -> Result<usize> {
        Ok(self.u32()? as usize)
    }
}

#[derive(Clone)]
pub struct QuorumSet {
    pub threshold: u32,
    pub validators: Vec<NodeId>,
    pub inner: Vec<QuorumSet>,
    pub raw: Vec<u8>,
}

fn read_node_id(r: &mut Reader<'_>) -> Result<NodeId> {
    match r.i32()? {
        0 => r.fixed32(),
        other => bail!("unsupported PublicKey type {other}"),
    }
}

fn read_quorum_set(r: &mut Reader<'_>) -> Result<QuorumSet> {
    let start = r.pos;
    let threshold = r.u32()?;

    let n = r.count()?;
    let mut validators = Vec::with_capacity(n);
    for _ in 0..n {
        validators.push(read_node_id(r)?);
    }

    let n = r.count()?;
    let mut inner = Vec::with_capacity(n);
    for _ in 0..n {
        inner.push(read_quorum_set(r)?);
    }

    Ok(QuorumSet {
        threshold,
        validators,
        inner,
        raw: r.buf[start..r.pos].to_vec(),
    })
}

fn read_ballot(r: &mut Reader<'_>) -> Result<Vec<u8>> {
    let _counter = r.u32()?;
    Ok(r.var()?.to_vec())
}

pub struct Statement {
    pub node_id: NodeId,
    pub slot: u64,
    pub kind: i32,
    pub commit_value: Vec<u8>,
    pub quorum_set_hash: [u8; 32],
    pub raw: Vec<u8>,
}

fn read_statement(r: &mut Reader<'_>) -> Result<Statement> {
    let start = r.pos;
    let node_id = read_node_id(r)?;
    let slot = r.u64()?;
    let kind = r.i32()?;

    let mut commit_value = Vec::new();
    let quorum_set_hash;

    match kind {
        SCP_ST_EXTERNALIZE => {
            commit_value = read_ballot(r)?;
            let _n_h = r.u32()?;
            quorum_set_hash = r.fixed32()?;
        }
        SCP_ST_CONFIRM => {
            let _ballot = read_ballot(r)?;
            let _n_prepared = r.u32()?;
            let _n_commit = r.u32()?;
            let _n_h = r.u32()?;
            quorum_set_hash = r.fixed32()?;
        }
        SCP_ST_PREPARE => {
            quorum_set_hash = r.fixed32()?;
            let _ballot = read_ballot(r)?;
            if r.u32()? != 0 {
                read_ballot(r)?;
            }
            if r.u32()? != 0 {
                read_ballot(r)?;
            }
            let _n_c = r.u32()?;
            let _n_h = r.u32()?;
        }
        _ => {
            quorum_set_hash = r.fixed32()?;
            let n = r.count()?;
            for _ in 0..n {
                r.var()?;
            }
            let n = r.count()?;
            for _ in 0..n {
                r.var()?;
            }
        }
    }

    Ok(Statement {
        node_id,
        slot,
        kind,
        commit_value,
        quorum_set_hash,
        raw: r.buf[start..r.pos].to_vec(),
    })
}

pub struct Envelope {
    pub statement: Statement,
    pub signature: Vec<u8>,
}

fn read_envelope(r: &mut Reader<'_>) -> Result<Envelope> {
    let statement = read_statement(r)?;
    let signature = r.var()?.to_vec();
    Ok(Envelope {
        statement,
        signature,
    })
}

pub struct HistoryEntry {
    pub ledger_seq: u32,
    pub quorum_sets: Vec<QuorumSet>,
    pub envelopes: Vec<Envelope>,
}

fn read_history_entry(record: &[u8]) -> Result<HistoryEntry> {
    let mut r = Reader::new(record);
    ensure!(r.i32()? == 0, "unsupported SCPHistoryEntry version");

    let n = r.count()?;
    let mut quorum_sets = Vec::with_capacity(n);
    for _ in 0..n {
        quorum_sets.push(read_quorum_set(&mut r)?);
    }

    let ledger_seq = r.u32()?;

    let n = r.count()?;
    let mut envelopes = Vec::with_capacity(n);
    for _ in 0..n {
        envelopes.push(read_envelope(&mut r)?);
    }

    Ok(HistoryEntry {
        ledger_seq,
        quorum_sets,
        envelopes,
    })
}

pub struct HeaderEntry {
    pub entry_hash: [u8; 32],
    pub previous_ledger_hash: [u8; 32],
    pub scp_value_raw: Vec<u8>,
    pub close_time: u64,
    pub tx_set_result_hash: [u8; 32],
    pub bucket_list_hash: [u8; 32],
    pub ledger_seq: u32,
    pub header_raw: Vec<u8>,
}

fn read_header_entry(record: &[u8]) -> Result<HeaderEntry> {
    let mut r = Reader::new(record);
    let entry_hash = r.fixed32()?;
    let header_start = r.pos;

    let _ledger_version = r.u32()?;
    let previous_ledger_hash = r.fixed32()?;

    let sv_start = r.pos;
    let _tx_set_hash = r.fixed32()?;
    let close_time = r.u64()?;
    let n = r.count()?;
    for _ in 0..n {
        r.var()?;
    }
    if r.i32()? == 1 {
        read_node_id(&mut r)?;
        r.var()?;
    }
    let scp_value_raw = record[sv_start..r.pos].to_vec();

    let tx_set_result_hash = r.fixed32()?;
    let bucket_list_hash = r.fixed32()?;
    let ledger_seq = r.u32()?;

    ensure!(record.len() >= header_start + 4, "truncated header entry");

    Ok(HeaderEntry {
        entry_hash,
        previous_ledger_hash,
        scp_value_raw,
        close_time,
        tx_set_result_hash,
        bucket_list_hash,
        ledger_seq,
        header_raw: record[header_start..record.len() - 4].to_vec(),
    })
}

pub fn frames(buf: &[u8]) -> Result<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= buf.len() {
        let n = (u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]])
            & 0x7fff_ffff) as usize;
        let start = pos + 4;
        let end = start
            .checked_add(n)
            .filter(|e| *e <= buf.len())
            .context("frame length exceeds the archive file")?;
        out.push(&buf[start..end]);
        pos = end;
    }
    Ok(out)
}

pub fn is_quorum_slice(qset: &QuorumSet, nodes: &[NodeId]) -> bool {
    let mut left = qset.threshold as i64;
    if left <= 0 {
        return true;
    }
    for v in &qset.validators {
        if nodes.contains(v) {
            left -= 1;
            if left <= 0 {
                return true;
            }
        }
    }
    for inner in &qset.inner {
        if is_quorum_slice(inner, nodes) {
            left -= 1;
            if left <= 0 {
                return true;
            }
        }
    }
    false
}

pub fn is_quorum(
    local: &QuorumSet,
    signers: &[NodeId],
    qset_of: &BTreeMap<NodeId, QuorumSet>,
) -> (bool, Vec<NodeId>) {
    let mut surviving = signers.to_vec();
    loop {
        let before = surviving.len();
        let snapshot = surviving.clone();
        surviving.retain(|id| {
            qset_of
                .get(id)
                .is_some_and(|q| is_quorum_slice(q, &snapshot))
        });
        if surviving.len() == before {
            break;
        }
    }
    (is_quorum_slice(local, &surviving), surviving)
}

pub fn checkpoint_for(ledger: u32) -> u32 {
    ((ledger / CHECKPOINT_FREQUENCY) + 1) * CHECKPOINT_FREQUENCY - 1
}

fn fetch(base: &str, category: &str, checkpoint: u32) -> Result<Vec<u8>> {
    let h = format!("{checkpoint:08x}");
    let url = format!(
        "{base}/{category}/{}/{}/{}/{category}-{h}.xdr.gz",
        &h[0..2],
        &h[2..4],
        &h[4..6]
    );

    let response = ureq::get(&url)
        .set("User-Agent", "scp-chain-check/1.0")
        .call()
        .with_context(|| format!("GET {url}"))?;

    let mut gz = Vec::new();
    response.into_reader().read_to_end(&mut gz)?;

    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut out)
        .with_context(|| format!("gunzip {url}"))?;
    Ok(out)
}

pub fn run(net: &Network, ledger: u32, export: Option<&Path>) -> Result<()> {
    let network_id = sha256(net.passphrase.as_bytes());
    let checkpoint = checkpoint_for(ledger);
    println!("{} ledger {ledger} (checkpoint {checkpoint})", net.label);

    let scp_bytes = fetch(net.base, "scp", checkpoint)?;
    let entry = frames(&scp_bytes)?
        .into_iter()
        .map(read_history_entry)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .find(|e| e.ledger_seq == ledger)
        .with_context(|| format!("no SCP messages archived for ledger {ledger}"))?;

    let ledger_bytes = fetch(net.base, "ledger", checkpoint)?;
    let header = frames(&ledger_bytes)?
        .into_iter()
        .map(read_header_entry)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .find(|h| h.ledger_seq == ledger)
        .with_context(|| format!("no ledger header archived for ledger {ledger}"))?;

    let mut by_hash: BTreeMap<[u8; 32], QuorumSet> = BTreeMap::new();
    for q in &entry.quorum_sets {
        by_hash.insert(sha256(&q.raw), q.clone());
    }
    println!(
        "  {} envelopes, {} quorum-set preimages",
        entry.envelopes.len(),
        by_hash.len()
    );

    let mut values: Vec<Vec<u8>> = Vec::new();
    let mut signers: Vec<NodeId> = Vec::new();
    let mut qset_of: BTreeMap<NodeId, QuorumSet> = BTreeMap::new();

    for env in &entry.envelopes {
        let st = &env.statement;
        ensure!(
            st.kind == SCP_ST_EXTERNALIZE,
            "not EXTERNALIZE: type {}",
            st.kind
        );
        ensure!(st.slot == u64::from(ledger), "slot {} != {ledger}", st.slot);

        let mut preimage = Vec::with_capacity(32 + 4 + st.raw.len());
        preimage.extend_from_slice(&network_id);
        preimage.extend_from_slice(&ENVELOPE_TYPE_SCP);
        preimage.extend_from_slice(&st.raw);
        ensure!(
            ed25519_verify(&st.node_id, &preimage, &env.signature),
            "bad signature from {}",
            hex::encode(st.node_id)
        );

        let q = by_hash.get(&st.quorum_set_hash).with_context(|| {
            format!(
                "missing quorum-set preimage for {}",
                hex::encode(st.node_id)
            )
        })?;

        if !values.contains(&st.commit_value) {
            values.push(st.commit_value.clone());
        }
        signers.push(st.node_id);
        qset_of.insert(st.node_id, q.clone());
    }

    println!(
        "  [1] {} signatures verified over ENVELOPE_TYPE_SCP preimage",
        signers.len()
    );
    println!("  [2] all statements are EXTERNALIZE for the requested slot");
    println!("  [3] all quorum-set preimages match their commitQuorumSetHash");

    let first = *signers.first().context("no envelopes")?;
    let local = qset_of.get(&first).context("no quorum set for signer")?;
    let (ok, survivors) = is_quorum(local, &signers, &qset_of);
    ensure!(ok, "signer set is not a quorum");
    println!(
        "  [4] isQuorum = true ({} of {} validators + {} inner sets; {}/{} survived)",
        local.threshold,
        local.validators.len(),
        local.inner.len(),
        survivors.len(),
        signers.len()
    );

    ensure!(
        values.len() == 1,
        "signers pledged {} distinct values",
        values.len()
    );
    let value = &values[0];
    println!("  [5] single agreed ballot value ({} bytes)", value.len());

    ensure!(
        header.scp_value_raw == *value,
        "header.scpValue != externalized value"
    );
    ensure!(header.ledger_seq == ledger, "header is for another ledger");
    println!("  [6] header.scpValue is byte-identical to the externalized value");

    let ledger_hash = sha256(&header.header_raw);
    ensure!(ledger_hash == header.entry_hash, "ledger hash mismatch");
    println!(
        "  [7] sha256(xdr(LedgerHeader)) = {}",
        hex::encode(ledger_hash)
    );
    println!(
        "      closeTime={} bucketListHash={}",
        header.close_time,
        hex::encode(header.bucket_list_hash)
    );
    println!(
        "      previousLedgerHash={}",
        hex::encode(header.previous_ledger_hash)
    );
    println!("\nALL CHECKS PASSED");

    if let Some(path) = export {
        write_vector(
            path,
            net,
            ledger,
            &network_id,
            &ledger_hash,
            &header,
            &entry,
        )?;
        println!("wrote test vector to {}", path.display());
    }

    Ok(())
}

fn write_vector(
    path: &Path,
    net: &Network,
    ledger: u32,
    network_id: &[u8; 32],
    ledger_hash: &[u8; 32],
    header: &HeaderEntry,
    entry: &HistoryEntry,
) -> Result<()> {
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);

    let vector = serde_json::json!({
        "network": net.label,
        "network_id": b64(network_id),
        "ledger_seq": ledger,
        "ledger_hash": b64(ledger_hash),
        "close_time": header.close_time,
        "bucket_list_hash": b64(&header.bucket_list_hash),
        "tx_set_result_hash": b64(&header.tx_set_result_hash),
        "ledger_header_xdr": b64(&header.header_raw),
        "quorum_sets_xdr": entry.quorum_sets.iter().map(|q| b64(&q.raw)).collect::<Vec<_>>(),
        "envelopes": entry.envelopes.iter().map(|e| serde_json::json!({
            "node_id": b64(&e.statement.node_id),
            "statement_xdr": b64(&e.statement.raw),
            "signature": b64(&e.signature),
        })).collect::<Vec<_>>(),
    });

    std::fs::write(path, serde_json::to_string_pretty(&vector)? + "\n")
        .with_context(|| format!("writing {}", path.display()))
}

use crate::history;
use crate::report;
use crate::strkey;

pub struct Cursor<'a> {
    buffer: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<(usize, &'a [u8])> {
        let start = self.pos;
        let end = start
            .checked_add(n)
            .filter(|candidate| *candidate <= self.buffer.len())?;

        self.pos = end;

        Some((start, &self.buffer[start..end]))
    }

    fn u32(&mut self) -> Option<(usize, u32)> {
        let (offset, b) = self.take(4)?;

        Some((offset, u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
    }

    fn u64(&mut self) -> Option<(usize, u64)> {
        let (offset, b) = self.take(8)?;

        Some((
            offset,
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        ))
    }

    fn remaining(&self) -> usize {
        self.buffer.len() - self.pos
    }
}

fn field(offset: usize, len: usize, name: &str, value: &str) {
    report::raw(&format!("{offset:>5}  {len:>5}  {name:<26}  {value}"));
}

fn scalar(offset: usize, len: usize, name: &str, value: impl std::fmt::Display) {
    field(offset, len, name, &value.to_string());
}

fn bytes_field(offset: usize, name: &str, bytes: &[u8]) {
    field(offset, bytes.len(), name, &hex::encode(bytes));
}

fn header_row() {
    report::raw("offset    len  field                       value");
}

fn shown(bytes: &[u8], keep: usize, full: bool) -> String {
    if full || bytes.len() <= keep {
        hex::encode(bytes)
    } else {
        format!(
            "{}… (+{} more bytes)",
            hex::encode(&bytes[..keep]),
            bytes.len() - keep
        )
    }
}

pub fn hex_block(bytes: &[u8], max_bytes: usize) {
    let shown = bytes.len().min(max_bytes);

    for (index, chunk) in bytes[..shown].chunks(32).enumerate() {
        report::raw(&format!("{:>5}  {}", index * 32, hex::encode(chunk)));
    }

    if shown < bytes.len() {
        report::raw(&format!("       … {} more bytes", bytes.len() - shown));
    }
}

fn padded(length: usize) -> usize {
    length.div_ceil(4) * 4
}

fn key_type_name(kind: u32) -> &'static str {
    match kind {
        0 => "ED25519",
        _ => "UNKNOWN",
    }
}

pub fn envelope(xdr: &[u8], full: bool) {
    header_row();
    let mut cursor = Cursor::new(xdr);
    let mut walk = || -> Option<()> {
        let (offset, kind) = cursor.u32()?;

        scalar(
            offset,
            4,
            "PublicKey type",
            format!("{kind} ({})", key_type_name(kind)),
        );

        if kind != 0 {
            return None;
        }

        let (offset, key) = cursor.take(32)?;
        let node_id: [u8; 32] = key.try_into().ok()?;

        field(
            offset,
            32,
            "nodeID",
            &format!("{}  {}", hex::encode(key), strkey::account_id(&node_id)),
        );
        let (offset, slot) = cursor.u64()?;

        scalar(offset, 8, "slotIndex", slot);
        let (offset, st) = cursor.u32()?;

        let statement_type = i32::try_from(st).unwrap_or(-1);

        scalar(
            offset,
            4,
            "SCPStatementType",
            format!("{st} ({})", history::statement_type_name(statement_type)),
        );

        if statement_type != history::SCP_ST_EXTERNALIZE {
            report::detail("only an EXTERNALIZE body is walked field by field");

            return None;
        }

        let (offset, counter) = cursor.u32()?;

        scalar(offset, 4, "commit.counter", counter);
        let (offset, n) = cursor.u32()?;

        scalar(offset, 4, "commit.value length", n);
        let (offset, value) = cursor.take(padded(n as usize))?;

        field(offset, value.len(), "commit.value", &shown(value, 40, full));
        let (offset, n_h) = cursor.u32()?;

        scalar(offset, 4, "nH", n_h);
        let (offset, qhash) = cursor.take(32)?;

        bytes_field(offset, "commitQuorumSetHash", qhash);
        let (offset, siglen) = cursor.u32()?;

        scalar(offset, 4, "signature length", siglen);
        let (offset, sig) = cursor.take(siglen as usize)?;

        bytes_field(offset, "signature", sig);

        Some(())
    };

    if walk().is_none() {
        report::warn("could not walk this envelope to the end; raw bytes follow");
        hex_block(xdr, 256);
    }
}

pub fn quorum_set(xdr: &[u8]) {
    header_row();
    let mut cursor = Cursor::new(xdr);

    if walk_quorum_set(&mut cursor, 0).is_none() {
        report::warn("could not walk this quorum set to the end; raw bytes follow");
        hex_block(xdr, 256);
    }
}

fn walk_quorum_set(cursor: &mut Cursor<'_>, depth: usize) -> Option<()> {
    let padding = "  ".repeat(depth);
    let (offset, threshold) = cursor.u32()?;

    scalar(offset, 4, &format!("{padding}threshold"), threshold);
    let (offset, n) = cursor.u32()?;

    scalar(offset, 4, &format!("{padding}validators.len"), n);

    for index in 0..n {
        let (offset, kind) = cursor.u32()?;

        scalar(offset, 4, &format!("{padding}  [{index}] key type"), kind);
        let (offset, key) = cursor.take(32)?;
        let node_id: [u8; 32] = key.try_into().ok()?;

        field(
            offset,
            32,
            &format!("{padding}  [{index}] validator"),
            &format!("{}  {}", hex::encode(key), strkey::account_id(&node_id)),
        );
    }

    let (offset, n_inner) = cursor.u32()?;

    scalar(offset, 4, &format!("{padding}innerSets.len"), n_inner);

    for _ in 0..n_inner {
        walk_quorum_set(cursor, depth + 1)?;
    }

    Some(())
}

pub fn ledger_header(xdr: &[u8]) {
    header_row();
    let mut cursor = Cursor::new(xdr);
    let mut walk = || -> Option<()> {
        let (offset, version) = cursor.u32()?;

        scalar(offset, 4, "ledgerVersion", version);
        let (offset, prev) = cursor.take(32)?;

        bytes_field(offset, "previousLedgerHash", prev);
        let sv_start = offset + 32;
        let (offset, tx_set_hash) = cursor.take(32)?;

        bytes_field(offset, "scpValue.txSetHash", tx_set_hash);
        let (offset, close_time) = cursor.u64()?;

        scalar(offset, 8, "scpValue.closeTime", close_time);
        let (offset, n_up) = cursor.u32()?;

        scalar(offset, 4, "scpValue.upgrades.len", n_up);

        for index in 0..n_up {
            let (offset, len) = cursor.u32()?;

            scalar(offset, 4, &format!("  upgrade[{index}] length"), len);
            let (offset, raw) = cursor.take(padded(len as usize))?;

            field(
                offset,
                raw.len(),
                &format!("  upgrade[{index}]"),
                &hex::encode(raw),
            );
        }

        let (offset, ext) = cursor.u32()?;

        scalar(
            offset,
            4,
            "scpValue.ext",
            format!(
                "{ext} ({})",
                match ext {
                    0 => "BASIC",
                    1 => "SIGNED",
                    _ => "UNKNOWN",
                }
            ),
        );

        if ext > 1 {
            return None;
        }

        if ext == 1 {
            let (offset, key) = cursor.take(36)?;

            bytes_field(offset, "  ext.nodeID", key);
            let (offset, len) = cursor.u32()?;

            scalar(offset, 4, "  ext.signature length", len);
            let (offset, sig) = cursor.take(len as usize)?;

            bytes_field(offset, "  ext.signature", sig);
        }

        let sv_end = cursor.pos;

        report::raw(&format!(
            "       scpValue spans bytes {sv_start}..{sv_end} ({} bytes) - this is the slice SCP signed",
            sv_end - sv_start
        ));
        let (offset, tsr) = cursor.take(32)?;

        bytes_field(offset, "txSetResultHash", tsr);
        let (offset, blh) = cursor.take(32)?;

        bytes_field(offset, "bucketListHash", blh);
        let (offset, sequence_number) = cursor.u32()?;

        scalar(offset, 4, "ledgerSeq", sequence_number);
        let (offset, total) = cursor.u64()?;

        scalar(offset, 8, "totalCoins", total);
        let (offset, fee_pool) = cursor.u64()?;

        scalar(offset, 8, "feePool", fee_pool);
        let (offset, inflation) = cursor.u32()?;

        scalar(offset, 4, "inflationSeq", inflation);
        let (offset, id_pool) = cursor.u64()?;

        scalar(offset, 8, "idPool", id_pool);
        let (offset, base_fee) = cursor.u32()?;

        scalar(offset, 4, "baseFee", base_fee);
        let (offset, base_reserve) = cursor.u32()?;

        scalar(offset, 4, "baseReserve", base_reserve);
        let (offset, max_tx) = cursor.u32()?;

        scalar(offset, 4, "maxTxSetSize", max_tx);

        for index in 0..4 {
            let (offset, skip) = cursor.take(32)?;

            bytes_field(offset, &format!("skipList[{index}]"), skip);
        }

        let (offset, ext) = cursor.u32()?;

        scalar(offset, 4, "ext", ext);

        Some(())
    };

    if walk().is_none() {
        report::warn("could not walk this header to the end; raw bytes follow");
        hex_block(xdr, 512);
    }
}

pub fn tx_set(xdr: &[u8], full: bool) {
    header_row();
    let mut cursor = Cursor::new(xdr);
    let mut walk = || -> Option<()> {
        let (offset, version) = cursor.u32()?;

        scalar(
            offset,
            4,
            "GeneralizedTxSet ext",
            format!(
                "{version} ({})",
                if version == 1 { "V1" } else { "UNKNOWN" }
            ),
        );

        if version != 1 {
            return None;
        }

        let (offset, prev) = cursor.take(32)?;

        bytes_field(offset, "previousLedgerHash", prev);
        report::raw(&format!(
            "   36  {:>5}  {:<26}  {}",
            cursor.remaining(),
            "phases (not decoded)",
            shown(xdr.get(36..)?, 32, full)
        ));

        Some(())
    };

    if walk().is_none() {
        report::warn("could not walk this tx set; raw bytes follow");
        hex_block(xdr, 256);
    }
}

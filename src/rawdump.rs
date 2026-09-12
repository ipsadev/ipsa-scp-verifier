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
        let (statement_offset, b) = self.take(4)?;

        Some((
            statement_offset,
            u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        ))
    }

    fn u64(&mut self) -> Option<(usize, u64)> {
        let (statement_offset, b) = self.take(8)?;

        Some((
            statement_offset,
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

pub fn envelope(xdr: &[u8], full: bool) {
    header_row();
    let mut cursor = Cursor::new(xdr);
    let mut walk = || -> Option<()> {
        let (statement_offset, kind) = cursor.u32()?;

        scalar(
            statement_offset,
            4,
            "PublicKey type",
            format!("{kind} (ED25519)"),
        );
        let (statement_offset, key) = cursor.take(32)?;
        let node_id: [u8; 32] = key.try_into().ok()?;

        field(
            statement_offset,
            32,
            "nodeID",
            &format!("{}  {}", hex::encode(key), strkey::account_id(&node_id)),
        );
        let (statement_offset, slot) = cursor.u64()?;

        scalar(statement_offset, 8, "slotIndex", slot);
        let (statement_offset, st) = cursor.u32()?;

        scalar(
            statement_offset,
            4,
            "SCPStatementType",
            format!("{st} (EXTERNALIZE)"),
        );
        let (statement_offset, counter) = cursor.u32()?;

        scalar(statement_offset, 4, "commit.counter", counter);
        let (statement_offset, n) = cursor.u32()?;

        scalar(statement_offset, 4, "commit.value length", n);
        let (statement_offset, value) = cursor.take(padded(n as usize))?;

        field(
            statement_offset,
            value.len(),
            "commit.value",
            &shown(value, 40, full),
        );
        let (statement_offset, n_h) = cursor.u32()?;

        scalar(statement_offset, 4, "nH", n_h);
        let (statement_offset, qhash) = cursor.take(32)?;

        bytes_field(statement_offset, "commitQuorumSetHash", qhash);
        let (statement_offset, siglen) = cursor.u32()?;

        scalar(statement_offset, 4, "signature length", siglen);
        let (statement_offset, sig) = cursor.take(siglen as usize)?;

        bytes_field(statement_offset, "signature", sig);

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
    let (statement_offset, threshold) = cursor.u32()?;

    scalar(
        statement_offset,
        4,
        &format!("{padding}threshold"),
        threshold,
    );
    let (statement_offset, n) = cursor.u32()?;

    scalar(statement_offset, 4, &format!("{padding}validators.len"), n);

    for index in 0..n {
        let (statement_offset, kind) = cursor.u32()?;

        scalar(
            statement_offset,
            4,
            &format!("{padding}  [{index}] key type"),
            kind,
        );
        let (statement_offset, key) = cursor.take(32)?;
        let node_id: [u8; 32] = key.try_into().ok()?;

        field(
            statement_offset,
            32,
            &format!("{padding}  [{index}] validator"),
            &format!("{}  {}", hex::encode(key), strkey::account_id(&node_id)),
        );
    }

    let (statement_offset, n_inner) = cursor.u32()?;

    scalar(
        statement_offset,
        4,
        &format!("{padding}innerSets.len"),
        n_inner,
    );

    for _ in 0..n_inner {
        walk_quorum_set(cursor, depth + 1)?;
    }

    Some(())
}

pub fn ledger_header(xdr: &[u8]) {
    header_row();
    let mut cursor = Cursor::new(xdr);
    let mut walk = || -> Option<()> {
        let (statement_offset, version) = cursor.u32()?;

        scalar(statement_offset, 4, "ledgerVersion", version);
        let (statement_offset, prev) = cursor.take(32)?;

        bytes_field(statement_offset, "previousLedgerHash", prev);
        let sv_start = statement_offset + 32;
        let (statement_offset, tx_set_hash) = cursor.take(32)?;

        bytes_field(statement_offset, "scpValue.txSetHash", tx_set_hash);
        let (statement_offset, close_time) = cursor.u64()?;

        scalar(statement_offset, 8, "scpValue.closeTime", close_time);
        let (statement_offset, n_up) = cursor.u32()?;

        scalar(statement_offset, 4, "scpValue.upgrades.len", n_up);

        for index in 0..n_up {
            let (statement_offset, len) = cursor.u32()?;

            scalar(
                statement_offset,
                4,
                &format!("  upgrade[{index}] length"),
                len,
            );
            let (statement_offset, raw) = cursor.take(padded(len as usize))?;

            field(
                statement_offset,
                raw.len(),
                &format!("  upgrade[{index}]"),
                &hex::encode(raw),
            );
        }

        let (statement_offset, ext) = cursor.u32()?;

        scalar(
            statement_offset,
            4,
            "scpValue.ext",
            format!("{ext} ({})", if ext == 0 { "BASIC" } else { "SIGNED" }),
        );

        if ext == 1 {
            let (statement_offset, key) = cursor.take(36)?;

            bytes_field(statement_offset, "  ext.nodeID", key);
            let (statement_offset, len) = cursor.u32()?;

            scalar(statement_offset, 4, "  ext.signature length", len);
            let (statement_offset, sig) = cursor.take(len as usize)?;

            bytes_field(statement_offset, "  ext.signature", sig);
        }

        let sv_end = cursor.pos;

        report::raw(&format!(
            "       scpValue spans bytes {sv_start}..{sv_end} ({} bytes) - this is the slice SCP signed",
            sv_end - sv_start
        ));
        let (statement_offset, tsr) = cursor.take(32)?;

        bytes_field(statement_offset, "txSetResultHash", tsr);
        let (statement_offset, blh) = cursor.take(32)?;

        bytes_field(statement_offset, "bucketListHash", blh);
        let (statement_offset, sequence_number) = cursor.u32()?;

        scalar(statement_offset, 4, "ledgerSeq", sequence_number);
        let (statement_offset, total) = cursor.u64()?;

        scalar(statement_offset, 8, "totalCoins", total);
        let (statement_offset, fee_pool) = cursor.u64()?;

        scalar(statement_offset, 8, "feePool", fee_pool);
        let (statement_offset, inflation) = cursor.u32()?;

        scalar(statement_offset, 4, "inflationSeq", inflation);
        let (statement_offset, id_pool) = cursor.u64()?;

        scalar(statement_offset, 8, "idPool", id_pool);
        let (statement_offset, base_fee) = cursor.u32()?;

        scalar(statement_offset, 4, "baseFee", base_fee);
        let (statement_offset, base_reserve) = cursor.u32()?;

        scalar(statement_offset, 4, "baseReserve", base_reserve);
        let (statement_offset, max_tx) = cursor.u32()?;

        scalar(statement_offset, 4, "maxTxSetSize", max_tx);

        for index in 0..4 {
            let (statement_offset, skip) = cursor.take(32)?;

            bytes_field(statement_offset, &format!("skipList[{index}]"), skip);
        }

        let (statement_offset, ext) = cursor.u32()?;

        scalar(statement_offset, 4, "ext", ext);

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
        let (statement_offset, version) = cursor.u32()?;

        scalar(
            statement_offset,
            4,
            "GeneralizedTxSet ext",
            format!("{version} (V1)"),
        );
        let (statement_offset, prev) = cursor.take(32)?;

        bytes_field(statement_offset, "previousLedgerHash", prev);
        report::raw(&format!(
            "   36  {:>5}  {:<26}  {}",
            cursor.remaining(),
            "phases (not decoded)",
            shown(&xdr[36..], 32, full)
        ));

        Some(())
    };

    if walk().is_none() {
        report::warn("could not walk this tx set; raw bytes follow");
        hex_block(xdr, 256);
    }
}

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use std::sync::OnceLock;

use flate2::read::GzDecoder;

use crate::error::{Error, Result};

pub const CHECKPOINT_FREQUENCY: u32 = 64;

pub const MAX_DOWNLOAD_BYTES: usize = 256 * 1024 * 1024;

pub const MAX_GUNZIPPED_BYTES: u64 = 1024 * 1024 * 1024;

pub fn checkpoint_for(ledger: u32) -> u32 {
    ledger | (CHECKPOINT_FREQUENCY - 1)
}

pub fn next_checkpoint(checkpoint: u32) -> Option<u32> {
    checkpoint.checked_add(CHECKPOINT_FREQUENCY)
}

pub fn is_remote(base: &str) -> bool {
    base.starts_with("http://") || base.starts_with("https://")
}

pub fn local_path(base: &str, rest: &str) -> PathBuf {
    let root = base.strip_prefix("file://").unwrap_or(base);

    PathBuf::from(root).join(rest)
}

pub fn history_url(base: &str) -> String {
    if is_remote(base) {
        format!("{base}/.well-known/stellar-history.json")
    } else {
        local_path(base, ".well-known/stellar-history.json")
            .display()
            .to_string()
    }
}

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .expect("the http client builds from static configuration")
    })
}

pub async fn latest_ledger(base: &str) -> Result<u32> {
    let url = history_url(base);
    let body = if is_remote(base) {
        remote_history_json(&url).await?
    } else {
        std::fs::read_to_string(&url).map_err(|error| Error::ArchiveBody {
            url: url.clone(),
            detail: error.to_string(),
        })?
    };

    let root: serde_json::Value =
        serde_json::from_str(&body).map_err(|error| Error::ArchiveJson {
            url: url.clone(),
            detail: error.to_string(),
        })?;

    root.get("currentLedger")
        .and_then(serde_json::Value::as_u64)
        .and_then(|ledger| u32::try_from(ledger).ok())
        .ok_or(Error::ArchiveNoCurrentLedger { url })
}

async fn remote_history_json(url: &str) -> Result<String> {
    let response = client()
        .get(url)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|error| Error::ArchiveRequest {
            url: url.to_string(),
            detail: error.to_string(),
        })?;
    let status = response.status();

    if !status.is_success() {
        return Err(Error::ArchiveStatus {
            url: url.to_string(),
            status: u32::from(status.as_u16()),
        });
    }

    response.text().await.map_err(|error| Error::ArchiveBody {
        url: url.to_string(),
        detail: error.to_string(),
    })
}

pub fn relative_path(category: &str, checkpoint: u32) -> String {
    let hex = format!("{checkpoint:08x}");

    format!(
        "{category}/{}/{}/{}/{category}-{hex}.xdr.gz",
        &hex[0..2],
        &hex[2..4],
        &hex[4..6],
    )
}

pub fn url(base: &str, category: &str, checkpoint: u32) -> String {
    let rest = relative_path(category, checkpoint);

    if is_remote(base) {
        format!("{base}/{rest}")
    } else {
        local_path(base, &rest).display().to_string()
    }
}

pub async fn fetch(base: &str, category: &str, checkpoint: u32) -> Result<Vec<u8>> {
    let url = url(base, category, checkpoint);
    let gzipped = if is_remote(base) {
        remote_bytes(&url).await?
    } else {
        std::fs::read(&url).map_err(|error| Error::ArchiveBody {
            url: url.clone(),
            detail: error.to_string(),
        })?
    };

    gunzip(&gzipped, MAX_GUNZIPPED_BYTES).map_err(|detail| Error::ArchiveGunzip { url, detail })
}

pub fn gunzip(gzipped: &[u8], limit: u64) -> core::result::Result<Vec<u8>, String> {
    let mut output = Vec::new();

    GzDecoder::new(gzipped)
        .take(limit.saturating_add(1))
        .read_to_end(&mut output)
        .map_err(|error| error.to_string())?;

    if output.len() as u64 > limit {
        return Err(format!("it expands past the {limit}-byte limit"));
    }

    Ok(output)
}

async fn remote_bytes(url: &str) -> Result<Vec<u8>> {
    let response = client()
        .get(url)
        .timeout(Duration::from_secs(120))
        .send()
        .await
        .map_err(|error| Error::ArchiveRequest {
            url: url.to_string(),
            detail: error.to_string(),
        })?;
    let status = response.status();

    if !status.is_success() {
        return Err(Error::ArchiveStatus {
            url: url.to_string(),
            status: u32::from(status.as_u16()),
        });
    }

    let too_large = || Error::ArchiveTooLarge {
        url: url.to_string(),
        limit: MAX_DOWNLOAD_BYTES,
    };

    if response
        .content_length()
        .is_some_and(|length| length > MAX_DOWNLOAD_BYTES as u64)
    {
        return Err(too_large());
    }

    let mut response = response;
    let mut body = Vec::new();

    while let Some(chunk) = response.chunk().await.map_err(|error| Error::ArchiveBody {
        url: url.to_string(),
        detail: error.to_string(),
    })? {
        if body.len() + chunk.len() > MAX_DOWNLOAD_BYTES {
            return Err(too_large());
        }

        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

pub fn frames(buffer: &[u8]) -> Result<Vec<&[u8]>> {
    let mut output = Vec::new();
    let mut pos = 0usize;

    while pos < buffer.len() {
        if pos + 4 > buffer.len() {
            return Err(Error::FrameTruncated { offset: pos });
        }

        let raw = u32::from_be_bytes([
            buffer[pos],
            buffer[pos + 1],
            buffer[pos + 2],
            buffer[pos + 3],
        ]);
        let len = (raw & 0x7fff_ffff) as usize;
        let start = pos + 4;
        let end = start
            .checked_add(len)
            .filter(|candidate| *candidate <= buffer.len())
            .ok_or(Error::FrameOverruns { offset: pos, len })?;

        output.push(&buffer[start..end]);
        pos = end;
    }

    Ok(output)
}

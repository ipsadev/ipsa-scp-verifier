use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "mainnet" | "public" | "pubnet" => Ok(Self::Mainnet),
            "testnet" | "test" => Ok(Self::Testnet),
            other => Err(Error::UnknownNetwork {
                name: other.to_string(),
            }),
        }
    }

    pub fn passphrase(self) -> &'static str {
        match self {
            Self::Mainnet => "Public Global Stellar Network ; September 2015",
            Self::Testnet => "Test SDF Network ; September 2015",
        }
    }

    pub fn id(self) -> [u8; 32] {
        Sha256::digest(self.passphrase().as_bytes()).into()
    }

    pub fn archive_base(self) -> &'static str {
        match self {
            Self::Mainnet => "https://history.stellar.org/prd/core-live/core_live_001",
            Self::Testnet => "https://history.stellar.org/prd/core-testnet/core_testnet_001",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }
}

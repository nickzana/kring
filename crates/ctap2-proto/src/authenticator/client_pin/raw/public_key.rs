use cosey::{EcdhEsHkdf256PublicKey, Ed25519PublicKey, P256PublicKey};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum PublicKey {
    P256Key(P256PublicKey),
    EcdhEsHkdf256Key(EcdhEsHkdf256PublicKey),
    Ed25519Key(Ed25519PublicKey),
}

impl Into<cosey::PublicKey> for PublicKey {
    fn into(self) -> cosey::PublicKey {
        match self {
            PublicKey::P256Key(key) => cosey::PublicKey::P256Key(key),
            PublicKey::EcdhEsHkdf256Key(key) => cosey::PublicKey::EcdhEsHkdf256Key(key),
            PublicKey::Ed25519Key(key) => cosey::PublicKey::Ed25519Key(key),
        }
    }
}

pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Option<cosey::PublicKey>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    PublicKey::deserialize(deserializer)
        .map(Into::into)
        .map(Some)
}


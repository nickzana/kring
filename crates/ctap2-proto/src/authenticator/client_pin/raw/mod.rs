//! Used to make serialization and deseriazation of the request and response
//! possible in CBOR format while maintaining ergonomic enum variants for public
//! API.

use serde::{Deserialize, Serialize};
mod public_key;

#[derive(Clone, Serialize, Deserialize)]
#[serde(into = "u8")]
pub(crate) enum RawSubcommand {
    GetPinRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPin = 0x03,
    ChangePin = 0x04,
    GetPinToken = 0x05,
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    GetUvRetries = 0x07,
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
}

impl From<RawSubcommand> for u8 {
    fn from(value: RawSubcommand) -> Self {
        value as u8
    }
}


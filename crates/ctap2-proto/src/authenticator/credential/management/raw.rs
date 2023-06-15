use super::Error;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
enum RawSubcommand {
    GetCredsMetadata = 0x01,
    EnumerateRpsBegin = 0x02,
    EnumerateRpsGetNextRp = 0x03,
    EnumerateCredentialsBegin = 0x04,
    EnumerateCredentialsGetNextCredential = 0x05,
    DeleteCredential = 0x06,
    UpdateUserInformation = 0x07,
}

impl From<RawSubcommand> for u8 {
    fn from(val: RawSubcommand) -> Self {
        val as u8
    }
}

impl TryFrom<u8> for RawSubcommand {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x01 => RawSubcommand::GetCredsMetadata,
            0x02 => RawSubcommand::EnumerateRpsBegin,
            0x03 => RawSubcommand::EnumerateRpsGetNextRp,
            0x04 => RawSubcommand::EnumerateCredentialsBegin,
            0x05 => RawSubcommand::EnumerateCredentialsGetNextCredential,
            0x06 => RawSubcommand::DeleteCredential,
            0x07 => RawSubcommand::UpdateUserInformation,
            _ => return Err(Error::InvalidParameter),
        })
    }
}

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(into = "u8", try_from = "u8")
)]
pub enum Version {
    One = 1,
    Two = 2,
}

impl From<Version> for u8 {
    fn from(value: Version) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for Version {
    type Error = super::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Version::One),
            2 => Ok(Version::Two),
            _ => Err(super::Error::InvalidParameter),
        }
    }
}

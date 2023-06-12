#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Policy {
    UserVerificationOptional = 0x01,
    UserVerificationOptionalWithCredentialIdList = 0x02,
    UserVerificationRequired = 0x03,
}

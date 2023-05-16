pub mod public_key;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// > This enumeration defines the valid credential types. It is an
/// > extension point; values can be added to it in the future, as
/// > more credential types are defined. The values of this
/// > enumeration are used for versioning the Authentication
/// > Assertion and attestation structures according to the type of
/// > the authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum Type {
    #[cfg_attr(feature = "serde", serde(rename = "public-key"))]
    PublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupState {
    BackedUp = 0b0,
    NotBackedUp = 0b1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupEligibility {
    Eligible,
    Ineligible,
}

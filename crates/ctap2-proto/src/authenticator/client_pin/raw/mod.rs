//! Used to make serialization and deseriazation of the request and response
//! possible in CBOR format while maintaining ergonomic enum variants for public
//! API.

use super::Permission;
use flagset::flags;
use flagset::FlagSet;
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


flags! {
    #[derive(Serialize, Deserialize)]
    pub enum RawPermission: u8 {
        MakeCredential = 0x01,
        GetAssertion = 0x02,
        CredentialManagement = 0x04,
        BioEnrollment = 0x08,
        LargeBlobWrite = 0x10,
        AuthenticatorConfiguration = 0x20,
    }
}

impl From<Permission> for RawPermission {
    fn from(value: Permission) -> Self {
        match value {
            Permission::MakeCredential => Self::MakeCredential,
            Permission::GetAssertion => Self::GetAssertion,
            Permission::CredentialManagement => Self::CredentialManagement,
            Permission::BiometricEnrollment => Self::BioEnrollment,
            Permission::LargeBlobWrite => Self::LargeBlobWrite,
            Permission::AuthenticatorConfiguration => Self::AuthenticatorConfiguration,
        }
    }
}

impl From<RawPermission> for Permission {
    fn from(value: RawPermission) -> Self {
        match value {
            RawPermission::MakeCredential => Self::MakeCredential,
            RawPermission::GetAssertion => Self::GetAssertion,
            RawPermission::CredentialManagement => Self::CredentialManagement,
            RawPermission::BioEnrollment => Self::BiometricEnrollment,
            RawPermission::LargeBlobWrite => Self::LargeBlobWrite,
            RawPermission::AuthenticatorConfiguration => Self::AuthenticatorConfiguration,
        }
    }
}

impl FromIterator<Permission> for FlagSet<RawPermission> {
    fn from_iter<T: IntoIterator<Item = Permission>>(iter: T) -> Self {
        iter.into_iter()
            .map(RawPermission::from)
            .fold(None.into(), |mut set, flag| {
                set |= flag;
                set
            })
    }
}

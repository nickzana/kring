//! Used to make serialization and deseriazation of the request and response
//! possible in CBOR format while maintaining ergonomic enum variants for public
//! API.

use super::auth_protocol;
use super::Error;
use super::Permission;
use super::{PinUvAuthParam, PinUvAuthToken};
use super::{Request, Response};
use flagset::flags;
use flagset::FlagSet;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use std::borrow::Cow;

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

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RawRequest<'a> {
    #[serde(rename = 0x01, skip_serializing_if = "Option::is_none")]
    pub pin_uv_auth_protocol: Option<auth_protocol::Version>,
    #[serde(rename = 0x02)]
    pub sub_command: RawSubcommand,
    #[serde(
        rename = 0x03,
        deserialize_with = "public_key::deserialize",
        skip_serializing_if = "Option::is_none"
    )]
    pub key_agreement: Option<cosey::PublicKey>,
    #[serde_as(as = "Option<Bytes>")]
    #[serde(rename = 0x04, skip_serializing_if = "Option::is_none")]
    pub pin_uv_auth_param: Option<PinUvAuthParam>,
    #[serde_as(as = "Option<Bytes>")]
    #[serde(rename = 0x05, skip_serializing_if = "Option::is_none")]
    pub new_pin_enc: Option<[u8; 64]>,
    #[serde_as(as = "Option<Bytes>")]
    #[serde(rename = 0x06, skip_serializing_if = "Option::is_none")]
    pub pin_hash_enc: Option<[u8; 16]>,
    #[serde(rename = 0x09, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<FlagSet<RawPermission>>, // TODO: Deserialize from bitfield
    #[serde(rename = 0x0A, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<Cow<'a, str>>,
}

impl<'a> From<Request<'a>> for RawRequest<'a> {
    fn from(value: Request<'a>) -> Self {
        match value {
            Request::GetPinRetries => Self {
                pin_uv_auth_protocol: None,
                sub_command: RawSubcommand::GetPinRetries,
                key_agreement: None,
                pin_uv_auth_param: None,
                new_pin_enc: None,
                pin_hash_enc: None,
                rp_id: None,
                permissions: None,
            },
            Request::GetKeyAgreement { version } => Self {
                pin_uv_auth_protocol: Some(version),
                sub_command: RawSubcommand::GetKeyAgreement,
                key_agreement: None,
                pin_uv_auth_param: None,
                new_pin_enc: None,
                pin_hash_enc: None,
                rp_id: None,
                permissions: None,
            },
            Request::SetPin {
                key_agreement,
                new_pin_encrypted,
                pin_uv_auth_param,
                version,
            } => Self {
                pin_uv_auth_protocol: Some(version),
                sub_command: RawSubcommand::SetPin,
                key_agreement: Some(key_agreement),
                pin_uv_auth_param: Some(pin_uv_auth_param),
                new_pin_enc: Some(new_pin_encrypted.clone()),
                pin_hash_enc: None,
                rp_id: None,
                permissions: None,
            },
            Request::ChangePin {
                version,
                pin_hash_encrypted,
                new_pin_encrypted,
                pin_uv_auth_param,
                key_agreement,
            } => Self {
                pin_uv_auth_protocol: Some(version),
                sub_command: RawSubcommand::ChangePin,
                key_agreement: Some(key_agreement),
                pin_uv_auth_param: Some(pin_uv_auth_param),
                new_pin_enc: Some(new_pin_encrypted.clone()),
                pin_hash_enc: Some(pin_hash_encrypted.clone()),
                rp_id: None,
                permissions: None,
            },
            Request::GetPinToken {
                version,
                key_agreement,
                pin_hash_encrypted,
            } => Self {
                pin_uv_auth_protocol: Some(version),
                sub_command: RawSubcommand::GetPinToken,
                key_agreement: Some(key_agreement),
                pin_uv_auth_param: None,
                new_pin_enc: None,
                pin_hash_enc: Some(pin_hash_encrypted.clone()),
                rp_id: None,
                permissions: None,
            },
            Request::GetPinUvAuthTokenUsingUvWithPermissions {
                version,
                key_agreement,
                permissions,
                relying_party_id,
            } => Self {
                pin_uv_auth_protocol: Some(version),
                sub_command: RawSubcommand::GetPinUvAuthTokenUsingUvWithPermissions,
                key_agreement: Some(key_agreement),
                pin_uv_auth_param: None,
                new_pin_enc: None,
                pin_hash_enc: None,
                rp_id: relying_party_id,
                permissions: Some(permissions.iter().map(Clone::clone).collect()),
            },
            Request::GetUvRetries => Self {
                pin_uv_auth_protocol: None,
                sub_command: RawSubcommand::GetUvRetries,
                key_agreement: None,
                pin_uv_auth_param: None,
                new_pin_enc: None,
                pin_hash_enc: None,
                rp_id: None,
                permissions: None,
            },
            Request::GetPinUvAuthTokenUsingPinWithPermissions {
                version,
                key_agreement,
                pin_hash_encrypted,
                permissions,
                relying_party_id,
            } => Self {
                pin_uv_auth_protocol: Some(version),
                sub_command: RawSubcommand::GetPinUvAuthTokenUsingPinWithPermissions,
                key_agreement: Some(key_agreement),
                pin_uv_auth_param: None,
                new_pin_enc: None,
                pin_hash_enc: Some(pin_hash_encrypted),
                rp_id: relying_party_id,
                permissions: Some(permissions.iter().map(Clone::clone).collect()),
            },
        }
    }
}

impl<'a> TryFrom<RawRequest<'a>> for Request<'a> {
    type Error = Error;

    fn try_from(value: RawRequest<'a>) -> Result<Self, Self::Error> {
        todo!()
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub(crate) struct RawResponse {
    #[serde(
        rename = 0x01,
        default, // Allows for None variant to be deserialized when 0x01 is not present, required
                 // because of deserialize_with
        deserialize_with = "public_key::deserialize",
        skip_serializing_if = "Option::is_none",
    )]
    pub key_agreement: Option<cosey::PublicKey>,
    #[serde_as(as = "Option<Bytes>")]
    #[serde(rename = 0x02, skip_serializing_if = "Option::is_none")]
    pub pin_uv_auth_token: Option<PinUvAuthToken>,
    #[serde(rename = 0x03, skip_serializing_if = "Option::is_none")]
    pub pin_retries: Option<usize>,
    #[serde(rename = 0x04, skip_serializing_if = "Option::is_none")]
    pub power_cycle_state: Option<usize>,
    #[serde(rename = 0x05, skip_serializing_if = "Option::is_none")]
    pub uv_retries: Option<usize>,
}

impl From<Response> for RawResponse {
    fn from(value: Response) -> Self {
        match value {
            Response::GetPinRetries {
                pin_retries,
                power_cycle_state,
            } => Self {
                key_agreement: None,
                pin_uv_auth_token: None,
                pin_retries: Some(pin_retries),
                power_cycle_state,
                uv_retries: None,
            },
            Response::GetKeyAgreement { key_agreement } => Self {
                key_agreement: Some(key_agreement),
                pin_uv_auth_token: None,
                pin_retries: None,
                power_cycle_state: None,
                uv_retries: None,
            },
            Response::SetPin => Self {
                key_agreement: None,
                pin_uv_auth_token: None,
                pin_retries: None,
                power_cycle_state: None,
                uv_retries: None,
            },
            Response::ChangePin => Self {
                key_agreement: None,
                pin_uv_auth_token: None,
                pin_retries: None,
                power_cycle_state: None,
                uv_retries: None,
            },
            Response::GetPinToken { pin_uv_auth_token } => Self {
                key_agreement: None,
                pin_uv_auth_token: Some(pin_uv_auth_token),
                pin_retries: None,
                power_cycle_state: None,
                uv_retries: None,
            },
            Response::GetPinUvAuthTokenUsingUvWithPermissions { pin_uv_auth_token } => Self {
                key_agreement: None,
                pin_uv_auth_token: Some(pin_uv_auth_token),
                pin_retries: None,
                power_cycle_state: None,
                uv_retries: None,
            },
            Response::GetUvRetries { uv_retries } => Self {
                key_agreement: None,
                pin_uv_auth_token: None,
                pin_retries: None,
                power_cycle_state: None,
                uv_retries: Some(uv_retries.get()),
            },
            Response::GetPinUvAuthTokenUsingPinWithPermissions { pin_uv_auth_token } => Self {
                key_agreement: None,
                pin_uv_auth_token: Some(pin_uv_auth_token),
                pin_retries: None,
                power_cycle_state: None,
                uv_retries: None,
            },
        }
    }
}

impl TryFrom<RawResponse> for Response {
    type Error = Error;

    fn try_from(value: RawResponse) -> Result<Self, Self::Error> {
        Ok(match value {
            RawResponse {
                key_agreement: None,
                pin_uv_auth_token: None,
                pin_retries: Some(pin_retries),
                power_cycle_state,
                uv_retries: None,
            } => Response::GetPinRetries {
                pin_retries,
                power_cycle_state,
            },
            RawResponse {
                key_agreement: Some(key_agreement),
                pin_uv_auth_token: None,
                pin_retries: None,
                power_cycle_state: None,
                uv_retries: None,
            } => Response::GetKeyAgreement { key_agreement },
            RawResponse {
                key_agreement: None,
                pin_uv_auth_token: Some(pin_uv_auth_token),
                pin_retries: None,
                power_cycle_state: None,
                uv_retries: None,
            } => Response::GetPinToken { pin_uv_auth_token },
            _ => todo!(),
        })
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

use bounded_integer::BoundedUsize;
use std::collections::BTreeSet;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod auth_protocol;

pub type PinUvAuthParam = [u8; 16];

#[derive(Clone)]
pub enum Request<'a> {
    GetPinRetries,
    GetKeyAgreement {
        version: auth_protocol::Version,
    },
    SetPin {
        key_agreement: &'a coset::CoseKey,
        new_pin_encrypted: &'a [u8],
        pin_uv_auth_param: &'a [u8],
    },
    ChangePin {
        version: auth_protocol::Version,
        pin_hash_encrypted: &'a [u8],
        new_pin_encrypted: &'a [u8],
        pin_uv_auth_param: &'a [u8],
    },
    GetPinToken {
        version: auth_protocol::Version,
        key_agreement: cosey::PublicKey,
        pin_hash_encrypted: &'a [u8],
    },
    GetPinUvAuthTokenUsingUvWithPermissions {
        version: auth_protocol::Version,
        key_agreement: &'a coset::CoseKey,
        permissions: &'a BTreeSet<Permission>, // TODO: Enforce non-empty set?
        relying_party_id: Option<usize>,
    },
    GetUvRetries,
    GetPinUvAuthTokenUsingPinWithPermissions {
        version: auth_protocol::Version,
        key_agreement: &'a coset::CoseKey,
        pin_hash_encrypted: usize,
        permissions: &'a BTreeSet<Permission>, // TODO: Enforce non-empty set?
        relying_party_id: Option<usize>,
    },
}

pub enum PinUvAuthToken {
    Short([u8; 16]),
    Long([u8; 32]),
}

pub enum Response {
    GetPinRetries {
        pin_retries: usize,
        power_cycle_state: Option<usize>,
    },
    GetKeyAgreement {
        key_agreement: coset::CoseKey,
    },
    SetPin {
        key_agreement: coset::CoseKey,
        new_pin_encrypted: [u8; 64],
        pin_uv_auth_param: (),
    },
    ChangePin,
    GetPinToken,
    GetPinUvAuthTokenUsingUvWithPermissions {
        /// > The pinUvAuthToken, encrypted by calling encrypt with the shared
        /// > secret as the key.
        pin_uv_auth_token: PinUvAuthToken,
    },
    GetUvRetries {
        /// > Number of uv attempts remaining before lockout.
        ///
        /// > The `uv_retries` counter represents the number of user
        /// > verification attempts left before built-in user verification is
        /// > disabled.
        uv_retries: BoundedUsize<1, 25>,
    },
    GetPinUvAuthTokenUsingPinWithPermissions {
        /// > The pinUvAuthToken, encrypted by calling encrypt with the shared
        /// > secret as the key.
        pin_uv_auth_token: PinUvAuthToken,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum Error {
    MissingParameter,
    InvalidParameter,
    PinAuthInvalid,
    PinPolicyViolation,
    PinBlocked,
    PinAuthBlocked,
    PinInvalid,
    OperationDenied,
    UnauthorizedPermission,
    NotAllowed,
    UserVerificationBlocked,
    UserActionTimeout,
    UserVerificationInvalid,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::MissingParameter => write!(f, "Missing parameter"),
            Error::InvalidParameter => write!(f, "Invalid parameter"),
            Error::PinAuthInvalid => write!(f, "PIN auth invalid"),
            Error::PinPolicyViolation => write!(f, "PIN policy violation"),
            Error::PinBlocked => write!(f, "PIN blocked"),
            Error::PinAuthBlocked => write!(f, "PIN auth blocked"),
            Error::PinInvalid => write!(f, "PIN invalid"),
            Error::OperationDenied => write!(f, "Operation denied"),
            Error::UnauthorizedPermission => write!(f, "Unauthorized permission"),
            Error::NotAllowed => write!(f, "Not allowed"),
            Error::UserVerificationBlocked => write!(f, "User verification blocked"),
            Error::UserActionTimeout => write!(f, "User action timeout"),
            Error::UserVerificationInvalid => write!(f, "User verification invalid"),
        }
    }
}

/// > When obtaining a `pinUvAuthToken`, the platform requests permissions
/// > appropriate for the operations it intends to perform. Consequently, the
/// > `pinUvAuthToken` can only be used for those operations.
#[derive(Clone, Copy)]
pub enum Permission {
    /// > This allows the `pinUvAuthToken` to be used for
    /// > `authenticatorMakeCredential` operations with the provided `rpId`
    /// > parameter.
    MakeCredential,
    /// > This allows the `pinUvAuthToken` to be used for
    /// > `authenticatorGetAssertion` operations with the provided `rpId`
    /// > parameter.
    GetAssertion,
    /// > This allows the `pinUvAuthToken` to be used with the
    /// > `authenticatorCredentialManagement` command. The `rpId` parameter is
    /// > optional, if it is present, the `pinUvAuthToken` can only be used for
    /// > Credential Management operations on Credentials associated with that
    /// > RP ID.
    CredentialManagement,
    /// > This allows the `pinUvAuthToken` to be used with the
    /// > `authenticatorBioEnrollment` command.
    BiometricEnrollment,
    /// > This allows the `pinUvAuthToken` to be used with the
    /// > `authenticatorLargeBlobs` command.
    LargeBlobWrite,
    /// > This allows the `pinUvAuthToken` to be used with the
    /// > `authenticatorConfig` command.
    AuthenticatorConfiguration,
}

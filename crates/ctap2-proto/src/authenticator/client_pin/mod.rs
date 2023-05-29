use bounded_integer::BoundedUsize;
use std::collections::BTreeSet;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AuthProtocolVersion {
    One,
    Two,
}

// workaround until <https://github.com/serde-rs/serde/pull/2056> is merged
// PR: ( Integer/boolean tags for internally/adjacently tagged enums #2056 )
#[cfg(feature = "serde")]
impl Serialize for AuthProtocolVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(match self {
            AuthProtocolVersion::One => 1,
            AuthProtocolVersion::Two => 2,
        })
    }
}

// workaround until <https://github.com/serde-rs/serde/pull/2056> is merged
// PR: ( Integer/boolean tags for internally/adjacently tagged enums #2056 )
#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for AuthProtocolVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        match u8::deserialize(deserializer)? {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            i => Err(de::Error::invalid_value(
                de::Unexpected::Unsigned(i.into()),
                &"1 or 2",
            )),
        }
    }
}

#[derive(Clone, Copy)]
pub enum Request<'a> {
    GetPinRetries,
    GetKeyAgreement {
        version: AuthProtocolVersion,
    },
    SetPin {
        key_agreement: &'a coset::CoseKey,
        new_pin_encrypted: &'a [u8],
        pin_uv_auth_param: &'a [u8],
    },
    ChangePin {
        version: AuthProtocolVersion,
        pin_hash_encrypted: &'a [u8],
        new_pin_encrypted: &'a [u8],
        pin_uv_auth_param: &'a [u8],
    },
    GetPinToken {
        version: AuthProtocolVersion,
        key_agreement: &'a coset::CoseKey,
        pin_hash_encrypted: &'a [u8],
    },
    GetPinUvAuthTokenUsingUvWithPermissions {
        version: AuthProtocolVersion,
        key_agreement: &'a coset::CoseKey,
        permissions: &'a BTreeSet<Permission>, // TODO: Enforce non-empty set?
        relying_party_id: Option<usize>,
    },
    GetUvRetries,
    GetPinUvAuthTokenUsingPinWithPermissions {
        version: AuthProtocolVersion,
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

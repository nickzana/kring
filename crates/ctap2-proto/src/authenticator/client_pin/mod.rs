use std::collections::{BTreeSet};

use bounded_integer::BoundedUsize;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AuthProtocolVersion {
    One,
    Two,
}

pub enum Subcommand {
    GetPinRetries,
    GetKeyAgreement,
    SetPin,
    ChangePin,
    GetPinToken,
    GetPinUvAuthTokenUsingUvWithPermissions,
    GetUvRetries,
    GetPinUvAuthTokenUsingPinWithPermissions,
}

#[derive(Clone, Copy)]
pub enum Request<'a> {
    GetPinRetries,
    GetKeyAgreement {
        version: AuthProtocolVersion,
    },
    SetPin {
        key_agreement: &'a KeyAgreement,
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
        key_agreement: &'a KeyAgreement,
        pin_hash_encrypted: &'a [u8],
    },
    GetPinUvAuthTokenUsingUvWithPermissions {
        version: AuthProtocolVersion,
        key_agreement: &'a KeyAgreement,
        permissions: &'a BTreeSet<Permission>, // TODO: Enforce non-empty set?
        relying_party_id: Option<usize>,
    },
    GetUvRetries,
    GetPinUvAuthTokenUsingPinWithPermissions {
        version: AuthProtocolVersion,
        key_agreement: &'a KeyAgreement,
        pin_hash_encrypted: usize,
        permissions: &'a BTreeSet<Permission>, // TODO: Enforce non-empty set?
        relying_party_id: Option<usize>,
    },
}

/// The [`Ctap2Device::client_pin`] command enforces several restrictions on the
/// COSE key used in a request and response. The restrictions are as follows:
///
/// > This COSE_Key-encoded public key MUST contain the optional "`alg`"
/// > parameter and MUST NOT contain any other optional parameters. The "`alg`"
/// > parameter MUST contain a `COSEAlgorithmIdentifier` value.
// This seems like it should be an enum where each `KeyType` variant has its own
// parameters? `coset` uses a CBOR map directly
pub struct KeyAgreement {
    pub kty: coset::KeyType,
    pub alg: Option<coset::Algorithm>,
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
        key_agreement: KeyAgreement,
    },
    SetPin {
        key_agreement: KeyAgreement,
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

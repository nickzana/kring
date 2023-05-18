use crate::Sha256Hash;
use crate::{authenticator::client_pin::AuthProtocolVersion, extensions};
use fido_common::credential::public_key;
use std::{collections::BTreeMap, usize};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::{serde_as, skip_serializing_none, Bytes};

#[derive(Debug)]
pub enum Error {
    OperationDenied,
    PinNotSet,
    PinInvalid,
    InvalidParameter,
    MissingParameter,
    InvalidOption,
    UnsupportedOption,
    PinUvAuthTokenRequired,
    PinAuthInvalid,
    UserActionTimeout,
    PinBlocked,
    NoCredentials,
}

/// > The following option keys are defined for use in
/// > [`assertion::get::Request`]'s `options` parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OptionKey {
    /// > user presence: Instructs the authenticator to require user consent
    /// > to complete the operation.
    #[serde(rename = "up")]
    UserPresence,
    /// > user verification: If true, instructs the authenticator to require
    /// > a user-verifying gesture in order to complete the request.
    /// > Examples of such gestures are fingerprint scan or a PIN.
    #[serde(rename = "uv")]
    UserVerification,
}

/// Request parameters for [`Ctap2Device::get_assertion`] operation.
#[cfg_eval]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", serde_as, skip_serializing_none, derive(Serialize))]
pub struct Request<'a> {
    /// > relying party identifier
    #[serde(rename = 0x01)]
    pub relying_party_id: &'a str,
    /// > Hash of the serialized client data collected by the host.
    #[cfg_attr(feature = "serde", serde_as(as = "Bytes"), serde(rename = 0x02))]
    pub client_data_hash: &'a Sha256Hash,
    /// > An array of [`public_key::Descriptor`] structures, each denoting a
    /// > credential, as specified in `WebAuthn`... If this parameter is present
    /// > the authenticator MUST only generate a assertion using one of the
    /// > denoted credentials.
    // Cannot be empty if present
    #[serde(rename = 0x03)]
    pub allow_list: Option<&'a Vec<&'a public_key::Descriptor>>,
    /// > Parameters to influence authenticator operation. These parameters
    /// > might be authenticator specific.
    #[serde(rename = 0x04)]
    pub extensions: Option<&'a BTreeMap<extensions::Identifier, &'a [u8]>>,
    /// > Parameters to influence authenticator operation.
    #[serde(rename = 0x05)]
    pub options: Option<&'a BTreeMap<OptionKey, bool>>,
    #[serde(rename = 0x06)]
    pub pin_uv_auth_param: Option<&'a [u8]>,
    /// > PIN/UV protocol version selected by platform.
    #[serde(rename = 0x07)]
    pub pin_uv_auth_protocol_version: Option<AuthProtocolVersion>,
}

/// Response structure for [`Ctap2Device::get_assertion`] operation.
#[derive(Debug, Clone)]
pub struct Response {
    /// > PublicKeyCredentialDescriptor structure containing the credential
    /// > identifier whose private key was used to generate the assertion.
    pub credential: public_key::Descriptor,
    /// > The signed-over contextual bindings made by the authenticator, as
    /// > specified in [WebAuthn].
    pub auth_data: Vec<u8>,
    /// > The assertion signature produced by the authenticator, as
    /// > specified in [WebAuthn].
    pub signature: Vec<u8>,
    /// > [`public_key::UserEntity`] structure containing the user account
    /// > information
    pub user: Option<public_key::UserEntity>,
    /// > Total number of account credentials for the RP. Optional; defaults
    /// > to one. This member is required when more than one credential is
    /// > found for an RP, and the authenticator does not have a display or
    /// > the UV & UP flags are false.
    pub number_of_credentials: Option<usize>,
    /// > Indicates that a credential was selected by the user via
    /// > interaction directly with the authenticator, and thus the platform
    /// > does not need to confirm the credential.
    pub user_selected: Option<bool>,
    /// > The contents of the associated `largeBlobKey` if present for the
    /// > asserted credential, and if `largeBlobKey` was true in the
    /// > extensions input.
    pub large_blob_key: Option<Vec<u8>>,
}

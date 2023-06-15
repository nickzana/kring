use crate::{authenticator::client_pin, extensions::cred_protect, Sha256Hash};
use fido_common::credential::public_key;

pub type PinUvAuthParam = [u8; 16];

#[cfg(feature = "serde")]
mod raw;

#[derive(Clone, Copy)]
pub enum Request<'a> {
    GetCredentialsMetadata {
        /// > PIN/UV protocol version chosen by the platform.
        pin_uv_auth_protocol: client_pin::auth_protocol::Version,
        /// > First 16 bytes of HMAC-SHA-256 of contents using `pinUvAuthToken`.
        pin_uv_auth_param: &'a PinUvAuthParam,
    },
    EnumerateRPsBegin {
        /// > PIN/UV protocol version chosen by the platform.
        pin_uv_auth_protocol: client_pin::auth_protocol::Version,
        /// > First 16 bytes of HMAC-SHA-256 of contents using `pinUvAuthToken`.
        pin_uv_auth_param: &'a PinUvAuthParam,
    },
    EnumerateRPsGetNextRP,
    EnumerateCredentialsBegin {
        /// The ID of the relying party to enumerate credentials for.
        relying_party_id_hash: &'a Sha256Hash,
        /// > PIN/UV protocol version chosen by the platform.
        pin_uv_auth_protocol: client_pin::auth_protocol::Version,
        /// > First 16 bytes of HMAC-SHA-256 of contents using `pinUvAuthToken`.
        pin_uv_auth_param: &'a PinUvAuthParam,
    },
    EnumerateCredentialsGetNextCredential,
    DeleteCredential {
        /// The ID of the credential to delete.
        credential_id: &'a public_key::Descriptor,
        /// > PIN/UV protocol version chosen by the platform.
        pin_uv_auth_protocol: client_pin::auth_protocol::Version,
        /// > First 16 bytes of HMAC-SHA-256 of contents using `pinUvAuthToken`.
        pin_uv_auth_param: &'a PinUvAuthParam,
    },
    UpdateUserInformation {
        /// The ID of the credential to update.
        credential_id: &'a public_key::Descriptor,
        /// The updated user information.
        user: &'a public_key::UserEntity,
        /// > PIN/UV protocol version chosen by the platform.
        pin_uv_auth_protocol: client_pin::auth_protocol::Version,
        /// > First 16 bytes of HMAC-SHA-256 of contents using `pinUvAuthToken`.
        pin_uv_auth_param: &'a PinUvAuthParam,
    },
}

pub enum Response {
    GetCredentialsMetadata {
        /// > Number of existing discoverable credentials present on the
        /// > authenticator.
        existing_resident_credentials_count: usize,
        /// > Number of maximum possible remaining discoverable credentials
        /// > which can be created on the authenticator.
        max_possible_remaining_resident_credentials_count: usize,
    },
    EnumerateRPsBegin {
        relying_party: RelyingParty,
        /// > total number of RPs present on the authenticator
        total_relying_parties: usize,
    },
    EnumerateRPsGetNextRP {
        relying_party: RelyingParty,
    },
    EnumerateCredentialsBegin {
        credential: Credential,
        /// > Total number of credentials present on the authenticator for the
        /// > RP in question
        total_credentials: usize,
    },
    EnumerateCredentialsGetNextCredential {
        credential: Credential,
    },
    DeleteCredential,
    UpdateUserInformation,
}

pub struct RelyingParty {
    /// The description of the relying party.
    pub relying_party: public_key::RelyingPartyEntity,
    /// The hash of the relying party ID.
    pub relying_party_id_hash: Sha256Hash,
}

pub struct Credential {
    /// The description of the user account associated with the credential.
    pub user: public_key::UserEntity,
    /// A description of the public key associated with the credential.
    pub credential_id: public_key::Descriptor,
    /// The public key associated with the credential.
    pub public_key: Vec<u8>, // TODO: Replace arbitrary bytes with parsed key type
    /// Indicates the level of user verification the authenticator requires for
    /// this credential.
    pub credential_protection_policy: cred_protect::Policy,
    /// > Large blob encryption key.
    pub large_blob_key: Vec<u8>,
}

pub enum Error {
    PinUvAuthTokenRequired,
    MissingParameter,
    InvalidParameter,
    PinAuthInvalid,
    NoCredentials,
    KeyStoreFull,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Error::PinUvAuthTokenRequired => "PIN/UV auth token required",
            Error::MissingParameter => "Missing parameter",
            Error::InvalidParameter => "Invalid parameter",
            Error::PinAuthInvalid => "PIN auth invalid",
            Error::NoCredentials => "No credentials",
            Error::KeyStoreFull => "Key store full",
        };
        write!(f, "{}", message)
    }
}

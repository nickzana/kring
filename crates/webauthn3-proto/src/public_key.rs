use crate::authenticator;
use credential_management_proto::{credential, discovery};

pub mod create;
pub mod request;

/// > The [`public_key::Credential`] interface inherits from
/// > [`credential::Credential`], and contains the attributes that are returned
/// > to the caller when a new credential is created, or a new assertion is
/// > requested.
/// >
/// > <https://w3c.github.io/webauthn/#iface-pkcredential/>
pub trait Credential: credential::Credential {
    /// Returns the raw byte array of the credential's `id`.
    fn raw_id(&self) -> &[u8];

    /// > This attribute contains the authenticator's response to the client’s
    /// > request to either create a public key credential, or generate an
    /// > authentication assertion. If the [`public_key::Credential`] is created
    /// > in response to `create()`, this attribute’s value will be an
    /// > [`authenticator::Response::Attestation`], otherwise, the
    /// > [`public_key::Credential`] was created in response to `get()`, and
    /// > this attribute’s value will be an
    /// > [`authenticator::Response::Assertion`].
    fn response(&self) -> &authenticator::Response;

    /// > This attribute reports the authenticator attachment modality in effect
    /// > at the time the `navigator.credentials.create()` or
    /// > `navigator.credentials.get()` methods successfully complete.
    ///
    /// If the attachment method is unknown, this function returns `None`.
    fn authenticator_attachment(&self) -> Option<authenticator::Attachment>;
}

pub trait Container:
    for<'a> credential::Container<
    Credential = Self::PublicKeyCredential,
    RequestOptions = Self::PublicKeyRequestOptions,
    CreateOptions = Self::PublicKeyCreateOptions,
    DISCOVERY_MODE = { discovery::Mode::Remote },
>
{
    type PublicKeyCredential: Credential;
    type PublicKeyRequestOptions: request::Options;
    type PublicKeyCreateOptions: create::Options;

    /// > ...indicate[s] availability for conditional mediation.
    /// >
    /// > <https://w3c.github.io/webauthn/#dom-publickeycredential-isconditionalmediationavailable/>
    async fn is_conditional_mediation_available() -> bool;
}

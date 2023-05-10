use fido_common::{attestation::FormatIdentifier, credential::public_key};

use crate::{attestation, authenticator, UserVerificationRequirement};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// > <https://w3c.github.io/webauthn/#dictionary-makecredentialoptions/>
pub trait Options {
    /// > This member contains a name and an identifier for the Relying Party
    /// > responsible for the request.
    fn public_key_credential_relying_party_entity(&self) -> &public_key::RelyingPartyEntity;

    /// > This member contains names and an identifier for the user account
    /// > performing the registration.
    fn public_key_credential_user_entity(&self) -> &public_key::UserEntity;

    /// > This member specifies a challenge that the authenticator signs, along
    /// > with other data, when producing an attestation object for the newly
    /// > created credential.
    fn challenge(&self) -> &[u8];

    /// > This member lists the key types and signature algorithms the Relying
    /// > Party supports, ordered from most preferred to least preferred.
    fn public_key_credential_parameters(&self) -> &[public_key::Parameters];

    /// > This OPTIONAL member specifies a time, in milliseconds, that the
    /// > Relying Party is willing to wait for the call to complete. This is
    /// > treated as a hint, and MAY be overridden by the client.
    fn timeout(&self) -> Option<u64>;

    /// > The Relying Party SHOULD use this OPTIONAL member to list any existing
    /// > credentials mapped to this user account (as identified by `user.id`).
    /// > This ensures that the new credential is not created on an
    /// > authenticator that already contains a credential mapped to this user
    /// > account. If it would be, the client is requested to instead guide the
    /// > user to use a different authenticator, or return an error if that
    /// > fails.
    fn exclude_credentials(&self) -> Option<&[public_key::Descriptor]>;

    /// > The Relying Party MAY use this OPTIONAL member to specify capabilities
    /// > and settings that the authenticator MUST or SHOULD satisfy to
    /// > participate in the `create()` operation.
    fn authenticator_selection(&self) -> Option<AuthenticatorSelectionCriteria>;

    /// > The Relying Party MAY use this OPTIONAL member to specify a preference
    /// > regarding attestation conveyance.
    fn attestation(&self) -> Option<attestation::ConveyancePreference>;

    /// > The Relying Party MAY use this OPTIONAL member to specify a preference
    /// > regarding the attestation statement format used by the authenticator.
    fn attestation_formats(&self) -> &[FormatIdentifier];
}

/// > WebAuthn Relying Parties may use the [`AuthenticatorSelectionCriteria`]
/// > dictionary to specify their requirements regarding authenticator
/// > attributes.
/// >
/// > <https://w3c.github.io/webauthn/#dictionary-authenticatorSelection/>
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuthenticatorSelectionCriteria {
    /// > If this member is present, eligible authenticators are filtered to be
    /// > only those authenticators attached with the specified authenticator
    /// > attachment modality... If this member is absent, then any attachment
    /// > modality is acceptable.
    #[cfg_attr(feature = "serde", serde(rename = "authenticatorAttachment"))]
    pub attachment: Option<authenticator::Attachment>,
    /// > Specifies the extent to which the Relying Party desires to create a
    /// > client-side discoverable credential.
    #[cfg_attr(feature = "serde", serde(rename = "residentKey"))]
    pub resident_key_requirement: ResidentKeyRequirement,
    /// > This member specifies the Relying Party's requirements regarding user
    /// > verification for the `create()` operation.
    pub user_verification_requirement: UserVerificationRequirement,
}

/// > This enumeration’s values describe the Relying Party's requirements for
/// > client-side discoverable credentials (formerly known as resident
/// > credentials or resident keys):
/// >
/// > <https://w3c.github.io/webauthn/#enumdef-residentkeyrequirement/>
#[derive(Debug, Clone, Copy)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum ResidentKeyRequirement {
    /// > The Relying Party prefers creating a server-side credential, but will
    /// > accept a client-side discoverable credential. The client and
    /// > authenticator SHOULD create a server-side credential if possible.
    Discouraged,
    /// > The Relying Party strongly prefers creating a client-side discoverable
    /// > credential, but will accept a server-side credential. The client and
    /// > authenticator SHOULD create a discoverable credential if possible. For
    /// > example, the client SHOULD guide the user through setting up user
    /// > verification if needed to create a discoverable credential. This takes
    /// > precedence over the setting of
    /// > [`AuthenticatorSelectionCriteria::user_verification`].
    Preferred,
    /// > The Relying Party requires a client-side discoverable credential. The
    /// > client MUST return an error if a client-side discoverable credential
    /// > cannot be created.
    Required,
}

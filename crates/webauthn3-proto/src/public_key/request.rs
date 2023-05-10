use fido_common::{attestation::FormatIdentifier, credential::public_key};

use crate::{attestation, UserVerificationRequirement};

/// > [This struct] supplies `get()` with the data it needs to generate an
/// > assertion.
pub trait Options {
    /// > This member specifies a challenge that the authenticator signs, along
    /// > with other data, when producing an authentication assertion.
    fn challenge(&self) -> &[u8];
    /// > This OPTIONAL member specifies a time, in milliseconds, that the
    /// > Relying Party is willing to wait for the call to complete. The value
    /// > is treated as a hint, and MAY be overridden by the client.
    fn timeout(&self) -> Option<u64>;
    /// > This OPTIONAL member specifies the RP ID claimed by the Relying Party.
    /// > The client MUST verify that the Relying Party's origin matches the
    /// > scope of this RP ID. The authenticator MUST verify that this RP ID
    /// > exactly equals the rpId of the credential to be used for the
    /// > authentication ceremony.
    /// >
    /// > If not specified, its value will be the [`CredentialsContainer`]
    /// > object’s relevant settings object's origin's effective domain.
    fn relying_party_id(&self) -> Option<&str>;
    /// > This OPTIONAL member is used by the client to find authenticators
    /// > eligible for this authentication ceremony.
    /// > ...
    /// > If not empty, the client MUST return an error if none of the listed
    /// > credentials can be used.
    /// >
    /// > The list is ordered in descending order of preference: the first item
    /// > in the list is the most preferred credential, and the last is the
    /// > least preferred.
    fn allow_credentials(&self) -> Option<&[public_key::Descriptor]>;
    /// > ... specifies the Relying Party's requirements regarding user
    /// > verification for the get() operation...  Eligible authenticators are
    /// > filtered to only those capable of satisfying this requirement.
    fn user_verification(&self) -> Option<UserVerificationRequirement>;
    /// > The Relying Party MAY use this OPTIONAL member to specify a preference
    /// > regarding attestation conveyance.
    fn attestation(&self) -> Option<attestation::ConveyancePreference>;
    /// > The Relying Party MAY use this OPTIONAL member to specify a preference
    /// > regarding the attestation statement format used by the
    /// > authenticator... Values are ordered from most preferable to least
    /// > preferable.
    fn attestation_formats(&self) -> Option<&[FormatIdentifier]>;
}

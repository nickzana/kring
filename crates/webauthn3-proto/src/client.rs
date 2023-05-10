use crate::token;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum DataType {
    #[cfg_attr(feature = "serde", serde(rename = "webauthn.create"))]
    Create,
    #[cfg_attr(feature = "serde", serde(rename = "webauthn.get"))]
    Get,
}

/// > The client data represents the contextual bindings of both the
/// > `WebAuthn` Relying Party and the client.
/// >
/// > <https://www.w3.org/TR/webauthn-3/#client-data/>
pub struct Data<const TYPE: DataType> {
    /// > This member contains the base64url encoding of the challenge
    /// > provided by the Relying Party.
    pub challenge: String,
    /// > This member contains the fully qualified origin of the requester,
    /// > as provided to the authenticator by the client, in the syntax
    /// > defined by
    /// > [RFC6454](https://www.w3.org/TR/webauthn-3/#biblio-rfc6454).
    pub origin: String,
    // TODO: Description
    pub cross_origin: Option<bool>,
    /// > ...contains information about the state of the Token Binding
    /// > protocol... used when communicating with the Relying Party. Its
    /// > absence indicates that the client doesn’t support token binding.
    pub token_binding: Option<token::Binding>,
}

#[cfg(feature = "serde")]
impl<const TYPE: DataType> Serialize for Data<TYPE> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Keys are: "type", "challenge", "origin", "topOrigin", "crossOrigin"
        const LEN: usize = 5;
        let mut map = serializer.serialize_map(Some(LEN))?;

        // map.serialize_entry("type", value)
        todo!()
    }
}

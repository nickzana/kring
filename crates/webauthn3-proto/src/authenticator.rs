#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
/// > This enumeration’s values describe authenticators' attachment modalities.
/// > Relying Parties use this to express a preferred authenticator attachment
/// > modality when calling `navigator.credentials.create()` to create a
/// > credential, and clients use this to report the authenticator attachment
/// > modality used to complete a registration or authentication ceremony.
/// >
/// > <https://w3c.github.io/webauthn/#enumdef-authenticatorattachment/>
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Attachment {
    #[cfg_attr(feature = "serde", serde(rename = "platform"))]
    Platform,
    #[cfg_attr(feature = "serde", serde(rename = "cross-platform"))]
    CrossPlatform,
}

#[derive(Debug)]
/// Contains the contents of an authenticator's response to a Relying Party's
/// request.
///
/// > <https://www.w3.org/TR/webauthn-3/#authenticatorresponse/>
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Response {
    // TODO: Fill out response???
    //    Attestation {
    // client_data: client::Data<{ client::DataType::Create }>,
    // attestation_object: Vec<u8>,
    // },
    // Assertion {
    // client_data: client::Data<{ client::DataType::Get }>,
    // },
}

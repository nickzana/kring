use crate::{authenticator::Transport, credential};
use std::collections::BTreeSet;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::{serde_as, skip_serializing_none, Bytes};

#[cfg(feature = "serde")]
pub(crate) mod algorithm {
    use coset::iana::{Algorithm, EnumI64};
    use serde::{Deserialize, Serialize};

    pub(crate) fn serialize<S>(algorithm: &Algorithm, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let i = algorithm.to_i64();
        i64::serialize(&i, serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Algorithm, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let i = i64::deserialize(deserializer)?;
        coset::iana::Algorithm::from_i64(i).ok_or(serde::de::Error::invalid_value(
            serde::de::Unexpected::Signed(i),
            &"an IANA-registered COSE algorithm value",
        ))
    }
}

/// > This dictionary is used to supply additional parameters when
/// > creating a new credential.
#[cfg_eval]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Parameters {
    /// > This member specifies the type of credential to be
    /// > created.
    #[cfg_attr(feature = "serde", serde(rename = "type"))]
    pub credential_type: credential::Type,
    /// # `WebAuthn` Specs
    /// > This member specifies the cryptographic signature
    /// > algorithm with which the newly generated credential will
    /// > be used, and thus also the type of asymmetric key pair to
    /// > be generated, e.g., RSA or Elliptic Curve.
    #[cfg_attr(feature = "serde", serde(rename = "alg", with = "algorithm"))]
    pub algorithm: coset::iana::Algorithm,
}

/// > This dictionary identifies a specific public key credential.
#[cfg_eval]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    serde_as,
    skip_serializing_none,
    derive(Serialize, Deserialize)
)]
pub struct Descriptor {
    /// > This member contains the type of the public key credential
    /// > the caller is referring to.
    #[cfg_attr(feature = "serde", serde(rename = "type"))]
    pub credential_type: credential::Type,
    /// > A probabilistically-unique byte sequence identifying a
    /// > public key credential source and its authentication
    /// > assertions.
    // Bounds: [16, 1023] bytes
    #[cfg_attr(feature = "serde", serde_as(as = "Bytes"))]
    pub id: Vec<u8>,
    /// > This... member contains a hint as to how the client might
    /// > communicate with the managing authenticator of the public
    /// > key credential the caller is referring to.
    pub transports: Option<BTreeSet<Transport>>,
}

/// > This `PublicKeyCredentialUserEntity` data structure describes the user
/// > account to which the new public key credential will be associated at
/// > the RP.
/// Due to deprecation, the `icon` URL is omitted. See <https://github.com/w3c/webauthn/pull/1337/>.
#[cfg_eval]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    serde_as,
    skip_serializing_none,
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct UserEntity {
    /// > an RP-specific user account identifier
    // Justfication for type from WebAuthn Specs:
    // > The user handle of the user account. A user handle is an opaque byte sequence with a
    // > maximum size of 64 bytes, and is not meant to be displayed to the user.
    //
    // CTAP says that "while an empty account identifier is valid, it has known
    // interoperability hurdles in practice and platforms are RECOMMENDED to avoid sending
    // them."
    //
    // WebAuthn says that "The user handle MUST NOT be empty." To maximimize compatibility, the
    // definition from the CTAP specs is used.
    // Bounds: [0, 64] bytes
    #[cfg_attr(feature = "serde", serde_as(as = "Bytes"))]
    pub id: Vec<u8>,
    /// > a human-palatable identifier for a user account. It is intended
    /// > only for display, i.e., aiding the user in determining the
    /// > difference between user accounts with similar displayNames. For
    /// > example, "alexm", "alex.mueller@example.com" or "+14255551234".
    pub name: Option<String>,
    /// > A human-palatable name for the user account, intended only for
    /// > display. For example, "Alex Müller" or "田中倫". The Relying Party
    /// > SHOULD let the user choose this, and SHOULD NOT restrict the
    /// > choice more than necessary.
    pub display_name: Option<String>,
}

/// > This `PublicKeyCredentialRpEntity` data structure describes a Relying
/// > Party with which the new public key credential will be associated.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RelyingPartyEntity {
    /// > A unique identifier for the Relying Party entity.
    pub id: String,
    /// > it is a human-palatable identifier for the Relying Party, intended
    /// > only for display. For example, "ACME Corporation", "Wonderful
    /// > Widgets, Inc." or "ОАО Примертех".
    pub name: Option<String>,
}

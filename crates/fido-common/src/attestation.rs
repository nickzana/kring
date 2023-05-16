#[cfg(feature = "serde")]
use crate::credential::public_key::algorithm;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::{serde_as, Bytes};

pub mod enterprise;

/// > Attestation statement formats are identified by a string, called an
/// > attestation statement format identifier, chosen by the author of the
/// > attestation statement format.
/// >
/// > Attestation statement format identifiers SHOULD be registered in the IANA
/// > "WebAuthn Attestation Statement Format Identifiers" registry
/// > [IANA-WebAuthn-Registries] established by [RFC8809]. All registered
/// > attestation statement format identifiers are unique amongst themselves as
/// > a matter of course.
/// >
/// > Unregistered attestation statement format identifiers SHOULD use lowercase
/// > reverse domain-name naming, using a domain name registered by the
/// > developer, in order to assure uniqueness of the identifier. All
/// > attestation statement format identifiers MUST be a maximum of 32 octets in
/// > length and MUST consist only of printable USASCII characters, excluding
/// > backslash and doublequote, i.e., VCHAR as defined in [RFC5234] but without
/// > %x22 and %x5c.
/// >
/// > > Note: This means attestation statement format identifiers based on
/// > > domain names MUST incorporate only LDH Labels [RFC5890].
/// >
/// > Implementations MUST match `WebAuthn` attestation statement format
/// > identifiers in a case-sensitive fashion.
/// >
/// > Attestation statement formats that may exist in multiple versions SHOULD
/// > include a version in their identifier. In effect, different versions are
/// > thus treated as different formats, e.g., packed2 as a new version of the §
/// > 8.2 Packed Attestation Statement Format.
/// >
/// > The following sections present a set of currently-defined and registered
/// > attestation statement formats and their identifiers. The up-to-date list
/// > of registered `WebAuthn` Extensions is maintained in the IANA "WebAuthn
/// > Attestation Statement Format Identifiers" registry
/// > [IANA-WebAuthn-Registries] established by [RFC8809].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum FormatIdentifier {
    /// > The "packed" attestation statement format is a WebAuthn-optimized
    /// > format for attestation. It uses a very compact but still extensible
    /// > encoding method. This format is implementable by authenticators with
    /// > limited resources (e.g., secure elements).
    #[cfg_attr(feature = "serde", serde(rename = "packed"))]
    Packed,
    /// > The TPM attestation statement format returns an attestation statement
    /// > in the same format as the packed attestation statement format,
    /// > although the rawData and signature fields are computed differently.
    #[cfg_attr(feature = "serde", serde(rename = "tpm"))]
    Tpm,
    /// > Platform authenticators on versions "N", and later, may provide this
    /// > proprietary "hardware attestation" statement.
    #[cfg_attr(feature = "serde", serde(rename = "android-key"))]
    AndroidKey,
    /// > Android-based platform authenticators MAY produce an attestation
    /// > statement based on the Android SafetyNet API.
    #[cfg_attr(feature = "serde", serde(rename = "android-safetynet"))]
    AndroidSafetyNet,
    /// > Used with FIDO U2F authenticators
    #[cfg_attr(feature = "serde", serde(rename = "fido-u2f"))]
    FidoU2f,
    /// > Used with Apple devices' platform authenticators
    #[cfg_attr(feature = "serde", serde(rename = "apple"))]
    Apple,
    /// > Used to replace any authenticator-provided attestation statement when
    /// > a WebAuthn Relying Party indicates it does not wish to receive
    /// > attestation information.
    #[cfg_attr(feature = "serde", serde(rename = "none"))]
    None,
}

#[cfg_eval]
#[derive(Debug)]
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    // TODO: Workaround until serde can use integer keys as tag, since "fmt" is CBOR key 0x01.
    serde(untagged) 
)]
pub enum Statement {
    #[cfg_attr(feature = "serde", serde(rename = "packed"))]
    Packed {
        #[cfg_attr(feature = "serde", serde(rename = "alg", with = "algorithm"))]
        algorithm: coset::iana::Algorithm,
        #[cfg_attr(feature = "serde", serde_as(as = "Bytes"), serde(rename = "sig"))]
        signature: Vec<u8>,
        #[cfg_attr(feature = "serde", serde_as(as = "Vec<Bytes>"), serde(rename = "x5c"))]
        attestation_certificate_chain: Vec<Vec<u8>>, // TODO: Parse X.509 certs
    },
    Unregistered {
        identifier: String,
        data: Vec<u8>,
    },
}

/// > Attested credential data is a variable-length byte array added to the
/// > authenticator data when generating an attestation object for a given
/// > credential.
#[derive(Debug)]
pub struct CredentialData {
    /// > The AAGUID of the authenticator.
    pub aaguid: [u8; 16],
    /// The ID of the credential.
    pub id: Vec<u8>,
    /// The public key of the credential.
    pub public_key: coset::CoseKey,
}

#[cfg(feature = "serde")]
impl TryFrom<&[u8]> for CredentialData {
    // TODO: Custom error type?
    type Error = coset::CoseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // aaguid: 16 Bytes
        // SAFETY: Validate that data.len >= 16 for aaguid bytes
        if data.len() < 16 {
            return Err(coset::CoseError::DecodeFailed(ciborium::de::Error::Io(
                coset::EndOfFile,
            )));
        }
        let (&aaguid, data) = data.split_array_ref::<16>();

        // credentialIdLengh: 2 Bytes
        // > Byte length L of credentialId, 16-bit unsigned big-endian integer. Value
        // > MUST be ≤ 1023.
        // SAFETY: Validate that there are 2 bytes for u16
        if data.len() < 2 {
            return Err(coset::CoseError::DecodeFailed(ciborium::de::Error::Io(
                coset::EndOfFile,
            )));
        }
        let (&credential_id_length, mut data) = data.split_array_ref::<2>();
        let credential_id_length = u16::from_be_bytes(credential_id_length);
        if credential_id_length > 1023 {
            return Err(coset::CoseError::UnexpectedItem(
                "a credentialIdLength (L) of greater than 1023",
                "a 16-bit unsigned big-endian integer less than or equal to 1023",
            ));
        }

        // credentialId: L (credential_id_length) Bytes
        let credential_id: &[u8] = data.take(..credential_id_length as usize)
            .ok_or(coset::CoseError::DecodeFailed(ciborium::de::Error::Io(
                coset::EndOfFile,
            )))?;

        Ok(Self { aaguid, id: credential_id.to_vec(), public_key: Default::default() })
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for CredentialData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
            let data = Vec::<u8>::deserialize(deserializer)?;
            // TODO: Improve error handling
            CredentialData::try_from(data.as_slice()).map_err(serde::de::Error::custom)
    }
}

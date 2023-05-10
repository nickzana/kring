#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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


#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// > Extensions are identified by a string, called an extension identifier,
/// > chosen by the extension author.
/// >
/// > Extension identifiers SHOULD be registered in the IANA "WebAuthn Extension
/// > Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].
/// > All registered extension identifiers are unique amongst themselves as a
/// > matter of course.
/// >
/// > Unregistered extension identifiers SHOULD aim to be globally unique, e.g.,
/// > by including the defining entity such as `myCompany_extension`.
/// >
/// > All extension identifiers MUST be a maximum of 32 octets in length and
/// > MUST consist only of printable USASCII characters, excluding backslash and
/// > doublequote, i.e., VCHAR as defined in [RFC5234] but without %x22 and
/// > %x5c. Implementations MUST match `WebAuthn` extension identifiers in a
/// > case-sensitive fashion.
/// >
/// > Extensions that may exist in multiple versions should take care to include
/// > a version in their identifier. In effect, different versions are thus
/// > treated as different extensions, e.g., `myCompany_extension_01`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Identifier {
    #[cfg_attr(feature = "serde", serde(rename = "appid"))]
    AppId,
    #[cfg_attr(feature = "serde", serde(rename = "txAuthSimple"))]
    TransactionAuthSimple,
    #[cfg_attr(feature = "serde", serde(rename = "txAuthGeneric"))]
    TransactionAuthGeneric,
    #[cfg_attr(feature = "serde", serde(rename = "authnSel"))]
    AuthenticationSelection,
    #[cfg_attr(feature = "serde", serde(rename = "exts"))]
    Extensions,
    #[cfg_attr(feature = "serde", serde(rename = "uvi"))]
    UserVerificationIndex,
    #[cfg_attr(feature = "serde", serde(rename = "loc"))]
    Location,
    #[cfg_attr(feature = "serde", serde(rename = "uvm"))]
    UserVerificationMethod,
    #[cfg_attr(feature = "serde", serde(rename = "credProtect"))]
    CredentialProtection,
    #[cfg_attr(feature = "serde", serde(rename = "credBlob"))]
    CredentialBlob,
    #[cfg_attr(feature = "serde", serde(rename = "largeBlobKey"))]
    LargeBlobKey,
    #[cfg_attr(feature = "serde", serde(rename = "minPinLength"))]
    MinPinLength,
    #[cfg_attr(feature = "serde", serde(rename = "hmac-secret"))]
    HmacSecret,
    #[cfg_attr(feature = "serde", serde(rename = "appidExclude"))]
    AppIdExclude,
    #[cfg_attr(feature = "serde", serde(rename = "credProps"))]
    CredentialProperties,
    #[cfg_attr(feature = "serde", serde(rename = "largeBlob"))]
    LargeBlob,
}

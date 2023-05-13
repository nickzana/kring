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
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Identifier {
    AppId,
    TransactionAuthSimple,
    TransactionAuthGeneric,
    AuthenticationSelection,
    Extensions,
    UserVerificationIndex,
    Location,
    UserVerificationMethod,
    CredentialProtection,
    CredentialBlob,
    LargeBlobKey,
    MinPinLength,
    HmacSecret,
    AppIdExclude,
    CredentialProperties,
    LargeBlob,
}

pub use fido_common::extensions::*;

pub mod cred_protect;

/// The extension input parameters passed to the authenticator during a call to
/// `make_credential` call. Defined by the extension author.
///
/// > An extension defines one or two request arguments. The client extension
/// > input, which is a value that can be encoded in JSON, is passed from the
/// > WebAuthn Relying Party to the client in the get() or create() call, while
/// > the CBOR authenticator extension input is passed from the client to the
/// > authenticator for authenticator extensions during the processing of these
/// > calls.
pub enum AuthenticatorExtensionInput {
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

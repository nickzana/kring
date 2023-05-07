use std::rc::Rc;

use crate::discovery;

#[derive(Clone)]
pub enum Type {
    Federated,
    Identity,
    Otp,
    Password,
    PublicKey,
    Other(Rc<str>),
}

impl AsRef<str> for Type {
    fn as_ref(&self) -> &str {
        match self {
            Type::Federated => "federated",
            Type::Identity => "identity",
            Type::Otp => "otp",
            Type::Password => "password",
            Type::PublicKey => "public-key",
            Type::Other(s) => s,
        }
    }
}

/// > <https://w3c.github.io/webappsec-credential-management/#the-credential-interface/>
pub trait Credential: Sized {
    /// > The credential’s identifier. The requirements for the identifier are
    /// > distinct for each type of credential. It might represent a username
    /// > for username/password tuples, for example.
    // TODO: The specs declare this as a "USVString" (presumably
    // "Unicode-Scalar-Value String"), which is subtly different from a typical
    // Rust str/String (which I believe allows for non-scalar unicode
    // sequences).
    fn id(&self) -> &str;

    /// > ...specifies the credential type represented by this object.
    ///
    /// Conforming types must be able to provide a String representation of
    /// their name to use as an identifier for the credential type.
    fn credential_type() -> Type;

    /// Origin-bound credentials can return the origin for which they are
    /// effective, otherwise returns `None`.
    // TODO: There's probably some structure to origins that can be encapsulated
    // in the return type here
    fn origin(&self) -> Option<&str>;
}

/// > Developers retrieve [`Credential`]s and interact with the user agent’s
/// > credential store via methods exposed on the [`Container`] interface, which
/// > hangs off the Navigator object as `navigator.credentials`.
/// >
/// > <https://w3c.github.io/webappsec-credential-management/#credentialscontainer/>
///
/// [`Container`]s are bound to a particular origin. Calls to associated
/// functions have an implicit restriction to be scoped to the particular origin
/// associated with the [`Container`].
pub trait Container {
    type Credential: Credential;
    type RequestOptions;
    type CreateOptions;

    const DISCOVERY_MODE: discovery::Mode;

    async fn get(&self, options: Option<&Self::RequestOptions>) -> Option<Self::Credential>;
    async fn store(&mut self, credential: Self::Credential)
        -> Result<Self::Credential, StoreError>;
    async fn create(&mut self, options: Option<&Self::CreateOptions>) -> Option<Self::Credential>;
    async fn prevent_silent_access(&mut self);
    async fn discover_from_external_source(
        origin: &str,
        options: &Self::RequestOptions,
        same_origin_with_ancestors: bool,
    ) -> Result<std::collections::BTreeSet<Self::Credential>, discovery::Error>;
}

// TODO: More types of errors here
pub enum StoreError {
    NotAllowed,
}

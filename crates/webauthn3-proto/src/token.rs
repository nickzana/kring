pub enum BindingStatus {
    /// > Indicates token binding was used when communicating with the
    /// > Relying
    /// > Party. In this case, the `TokenBinding::id` member MUST be
    /// > present.
    Present,
    /// > Indicates the client supports token binding, but it was not
    /// > negotiated
    /// > when communicating with the Relying Party.
    Supported,
}

pub struct Binding {
    /// > ...a base64url encoding of the Token Binding ID that was used when
    /// > communicating with the Relying Party.
    pub id: String,
    /// Indicates the usage and support status of token binding by the
    /// client.
    pub status: BindingStatus,
}

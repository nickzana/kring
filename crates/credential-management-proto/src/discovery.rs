#[derive(Clone, Copy)]
pub enum Mode {
    CredentialStore,
    Remote,
}

// TODO: Error types are not obviously specified in spec
pub enum Error {}

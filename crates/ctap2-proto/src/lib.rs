use authenticator::{
    assertion::get,
    bio_enrollment, client_pin, config,
    credential::{make, management},
    reset,
};

pub mod attestation;
pub mod authenticator;
pub mod extensions;

/// Defines the raw CTAP operations
pub trait Ctap2_2Authenticator {
    #[allow(clippy::missing_errors_doc)]
    /// > This method is invoked by the host to request generation of a new
    /// > credential in the authenticator.
    fn make_credential(request: make::Request) -> Result<make::Response, make::Error>;

    #[allow(clippy::missing_errors_doc)]
    /// > This method is used by a host to request cryptographic proof of user
    /// > authentication as well as user consent to a given transaction, using a
    /// > previously generated credential that is bound to the authenticator and
    /// > relying party identifier.
    fn get_assertion(request: get::Request) -> Result<get::Response, get::Error>;

    /// > Using this method, platforms can request that the authenticator report
    /// > a list of its supported protocol versions and extensions, its AAGUID,
    /// > and other aspects of its overall capabilities. Platforms should use
    /// > this information to tailor their command parameters choices.
    fn get_info() -> authenticator::device::Info;

    #[allow(clippy::missing_errors_doc)]
    /// > This command exists so that plaintext PINs are not sent to the
    /// > authenticator. Instead, a PIN/UV auth protocol (aka
    /// > `pinUvAuthProtocol`) ensures that PINs are encrypted when sent to an
    /// > authenticator and are exchanged for a `pinUvAuthToken` that serves to
    /// > authenticate subsequent commands.
    fn client_pin(request: client_pin::Request) -> Result<client_pin::Response, client_pin::Error>;

    #[allow(clippy::missing_errors_doc)]
    /// > This method is used by the client to reset an authenticator back to a
    /// > factory default state.
    fn reset() -> Result<(), reset::Error>;

    fn bio_enrollment(request: bio_enrollment::Request, response: bio_enrollment::Response);

    #[allow(clippy::missing_errors_doc)]
    /// > This command is used by the platform to manage discoverable
    /// > credentials on the authenticator.
    fn credential_management(
        request: management::Request,
    ) -> Result<management::Response, management::Error>;

    #[allow(clippy::missing_errors_doc)]
    /// > This command allows the platform to let a user select a certain
    /// > authenticator by asking for user presence.
    fn selection() -> Result<(), authenticator::selection::Error>;

    fn large_blobs() -> Result<(), ()>;

    #[allow(clippy::missing_errors_doc)]
    /// > This command is used to configure various authenticator features
    /// > through the use of its subcommands.
    fn authenticator_config(request: config::Request) -> Result<(), config::Error>;
}

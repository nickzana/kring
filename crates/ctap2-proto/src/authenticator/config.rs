use std::collections::{BTreeMap};

use super::client_pin::AuthProtocolVersion;

#[derive(Clone, Copy)]
pub enum Request<'a> {
    /// > This `enableEnterpriseAttestation` subcommand is only implemented if
    /// > the enterprise attestation feature is supported.
    EnableEnterpriseAttestation {
        pin_uv_auth_protocol: AuthProtocolVersion,
        pin_uv_auth_param: &'a [u8], // TODO: Is using a more specific type possible?
    },
    /// > This `toggleAlwaysUv` subcommand is only implemented if the Always
    /// > Require User Verification feature is supported.
    ToggleAlwaysUserVerification {
        pin_uv_auth_protocol: AuthProtocolVersion,
        pin_uv_auth_param: &'a [u8], // TODO: Is using a more specific type possible?
    },
    /// > This `setMinPINLength` subcommand is only implemented if the
    /// > `setMinPINLength` option ID is present.
    /// >
    /// > This command sets the minimum PIN length in Unicode code points to be
    /// > enforced by the authenticator while changing/setting up a ClientPIN.
    SetMinPinLength {
        pin_uv_auth_protocol: AuthProtocolVersion,
        pin_uv_auth_param: &'a [u8], // TODO: Is using a more specific type possible?
    },
    /// > This subCommand allows vendors to test authenticator configuration
    /// > features.
    /// >
    /// > This `vendorPrototype` subcommand is only implemented if the
    /// > `vendorPrototypeConfigCommands` member in the `authenticatorGetInfo`
    /// > response is present.
    /// >
    /// > Note: The `vendorPrototype` subCommand is reserved for vendor-specific
    /// > authenticator configuration and experimentation. Platforms are not
    /// > expected to generally utilize this subCommand.
    VendorPrototype {
        vendor_command_id: usize,
        params: &'a BTreeMap<Vec<u8>, Vec<u8>>, /* TODO: Is the character space of keys
                                                * restricted to UTF-8? */
        pin_uv_auth_protocol: AuthProtocolVersion,
        pin_uv_auth_param: &'a [u8], // TODO: Is using a more specific type possible?
    },
}

pub enum Error {
    MissingParameter,
    InvalidParameter,
    PinUvAuthTokenRequired,
    PinAuthInvalid,
}

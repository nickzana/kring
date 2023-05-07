pub mod attestation;
pub mod credential;
pub mod extension;
pub mod registry;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// > Authenticators may implement various transports for communicating with
/// > clients. This enumeration defines hints as to how clients might
/// > communicate with a particular authenticator in order to obtain an
/// > assertion for a specific credential. Note that these hints represent the
/// > `WebAuthn` Relying Party's best belief as to how an authenticator may be
/// > reached. A Relying Party will typically learn of the supported transports
/// > for a public key credential via getTransports().
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum Transport {
    /// > Indicates the respective authenticator can be contacted over removable
    /// > USB.
    #[cfg_attr(feature = "serde", serde(rename = "usb"))]
    Usb,
    /// > Indicates the respective authenticator can be contacted over Near
    /// > Field Communication (NFC).
    #[cfg_attr(feature = "serde", serde(rename = "nfc"))]
    Nfc,
    /// > Indicates the respective authenticator can be contacted over Bluetooth
    /// > Smart (Bluetooth Low Energy / BLE).
    #[cfg_attr(feature = "serde", serde(rename = "ble"))]
    Ble,
    /// > Indicates the respective authenticator can be contacted using a
    /// > combination of (often separate) data-transport and proximity
    /// > mechanisms. This supports, for example, authentication on a desktop
    /// > computer using a smartphone.
    #[cfg_attr(feature = "serde", serde(rename = "hybrid"))]
    Hybrid,
    /// > Indicates the respective authenticator is contacted using a client
    /// > device-specific transport, i.e., it is a platform authenticator. These
    /// > authenticators are not removable from the client device.
    #[cfg_attr(feature = "serde", serde(rename = "internal"))]
    Internal,
    Unknown(String),
}

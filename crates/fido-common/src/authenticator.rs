use crate::{
    attestation,
    credential::{BackupEligibility, BackupState},
    extensions, Sha256Hash,
};
use std::collections::BTreeMap;

pub enum Flags {}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserPresence {
    Present,
    NotPresent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserVerification {
    Verified,
    NotVerified,
}

/// > The authenticator data structure encodes contextual bindings made by the
/// > authenticator. These bindings are controlled by the authenticator itself,
/// > and derive their trust from the `WebAuthn` Relying Party's assessment of
/// > the security properties of the authenticator. In one extreme case, the
/// > authenticator may be embedded in the client, and its bindings may be no
/// > more trustworthy than the client data. At the other extreme, the
/// > authenticator may be a discrete entity with high-security hardware and
/// > software, connected to the client over a secure channel. In both cases,
/// > the Relying Party receives the authenticator data in the same format, and
/// > uses its knowledge of the authenticator to make trust decisions.
pub struct Data {
    /// > SHA-256 hash of the RP ID the credential is scoped to.
    pub relying_party_id_hash: Sha256Hash,
    pub user_presence: UserPresence,
    pub user_verification: UserVerification,
    pub backup_eligibility: BackupEligibility,
    pub backup_state: BackupState,
    pub signature_counter: u32,
    pub attested_credential_data: Option<attestation::CredentialData>,
    pub extensions: Option<BTreeMap<extensions::Identifier, Vec<u8>>>,
}

impl Data {
    fn try_from(value: &[u8]) -> Option<Self> {
        // 32 bytes: RP id hash
        let rp_id = value.get(0..32)?.as_ref();
        //
        let flags = value.get(32)?;

        None
    }
}

impl TryFrom<&[u8]> for Data {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(value).ok_or(())
    }
}

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

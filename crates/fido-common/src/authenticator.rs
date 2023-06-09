use crate::{
    attestation,
    credential::{BackupEligibility, BackupState},
    extensions, Sha256Hash,
};
use std::collections::BTreeMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use bitflags::bitflags;

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
#[derive(Debug)]
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

#[cfg(feature = "serde")]
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    // > Flags (bit 0 is the least significant bit):
    struct DataFlags: u8 {
        // > Bit 0: User Present (UP) result.
        // >    1 means the user is present.
        const USER_PRESENCE = 0b1 << 0;
        // > Bit 2: User Verified (UV) result.
        // >    1 means the user is verified.
        const USER_VERIFIED = 0b1 << 2;
        // > Bit 3: Backup Eligibility (BE).
        // >    1 means the public key credential source is backup eligible.
        const BACKUP_ELIGIBLE = 0b1 << 3;
        // > Bit 4: Backup State (BS).
        // >    1 means the public key credential source is currently backed up.
        const BACKUP_STATE = 0b1 << 4;
        // > Bit 6: Attested credential data included (AT).
        // >    Indicates whether the authenticator added attested credential data.
        const ATTESTED_CREDENTIAL_DATA = 0b1 << 6;
        // > Bit 7: Extension data included (ED).
        // >    Indicates if the authenticator data has extensions.
        const EXTENSION_DATA_INCLUDED = 0b1 << 7;
    }
}

#[cfg(feature = "serde")]
impl DataFlags {
    fn user_presence(&self) -> UserPresence {
        if self.contains(DataFlags::USER_PRESENCE) {
            UserPresence::Present
        } else {
            UserPresence::NotPresent
        }
    }

    fn user_verification(&self) -> UserVerification {
        if self.contains(DataFlags::USER_VERIFIED) {
            UserVerification::Verified
        } else {
            UserVerification::NotVerified
        }
    }

    fn backup_eligibility(&self) -> BackupEligibility {
        if self.contains(DataFlags::BACKUP_ELIGIBLE) {
            BackupEligibility::Eligible
        } else {
            BackupEligibility::Ineligible
        }
    }

    fn backup_state(&self) -> BackupState {
        if self.contains(DataFlags::BACKUP_STATE) {
            BackupState::BackedUp
        } else {
            BackupState::NotBackedUp
        }
    }

    fn has_attested_credential_data(&self) -> bool {
        self.contains(DataFlags::ATTESTED_CREDENTIAL_DATA)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Data {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        let data = Vec::<u8>::deserialize(deserializer)?;

        // The authenticator data structure is a byte array of 37 bytes or more
        if data.len() < 37 {
            return Err(de::Error::invalid_length(data.len(), &"at least 37 bytes"));
        }

        // SAFETY: split_array_ref panics if const param is out of bounds for slice.
        // data.len() guard protects against out of bounds indicies.

        // rpIdHash: 32 Bytes
        // > SHA-256 hash of the RP ID the credential is scoped to.
        let (&relying_party_id_hash, data): (&Sha256Hash, _) = data.split_array_ref::<32>();

        // flags: 1 Byte
        let (&[flags], data): (&[u8; 1], _) = data.split_array_ref::<1>();
        let flags = DataFlags::from_bits_truncate(flags);

        // signCount: 4 Bytes
        // > Signature counter, 32-bit unsigned big-endian integer.
        let (&counter_be_bytes, data) = data.split_array_ref::<4>();
        let signature_counter = u32::from_be_bytes(counter_be_bytes);

        let attested_credential_data: Option<attestation::CredentialData> =
            if flags.has_attested_credential_data() {
                Some(attestation::CredentialData::try_from(data).map_err(de::Error::custom)?)
            } else {
                None
            };

        Ok(Self {
            relying_party_id_hash,
            user_presence: flags.user_presence(),
            user_verification: flags.user_verification(),
            backup_eligibility: flags.backup_eligibility(),
            backup_state: flags.backup_state(),
            signature_counter,
            attested_credential_data,
            extensions: None,
        })
    }
}

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
    // TODO: Serialize as contents of string
    Unknown(String), 
}

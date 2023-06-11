#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub trait Authenticator {
    type Error; // TODO: Can the error cases be enumerated here?

    /// This process is run by the authenticator at power-on.
    fn initialize(&mut self) -> Result<(), Self::Error>;

    /// Generates a fresh public key.
    fn regenerate(&mut self) -> Result<(), Self::Error>;

    /// Generates a fresh pinUvAuthToken.
    fn reset_pin_uv_auth_token(&mut self) -> Result<(), Self::Error>;

    /// Returns the authenticator’s public key as a COSE_Key structure.
    fn get_public_key(&self) -> Result<cosey::PublicKey, Self::Error>;

    /// Processes the output of encapsulate from the peer and produces a shared
    /// secret, known to both platform and authenticator.
    fn decapsulate(&self, peer_cose_key: cosey::PublicKey) -> Result<Vec<u8>, Self::Error>;

    /// Decrypts a ciphertext, using sharedSecret as a key, and returns the
    /// plaintext.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Verifies that the signature is a valid MAC for the given message. If the
    /// key parameter value is the current pinUvAuthToken, it also checks
    /// whether the pinUvAuthToken is in use or not.
    fn verify(&self, key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Self::Error>;
}

pub trait Platform {
    type Error; // TODO: Can the error cases be enumerated here?
    /// This is run by the platform when starting a series of transactions
    /// with a specific authenticator.
    fn initialize(&self) -> Result<(), Self::Error>;

    /// Generates an encapsulation for the authenticator’s public key and
    /// returns the message to transmit and the shared secret.
    fn encapsulate(
        &self,
        peer_cose_key: cosey::PublicKey,
    ) -> Result<(cosey::PublicKey, Vec<u8>), Self::Error>; // TODO: Return a struct for OK variant?

    /// Encrypts a plaintext to produce a ciphertext, which may be longer
    /// than the plaintext. The plaintext is restricted to being a
    /// multiple of the AES block size (16 bytes) in length.
    // TODO: Return a specific type instead of raw bytes?
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Decrypts a ciphertext and returns the plaintext.
    // TODO: Return a specific type instead of raw bytes?
    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Computes a MAC of the given message.
    // TODO: Return a specific type instead of raw bytes?
    fn authenticate(&self, key: &[u8], message: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(into = "u8", try_from = "u8")
)]
pub enum Version {
    One = 1,
    Two = 2,
}

impl From<Version> for u8 {
    fn from(value: Version) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for Version {
    type Error = super::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Version::One),
            2 => Ok(Version::Two),
            _ => Err(super::Error::InvalidParameter),
        }
    }
}

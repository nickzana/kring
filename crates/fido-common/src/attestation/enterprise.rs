#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[repr(usize)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Kind {
    /// > In this case, an enterprise attestation capable authenticator, on
    /// > which enterprise attestation is enabled, upon receiving the
    /// > enterpriseAttestation parameter with a value of 1 (or 2, see Note
    /// > below) on a authenticatorMakeCredential command, will provide
    /// > enterprise attestation to a non-updateable pre-configured RP ID
    /// > list, as identified by the enterprise and provided to the
    /// > authenticator vendor, which is "burned into" the authenticator by
    /// > the vendor.
    /// > If enterprise attestation is requested for any RP ID other than
    /// > the pre-configured RP ID(s), the attestation returned along with
    /// > the new credential is a regular privacy-preserving attestation,
    /// > i.e., NOT an enterprise attestation.
    VendorFacilitated = 1,
    /// > In this case, an enterprise attestation capable authenticator on
    /// > which enterprise attestation is enabled, upon receiving the
    /// > enterpriseAttestation parameter with a value of 2 on a
    /// > authenticatorMakeCredential command, will return an enterprise
    /// > attestation. The platform is enterprise-managed and has already
    /// > performed the necessary vetting of the RP ID.
    PlatformManaged = 2,
}

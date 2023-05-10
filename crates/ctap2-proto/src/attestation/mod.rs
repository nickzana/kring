pub mod enterprise {
    #[repr(usize)]
    #[derive(Clone, Copy)]
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
}

/// > Attested credential data is a variable-length byte array added to the
/// > authenticator data when generating an attestation object for a given
/// > credential.
pub struct CredentialData {
    /// > The AAGUID of the authenticator.
    pub aaguid: [u8; 16],
    /// The ID of the credential.
    pub id: Vec<u8>,
    /// The public key of the credential.
    pub public_key: coset::CoseKey,
}

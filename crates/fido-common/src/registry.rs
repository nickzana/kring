#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// > The [`UserVerify`] constants are flags in a bitfield represented as a 32
/// > bit long integer. They describe the methods and capabilities of a FIDO
/// > authenticator for locally verifying a user. The operational details of
/// > these methods are opaque to the server. These constants are used in the
/// > authoritative metadata for FIDO authenticators, reported and queried
/// > through the UAF Discovery APIs, and used to form authenticator policies in
/// > UAF protocol messages. Each constant has a case-sensitive string
/// > representation (in quotes), which is used in the authoritative metadata
/// > for FIDO authenticators.
#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum UserVerify {
    /// > This flag MUST be set if the authenticator is able to confirm user
    /// > presence in any fashion. If this flag and no other is set for user
    /// > verification, the guarantee is only that the authenticator cannot be
    /// > operated without some human intervention, not necessarily that the
    /// > sensing of "presence" provides any level of user verification (e.g. a
    /// > device that requires a button press to activate).
    #[cfg_attr(feature = "serde", serde(rename = "presence_internal"))]
    PresenceInternal = 0x0000_0001,

    /// > This flag MUST be set if the authenticator uses any type of
    /// > measurement of a fingerprint for user verification.
    #[cfg_attr(feature = "serde", serde(rename = "fingerprint_internal"))]
    FingerprintInternal = 0x0000_0002,

    /// > This flag MUST be set if the authenticator uses a local-only passcode
    /// > (i.e. a passcode not known by the server) for user verification.
    #[cfg_attr(feature = "serde", serde(rename = "passcode_internal"))]
    PasscodeInternal = 0x0000_0004,

    /// > This flag MUST be set if the authenticator uses a local-only passcode
    /// > (i.e. a passcode not known by the server) for user verification.
    #[cfg_attr(feature = "serde", serde(rename = "voiceprint_internal"))]
    VoiceprintInternal = 0x0000_0008,

    /// > This flag MUST be set if the authenticator uses any manner of face
    /// > recognition to verify the user.
    #[cfg_attr(feature = "serde", serde(rename = "faceprint_internal"))]
    FaceprintInternal = 0x0000_0010,

    /// > This flag MUST be set if the authenticator uses any form of location
    /// > sensor or measurement for user verification.
    #[cfg_attr(feature = "serde", serde(rename = "location_internal"))]
    LocationInternal = 0x0000_0020,

    /// > This flag MUST be set if the authenticator uses any form of eye
    /// > biometrics for user verification.
    #[cfg_attr(feature = "serde", serde(rename = "eyeprint_internal"))]
    EyeprintInternal = 0x0000_0040,

    /// > This flag MUST be set if the authenticator uses a drawn pattern for
    /// > user verification.
    #[cfg_attr(feature = "serde", serde(rename = "pattern_internal"))]
    PatternInternal = 0x0000_0080,

    /// > This flag MUST be set if the authenticator uses any measurement of a
    /// > full hand (including palm-print, hand geometry or vein geometry) for
    /// > user verification.
    #[cfg_attr(feature = "serde", serde(rename = "handprint_internal"))]
    HandprintInternal = 0x0000_0100,

    /// > This flag MUST be set if the authenticator uses a local-only passcode
    /// > (i.e. a passcode not known by the server) for user verification that
    /// > might be gathered outside the authenticator boundary.
    #[cfg_attr(feature = "serde", serde(rename = "passcode_external"))]
    PasscodeExternal = 0x0000_0800,

    /// > This flag MUST be set if the authenticator uses a drawn pattern for
    /// > user verification that might be gathered outside the authenticator
    /// > boundary.
    #[cfg_attr(feature = "serde", serde(rename = "pattern_external"))]
    PatternExternal = 0x0000_1000,

    /// > This flag MUST be set if the authenticator will respond without any
    /// > user interaction (e.g. Silent Authenticator).
    #[cfg_attr(feature = "serde", serde(rename = "none"))]
    None = 0x0000_0200,

    /// > If an authenticator sets multiple flags for the "_INTERNAL" and/or
    /// > "_EXTERNAL" user verification types, it MAY also set this flag to
    /// > indicate that all verification methods with respective flags set will
    /// > be enforced (e.g. faceprint AND voiceprint). If flags for multiple
    /// > user verification methods are set and this flag is not set,
    /// > verification with only one is necessary (e.g. fingerprint OR
    /// > passcode).
    #[cfg_attr(feature = "serde", serde(rename = "all"))]
    All = 0x0000_0400,
}

/// > The [`KeyProtection`] constants are flags in a bit field represented as a
/// > 16 bit long integer. They describe the method an authenticator uses to
/// > protect the private key material for FIDO registrations. Refer to
/// > [UAFAuthnrCommands] for more details on the relevance of keys and key
/// > protection. These constants are reported and queried through the UAF
/// > Discovery APIs and used to form authenticator policies in UAF protocol
/// > messages. Each constant has a case-sensitive string representation (in
/// > quotes), which is used in the authoritative metadata for FIDO
/// > authenticators.
/// >
/// > When used in metadata describing an authenticator, several of these flags
/// > are exclusive of others (i.e. can not be combined) - the certified
/// > metadata may have at most one of the mutually exclusive string constant
/// > values. When used in authenticator policy, any bit may be set to 1, e.g.
/// > to indicate that a server is willing to accept authenticators using either
/// > [`KeyProtection::Software`] or [`KeyProtection::Hardware`].
/// >
/// > > ## NOTE
/// > > These flags must be set according to the effective security of the keys,
/// > > in order to follow the assumptions made in [FIDOSecRef]. For example, if
/// > > a key is stored in a secure element but software running on the FIDO
/// > > User Device could call a function in the secure element to export the
/// > > key either in the clear or using an arbitrary wrapping key, then the
/// > > effective security is [`KeyProtection::Software`] and not
/// > > [`KeyProtection::SecureElement`].
#[repr(u16)]
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum KeyProtection {
    /// > This flag MUST be set if the authenticator uses software-based key
    /// > management. Exclusive in authenticator metadata with
    /// > [`KeyProtection::Hardware`], [`KeyProtection::Tee`],
    /// > [`KeyProtection::SecureElement`]
    #[cfg_attr(feature = "serde", serde(rename = "software"))]
    Software = 0x0001,

    /// > This flag SHOULD be set if the authenticator uses hardware-based key
    /// > management. Exclusive in authenticator metadata with
    /// > [`KeyProtection::Software`]
    #[cfg_attr(feature = "serde", serde(rename = "hardware"))]
    Hardware = 0x0002,

    /// > This flag SHOULD be set if the authenticator uses the Trusted
    /// > Execution Environment (TEE) for key management. In authenticator
    /// > metadata, this flag should be set in conjunction with
    /// > [`KeyProtection::Hardware`]. Mutually exclusive in authenticator
    /// > metadata with [`KeyProtection::Software`],
    /// > [`KeyProtection::SecureElement`]
    #[cfg_attr(feature = "serde", serde(rename = "tee"))]
    Tee = 0x0004,

    /// > This flag SHOULD be set if the authenticator uses a Secure Element
    /// > for key management. In authenticator metadata, this
    /// > flag should be set in conjunction with [`KeyProtection::Hardware`].
    /// > Mutually exclusive in authenticator metadata with
    /// > [`KeyProtection::Tee`],[`KeyProtection::Software`]
    #[cfg_attr(feature = "serde", serde(rename = "secure_element"))]
    SecureElement = 0x0008,

    /// > This flag MUST be set if the authenticator does not store (wrapped)
    /// > UAuth keys at the client, but relies on a server-provided key handle.
    /// > This flag MUST be set in conjunction with one of the other
    /// > [`KeyProtection`] flags to indicate how the local key handle wrapping
    /// > key and operations are protected. Servers MAY unset this flag in
    /// > authenticator policy if they are not prepared to store and return key
    /// > handles, for example, if they have a requirement to respond
    /// > indistinguishably to authentication attempts against userIDs that do
    /// > and do not exist. Refer to [UAFProtocol] for more details.
    #[cfg_attr(feature = "serde", serde(rename = "remote_handle"))]
    RemoteHandle = 0x0010,
}

/// > The [`MatcherProtection`] constants are flags in a bit field represented
/// > as a 16 bit long integer. They describe the method an authenticator uses
/// > to protect the matcher that performs user verification. These constants
/// > are reported and queried through the UAF Discovery APIs and used to form
/// > authenticator policies in UAF protocol messages. Refer to
/// > [UAFAuthnrCommands] for more details on the matcher component. Each
/// > constant has a case-sensitive string representation (in quotes), which is
/// > used in the authoritative metadata for FIDO authenticators.
/// >
/// > > ## NOTE
/// > > These flags must be set according to the effective security of the
/// > > matcher, in order to follow the assumptions made in [FIDOSecRef]. For
/// > > example, if a passcode based matcher is implemented in a secure element,
/// > > but the passcode is expected to be provided as unauthenticated
/// > > parameter, then the effective security is
/// > > [`MatcherProtection::Software`] and not [`MatcherProtection::OnChip`].
#[repr(u16)]
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum MatcherProtection {
    /// > This flag MUST be set if the authenticator's matcher is running in
    /// > software. Exclusive in authenticator metadata with
    /// > [`MatcherProtection::Tee`], [`MatcherProtection::OnChip`]
    #[cfg_attr(feature = "serde", serde(rename = "software"))]
    Software = 0x0001,
    /// > This flag SHOULD be set if the authenticator's matcher is running
    /// > inside the Trusted Execution Environment (TEE). Mutually exclusive in
    /// > authenticator metadata with [`MatcherProtection::Software`],
    /// > [`MatcherProtection::OnChip`]
    #[cfg_attr(feature = "serde", serde(rename = "tee"))]
    Tee = 0x0002,
    /// > This flag SHOULD be set if the authenticator's matcher is running on
    /// > the chip. Mutually exclusive in authenticator metadata with
    /// > [`MatcherProtection::Tee`], [`MatcherProtection::Software`]
    #[cfg_attr(feature = "serde", serde(rename = "on_chip"))]
    OnChip = 0x0004,
}

/// > The [`AttachmentHint`] constants are flags in a bit field represented as a
/// > 32 bit long. They describe the method FIDO authenticators use to
/// > communicate with the FIDO User Device. These constants are reported and
/// > queried through the UAF Discovery APIs [UAFAppAPIAndTransport], and used
/// > to form Authenticator policies in UAF protocol messages. Because the
/// > connection state and topology of an authenticator may be transient, these
/// > values are only hints that can be used by server-supplied policy to guide
/// > the user experience, e.g. to prefer a device that is connected and ready
/// > for authenticating or confirming a low-value transaction, rather than one
/// > that is more secure but requires more user effort. Each constant has a
/// > case-sensitive string representation (in quotes), which is used in the
/// > authoritative metadata for FIDO authenticators.
/// >
/// > > ## NOTE
/// > > These flags are not a mandatory part of authenticator metadata and, when
/// > > present, only indicate possible states that may be reported during
/// > > authenticator discovery.
#[repr(u32)]
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum AttachmentHint {
    /// > This flag MAY be set to indicate that the authenticator is permanently
    /// > attached to the FIDO User Device.
    /// >
    /// > A device such as a smartphone may have authenticator functionality
    /// > that is able to be used both locally and remotely. In such a case, the
    /// > FIDO client MUST filter and exclusively report only the relevant bit
    /// > during Discovery and when performing policy matching.
    /// >
    /// > This flag cannot be combined with any other ATTACHMENT_HINT flags.
    #[cfg_attr(feature = "serde", serde(rename = "internal"))]
    Internal = 0x0001,

    /// > This flag MAY be set to indicate, for a hardware-based authenticator,
    /// > that it is removable or remote from the FIDO User Device.
    /// >
    /// > A device such as a smartphone may have authenticator functionality
    /// > that is able to be used both locally and remotely. In such a case, the
    /// > FIDO UAF Client MUST filter and exclusively report only the relevant
    /// > bit during discovery and when performing policy matching. This flag
    /// > MUST be combined with one or more other [`AttachmentHint`] flag(s).
    #[cfg_attr(feature = "serde", serde(rename = "external"))]
    External = 0x0002,

    /// > This flag MAY be set to indicate that an external authenticator
    /// > currently has an exclusive wired connection, e.g. through USB,
    /// > Firewire or similar, to the FIDO User Device.
    #[cfg_attr(feature = "serde", serde(rename = "wired"))]
    Wired = 0x0004,

    /// > This flag MAY be set to indicate that an external authenticator
    /// > communicates with the FIDO User Device through a personal area or
    /// > otherwise non-routed wireless protocol, such as Bluetooth or NFC.
    #[cfg_attr(feature = "serde", serde(rename = "wireless"))]
    Wireless = 0x0008,

    /// > This flag MAY be set to indicate that an external authenticator is
    /// > able to communicate by NFC to the FIDO User Device. As part of
    /// > authenticator metadata, or when reporting characteristics through
    /// > discovery, if this flag is set, the [`AttachmentHint::Wireless`] flag
    /// > SHOULD also be set as well.
    #[cfg_attr(feature = "serde", serde(rename = "nfc"))]
    Nfc = 0x0010,

    /// > This flag MAY be set to indicate that an external authenticator is
    /// > able to communicate using Bluetooth with the FIDO User Device. As part
    /// > of authenticator metadata, or when reporting characteristics through
    /// > discovery, if this flag is set, the [`AttachmentHint::Wireless`] flag
    /// > SHOULD also be set.
    #[cfg_attr(feature = "serde", serde(rename = "bluetooth"))]
    Bluetooth = 0x0020,

    /// > This flag MAY be set to indicate that the authenticator is connected
    /// > to the FIDO User Device over a non-exclusive network (e.g. over a
    /// > TCP/IP LAN or WAN, as opposed to a PAN or point-to-point connection).
    #[cfg_attr(feature = "serde", serde(rename = "network"))]
    Network = 0x0040,

    /// > This flag MAY be set to indicate that an external authenticator is in
    /// > a "ready" state. This flag is set by the ASM at its discretion.
    /// >
    /// > > ## NOTE
    /// > > Generally this should indicate that the device is immediately
    /// > > available to perform user verification without additional actions
    /// > > such as connecting the device or creating a new biometric profile
    /// > > enrollment, but the exact meaning may vary for different types of
    /// > > devices. For example, a USB authenticator may only report itself as
    /// > > ready when it is plugged in, or a Bluetooth authenticator when it is
    /// > > paired and connected, but an NFC-based authenticator may always
    /// > > report itself as ready.
    #[cfg_attr(feature = "serde", serde(rename = "ready"))]
    Ready = 0x0080,

    /// > This flag MAY be set to indicate that an external authenticator is
    /// > able to communicate using WiFi Direct with the FIDO User Device. As
    /// > part of authenticator metadata and when reporting characteristics
    /// > through discovery, if this flag is set, the
    /// > [`AttachmentHint::Wireless`] flag SHOULD also be set.
    #[cfg_attr(feature = "serde", serde(rename = "wifi_direct"))]
    WifiDirect = 0x0100,
}

/// > The [`TransactionConfirmationDisplay`] constants are flags in a bit field
/// > represented as a 16 bit long integer. They describe the availability and
/// > implementation of a transaction confirmation display capability required
/// > for the transaction confirmation operation. These constants are reported
/// > and queried through the UAF Discovery APIs and used to form authenticator
/// > policies in UAF protocol messages. Each constant has a case-sensitive
/// > string representation (in quotes), which is used in the authoritative
/// > metadata for FIDO authenticators. Refer to [UAFAuthnrCommands] for more
/// > details on the security aspects of TransactionConfirmation Display.
#[repr(u16)]
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum TransactionConfirmationDisplay {
    /// > This flag MUST be set to indicate that a transaction confirmation
    /// > display, of any type, is available on this authenticator. Other
    /// > [`TransactionConfirmationDisplay`] flags MAY also be set if this flag
    /// > is set. If the authenticator does not support a transaction
    /// > confirmation display, then the value of
    /// > [`TransactionConfirmationDisplay`] MUST be set to 0.
    #[cfg_attr(feature = "serde", serde(rename = "any"))]
    Any = 0x0001,

    /// > This flag MUST be set to indicate, that a software-based transaction
    /// > confirmation display operating in a privileged context is available on
    /// > this authenticator.
    /// >
    /// > A FIDO client that is capable of providing this capability MAY set
    /// > this bit (in conjunction with [`TransactionDisplayConfirm::Any`]) for
    /// > all authenticators of type [`AttachmentHint::Internal`], even if the
    /// > authoritative metadata for the authenticator does not indicate this
    /// > capability.
    /// >
    /// > > ## NOTE
    /// > > Software based transaction confirmation displays might be
    /// > > implemented within the boundaries of the ASM rather than by the
    /// > > authenticator itself [UAFASM].
    /// >
    /// > This flag is mutually exclusive with
    /// > [`TransactionConfirmationDisplay::Tee`] and
    /// > [`TransactionConfirmationDisplay::Hardware`].
    #[cfg_attr(feature = "serde", serde(rename = "privileged_software"))]
    PrivilegedSoftware = 0x0002,

    /// > This flag SHOULD be set to indicate that the authenticator implements
    /// > a transaction confirmation display in a Trusted Execution Environment
    /// > ([TEE], [TEESecureDisplay]). This flag is mutually exclusive with
    /// > [`TransactionConfirmationDisplay::PrivilegedSoftware`] and
    /// > [`TransactionConfirmationDisplay::Hardware`].
    #[cfg_attr(feature = "serde", serde(rename = "tee"))]
    Tee = 0x0004,

    /// > This flag SHOULD be set to indicate that a transaction confirmation
    /// > display based on hardware assisted capabilities is available on this
    /// > authenticator. This flag is mutually exclusive with
    /// > [`TransactionConfirmationDisplay::PrivilegedSoftware`] and
    /// > [`TransactionConfirmationDisplay::Tee`].
    #[cfg_attr(feature = "serde", serde(rename = "hardware"))]
    Hardware = 0x0008,

    /// > This flag SHOULD be set to indicate that the transaction confirmation
    /// > display is provided on a distinct device from the FIDO User Device.
    /// > This flag can be combined with any other flag.
    #[cfg_attr(feature = "serde", serde(rename = "remote"))]
    Remote = 0x0010,
}

pub mod algorithms {
    //! > These tags indicate the specific authentication algorithms, public key
    //! > formats and other crypto relevant data.

    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};

    /// > The [`Signature`] constants are 16 bit long integers indicating the
    /// > specific signature algorithm and encoding.
    /// >
    /// > Each constant has a case-sensitive string representation (in quotes),
    /// > which is used in the authoritative metadata for FIDO authenticators.
    #[repr(u16)]
    #[derive(Debug)]
    #[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
    pub enum Signature {
        #[cfg_attr(feature = "serde", serde(rename = "secp256r1_ecdsa_sha256_raw"))]
        Secp256r1EcdsaSha256Raw = 0x0001,
        #[cfg_attr(feature = "serde", serde(rename = "secp256r1_ecdsa_sha256_der"))]
        Secp256r1EcdsaSha256Der = 0x0002,
        #[cfg_attr(feature = "serde", serde(rename = "rsassa_pss_sha256_raw"))]
        RsaSsaPssSha256Raw = 0x0003,
        #[cfg_attr(feature = "serde", serde(rename = "rsassa_pss_sha256_der"))]
        RsaSsaPssSha256Der = 0x0004,
        #[cfg_attr(feature = "serde", serde(rename = "secp256k1_ecdsa_sha256_raw"))]
        Secp256k1EcdsaSha256Raw = 0x0005,
        #[cfg_attr(feature = "serde", serde(rename = "secp256k1_ecdsa_sha256_der"))]
        Secp256k1EcdsaSha256Der = 0x0006,
        #[cfg_attr(feature = "serde", serde(rename = "sm2_sm3_raw"))]
        Sm2Sm3Raw = 0x0007,
        #[cfg_attr(feature = "serde", serde(rename = "rsa_emsa_pkcs1_sha256_raw"))]
        RsaEmsaPkcs1Sha256Raw = 0x0008,
        #[cfg_attr(feature = "serde", serde(rename = "rsa_emsa_pkcs1_sha256_der"))]
        RsaEmsaPkcs1Sha256Der = 0x0009,
        #[cfg_attr(feature = "serde", serde(rename = "rsassa_pss_sha384_raw"))]
        RsaSsaPsSha384Raw = 0x000A,
        #[cfg_attr(feature = "serde", serde(rename = "rsassa_pss_sha512_raw"))]
        RsaSsaPssSha512Raw = 0x000B,
        #[cfg_attr(feature = "serde", serde(rename = "rsassa_pkcsv15_sha256_raw"))]
        RsaSsaPkcsv15Sha256Raw = 0x000C,
        #[cfg_attr(feature = "serde", serde(rename = "rsassa_pkcsv15_sha384_raw"))]
        RsaSsaPkcsv15Sha384Raw = 0x000D,
        #[cfg_attr(feature = "serde", serde(rename = "rsassa_pkcsv15_sha512_raw"))]
        RsaSsaPkcsv15Sha512Raw = 0x000E,
        #[cfg_attr(feature = "serde", serde(rename = "rsassa_pkcsv15_sha1_raw"))]
        RsaSsaPkcsv15Sha1Raw = 0x000F,
        #[cfg_attr(feature = "serde", serde(rename = "secp384r1_ecdsa_sha384_raw"))]
        Secp384r1EcdsaSha384Raw = 0x0010,
        #[cfg_attr(feature = "serde", serde(rename = "secp521r1_ecdsa_sha512_raw"))]
        Secp521r1EcdsaSha512Raw = 0x0011,
        #[cfg_attr(feature = "serde", serde(rename = "ed25519_eddsa_sha512_raw"))]
        Ed25519EddsaSha512Raw = 0x0012,
        #[cfg_attr(feature = "serde", serde(rename = "ed448_eddsa_sha512_raw"))]
        Ed448EddsaSha512Raw = 0x0013,
    }

    /// > The [`PublicKey`] constants are 16 bit long integers indicating the
    /// > specific Public Key algorithm and encoding.
    #[repr(u16)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub enum PublicKey {
        #[cfg_attr(feature = "serde", serde(rename = "ecc_x962_raw"))]
        EccX962Raw = 0x0100,
        #[cfg_attr(feature = "serde", serde(rename = "ecc_x962_der"))]
        EccX962Der = 0x0101,
        #[cfg_attr(feature = "serde", serde(rename = "rsa_2048_raw"))]
        Rsa2048Raw = 0x0102,
        #[cfg_attr(feature = "serde", serde(rename = "rsa_2048_der"))]
        Rsa2048Der = 0x0103,
        #[cfg_attr(feature = "serde", serde(rename = "cose"))]
        Cose = 0x0104,
    }
}

/// > The [`Attestation`] constants are 16 bit long integers indicating the
/// > specific attestation that authenticator supports.
#[repr(u16)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Attestation {
    /// > Indicates full basic attestation, based on an attestation private key
    /// > shared among a class of authenticators (e.g. same model).
    /// > Authenticators must provide its attestation signature during the
    /// > registration process for the same reason. The attestation trust anchor
    /// > is shared with FIDO Servers out of band (as part of the Metadata).
    /// > This sharing process should be done according to
    /// > [FIDOMetadataService].
    #[cfg_attr(feature = "serde", serde(rename = "basic_full"))]
    BasicFull = 0x3E07,
    /// > Just syntactically a Basic Attestation. The attestation object
    /// > self-signed, i.e. it is signed using the UAuth.priv key, i.e. the key
    /// > corresponding to the UAuth.pub key included in the attestation object.
    /// > As a consequence it does not provide a cryptographic proof of the
    /// > security characteristics. But it is the best thing we can do if the
    /// > authenticator is not able to have an attestation private key.
    #[cfg_attr(feature = "serde", serde(rename = "basic_surrogate"))]
    BasicSurrogate = 0x3E08,
    /// > Indicates use of elliptic curve based direct anonymous attestation as
    /// > defined in [FIDOEcdaaAlgorithm]. Support for this attestation type is
    /// > optional at this time. It might be required by FIDO Certification.
    #[cfg_attr(feature = "serde", serde(rename = "ecdaa"))]
    EllipticCurveDirectAnonymous = 0x3E09,
    /// > Indicates PrivacyCA attestation as defined in
    /// > [TCG-CMCProfile-AIKCertEnroll]. Support for this attestation type is
    /// > optional at this time. It might be required by FIDO Certification.
    #[cfg_attr(feature = "serde", serde(rename = "attca"))]
    PrivacyCA = 0x3E0A,
    /// > In this case, the authenticator uses an Anonymization CA which
    /// > dynamically generates per-credential attestation certificates such
    /// > that the attestation statements presented to Relying Parties do not
    /// > provide uniquely identifiable information, e.g., that might be used
    /// > for tracking purposes. The applicable [WebAuthn] attestation formats
    /// > "fmt" are Google SafetyNet Attestation "android-safetynet", Android
    /// > Keystore Attestation "android-key", Apple Anonymous Attestation
    /// > "apple", and Apple Application Attestation "apple-appattest".
    #[cfg_attr(feature = "serde", serde(rename = "anonca"))]
    AnonymizationCA = 0x3E0C,
    /// > Indicates absence of attestation.
    #[cfg_attr(feature = "serde", serde(rename = "none"))]
    None = 0x3E0B,
}

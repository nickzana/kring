use crate::authenticator::client_pin::AuthProtocolVersion;
use crate::authenticator::Transport;
use crate::extensions;
use fido_common::credential::public_key;
use fido_common::{attestation, registry};
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::usize;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A usize with a minimum value of N
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UsizeN<const N: usize>(bounded_integer::BoundedUsize<N, { usize::MAX }>);

/// > data type byte string and identifying the authenticator model, i.e.
/// > identical values mean that they refer to the same authenticator model and
/// > different values mean they refer to different authenticator models.
pub type Aaguid = [u8; 16];

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Version {
    #[cfg_attr(feature = "serde", serde(rename = "FIDO_2_1"))]
    Fido2_1,
    #[cfg_attr(feature = "serde", serde(rename = "FIDO_2_0"))]
    Fido2_0,
    #[cfg_attr(feature = "serde", serde(rename = "FIDO_2_1_PRE"))]
    Fido2_1Preview,
    #[cfg_attr(feature = "serde", serde(rename = "U2F_V2"))]
    U2fV2,
}

/// > The certifications member provides a hint to the platform with additional
/// > information about certifications that the authenticator has received.
/// > Certification programs may revoke certification of specific devices at any
/// > time. Relying partys are responsible for validating attestations and
/// > `AAGUID` via appropriate methods. Platforms may alter their behaviour
/// > based on these hints such as selecting a PIN protocol or `credProtect`
/// > level.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Certification {
    /// > The [FIPS140-2] Cryptographic-Module-Validation-Program overall
    /// > certification level.
    FipsCryptoValidation2(FipsCryptoValidation2Level),
    FipsCryptoValidation3(FipsCryptoValidation3Level),
    FipsPhysicalCryptoValidation2(FipsPhysicalCryptoValidation2Level),
    FipsPhysicalCryptoValidation3(FipsPhysicalCryptoValidation3Level),
    CommonCriteria(CommonCriterialLevel),
    Fido(FidoLevel),
}

#[repr(usize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FipsCryptoValidation2Level {
    Level1 = 1,
    Level2 = 2,
    Level3 = 3,
    Level4 = 4,
}

#[repr(usize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FipsCryptoValidation3Level {
    Level1 = 1,
    Level2 = 2,
    Level3 = 3,
    Level4 = 4,
}

#[repr(usize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FipsPhysicalCryptoValidation2Level {
    Level1 = 1,
    Level2 = 2,
    Level3 = 3,
    Level4 = 4,
}

#[repr(usize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FipsPhysicalCryptoValidation3Level {
    Level1 = 1,
    Level2 = 2,
    Level3 = 3,
    Level4 = 4,
}

/// > Common Criteria Evaluation Assurance Level [CC1V3-1R5]. This is a integer
/// > from 1 to 7. The intermediate-plus levels are not represented.
#[repr(usize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommonCriterialLevel {
    EAL1 = 1,
    EAL2 = 2,
    EAL3 = 3,
    EAL4 = 4,
    EAL5 = 5,
    EAL6 = 6,
    EAL7 = 7,
}

/// > FIDO Alliance certification level. This is an integer from 1 to 6. The
/// > numbered levels are mapped to the odd numbers, with the plus levels mapped
/// > to the even numbers e.g., level 3+ is mapped to 6.
#[repr(usize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FidoLevel {
    L1 = 1,
    L1Plus = 2,
    L2 = 3,
    L2Plus = 4,
    L3 = 5,
    L3Plus = 6,
}

/// These options describe properties of a CTAP device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OptionId {
    /// > Indicates that the device is attached to the client and therefore
    /// > can’t be removed and used on another client.
    PlatformDevice,
    /// > Specifies whether this authenticator can create discoverable
    /// > credentials, and therefore can satisfy `authenticatorGetAssertion`
    /// > requests with the `allowList` parameter omitted.
    DiscoverableCredentials,
    /// > ClientPIN feature support:
    /// > If present and set to true, it indicates that the device is capable of
    /// > accepting a PIN from the client and PIN has been set.
    /// >
    /// > If present and set to false, it indicates that the device is capable
    /// > of accepting a PIN from the client and PIN has not been set yet.
    /// >
    /// > If absent, it indicates that the device is not capable of accepting a
    /// > PIN from the client.
    ClientPin,
    /// > Indicates that the device is capable of testing user presence.
    UserPresence,
    /// > Indicates that the authenticator supports a built-in user verification
    /// > method. For example, devices with UI, biometrics fall into this
    /// > category.
    /// >
    /// > If present and set to true, it indicates that the device is capable of
    /// > built-in user verification and its user verification feature is
    /// > presently configured.
    /// >
    /// > If present and set to false, it indicates that the authenticator is
    /// > capable of built-in user verification and its user verification
    /// > feature is not presently configured. For example, an authenticator
    /// > featuring a built-in biometric user verification feature that is not
    /// > presently configured will return this "uv" option id set to false.
    /// >
    /// > If absent, it indicates that the authenticator does not have a
    /// > built-in user verification capability.
    /// >
    /// > A device that can only do Client PIN will not return the "uv" option
    /// > id.
    /// >
    /// > If a device is capable of both built-in user verification and Client
    /// > PIN, the authenticator will return both the "uv" and the "clientPin"
    /// > option ids.
    UserVerification,
    PinUvAuthToken,
    /// > If this noMcGaPermissionsWithClientPin is:
    /// > - present and set to true: A `pinUvAuthToken` obtained via
    /// > `getPinUvAuthTokenUsingPinWithPermissions` (or `getPinToken`) cannot
    /// > be used for `authenticatorMakeCredential` or
    /// > `authenticatorGetAssertion` commands, because it will lack the
    /// > necessary `mc` and `ga` permissions. In this situation, platforms
    /// > SHOULD NOT attempt to use `getPinUvAuthTokenUsingPinWithPermissions`
    /// > if using `getPinUvAuthTokenUsingUvWithPermissions` fails.
    /// >
    /// > - present and set to false, or absent: A `pinUvAuthToken` obtained via
    /// > `getPinUvAuthTokenUsingPinWithPermissions` (or `getPinToken`) can be
    /// > used for `authenticatorMakeCredential` or `authenticatorGetAssertion`
    /// > commands.
    /// >
    /// > Note: `noMcGaPermissionsWithClientPin` MUST only be present if the
    /// > `clientPin` option ID is present.
    NoMcGaPermissionsWithClientPin,
    LargeBlobs,
    EnterpriseAttestation,
    BiometricEnroll,
    UvManagementPreview,
    UvBiometricEnroll,
    AuthenticatorConfig,
    UvAuthenticatorConfig,
    CredentialManagement,
    SetMinPinLength,
    MakeCredentialUvNotRequired,
    AlwaysRequireUv,
}

/// > Using this method, platforms can request that the authenticator report a
/// > list of its supported protocol versions and extensions, its AAGUID, and
/// > other aspects of its overall capabilities. Platforms should use this
/// > information to tailor their command parameters choices.
pub struct Info {
    /// > List of supported CTAP versions.
    pub versions: BTreeSet<Version>,
    /// > List of supported extensions.
    pub extensions: Option<BTreeSet<extensions::Identifier>>,
    /// > The claimed AAGUID.
    pub aaguid: Aaguid,
    /// > List of supported options.
    pub options: Option<BTreeMap<OptionId, bool>>,
    /// > Maximum message size supported by the authenticator.
    pub max_message_size: Option<usize>,
    /// > List of supported PIN/UV auth protocols in order of decreasing
    /// > authenticator preference. MUST NOT contain duplicate values...
    // Cannot be empty if present
    pub pin_uv_auth_protocols: Option<Vec<AuthProtocolVersion>>,
    /// > Maximum number of credentials supported in credentialID list at a time
    /// > by the authenticator.
    pub max_credential_count_in_list: Option<NonZeroUsize>,
    /// > Maximum Credential ID Length supported by the authenticator.
    pub max_credential_id_length: Option<NonZeroUsize>,
    /// > List of supported transports.
    pub transports: Option<BTreeSet<Transport>>,
    /// > List of supported algorithms for credential generation... The array is
    /// > ordered from most preferred to least preferred and MUST NOT include
    /// > duplicate entries...
    // Cannot be empty if present
    pub algorithms: Option<Vec<public_key::Parameters>>,
    /// > The maximum size, in bytes, of the serialized large-blob array that
    /// > this authenticator can store. If the `authenticatorLargeBlobs` command
    /// > is supported, this MUST be specified. Otherwise it MUST NOT be.
    pub max_serialized_large_blob_array_size: Option<UsizeN<1024>>,
    /// > If this member is:
    /// > - present and set to true: `getPinToken` and
    /// > `getPinUvAuthTokenUsingPinWithPermissions` will return errors until
    /// > after a successful PIN Change.
    /// > - present and set to false, or absent: no PIN Change is required.
    pub force_pin_change: Option<bool>,
    /// > This specifies the current minimum PIN length, in Unicode code points,
    /// > the authenticator enforces for ClientPIN. This is applicable for
    /// > ClientPIN only: the minPINLength member MUST be absent if the
    /// > clientPin option ID is absent; it MUST be present if the authenticator
    /// > supports authenticatorClientPIN.
    pub min_pin_length: Option<usize>,
    /// > Indicates the firmware version of the authenticator model identified
    /// > by AAGUID.
    pub firmware_version: Option<usize>,
    /// > Maximum credBlob length in bytes supported by the authenticator. Must
    /// > be present if, and only if, credBlob is included in the supported
    /// > extensions list.
    pub max_cred_blob_length: Option<UsizeN<32>>,
    /// > This specifies the max number of RP IDs that authenticator can set via
    /// > `setMinPINLength` subcommand. This is in addition to pre-configured
    /// > list authenticator may have. If the authenticator does not support
    /// > adding additional RP IDs, its value is 0. This MUST ONLY be present
    /// > if, and only if, the authenticator supports the `setMinPINLength`
    /// > subcommand.
    pub max_rpids_for_set_min_pin_length: Option<usize>,
    /// > This specifies the preferred number of invocations of the
    /// > `getPinUvAuthTokenUsingUvWithPermissions` subCommand the platform may
    /// > attempt before falling back to the
    /// > `getPinUvAuthTokenUsingPinWithPermissions` subCommand or displaying an
    /// > error.
    pub preferred_platform_uv_attempts: Option<NonZeroUsize>,
    /// > This specifies the user verification modality supported by the
    /// > authenticator via `authenticatorClientPIN`'s
    /// > `getPinUvAuthTokenUsingUvWithPermissions` subcommand. This is a hint
    /// > to help the platform construct user dialogs. If `clientPin`
    /// > is supported it MUST NOT be included in the bit-flags, as `clientPIN`
    /// > is not a built-in user verification method.
    pub uv_modality: Option<BTreeSet<registry::UserVerify>>,
    /// > This specifies a list of authenticator certifications.
    pub certifications: Option<BTreeSet<Certification>>,
    /// > If this member is present it indicates the estimated number of
    /// > additional discoverable credentials that can be stored. If this value
    /// > is zero then platforms SHOULD create non-discoverable credentials if
    /// > possible.
    /// >
    /// > This estimate SHOULD be based on the assumption that all future
    /// > discoverable credentials will have maximally-sized fields and SHOULD
    /// > be zero whenever an attempt to create a discoverable credential may
    /// > fail due to lack of space, even if it’s possible that some specific
    /// > request might succeed. For example, a specific request might include
    /// > fields that are smaller than the maximum possible size and thus
    /// > succeed, but this value should be zero if a request with maximum-sized
    /// > fields would fail. Also, a specific request might have an rp.id and
    /// > user.id that match an existing discoverable credential and thus
    /// > overwrite it, but this value should be set assuming that will not
    /// > happen.
    pub remaining_discoverable_credentials: Option<usize>,
    /// > If present the authenticator supports the `authenticatorConfig`
    /// > `vendorPrototype` subcommand, and its value is a list of
    /// > `authenticatorConfig` `vendorCommandId` values supported, which MAY be
    /// > empty.
    pub vendor_prototype_config_commands: Option<BTreeSet<usize>>,
    /// > List of supported attestation formats.
    pub attestation_formats: Option<BTreeSet<attestation::FormatIdentifier>>,
    /// > If present the number of internal User Verification operations since
    /// > the last pin entry including all failed attempts.
    pub uv_count_since_last_pin_entry: Option<usize>,
    /// > If present the authenticator requires a 10 second touch for reset.
    pub long_touch_for_reset: Option<bool>,
}

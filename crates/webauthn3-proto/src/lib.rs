#![feature(async_fn_in_trait, adt_const_params, associated_const_equality)]
#![allow(incomplete_features)]

pub mod attestation;
pub mod authenticator;
pub mod client;
pub mod public_key;
pub mod token;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy)]
/// > A WebAuthn Relying Party may require user verification for some of its
/// > operations but not for others, and may use this type to express its needs.
pub enum UserVerificationRequirement {
    /// > The Relying Party requires user verification for the operation and
    /// > will fail the overall ceremony if the response does not have the UV
    /// > flag set. The client MUST return an error if user verification cannot
    /// > be performed.
    #[cfg_attr(feature = "serde", serde(rename = "required"))]
    Required,
    /// > The Relying Party prefers user verification for the operation if
    /// > possible, but will not fail the operation if the response does not
    /// > have the UV flag set.
    #[cfg_attr(feature = "serde", serde(rename = "preferred"))]
    Preferred,
    /// > The Relying Party does not want user verification employed during the
    /// > operation (e.g., in the interest of minimizing disruption to the user
    /// > interaction flow).
    #[cfg_attr(feature = "serde", serde(rename = "discouraged"))]
    Discouraged,
}

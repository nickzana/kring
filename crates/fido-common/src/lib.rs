#![feature(cfg_eval, split_array, slice_take)]

#![cfg_attr(not(feature = "std"), no_std)]

pub mod attestation;
pub mod authenticator;
pub mod credential;
pub mod extensions;
pub mod registry;

pub type Sha256Hash = [u8; 32];

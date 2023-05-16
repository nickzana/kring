#![feature(cfg_eval, split_array, slice_take)]

pub mod attestation;
pub mod authenticator;
pub mod credential;
pub mod extensions;
pub mod registry;

pub type Sha256Hash = [u8; 32];

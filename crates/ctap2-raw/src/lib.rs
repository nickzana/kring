#![cfg_attr(not(test), no_std)]

use fido_common::credential::public_key;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize};

use heapless::Vec;

pub enum BoO<'a, T>
where
    T: ToBorrowed<'a> + Sized,
{
    Borrowed(&'a T::Borrowed),
    Owned(T),
}

pub trait ToBorrowed<'a> {
    type Borrowed: ?Sized;
    fn borrowed(&self) -> &Self::Borrowed;
}

pub trait BorrowAsSelf {}

impl BorrowAsSelf for public_key::RelyingPartyEntity {}

impl<'a, T> ToBorrowed<'a> for T
where
    T: BorrowAsSelf,
{
    type Borrowed = Self;

    fn borrowed(&self) -> &Self::Borrowed {
        &self
    }
}

impl<'a, T, const N: usize> ToBorrowed<'a> for Vec<T, N> {
    type Borrowed = [T];

    fn borrowed(&self) -> &[T] {
        todo!()
    }
}

impl<'a, T> AsRef<T::Borrowed> for BoO<'a, T>
where
    T: ToBorrowed<'a>,
{
    fn as_ref(&self) -> &T::Borrowed {
        match self {
            BoO::Borrowed(borrowed) => borrowed,
            BoO::Owned(owned) => owned.borrowed(),
        }
    }
}

#[cfg(feature = "serde")]
impl<'a, T> Serialize for BoO<'a, T>
where
    T: ToBorrowed<'a>,
    T::Borrowed: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_ref().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, 'a, T> Deserialize<'de> for BoO<'a, T>
where
    T: ToBorrowed<'a> + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(BoO::Owned)
    }
}

/// MAX_LEN is the maximum number of elements in unbouned arrays.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuthenticatorMakeCredentialRequest<'a, const MAX_LEN: usize = 128> {
    client_data_hash: BoO<'a, Vec<u8, 32>>,
    rp: BoO<'a, public_key::RelyingPartyEntity>,
    pub_key_cred_params: BoO<'a, Vec<public_key::Parameters, MAX_LEN>>,
}

#[cfg(test)]
mod tests {}

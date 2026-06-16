// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Transaction skeleton defining the minimum amount of data needed for a
//! phoenix transaction.

extern crate alloc;
use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use crate::{Note, OUTPUT_NOTES};

/// A phoenix transaction, referred to as tx-skeleton in the specs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TxSkeleton {
    /// The root of the transfer tree on top of which this transaction is
    /// based.
    pub root: BlsScalar,
    /// The nullifiers of the old notes this transaction spends.
    pub nullifiers: Vec<BlsScalar>,
    /// The new output notes of this transaction.
    pub outputs: [Note; OUTPUT_NOTES],
    /// Describes the maximum fee to be paid for this transaction.
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_with::As::<serde_with::DisplayFromStr>")
    )]
    pub max_fee: u64,
    /// A deposit is used to transferring funds to a contract
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_with::As::<serde_with::DisplayFromStr>")
    )]
    pub deposit: u64,
}

impl TxSkeleton {
    fn from_slice_with(
        buf: &[u8],
        read_note: fn(&mut &[u8]) -> Result<Note, BytesError>,
    ) -> Result<Self, BytesError> {
        let mut buffer = buf;
        let root = BlsScalar::from_reader(&mut buffer)?;

        let num_nullifiers_u64 = u64::from_reader(&mut buffer)?;
        let min_tail_len = OUTPUT_NOTES
            .checked_mul(Note::SIZE)
            .and_then(|len| len.checked_add(u64::SIZE + u64::SIZE))
            .ok_or(BytesError::InvalidData)?;
        if buffer.len() < min_tail_len {
            return Err(BytesError::InvalidData);
        }

        let max_nullifiers_by_len =
            (buffer.len() - min_tail_len) / BlsScalar::SIZE;
        let num_nullifiers = usize::try_from(num_nullifiers_u64)
            .map_err(|_| BytesError::InvalidData)?;
        if num_nullifiers > max_nullifiers_by_len {
            return Err(BytesError::InvalidData);
        }

        let mut nullifiers = Vec::with_capacity(num_nullifiers);
        for _ in 0..num_nullifiers {
            nullifiers.push(BlsScalar::from_reader(&mut buffer)?);
        }

        let mut outputs = Vec::with_capacity(OUTPUT_NOTES);
        for _ in 0..OUTPUT_NOTES {
            outputs.push(read_note(&mut buffer)?);
        }
        let outputs: [Note; OUTPUT_NOTES] =
            outputs.try_into().map_err(|_| BytesError::InvalidData)?;

        let max_fee = u64::from_reader(&mut buffer)?;
        let deposit = u64::from_reader(&mut buffer)?;

        Ok(Self {
            root,
            nullifiers,
            outputs,
            max_fee,
            deposit,
        })
    }

    /// Return input bytes to a hash function for the transaction.
    #[must_use]
    pub fn to_hash_input_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.root.to_bytes());

        for nullifier in &self.nullifiers {
            bytes.extend(nullifier.to_bytes());
        }
        for note in &self.outputs {
            bytes.extend(note.to_bytes());
        }

        bytes.extend(self.max_fee.to_bytes());
        bytes.extend(self.deposit.to_bytes());

        bytes
    }

    /// Serialize the transaction to a variable length byte buffer.
    #[allow(unused_must_use)]
    pub fn to_var_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.root.to_bytes());

        let num_nullifiers = self.nullifiers.len() as u64;
        bytes.extend(num_nullifiers.to_bytes());
        self.nullifiers.iter().for_each(|nullifier| {
            bytes.extend(nullifier.to_bytes());
        });

        self.outputs.iter().for_each(|note| {
            bytes.extend(note.to_bytes());
        });

        bytes.extend(self.max_fee.to_bytes());
        bytes.extend(self.deposit.to_bytes());

        bytes
    }

    /// Deserialize the transaction from a bytes buffer.
    pub fn from_slice(buf: &[u8]) -> Result<Self, BytesError> {
        Self::from_slice_with(buf, Note::read_strict)
    }

    /// Deserialize the transaction from a bytes buffer, accepting historical
    /// on-curve `JubJub` points inside output notes.
    pub fn from_slice_legacy_compat(buf: &[u8]) -> Result<Self, BytesError> {
        Self::from_slice_with(buf, Note::read_legacy_compat)
    }

    /// Returns the inputs to the transaction.
    pub fn nullifiers(&self) -> &[BlsScalar] {
        &self.nullifiers
    }

    /// Returns the outputs of the transaction.
    pub fn outputs(&self) -> &[Note] {
        &self.outputs
    }

    /// Returns the maximum fee of the transaction.
    pub fn max_fee(&self) -> u64 {
        self.max_fee
    }

    /// Returns the deposit of the transaction.
    pub fn deposit(&self) -> u64 {
        self.deposit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_slice_rejects_unbounded_nullifier_count() {
        let mut bytes = Vec::new();
        bytes.extend(BlsScalar::from(0u64).to_bytes());
        bytes.extend(u64::MAX.to_bytes());

        // Fill enough bytes to pass fixed-tail length checks while keeping the
        // nullifier count obviously inconsistent with the available payload.
        let min_tail_len = OUTPUT_NOTES * Note::SIZE + u64::SIZE + u64::SIZE;
        bytes.resize(BlsScalar::SIZE + u64::SIZE + min_tail_len, 0u8);

        let err = TxSkeleton::from_slice(&bytes).unwrap_err();
        assert_eq!(err, BytesError::InvalidData);
    }
}

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

/// Selects how a [`TxSkeleton`] byte-region is decoded. Each variant fixes
/// both the note reader and whether trailing bytes are rejected, so the two
/// cannot be mismatched by a caller.
#[derive(Clone, Copy)]
enum DecodeMode {
    /// Historical (`legacy_compat`) decode: accepts on-curve points without
    /// subgroup checks and tolerates trailing bytes. For already-finalized
    /// pre-strict-format transactions only.
    Legacy,
    /// Strict decode: torsion-free points, trailing bytes tolerated. The
    /// decoder for both live strict-format ingress and replay of
    /// already-finalized strict-format transactions.
    Strict,
    /// Checked decode: strict points that must additionally be prime-order, and
    /// the region must be fully drained. Callers pick this mode through
    /// [`TxSkeleton::from_slice_checked`]. Which transactions are decoded
    /// through it is a routing decision for the node: it selects this mode at
    /// the protocol fork that introduces these checks, and leaves `Strict` to
    /// decode the transactions finalized before the fork.
    Checked,
}

impl DecodeMode {
    fn read_note(self) -> fn(&mut &[u8]) -> Result<Note, BytesError> {
        match self {
            Self::Legacy => Note::read_legacy_compat,
            Self::Strict => Note::read_strict,
            Self::Checked => Note::read_checked,
        }
    }

    fn reject_trailing(self) -> bool {
        matches!(self, Self::Checked)
    }
}

impl TxSkeleton {
    fn from_slice_with(
        buf: &[u8],
        mode: DecodeMode,
    ) -> Result<Self, BytesError> {
        let read_note = mode.read_note();
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

        // The skeleton is decoded from its own length-prefixed sub-region, so
        // any residual byte is intra-region padding: a distinct, non-canonical
        // wire-encoding of the same transaction. Hashes computed by re-encoding
        // the decoded fields would normalize such padding away rather than
        // reject it, so on the checked path require the region be fully drained
        // to keep the encoding canonical for block acceptance.
        if mode.reject_trailing() && !buffer.is_empty() {
            return Err(BytesError::InvalidData);
        }

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
        Self::from_slice_with(buf, DecodeMode::Strict)
    }

    /// Deserialize the transaction from a bytes buffer, additionally rejecting
    /// non-canonical trailing padding and non-prime-order stealth-address
    /// points inside output notes.
    ///
    /// The buffer must contain exactly one skeleton and no trailing bytes.
    /// Intended for the protocol fork that introduces these checks; the
    /// existing [`Self::from_slice`] and [`Self::from_slice_legacy_compat`]
    /// decoders are left as-is so already-finalized transactions still decode.
    pub fn from_slice_checked(buf: &[u8]) -> Result<Self, BytesError> {
        Self::from_slice_with(buf, DecodeMode::Checked)
    }

    /// Deserialize the transaction from a bytes buffer, accepting historical
    /// on-curve `JubJub` points inside output notes.
    pub fn from_slice_legacy_compat(buf: &[u8]) -> Result<Self, BytesError> {
        Self::from_slice_with(buf, DecodeMode::Legacy)
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
    use dusk_jubjub::JubJubScalar;
    use ff::Field;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;
    use crate::{NoteType, PublicKey, SecretKey, StealthAddress};

    fn dummy_output(rng: &mut StdRng) -> Note {
        let sender_pk = PublicKey::from(&SecretKey::random(&mut *rng));
        let receiver_pk = PublicKey::from(&SecretKey::random(&mut *rng));
        let sender_blinder = [
            JubJubScalar::random(&mut *rng),
            JubJubScalar::random(&mut *rng),
        ];
        let value_blinder = JubJubScalar::random(&mut *rng);
        Note::new(
            rng,
            NoteType::Obfuscated,
            &sender_pk,
            &receiver_pk,
            42,
            value_blinder,
            sender_blinder,
        )
    }

    fn dummy_skeleton() -> TxSkeleton {
        let mut rng = StdRng::seed_from_u64(0xbeef);

        let nullifiers =
            Vec::from([BlsScalar::from(2u64), BlsScalar::from(3u64)]);

        TxSkeleton {
            root: BlsScalar::from(1u64),
            nullifiers,
            outputs: [dummy_output(&mut rng), dummy_output(&mut rng)],
            max_fee: 7,
            deposit: 0,
        }
    }

    #[test]
    fn checked_rejects_trailing_bytes() {
        let skeleton = dummy_skeleton();
        let mut bytes = skeleton.to_var_bytes();

        // The canonical encoding round-trips on the checked path.
        assert_eq!(skeleton, TxSkeleton::from_slice_checked(&bytes).unwrap());

        bytes.push(0u8);

        // A single padding byte inside the length-prefixed region is a
        // distinct, non-canonical encoding: the checked path rejects it, while
        // the strict path — live strict-format ingress and replay of
        // already-finalized transactions — must stay lenient.
        let err = TxSkeleton::from_slice_checked(&bytes).unwrap_err();
        assert_eq!(err, BytesError::InvalidData);
        assert_eq!(skeleton, TxSkeleton::from_slice(&bytes).unwrap());
    }

    #[test]
    fn checked_rejects_non_prime_order_output_stealth_point() {
        let mut skeleton = dummy_skeleton();

        // Replace one output with a note carrying the identity stealth address
        // (a non-prime-order point) — accepted by the strict decoder (live
        // ingress and replay), rejected by the checked decoder.
        skeleton.outputs[0] = Note::transparent_stealth(
            StealthAddress::default(),
            1,
            *skeleton.outputs[0].sender(),
        );
        let bytes = skeleton.to_var_bytes();

        let err = TxSkeleton::from_slice_checked(&bytes).unwrap_err();
        assert_eq!(err, BytesError::InvalidData);
        assert_eq!(skeleton, TxSkeleton::from_slice(&bytes).unwrap());
    }

    #[test]
    fn legacy_compat_tolerates_trailing_bytes() {
        let skeleton = dummy_skeleton();
        let mut bytes = skeleton.to_var_bytes();
        bytes.push(0u8);

        // The historical decode path must not tighten: appending padding
        // still parses, so replaying already-finalized blocks stays valid.
        assert_eq!(
            skeleton,
            TxSkeleton::from_slice_legacy_compat(&bytes).unwrap()
        );
    }

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

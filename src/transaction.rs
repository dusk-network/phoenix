// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Verifier data for the transfer circuits

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_poseidon::cipher::PoseidonCipher;

use crate::{Crossover, Fee, Message, Note};

const STCO_MESSAGE_SIZE: usize = 7 + 2 * PoseidonCipher::cipher_size();
const STCT_MESSAGE_SIZE: usize = 5 + PoseidonCipher::cipher_size();

/// A phoenix transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Transaction {
    /// The root of the transfer tree on top of which this transaction is
    /// based.
    pub anchor: BlsScalar,
    /// The nullifiers of the notes this transaction spends.
    pub nullifiers: Vec<BlsScalar>,
    /// The output notes of this transaction.
    pub outputs: Vec<Note>,
    /// Describes the fee to be paid for this transaction.
    pub fee: Fee,
    /// A crossover is used to transferring funds to a contract - i.e. in
    /// [`Stct`] and [`Stco`].
    pub crossover: Option<Crossover>,
    /// Serialized proof of the `Execute` circuit for this transaction.
    pub proof: Vec<u8>,
    /// A call to a contract. The `Vec<u8>` must be an `rkyv`ed representation
    /// of the data the contract expects, and the `String` the name of the
    /// function to call.
    pub call: Option<(BlsScalar, String, Vec<u8>)>,
}

impl Transaction {
    /// Return input bytes to a hash function for the transaction.
    #[must_use]
    pub fn to_hash_input_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        for nullifier in &self.nullifiers {
            bytes.extend(nullifier.to_bytes());
        }
        for note in &self.outputs {
            bytes.extend(note.to_bytes());
        }

        bytes.extend(self.anchor.to_bytes());
        bytes.extend(self.fee.to_bytes());

        if let Some(crossover) = &self.crossover {
            bytes.extend(crossover.to_bytes());
        }

        if let Some((module, fn_name, call_data)) = &self.call {
            bytes.extend(module.to_bytes());
            bytes.extend(fn_name.as_bytes());
            bytes.extend(call_data);
        }

        bytes
    }

    /// Serialize the transaction to a variable length byte buffer.
    #[allow(unused_must_use)]
    pub fn to_var_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.anchor.to_bytes());

        let size = self.nullifiers.len() as u64;
        bytes.extend(size.to_bytes());

        self.nullifiers.iter().for_each(|val| {
            bytes.extend(val.to_bytes());
        });

        let size = self.outputs.len() as u64;
        bytes.extend(size.to_bytes());
        self.outputs.iter().for_each(|val| {
            bytes.extend(val.to_bytes());
        });

        bytes.extend(self.fee.to_bytes());

        if let Some(co) = self.crossover {
            bytes.push(1);
            bytes.extend(co.to_bytes());
        } else {
            bytes.push(0);
        }

        let proof_len = self.proof.len() as u64;
        bytes.extend(proof_len.to_bytes());
        bytes.extend(&self.proof);

        if let Some((module, fn_name, call_data)) = &self.call {
            bytes.push(1);
            bytes.extend(module.to_bytes());

            let size = fn_name.len() as u64;
            bytes.extend(size.to_bytes());
            bytes.extend(fn_name.as_bytes());
            bytes.extend(call_data);
        } else {
            bytes.push(0);
        }
        bytes
    }

    /// Deserialize the transaction from a bytes buffer.
    pub fn from_slice(buf: &[u8]) -> Result<Self, BytesError> {
        let mut buffer = buf;
        let anchor = BlsScalar::from_reader(&mut buffer)?;
        let num_nullifiers = u64::from_reader(&mut buffer)?;
        let mut nullifiers = Vec::with_capacity(num_nullifiers as usize);

        for _ in 0..num_nullifiers {
            nullifiers.push(BlsScalar::from_reader(&mut buffer)?);
        }

        let num_outputs = u64::from_reader(&mut buffer)?;
        let mut outputs = Vec::with_capacity(num_outputs as usize);
        for _ in 0..num_outputs {
            outputs.push(Note::from_reader(&mut buffer)?);
        }

        let fee = Fee::from_reader(&mut buffer)?;

        let has_crossover = buffer[0] != 0;
        let mut buffer = &buffer[1..];

        let crossover = if has_crossover {
            Some(Crossover::from_reader(&mut buffer)?)
        } else {
            None
        };

        let proof_size = u64::from_reader(&mut buffer)? as usize;
        let proof = buffer[..proof_size].to_vec();
        let buffer = &buffer[proof_size..];

        let has_call = buffer[0] != 0;
        let mut buffer = &buffer[1..];
        let call = if has_call {
            let module = BlsScalar::from_reader(&mut buffer)?;
            let fn_name_size = u64::from_reader(&mut buffer)? as usize;
            let fn_name = String::from_utf8(buffer[..fn_name_size].to_vec())
                .map_err(|_err| BytesError::InvalidData)?;
            let call_data = buffer[fn_name_size..].to_vec();
            Some((module, fn_name, call_data))
        } else {
            None
        };

        Ok(Self {
            anchor,
            nullifiers,
            outputs,
            fee,
            crossover,
            proof,
            call,
        })
    }

    /// Returns the inputs to the transaction.
    pub fn nullifiers(&self) -> &[BlsScalar] {
        &self.nullifiers
    }

    /// Returns the outputs of the transaction.
    pub fn outputs(&self) -> &[Note] {
        &self.outputs
    }

    /// Returns the fee of the transaction.
    pub fn fee(&self) -> &Fee {
        &self.fee
    }

    /// Returns the crossover of the transaction.
    pub fn crossover(&self) -> Option<&Crossover> {
        self.crossover.as_ref()
    }

    /// Returns the call of the transaction.
    pub fn call(&self) -> Option<&(BlsScalar, String, Vec<u8>)> {
        self.call.as_ref()
    }
}

/// Signature message used for [`Stct`].
#[must_use]
pub fn process_message_stct(
    crossover: &Crossover,
    value: u64,
    module_id: BlsScalar,
) -> [BlsScalar; STCT_MESSAGE_SIZE] {
    let mut array = [BlsScalar::default(); STCT_MESSAGE_SIZE];
    let hash_inputs = crossover.to_hash_inputs();
    array[..hash_inputs.len()].copy_from_slice(&hash_inputs);
    array[hash_inputs.len()..].copy_from_slice(&[value.into(), module_id]);
    array
}

/// Signature message used for [`Stco`].
#[must_use]
pub fn process_message_stco(
    crossover: &Crossover,
    message: &Message,
    module_id: BlsScalar,
) -> [BlsScalar; STCO_MESSAGE_SIZE] {
    let mut array = [BlsScalar::default(); STCO_MESSAGE_SIZE];
    let crossover_inputs = crossover.to_hash_inputs();
    let message_inputs = message.to_hash_inputs();
    array[..crossover_inputs.len()].copy_from_slice(&crossover_inputs);
    array
        [crossover_inputs.len()..crossover_inputs.len() + message_inputs.len()]
        .copy_from_slice(&message_inputs);
    array[crossover_inputs.len() + message_inputs.len()..]
        .copy_from_slice(&[module_id]);
    array
}

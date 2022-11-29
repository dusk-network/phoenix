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
use dusk_bytes::Serializable;
use dusk_pki::StealthAddress;
use dusk_poseidon::cipher::PoseidonCipher;

use crate::Crossover;
use crate::Fee;
use crate::Message;
use crate::Note;

/// For the purposes of our transaction model, ModuleId is always a BlsScalar
pub type ModuleId = BlsScalar;

const STCO_MESSAGE_SIZE: usize = 7 + 2 * PoseidonCipher::cipher_size();
const STCT_MESSAGE_SIZE: usize = 5 + PoseidonCipher::cipher_size();

/// A phoenix transaction.
#[derive(Debug, Clone)]
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
    pub call: Option<(ModuleId, String, Vec<u8>)>,
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
}

/// Send value to a contract transparently.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Stct {
    /// Module to send the value to.
    pub module: ModuleId,
    /// The value to send to the contract.
    pub value: u64,
    /// Serialized proof of the `STCT` circuit.
    pub proof: Vec<u8>,
}

/// Withdraw value from a contract transparently.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Wfct {
    /// The value to withdraw
    pub value: u64,
    /// The note to withdraw transparently to
    pub note: Note,
    /// Serialized proof of the `WFCT` circuit.
    pub proof: Vec<u8>,
}

/// Send value to a contract anonymously.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Stco {
    /// Module to send the value to.
    pub module: ModuleId,
    /// Message containing the value commitment.
    pub message: Message,
    /// The stealth address of the message.
    pub message_address: StealthAddress,
    /// Serialized proof of the `STCO` circuit.
    pub proof: Vec<u8>,
}

/// Withdraw value from a contract anonymously.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Wfco {
    /// Message containing the value commitment.
    pub message: Message,
    /// The stealth address of the message.
    pub message_address: StealthAddress,
    /// Message containing commitment on the change value.
    pub change: Message,
    /// The stealth address of the change message.
    pub change_address: StealthAddress,
    /// The note to withdraw to.
    pub output: Note,
    /// Serialized proof of the `WFCO` circuit.
    pub proof: Vec<u8>,
}

/// Withdraw value from the calling contract to another contract.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Wfctc {
    /// The contract to transfer value to.
    pub module: ModuleId,
    /// The value to transfer.
    pub value: u64,
}

/// Mint value to a stealth address.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Mint {
    /// The address to mint to.
    pub address: StealthAddress,
    /// The value to mint to the address.
    pub value: u64,
    /// A nonce to prevent replay.
    pub nonce: BlsScalar,
}

/// Signature message used for [`Stct`].
#[must_use]
pub fn sign_message_stct(
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
pub fn sign_message_stco(
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

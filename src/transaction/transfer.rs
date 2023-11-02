// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
use dusk_poseidon::cipher::PoseidonCipher;
#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use crate::crossover::Crossover;
use crate::message::Message;
use crate::note::Note;
use crate::transaction::ModuleId;
use crate::StealthAddress;

/// The depth of the transfer tree.
pub const TRANSFER_TREE_DEPTH: usize = 17;

const STCO_MESSAGE_SIZE: usize = 7 + 2 * PoseidonCipher::cipher_size();
const STCT_MESSAGE_SIZE: usize = 5 + PoseidonCipher::cipher_size();

/// A leaf of the transfer tree.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct TreeLeaf {
    /// The height of the block when the note was inserted in the tree.
    pub block_height: u64,
    /// The note inserted in the tree.
    pub note: Note,
}

/// Send value to a contract transparently.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Proof of the `STCT` circuit.
    pub proof: Vec<u8>,
}

/// Withdraw value from a contract transparently.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// A proof of the `WFCT` circuit.
    pub proof: Vec<u8>,
}

/// Send value to a contract anonymously.
#[derive(Debug, Clone, PartialEq)]
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
    /// Proof of the `STCO` circuit.
    pub proof: Vec<u8>,
}

/// Withdraw value from a contract anonymously.
#[derive(Debug, Clone, PartialEq)]
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
    /// Proof of the `WFCO` circuit.
    pub proof: Vec<u8>,
}

/// Withdraw value from the calling contract to another contract.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq)]
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
pub fn stct_signature_message(
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
pub fn stco_signature_message(
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

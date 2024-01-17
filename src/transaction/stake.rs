// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;

use crate::StealthAddress;
use bls12_381_bls::{PublicKey, Signature};
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use crate::note::Note;

const ALLOW_MESSAGE_SIZE: usize = u64::SIZE + PublicKey::SIZE;
const STAKE_MESSAGE_SIZE: usize = u64::SIZE + u64::SIZE;
const UNSTAKE_MESSAGE_SIZE: usize = u64::SIZE + Note::SIZE;
const WITHDRAW_MESSAGE_SIZE: usize =
    u64::SIZE + StealthAddress::SIZE + BlsScalar::SIZE;

/// The representation of a public key's stake.
///
/// A user can stake for a particular `amount` larger in value than the
/// `MINIMUM_STAKE` value and is `reward`ed for participating in the consensus.
/// A stake is valid only after a particular block height - called the
/// eligibility.
///
/// To keep track of the number of interactions a public key has had with the
/// contract a `counter` is used to prevent replay attacks - where the same
/// signature could be used to prove ownership of the secret key in two
/// different transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct StakeData {
    /// Amount staked and eligibility.
    pub amount: Option<(u64, u64)>,
    /// The reward for participating in consensus.
    pub reward: u64,
    /// The signature counter to prevent replay.
    pub counter: u64,
}

/// Stake a value on the stake contract.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Stake {
    /// Public key to which the stake will belong.
    pub public_key: PublicKey,
    /// Signature belonging to the given public key.
    pub signature: Signature,
    /// Value to stake.
    pub value: u64,
    /// Proof of the `STCT` circuit.
    pub proof: Vec<u8>,
}

/// Unstake a value from the stake contract.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Unstake {
    /// Public key to unstake.
    pub public_key: PublicKey,
    /// Signature belonging to the given public key.
    pub signature: Signature,
    /// Note to withdraw to.
    pub note: Note,
    /// A proof of the `WFCT` circuit.
    pub proof: Vec<u8>,
}

/// Withdraw the accumulated reward.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Withdraw {
    /// Public key to withdraw the rewards.
    pub public_key: PublicKey,
    /// Signature belonging to the given public key.
    pub signature: Signature,
    /// The address to mint to.
    pub address: StealthAddress,
    /// A nonce to prevent replay.
    pub nonce: BlsScalar,
}

/// Allow a public key to stake.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Allow {
    /// The public key to allow staking to.
    pub public_key: PublicKey,
    /// The "owner" of the smart contract.
    pub owner: PublicKey,
    /// Signature of the `owner` key.
    pub signature: Signature,
}

/// Signature message used for [`Allow`].
#[must_use]
pub fn allow_signature_message(
    counter: u64,
    staker: PublicKey,
) -> [u8; ALLOW_MESSAGE_SIZE] {
    let mut bytes = [0u8; ALLOW_MESSAGE_SIZE];

    bytes[..u64::SIZE].copy_from_slice(&counter.to_bytes());
    bytes[u64::SIZE..].copy_from_slice(&staker.to_bytes());

    bytes
}

/// Signature message used for [`Stake`].
#[must_use]
pub fn stake_signature_message(
    counter: u64,
    value: u64,
) -> [u8; STAKE_MESSAGE_SIZE] {
    let mut bytes = [0u8; STAKE_MESSAGE_SIZE];

    bytes[..u64::SIZE].copy_from_slice(&counter.to_bytes());
    bytes[u64::SIZE..].copy_from_slice(&value.to_bytes());

    bytes
}

/// Signature message used for [`Unstake`].
#[must_use]
pub fn unstake_signature_message(
    counter: u64,
    note: Note,
) -> [u8; UNSTAKE_MESSAGE_SIZE] {
    let mut bytes = [0u8; UNSTAKE_MESSAGE_SIZE];

    bytes[..u64::SIZE].copy_from_slice(&counter.to_bytes());
    bytes[u64::SIZE..].copy_from_slice(&note.to_bytes());

    bytes
}

/// Signature message used for [`Withdraw`].
#[must_use]
pub fn withdraw_signature_message(
    counter: u64,
    address: StealthAddress,
    nonce: BlsScalar,
) -> [u8; WITHDRAW_MESSAGE_SIZE] {
    let mut bytes = [0u8; WITHDRAW_MESSAGE_SIZE];

    bytes[..u64::SIZE].copy_from_slice(&counter.to_bytes());
    bytes[u64::SIZE..u64::SIZE + StealthAddress::SIZE]
        .copy_from_slice(&address.to_bytes());
    bytes[u64::SIZE + StealthAddress::SIZE..]
        .copy_from_slice(&nonce.to_bytes());

    bytes
}

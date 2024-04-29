// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Verifier data for the transfer circuits

mod stake;
pub use stake::*;

mod transfer;
pub use transfer::*;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};

use crate::{Crossover, Fee, Note, PublicKey};

/// Type alias for the ID of a module.
pub type ModuleId = [u8; 32];

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
    /// An optional execution carried by the transaction.
    pub exec: Option<Execution>,
}

/// An execution is either a call to a contract, or a contract deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub enum Execution {
    /// A call to a contract. The `Vec<u8>` must be an `rkyv`ed representation
    /// of the data the contract expects, and the `String` the name of the
    /// contract function to call.
    Call {
        /// The contract to be called
        contract: ModuleId,
        /// The function to call in the contract
        fn_name: String,
        /// The argument to the function to call
        fn_arg: Vec<u8>,
    },
    /// A contract deployment.
    Deploy {
        /// The owner of the contract
        owner: Box<PublicKey>, /* boxed due to a large size difference
                                * between variants */
        /// The contract's bytecode
        bytecode: Vec<u8>,
        /// Arguments to the constructor of the contract. If the contract has
        /// no constructor this should be empty.
        constructor_args: Vec<u8>,
    },
}

impl Transaction {
    /// Return the input bytes to a hash function for the transaction from its
    /// components.
    #[must_use]
    pub fn hash_input_bytes_from_components(
        nullifiers: &[BlsScalar],
        outputs: &[Note],
        anchor: &BlsScalar,
        fee: &Fee,
        crossover: &Option<Crossover>,
        call: &Option<Execution>,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();

        for nullifier in nullifiers {
            bytes.extend(nullifier.to_bytes());
        }
        for note in outputs {
            bytes.extend(note.to_bytes());
        }

        bytes.extend(anchor.to_bytes());
        bytes.extend(fee.to_bytes());

        if let Some(crossover) = crossover {
            bytes.extend(crossover.to_bytes());
        }

        if let Some(execution) = call {
            match execution {
                Execution::Call {
                    contract,
                    fn_name,
                    fn_arg,
                } => {
                    bytes.extend(contract);
                    bytes.extend(fn_name.as_bytes());
                    bytes.extend(fn_arg);
                }
                Execution::Deploy {
                    owner,
                    bytecode,
                    constructor_args,
                } => {
                    bytes.extend(owner.to_bytes());
                    bytes.extend(bytecode);
                    bytes.extend(constructor_args);
                }
            }
        }

        bytes
    }

    /// Return input bytes to a hash function for the transaction.
    #[must_use]
    pub fn to_hash_input_bytes(&self) -> Vec<u8> {
        Self::hash_input_bytes_from_components(
            &self.nullifiers,
            &self.outputs,
            &self.anchor,
            &self.fee,
            &self.crossover,
            &self.exec,
        )
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

        if let Some(co) = &self.crossover {
            bytes.push(1);
            bytes.extend(co.to_bytes());
        } else {
            bytes.push(0);
        }

        let proof_len = self.proof.len() as u64;
        bytes.extend(proof_len.to_bytes());
        bytes.extend(&self.proof);

        match &self.exec {
            None => bytes.push(0),
            Some(execution) => match execution {
                Execution::Call {
                    contract,
                    fn_name,
                    fn_arg,
                } => {
                    bytes.push(1);

                    bytes.extend(contract);

                    let fn_name_size = fn_name.len() as u64;
                    bytes.extend(fn_name_size.to_bytes());
                    bytes.extend(fn_name.as_bytes());

                    bytes.extend(fn_arg);
                }
                Execution::Deploy {
                    owner,
                    bytecode,
                    constructor_args,
                } => {
                    bytes.push(2);

                    bytes.extend(owner.to_bytes());

                    let bytecode_size = bytecode.len() as u64;
                    bytes.extend(bytecode_size.to_bytes());
                    bytes.extend(bytecode);

                    bytes.extend(constructor_args);
                }
            },
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

        let exec_id = buffer[0];
        let mut buffer = &buffer[1..];

        let exec = match exec_id {
            0 => None,
            1 => {
                let buffer_len = buffer.len();
                if buffer.len() < 32 {
                    return Err(BytesError::BadLength {
                        found: buffer_len,
                        expected: 32,
                    });
                }

                let (module_buf, buf) = buffer.split_at(32);
                buffer = buf;

                let mut contract = [0u8; 32];
                contract.copy_from_slice(module_buf);

                let fn_name_size = u64::from_reader(&mut buffer)? as usize;
                let fn_name =
                    String::from_utf8(buffer[..fn_name_size].to_vec())
                        .map_err(|_err| BytesError::InvalidData)?;
                let fn_arg = buffer[fn_name_size..].to_vec();

                Some(Execution::Call {
                    contract,
                    fn_name,
                    fn_arg,
                })
            }
            2 => {
                let owner = PublicKey::from_reader(&mut buffer)?;
                let owner = Box::new(owner);

                let bytecode_size = u64::from_reader(&mut buffer)? as usize;
                let bytecode = buffer[..bytecode_size].to_vec();

                let constructor_args = buffer[bytecode_size..].to_vec();

                Some(Execution::Deploy {
                    owner,
                    bytecode,
                    constructor_args,
                })
            }
            _ => return Err(BytesError::InvalidData),
        };

        Ok(Self {
            anchor,
            nullifiers,
            outputs,
            fee,
            crossover,
            proof,
            exec,
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

    /// Returns the execution of the transaction.
    pub fn exec(&self) -> Option<&Execution> {
        self.exec.as_ref()
    }
}

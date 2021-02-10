// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::note::TRANSPARENT_BLINDER;
use crate::{BlsScalar, JubJubScalar};
use crate::{Crossover, Error, Fee, Note, NoteType, Remainder};

use core::convert::TryFrom;
use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use poseidon252::cipher::PoseidonCipher;

impl From<(Fee, Crossover)> for Note {
    fn from((fee, crossover): (Fee, Crossover)) -> Note {
        let Fee {
            stealth_address, ..
        } = fee;
        let Crossover {
            value_commitment,
            nonce,
            encrypted_data,
            ..
        } = crossover;

        let note_type = NoteType::Obfuscated;
        let pos = u64::MAX;

        Note {
            note_type,
            value_commitment,
            nonce,
            stealth_address,
            pos,
            encrypted_data,
        }
    }
}

impl TryFrom<Note> for (Fee, Crossover) {
    type Error = Error;

    fn try_from(note: Note) -> Result<Self, Self::Error> {
        match note.note_type {
            NoteType::Obfuscated => {
                let gas_limit = 0;
                let gas_price = 0;
                let Note {
                    stealth_address,
                    value_commitment,
                    nonce,
                    encrypted_data,
                    ..
                } = note;

                Ok((
                    Fee {
                        gas_limit,
                        gas_price,
                        stealth_address,
                    },
                    Crossover {
                        value_commitment,
                        nonce,
                        encrypted_data,
                    },
                ))
            }
            _ => Err(Error::InvalidNoteConversion),
        }
    }
}

impl From<Remainder> for Note {
    fn from(remainder: Remainder) -> Note {
        let note_type = NoteType::Transparent;
        let pos = u64::MAX;

        let stealth_address = remainder.stealth_address;
        let value = remainder.gas_changes;
        let nonce = JubJubScalar::zero();

        let value_commitment = JubJubScalar::from(value);
        let value_commitment = (GENERATOR_EXTENDED * value_commitment)
            + (GENERATOR_NUMS_EXTENDED * TRANSPARENT_BLINDER);

        let encrypted_data = {
            let zero = TRANSPARENT_BLINDER.into();
            let mut encrypted_data = [zero; PoseidonCipher::cipher_size()];

            encrypted_data[0] = BlsScalar::from(value);

            PoseidonCipher::new(encrypted_data)
        };

        Note {
            note_type,
            value_commitment,
            nonce,
            stealth_address,
            pos,
            encrypted_data,
        }
    }
}

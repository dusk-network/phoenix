// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::note::ENCRYPTION_SIZE;
use crate::note::TRANSPARENT_BLINDER;
use crate::{Crossover, Error, Fee, Note, NoteType, Remainder};

use core::convert::TryFrom;
use dusk_bytes::Serializable;
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};

impl From<(Fee, Crossover)> for Note {
    fn from((fee, crossover): (Fee, Crossover)) -> Note {
        let Fee {
            stealth_address, ..
        } = fee;
        let Crossover {
            value_commitment,
            encryption,
            ..
        } = crossover;

        let note_type = NoteType::Obfuscated;
        let pos = u64::MAX;

        Note {
            note_type,
            value_commitment,
            stealth_address,
            pos,
            encryption,
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
                    encryption,
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
                        encryption,
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

        let value_commitment = JubJubScalar::from(value);
        let value_commitment = (GENERATOR_EXTENDED * value_commitment)
            + (GENERATOR_NUMS_EXTENDED * TRANSPARENT_BLINDER);

        let mut encryption = [0u8; ENCRYPTION_SIZE];
        encryption[..u64::SIZE].copy_from_slice(&value.to_bytes());

        Note {
            note_type,
            value_commitment,
            stealth_address,
            pos,
            encryption,
        }
    }
}

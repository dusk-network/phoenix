// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{Crossover, Fee, Note, NoteType};

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

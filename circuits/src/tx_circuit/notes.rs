// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::prelude::*;
use dusk_poseidon::{Domain, Hash};
use jubjub_schnorr::SignatureDouble;
use poseidon_merkle::Opening;

use rand::{CryptoRng, RngCore};

use phoenix_core::{Error as PhoenixError, Note, Ownable, SecretKey, ViewKey};

/// Struct representing a note willing to be spent, in a way
/// suitable for being introduced in the transfer circuit
#[derive(Debug, Clone)]
pub struct TxInputNote<const H: usize> {
    pub(crate) merkle_opening: Opening<(), H>,
    pub(crate) note: Note,
    pub(crate) note_pk_p: JubJubAffine,
    pub(crate) value: u64,
    pub(crate) blinding_factor: JubJubScalar,
    pub(crate) nullifier: BlsScalar,
    pub(crate) signature: SignatureDouble,
}

#[derive(Debug, Clone)]
pub struct WitnessTxInputNote {
    pub(crate) note_pk: WitnessPoint,
    pub(crate) note_pk_p: WitnessPoint,
    pub(crate) note_type: Witness,
    pub(crate) pos: Witness,
    pub(crate) value: Witness,
    pub(crate) blinding_factor: Witness,
    pub(crate) nullifier: Witness,
    pub(crate) signature_u: Witness,
    pub(crate) signature_r: WitnessPoint,
    pub(crate) signature_r_p: WitnessPoint,
}

impl<const H: usize> TxInputNote<H> {
    /// Create a tx input note
    pub fn new(
        rng: &mut (impl RngCore + CryptoRng),
        note: Note,
        merkle_opening: poseidon_merkle::Opening<(), H>,
        sk: &SecretKey,
        payload_hash: BlsScalar,
    ) -> Result<Self, PhoenixError> {
        let note_sk = sk.gen_note_sk(&note);
        let note_pk_p =
            JubJubAffine::from(GENERATOR_NUMS_EXTENDED * note_sk.as_ref());

        let vk = ViewKey::from(sk);
        let value = note.value(Some(&vk))?;
        let blinding_factor = note.blinding_factor(Some(&vk))?;

        let nullifier = Hash::digest(
            Domain::Other,
            &[note_pk_p.get_u(), note_pk_p.get_v(), (*note.pos()).into()],
        )[0];

        let signature = note_sk.sign_double(rng, payload_hash);

        Ok(Self {
            merkle_opening,
            note,
            note_pk_p,
            value,
            blinding_factor,
            nullifier,
            signature,
        })
    }

    /// Append the values of the input-note to the circuit
    pub fn append_to_circuit(
        &self,
        composer: &mut Composer,
    ) -> WitnessTxInputNote {
        let nullifier = composer.append_public(self.nullifier);

        let note_pk = composer
            .append_point(*self.note.stealth_address().note_pk().as_ref());
        let note_pk_p = composer.append_point(self.note_pk_p);

        let note_type = composer
            .append_witness(BlsScalar::from(self.note.note_type() as u64));
        let pos = composer.append_witness(BlsScalar::from(*self.note.pos()));

        let value = composer.append_witness(self.value);
        let blinding_factor = composer.append_witness(self.blinding_factor);

        let signature_u = composer.append_witness(*self.signature.u());
        let signature_r = composer.append_point(self.signature.R());
        let signature_r_p = composer.append_point(self.signature.R_prime());

        WitnessTxInputNote {
            note_pk,
            note_pk_p,

            note_type,
            pos,
            value,
            blinding_factor,

            nullifier,

            signature_u,
            signature_r,
            signature_r_p,
        }
    }
}

/// Struct representing a note willing to be created, in a way
/// suitable for being introduced in the transfer circuit
#[derive(Debug, Clone)]
pub struct TxOutputNote {
    pub(crate) value: u64,
    pub(crate) value_commitment: JubJubAffine,
    pub(crate) blinding_factor: JubJubScalar,
}

#[derive(Debug, Clone)]
pub struct WitnessTxOutputNote {
    pub(crate) value: Witness,
    pub(crate) value_commitment: WitnessPoint,
    pub(crate) blinding_factor: Witness,
}

impl TxOutputNote {
    /// Create a new `TxOutputNote`.
    pub fn new(
        value: u64,
        value_commitment: JubJubAffine,
        blinding_factor: JubJubScalar,
    ) -> Self {
        Self {
            value,
            value_commitment,
            blinding_factor,
        }
    }

    /// Append the values of the input-note to the circuit
    pub fn append_to_circuit(
        &self,
        composer: &mut Composer,
    ) -> WitnessTxOutputNote {
        let value = composer.append_witness(self.value);
        let value_commitment =
            composer.append_public_point(self.value_commitment);
        let blinding_factor = composer.append_witness(self.blinding_factor);

        WitnessTxOutputNote {
            value,
            value_commitment,
            blinding_factor,
        }
    }
}

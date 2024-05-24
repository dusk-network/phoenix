// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubScalar};
use dusk_plonk::prelude::*;
use ff::Field;
use jubjub_schnorr::{SecretKey as SchnorrSecretKey, Signature};
use phoenix_circuits::{elgamal, recipient};
use phoenix_core::{PublicKey, SecretKey};
use rand_core::OsRng;

static LABEL: &[u8; 12] = b"dusk-network";
const CAPACITY: usize = 15; // capacity required for the setup
const TX_OUTPUT_NOTES: usize = 2;

#[allow(non_snake_case)]
#[derive(Debug)]
pub struct RecipientCircuit {
    pk: PublicKey,
    note_pks: [JubJubAffine; TX_OUTPUT_NOTES],
    sigs: [Signature; TX_OUTPUT_NOTES],
    recipient_hash: BlsScalar,
    A_encs: [(JubJubExtended, JubJubExtended); TX_OUTPUT_NOTES],
    B_encs: [(JubJubExtended, JubJubExtended); TX_OUTPUT_NOTES],
    r_A: [JubJubScalar; TX_OUTPUT_NOTES],
    r_B: [JubJubScalar; TX_OUTPUT_NOTES],
}

#[allow(non_snake_case)]
impl RecipientCircuit {
    pub fn new(
        pk: &PublicKey,
        note_pks: &[JubJubAffine; TX_OUTPUT_NOTES],
        sigs: &[Signature; TX_OUTPUT_NOTES],
        recipient_hash: &BlsScalar,
        A_encs: &[(JubJubExtended, JubJubExtended); TX_OUTPUT_NOTES],
        B_encs: &[(JubJubExtended, JubJubExtended); TX_OUTPUT_NOTES],
        r_A: &[JubJubScalar; TX_OUTPUT_NOTES],
        r_B: &[JubJubScalar; TX_OUTPUT_NOTES],
    ) -> Self {
        Self {
            pk: *pk,
            note_pks: *note_pks,
            sigs: *sigs,
            recipient_hash: *recipient_hash,
            A_encs: *A_encs,
            B_encs: *B_encs,
            r_A: *r_A,
            r_B: *r_B,
        }
    }
}

#[allow(non_snake_case)]
impl Default for RecipientCircuit {
    fn default() -> Self {
        let sk = SecretKey::random(&mut OsRng);
        let pk = PublicKey::from(&sk);

        Self {
            pk,
            note_pks: [JubJubAffine::default(), JubJubAffine::default()],
            sigs: [Signature::default(), Signature::default()],
            recipient_hash: BlsScalar::default(),
            A_encs: [
                (JubJubExtended::default(), JubJubExtended::default()),
                (JubJubExtended::default(), JubJubExtended::default()),
            ],
            B_encs: [
                (JubJubExtended::default(), JubJubExtended::default()),
                (JubJubExtended::default(), JubJubExtended::default()),
            ],
            r_A: [JubJubScalar::default(), JubJubScalar::default()],
            r_B: [JubJubScalar::default(), JubJubScalar::default()],
        }
    }
}

impl Circuit for RecipientCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        recipient::gadget(
            composer,
            &self.pk,
            &self.note_pks,
            &self.sigs,
            &self.recipient_hash,
            &self.A_encs,
            &self.B_encs,
            &self.r_A,
            &self.r_B,
        )?;

        Ok(())
    }
}

#[allow(non_snake_case)]
#[test]
fn test_recipient_gadget() {
    // Compute the tx output note public keys using
    // the receiver public key
    let sk_receiver = SecretKey::random(&mut OsRng);
    let pk_receiver = PublicKey::from(&sk_receiver);

    let r = JubJubScalar::random(&mut OsRng);
    let sa = pk_receiver.gen_stealth_address(&r);
    let note_pk_1 = sa.note_pk();

    let r = JubJubScalar::random(&mut OsRng);
    let sa = pk_receiver.gen_stealth_address(&r);
    let note_pk_2 = sa.note_pk();

    let note_pks = [
        JubJubAffine::from(note_pk_1.as_ref()),
        JubJubAffine::from(note_pk_2.as_ref()),
    ];

    // Encrypt the public key of the sender. We need to encrypt
    // both 'A' and 'B', using both tx output note public keys
    let sk_sender = SecretKey::random(&mut OsRng);
    let pk_sender = PublicKey::from(&sk_sender);

    let r_A_1 = JubJubScalar::random(&mut OsRng);
    let (A_enc_1_c1, A_enc_1_c2) =
        elgamal::encrypt(note_pk_1.as_ref(), &pk_sender.A(), &r_A_1);

    let r_B_1 = JubJubScalar::random(&mut OsRng);
    let (B_enc_1_c1, B_enc_1_c2) =
        elgamal::encrypt(note_pk_1.as_ref(), &pk_sender.B(), &r_B_1);

    let r_A_2 = JubJubScalar::random(&mut OsRng);
    let (A_enc_2_c1, A_enc_2_c2) =
        elgamal::encrypt(note_pk_2.as_ref(), &pk_sender.A(), &r_A_2);

    let r_B_2 = JubJubScalar::random(&mut OsRng);
    let (B_enc_2_c1, B_enc_2_c2) =
        elgamal::encrypt(note_pk_2.as_ref(), &pk_sender.B(), &r_B_2);

    let A_encs = [(A_enc_1_c1, A_enc_1_c2), (A_enc_2_c1, A_enc_2_c2)];
    let B_encs = [(B_enc_1_c1, B_enc_1_c2), (B_enc_2_c1, B_enc_2_c2)];

    let r_A = [r_A_1, r_A_2];
    let r_B = [r_B_1, r_B_2];

    // Sign the recipient hash using both 'a' and 'b'
    let recipient_hash = BlsScalar::from(1234u64);

    let schnorr_sk_a = SchnorrSecretKey::from(sk_sender.a());
    let sig_A = schnorr_sk_a.sign(&mut OsRng, recipient_hash);

    let schnorr_sk_b = SchnorrSecretKey::from(sk_sender.b());
    let sig_B = schnorr_sk_b.sign(&mut OsRng, recipient_hash);

    let sigs = [sig_A, sig_B];

    // Compute and verify the ZKP
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();

    let (prover, verifier) = Compiler::compile::<RecipientCircuit>(&pp, LABEL)
        .expect("failed to compile circuit");

    let (proof, public_inputs) = prover
        .prove(
            &mut OsRng,
            &RecipientCircuit::new(
                &pk_sender,
                &note_pks,
                &sigs,
                &recipient_hash,
                &A_encs,
                &B_encs,
                &r_A,
                &r_B,
            ),
        )
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Proofs of the current circuits against stored verifier data.
//!
//! `DEPLOYED_VD_*` are copies of the verifier data embedded in rusk's transfer
//! contract, compiled from the circuits of `phoenix-circuits` 0.8. The circuits
//! have changed since, and with them their keys: a proof of the current
//! circuits must not verify against the deployed verifier data. `VD_*` are the
//! verifier data of the current circuits, which compiling them reproduces and
//! their proofs verify against.
//!
//! The files are named as rusk-recovery names verifier data: by the blake3
//! hash of the compressed circuit description followed by the major and minor
//! version of `dusk-plonk`, big-endian `u16`s, 0.20 for the deployed data and
//! 0.24 for the current.
//!
//! The 1- and 2-input circuits compile with the production CRS, the 3- and
//! 4-input ones with the extended CRS only, see `common::EXTENDED_PP`. The
//! extended CRS appends powers of the same secret to the production one, so
//! both compile the 1- and 2-input circuits to the same verifier data.

#![cfg(feature = "plonk")]

use dusk_plonk::prelude::{Compiler, Verifier};
use phoenix_circuits::TxCircuit;
use rand::SeedableRng;
use rand::rngs::StdRng;

mod common;
use common::*;

const DEPLOYED_VD_1_2: &[u8] = include_bytes!(
    "assets/c8fed2bfcc0e0e64709586b56636fc1831be5f0227e533363e9a49b8fae5cd2f.vd"
);
const DEPLOYED_VD_2_2: &[u8] = include_bytes!(
    "assets/98c9786a8cf36f19bcbdf97f4bc140fe402ae5f72cef3f60f24b96071c0faa73.vd"
);
const DEPLOYED_VD_3_2: &[u8] = include_bytes!(
    "assets/1210b96327d25a0403be7b8e027cfe964370700b94ec7f47d22128ecbe7e9803.vd"
);
const DEPLOYED_VD_4_2: &[u8] = include_bytes!(
    "assets/0095785bd378e5cd3c7427c03b6d4420966c03156bf045b556f22419252fc8bc.vd"
);

const VD_1_2: &[u8] = include_bytes!(
    "assets/bf184dc7e0569daef4e74bc6b681e5651b0d5a054b9cfc656d91b83d54343f71.vd"
);
const VD_2_2: &[u8] = include_bytes!(
    "assets/456f644ee101e40eea33af55ad915f4e3c4fd04572da1b00cda57a09050080c3.vd"
);
const VD_3_2: &[u8] = include_bytes!(
    "assets/63cacc7adb37b19b6d10066e2d01ac2939422d9496d27f03dbc875b5458a36a5.vd"
);
const VD_4_2: &[u8] = include_bytes!(
    "assets/929b3a0024cd60e3d56deb039e8a112e78caa3f23060193f21f533ad0557b8e2.vd"
);

/// Compiles the `I`-input circuit to `vd`, and proves a transaction whose
/// proof verifies against `vd` and not against `deployed_vd`.
fn assert_verifier_data<const I: usize>(
    test: &str,
    output_values: [u64; 2],
    vd: &[u8],
    deployed_vd: &[u8],
) {
    let Some(pp) = crs::<I>(test) else {
        return;
    };
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let (prover, verifier) =
        Compiler::compile::<TxCircuit<HEIGHT, I>>(pp, LABEL)
            .expect("failed to compile circuit");
    assert!(
        verifier.to_bytes() == vd,
        "the circuit compiles to other verifier data than the stored one"
    );

    let output_notes_info = [
        create_output_note_information(
            &mut rng,
            output_values[0],
            TP.output_npk[0],
            TP.sender_blinder[0],
        ),
        create_output_note_information(
            &mut rng,
            output_values[1],
            TP.output_npk[1],
            TP.sender_blinder[1],
        ),
    ];

    let (proof, public_inputs) = prover
        .prove(
            &mut rng,
            &TxCircuit::<HEIGHT, I> {
                input_notes_info: core::array::from_fn(|i| {
                    TP.input_notes_info[i].clone()
                }),
                output_notes_info,
                payload_hash: TP.payload_hash,
                root: TP.root,
                deposit: TP.deposit,
                max_fee: TP.max_fee,
                sender_pk: TP.sender_pk,
                signatures: TP.signatures,
            },
        )
        .expect("failed to prove");

    Verifier::try_from_bytes(vd)
        .expect("failed to deserialize stored verifier data")
        .verify(&proof, &public_inputs)
        .expect("proof failed to verify against stored verifier data");

    let deployed = Verifier::try_from_bytes(deployed_vd)
        .expect("failed to deserialize deployed verifier data");
    assert!(
        deployed.verify(&proof, &public_inputs).is_err(),
        "a proof of the current circuit verifies against the deployed \
         verifier data"
    );
}

/// Compiles the `I`-input circuit with the production and the extended CRS,
/// to the same verifier data.
fn assert_crs_extension_keeps_vd<const I: usize>(test: &str) {
    let Some(extended) = extended_crs(test) else {
        return;
    };

    let (_, production) =
        Compiler::compile::<TxCircuit<HEIGHT, I>>(&TP.pp, LABEL)
            .expect("failed to compile circuit with the production CRS");
    let (_, extended) =
        Compiler::compile::<TxCircuit<HEIGHT, I>>(extended, LABEL)
            .expect("failed to compile circuit with the extended CRS");
    assert!(
        production.to_bytes() == extended.to_bytes(),
        "the production and extended CRS compile to other verifier data"
    );
}

#[test]
fn test_verifier_data_1_2() {
    assert_verifier_data::<1>(
        "test_verifier_data_1_2",
        [10, 5],
        VD_1_2,
        DEPLOYED_VD_1_2,
    );
}

#[test]
fn test_verifier_data_2_2() {
    assert_verifier_data::<2>(
        "test_verifier_data_2_2",
        [35, 5],
        VD_2_2,
        DEPLOYED_VD_2_2,
    );
}

#[test]
fn test_verifier_data_3_2() {
    assert_verifier_data::<3>(
        "test_verifier_data_3_2",
        [35, 30],
        VD_3_2,
        DEPLOYED_VD_3_2,
    );
}

#[test]
fn test_verifier_data_4_2() {
    assert_verifier_data::<4>(
        "test_verifier_data_4_2",
        [60, 30],
        VD_4_2,
        DEPLOYED_VD_4_2,
    );
}

#[test]
fn test_crs_extension_keeps_verifier_data_1_2() {
    assert_crs_extension_keeps_vd::<1>(
        "test_crs_extension_keeps_verifier_data_1_2",
    );
}

#[test]
fn test_crs_extension_keeps_verifier_data_2_2() {
    assert_crs_extension_keeps_vd::<2>(
        "test_crs_extension_keeps_verifier_data_2_2",
    );
}

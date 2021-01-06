// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::convert::TryInto;

use assert_matches::*;
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_pki::{Ownable, SecretSpendKey};
use phoenix_core::{Crossover, Error, Fee, Note, NoteType};

#[test]
fn transparent_note() -> Result<(), Error> {
    let rng = &mut rand::thread_rng();

    let ssk = SecretSpendKey::random(rng);
    let psk = ssk.public_key();
    let value = 25;

    let note = Note::transparent(rng, &psk, value);

    assert_eq!(note.note(), NoteType::Transparent);
    assert_eq!(value, note.value(None)?);

    Ok(())
}

#[test]
fn obfuscated_note() -> Result<(), Error> {
    let rng = &mut rand::thread_rng();

    let ssk = SecretSpendKey::random(rng);
    let psk = ssk.public_key();
    let vk = ssk.view_key();
    let value = 25;

    let note = Note::obfuscated(rng, &psk, value);

    assert_eq!(note.note(), NoteType::Obfuscated);
    assert_eq!(value, note.value(Some(&vk))?);

    Ok(())
}

#[test]
fn obfuscated_deterministic_note() -> Result<(), Error> {
    let rng = &mut rand::thread_rng();

    let ssk = SecretSpendKey::random(rng);
    let psk = ssk.public_key();
    let vk = ssk.view_key();
    let value = 25;

    let r = JubJubScalar::random(rng);
    let nonce = JubJubScalar::random(rng);
    let blinding_factor = JubJubScalar::random(rng);

    let note = Note::deterministic(
        NoteType::Obfuscated,
        &r,
        nonce,
        &psk,
        value,
        blinding_factor,
    );

    assert_eq!(value, note.value(Some(&vk))?);
    assert_eq!(blinding_factor, note.blinding_factor(Some(&vk))?);

    Ok(())
}

#[test]
fn value_commitment_transparent() {
    let rng = &mut rand::thread_rng();

    let ssk = SecretSpendKey::random(rng);
    let vsk = ssk.view_key();
    let psk = ssk.public_key();
    let value = 25;

    let note = Note::transparent(rng, &psk, value);

    let value = note
        .value(Some(&vsk))
        .expect("Value not returned with the correct view key");
    let value = JubJubScalar::from(value);

    let blinding_factor = note
        .blinding_factor(Some(&vsk))
        .expect("Blinding factor not returned with the correct view key");

    let commitment = note.value_commitment();
    let commitment_p = (GENERATOR_EXTENDED * value)
        + (GENERATOR_NUMS_EXTENDED * blinding_factor);

    assert_eq!(commitment, &commitment_p);
}

#[test]
fn value_commitment_obfuscated() {
    let rng = &mut rand::thread_rng();

    let ssk = SecretSpendKey::random(rng);
    let vsk = ssk.view_key();
    let psk = ssk.public_key();
    let value = 25;

    let note = Note::obfuscated(rng, &psk, value);

    let value = note
        .value(Some(&vsk))
        .expect("Value not returned with the correct view key");
    let value = JubJubScalar::from(value);

    let blinding_factor = note
        .blinding_factor(Some(&vsk))
        .expect("Blinding factor not returned with the correct view key");

    let commitment = note.value_commitment();
    let commitment_p = (GENERATOR_EXTENDED * value)
        + (GENERATOR_NUMS_EXTENDED * blinding_factor);

    assert_eq!(commitment, &commitment_p);
}

#[test]
fn crossover_fee_decrypt() {
    let rng = &mut rand::thread_rng();

    let ssk = SecretSpendKey::random(rng);
    let vsk = ssk.view_key();
    let psk = ssk.public_key();

    let value = 25;
    let note = Note::obfuscated(rng, &psk, value);

    let (fee, crossover) = note
        .try_into()
        .expect("Failed to generate fee/crossover from an obfuscated noted!");

    let value_p = crossover
        .value(&fee, &vsk)
        .expect("Failed to decrypt value from crossover");
    assert_eq!(value, value_p);

    let blinding_factor = crossover
        .blinding_factor(&fee, &vsk)
        .expect("Failed to decrypt blinding factor from crossover");

    let value = JubJubScalar::from(value_p);
    let commitment = crossover.value_commitment();
    let commitment_p = (GENERATOR_EXTENDED * value)
        + (GENERATOR_NUMS_EXTENDED * blinding_factor);

    assert_eq!(commitment, &commitment_p);
}

#[test]
fn note_keys_consistency() {
    let rng = &mut rand::thread_rng();

    let ssk = SecretSpendKey::random(rng);
    let psk = ssk.public_key();
    let vk = ssk.view_key();
    let value = 25;

    let wrong_ssk = SecretSpendKey::random(rng);
    let wrong_vk = wrong_ssk.view_key();

    assert_ne!(ssk, wrong_ssk);
    assert_ne!(vk, wrong_vk);

    let note = Note::obfuscated(rng, &psk, value);

    assert!(!wrong_vk.owns(&note));
    assert!(vk.owns(&note));
}

#[test]
fn fee_and_crossover_generation() -> Result<(), Error> {
    let rng = &mut rand::thread_rng();

    let ssk = SecretSpendKey::random(rng);
    let psk = ssk.public_key();
    let vk = ssk.view_key();
    let value = 25;

    let note = Note::obfuscated(rng, &psk, value);
    let (fee, crossover): (Fee, Crossover) = note.try_into()?;

    let ssk_fee = SecretSpendKey::random(rng);
    let wrong_fee = Fee::new(rng, 0, 0, &ssk_fee.into());
    let wrong_note: Note = (wrong_fee, crossover).into();

    assert_ne!(note, wrong_note);
    assert_matches!(
        wrong_note.value(Some(&vk)),
        Err(Error::PoseidonError),
        "Expected to fail the decryption of the cipher"
    );

    let correct_note: Note = (fee, crossover).into();

    assert_eq!(note, correct_note);
    assert_eq!(value, correct_note.value(Some(&vk))?);
    Ok(())
}

#[test]
fn fail_fee_and_crossover_from_transparent() -> Result<(), Error> {
    let rng = &mut rand::thread_rng();

    let ssk = SecretSpendKey::random(rng);
    let psk = ssk.public_key();
    let value = 25;

    let note = Note::transparent(rng, &psk, value);
    let result: Result<(Fee, Crossover), Error> = note.try_into();

    assert_matches!(
        result,
        Err(Error::InvalidNoteConversion),
        "Expected to fail the Note Conversion"
    );

    Ok(())
}

#[test]
fn transparent_from_fee_remainder() -> Result<(), Error> {
    let rng = &mut rand::thread_rng();

    let ssk = SecretSpendKey::random(rng);
    let psk = ssk.public_key();
    let vk = ssk.view_key();

    let gas_consumed = 3;
    let gas_limit = 10;
    let gas_price = 2;

    let fee = Fee::new(rng, gas_limit, gas_price, &psk);
    let remainder = fee.gen_remainder(gas_consumed);
    let note = Note::from_remainder(rng, remainder, &psk);

    assert_eq!(note.stealth_address(), fee.stealth_address());
    assert_eq!(
        note.value(Some(&vk))?,
        (gas_limit - gas_consumed) * gas_price
    );

    Ok(())
}

#[test]
fn transparent_from_fee_remainder_with_invalid_consumed() -> Result<(), Error> {
    let rng = &mut rand::thread_rng();

    let ssk = SecretSpendKey::random(rng);
    let psk = ssk.public_key();
    let vk = ssk.view_key();

    let gas_consumed = 30;
    let gas_limit = 10;
    let gas_price = 2;

    let fee = Fee::new(rng, gas_limit, gas_price, &psk);
    let remainder = fee.gen_remainder(gas_consumed);
    let note = Note::from_remainder(rng, remainder, &psk);

    assert_eq!(note.stealth_address(), fee.stealth_address());
    assert_eq!(note.value(Some(&vk))?, 0);

    Ok(())
}

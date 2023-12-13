// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::convert::TryInto;
use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use ff::Field;
use phoenix_core::{
    Crossover, Error, Fee, Note, NoteType, Ownable, PublicKey, SecretKey,
    ViewKey,
};
use rand_core::OsRng;

#[test]
fn transparent_note() -> Result<(), Error> {
    let mut rng = OsRng;

    let ssk = SecretKey::random(&mut rng);
    let psk = PublicKey::from(ssk);
    let value = 25;

    let note = Note::transparent(&mut rng, &psk, value);

    assert_eq!(note.note(), NoteType::Transparent);
    assert_eq!(value, note.value(None)?);

    Ok(())
}

#[test]
fn transparent_stealth_note() -> Result<(), Error> {
    let mut rng = OsRng;

    let ssk = SecretKey::random(&mut rng);
    let psk = PublicKey::from(ssk);

    let r = JubJubScalar::random(&mut rng);

    let sa = psk.gen_stealth_address(&r);
    let nonce = BlsScalar::random(&mut rng);
    let value = 25;

    let note = Note::transparent_stealth(sa, value, nonce);

    assert_eq!(note.note(), NoteType::Transparent);
    assert_eq!(value, note.value(None)?);
    assert_eq!(sa, *note.stealth_address());

    Ok(())
}

#[test]
fn obfuscated_note() -> Result<(), Error> {
    let mut rng = OsRng;

    let ssk = SecretKey::random(&mut rng);
    let psk = PublicKey::from(ssk);
    let vk = ViewKey::from(ssk);
    let value = 25;

    let blinding_factor = JubJubScalar::random(&mut rng);
    let note = Note::obfuscated(&mut rng, &psk, value, blinding_factor);

    assert_eq!(note.note(), NoteType::Obfuscated);
    assert_eq!(value, note.value(Some(&vk))?);

    Ok(())
}

#[test]
fn obfuscated_deterministic_note() -> Result<(), Error> {
    let mut rng = OsRng;

    let ssk = SecretKey::random(&mut rng);
    let psk = PublicKey::from(ssk);
    let vk = ViewKey::from(ssk);
    let value = 25;

    let r = JubJubScalar::random(&mut rng);
    let nonce = BlsScalar::random(&mut rng);
    let blinding_factor = JubJubScalar::random(&mut rng);

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
    let mut rng = OsRng;

    let ssk = SecretKey::random(&mut rng);
    let vk = ViewKey::from(ssk);
    let psk = PublicKey::from(ssk);
    let value = 25;

    let note = Note::transparent(&mut rng, &psk, value);

    let value = note
        .value(Some(&vk))
        .expect("Value not returned with the correct view key");
    let value = JubJubScalar::from(value);

    let blinding_factor = note
        .blinding_factor(Some(&vk))
        .expect("Blinding factor not returned with the correct view key");

    let commitment = note.value_commitment();
    let commitment_p = (GENERATOR_EXTENDED * value)
        + (GENERATOR_NUMS_EXTENDED * blinding_factor);

    assert_eq!(commitment, &commitment_p);
}

#[test]
fn value_commitment_obfuscated() {
    let mut rng = OsRng;

    let ssk = SecretKey::random(&mut rng);
    let vk = ViewKey::from(ssk);
    let psk = PublicKey::from(ssk);
    let value = 25;

    let blinding_factor = JubJubScalar::random(&mut rng);
    let note = Note::obfuscated(&mut rng, &psk, value, blinding_factor);

    let value = note
        .value(Some(&vk))
        .expect("Value not returned with the correct view key");
    let value = JubJubScalar::from(value);

    let blinding_factor = note
        .blinding_factor(Some(&vk))
        .expect("Blinding factor not returned with the correct view key");

    let commitment = note.value_commitment();
    let commitment_p = (GENERATOR_EXTENDED * value)
        + (GENERATOR_NUMS_EXTENDED * blinding_factor);

    assert_eq!(commitment, &commitment_p);
}

#[test]
fn note_keys_consistency() {
    let mut rng = OsRng;

    let ssk = SecretKey::random(&mut rng);
    let psk = PublicKey::from(ssk);
    let vk = ViewKey::from(ssk);
    let value = 25;

    let wrong_ssk = SecretKey::random(&mut rng);
    let wrong_vk = ViewKey::from(wrong_ssk);

    assert_ne!(ssk, wrong_ssk);
    assert_ne!(vk, wrong_vk);

    let blinding_factor = JubJubScalar::random(&mut rng);
    let note = Note::obfuscated(&mut rng, &psk, value, blinding_factor);

    assert!(!wrong_vk.owns(&note));
    assert!(vk.owns(&note));
}

#[test]
fn fee_and_crossover_generation() -> Result<(), Error> {
    let mut rng = OsRng;

    let ssk = SecretKey::random(&mut rng);
    let psk = PublicKey::from(ssk);
    let vk = ViewKey::from(ssk);
    let value = 25;

    let blinding_factor = JubJubScalar::random(&mut rng);
    let note = Note::obfuscated(&mut rng, &psk, value, blinding_factor);
    let (fee, crossover): (Fee, Crossover) = note.try_into()?;

    let ssk_fee = SecretKey::random(&mut rng);
    let wrong_fee = Fee::new(&mut rng, 0, 0, &ssk_fee.into());
    let wrong_note: Note = (wrong_fee, crossover).into();

    assert_ne!(note, wrong_note);
    assert!(
        matches!(wrong_note.value(Some(&vk)), Err(Error::InvalidCipher),),
        "Expected to fail the decryption of the cipher"
    );

    let correct_note: Note = (fee, crossover).into();

    assert_eq!(note, correct_note);
    assert_eq!(value, correct_note.value(Some(&vk))?);
    Ok(())
}

#[test]
fn fail_fee_and_crossover_from_transparent() {
    let mut rng = OsRng;

    let ssk = SecretKey::random(&mut rng);
    let psk = PublicKey::from(ssk);
    let value = 25;

    let note = Note::transparent(&mut rng, &psk, value);
    let result: Result<(Fee, Crossover), Error> = note.try_into();

    assert!(
        matches!(result, Err(Error::InvalidNoteConversion),),
        "Expected to fail the Note Conversion"
    );
}

#[test]
fn transparent_from_fee_remainder() -> Result<(), Error> {
    let mut rng = OsRng;

    let ssk = SecretKey::random(&mut rng);
    let psk = PublicKey::from(ssk);
    let vk = ViewKey::from(ssk);

    let gas_consumed = 3;
    let gas_limit = 10;
    let gas_price = 2;

    let fee = Fee::new(&mut rng, gas_limit, gas_price, &psk);
    let remainder = fee.gen_remainder(gas_consumed);
    let note = Note::from(remainder);

    assert_eq!(note.stealth_address(), fee.stealth_address());
    assert_eq!(
        note.value(Some(&vk))?,
        (gas_limit - gas_consumed) * gas_price
    );

    Ok(())
}

#[test]
fn transparent_from_fee_remainder_with_invalid_consumed() -> Result<(), Error> {
    let mut rng = OsRng;

    let ssk = SecretKey::random(&mut rng);
    let psk = PublicKey::from(ssk);
    let vk = ViewKey::from(ssk);

    let gas_consumed = 30;
    let gas_limit = 10;
    let gas_price = 2;

    let fee = Fee::new(&mut rng, gas_limit, gas_price, &psk);
    let remainder = fee.gen_remainder(gas_consumed);
    let note = Note::from(remainder);

    assert_eq!(note.stealth_address(), fee.stealth_address());
    assert_eq!(note.value(Some(&vk))?, 0);

    Ok(())
}

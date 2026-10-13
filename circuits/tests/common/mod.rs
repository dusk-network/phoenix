// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::LazyLock;

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{GENERATOR_NUMS_EXTENDED, JubJubAffine, JubJubScalar};
use dusk_plonk::prelude::PublicParameters;
use ff::Field;
use jubjub_elgamal::Encryption as ElGamal;
use jubjub_schnorr::{
    SecretKey as SchnorrSecretKey, Signature as SchnorrSignature,
};
pub use phoenix_circuits::{InputNoteInfo, OutputNoteInfo};
use phoenix_core::{
    Note, OUTPUT_NOTES, PublicKey, SecretKey, ViewKey, value_commitment,
};
use poseidon_merkle::{Item, Tree};
use rand::rngs::StdRng;
use rand::{CryptoRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};

const CRS_URL: &str = "https://testnet.nodes.dusk.network/trusted-setup";
const CRS_HASH: &str =
    "6161605616b62356cf09fa28252c672ef53b2c8489ad5f81d87af26e105f6059";

fn crs_cache_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .expect("failed to get home directory");
    PathBuf::from(home)
        .join(".dusk")
        .join("rusk")
        .join("devnet-piecrust.crs")
}

fn verify_crs(data: &[u8]) -> bool {
    let hash = format!("{:x}", Sha256::digest(data));
    hash == CRS_HASH
}

/// The production CRS, read from the cache or downloaded.
///
/// It has `2^17 + 6` powers, which fit the 1- and 2-input circuits only:
/// `dusk-plonk` 0.24 needs `2^17 + 9` for the 3- and 4-input circuits, see
/// [`EXTENDED_PP`].
pub fn load_production_crs() -> PublicParameters {
    let cache_path = crs_cache_path();

    // try loading from cache
    if let Ok(data) = fs::read(&cache_path)
        && verify_crs(&data)
    {
        return PublicParameters::from_slice(&data)
            .expect("failed to deserialize cached CRS");
    }

    // download from network
    eprintln!("CRS not found in cache, downloading from {CRS_URL}");
    let mut data = Vec::new();
    ureq::get(CRS_URL)
        .call()
        .expect("failed to download CRS")
        .into_body()
        .into_reader()
        .read_to_end(&mut data)
        .expect("failed to read CRS response");

    assert!(verify_crs(&data), "downloaded CRS hash mismatch");

    // cache for future runs
    if let Some(parent) = cache_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&cache_path, &data);

    PublicParameters::from_slice(&data)
        .expect("failed to deserialize downloaded CRS")
}

/// The variable naming the file of the extended CRS.
const EXTENDED_CRS_VAR: &str = "PHOENIX_EXTENDED_CRS";

/// SHA-256 of the production CRS extended to `2^17 + 9` powers of the same
/// secret: the production file with three more powers appended.
const EXTENDED_CRS_HASH: &str =
    "888fbab6c9d267c26199d9fd1a8c21f315590459ae180bc9e6a27aa433479d03";

/// The extended CRS, read from the file `PHOENIX_EXTENDED_CRS` names and
/// checked against its SHA-256, or `None` if the variable is unset.
///
/// The 3- and 4-input circuits need it. Until it is hosted publicly next to
/// the production CRS, their tests skip when it is not given.
pub static EXTENDED_PP: LazyLock<Option<PublicParameters>> =
    LazyLock::new(|| {
        let path = std::env::var_os(EXTENDED_CRS_VAR)?;
        let data = fs::read(&path).unwrap_or_else(|e| {
            panic!("failed to read the extended CRS at {path:?}: {e}")
        });
        let hash = format!("{:x}", Sha256::digest(&data));
        assert_eq!(hash, EXTENDED_CRS_HASH, "extended CRS hash mismatch");

        Some(
            PublicParameters::from_slice(&data)
                .expect("failed to deserialize the extended CRS"),
        )
    });

/// The extended CRS, or `None` after telling that `test` skips without it.
///
/// The notice goes to the process' stderr, so it shows without
/// `--nocapture`.
pub fn extended_crs(test: &str) -> Option<&'static PublicParameters> {
    let pp = EXTENDED_PP.as_ref();
    if pp.is_none() {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED {test}: needs the CRS extended to 2^17 + 9 powers; set \
             {EXTENDED_CRS_VAR} to its path"
        );
    }
    pp
}

/// The CRS to compile an `I`-input circuit with: the production CRS for one
/// and two inputs, the extended CRS for more, see [`extended_crs`].
// Each test binary uses a different subset of the helpers.
#[allow(dead_code)]
pub fn crs<const I: usize>(test: &str) -> Option<&'static PublicParameters> {
    match I {
        0..=2 => Some(&TP.pp),
        _ => extended_crs(test),
    }
}

pub static LABEL: &[u8; 12] = b"dusk-network";

pub const HEIGHT: usize = 17;

// Each test binary reads a different subset of the fields.
#[allow(dead_code)]
pub struct TestingParameters {
    pub pp: PublicParameters,
    pub input_notes_info: Vec<InputNoteInfo<HEIGHT>>,
    pub payload_hash: BlsScalar,
    pub root: BlsScalar,
    pub deposit: u64,
    pub max_fee: u64,
    pub sender_sk: SecretKey,
    pub sender_pk: PublicKey,
    pub output_npk: [JubJubAffine; OUTPUT_NOTES],
    pub signatures: (SchnorrSignature, SchnorrSignature),
    pub sender_blinder: [[JubJubScalar; 2]; OUTPUT_NOTES],
}

pub static TP: LazyLock<TestingParameters> = LazyLock::new(|| {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let pp = load_production_crs();
    let sender_sk = SecretKey::random(&mut rng);
    let sender_pk = PublicKey::from(&sender_sk);
    let receiver_pk = PublicKey::from(&SecretKey::random(&mut rng));

    let mut tree = Tree::<(), HEIGHT>::new();
    let payload_hash = BlsScalar::from(1234u64);

    let input_notes_info = create_test_input_notes_information(
        &mut rng,
        &mut tree,
        &sender_sk,
        payload_hash,
    );

    let root = tree.root().hash;

    let deposit = 5;
    let max_fee = 5;

    let receiver_npk = *receiver_pk
        .gen_stealth_address(&JubJubScalar::random(&mut rng))
        .note_pk()
        .as_ref();
    let sender_npk = *sender_pk
        .gen_stealth_address(&JubJubScalar::random(&mut rng))
        .note_pk()
        .as_ref();
    let output_npk = [
        JubJubAffine::from(receiver_npk),
        JubJubAffine::from(sender_npk),
    ];

    let schnorr_sk_a = SchnorrSecretKey::from(sender_sk.a());
    let sig_a = schnorr_sk_a.sign(&mut rng, payload_hash);
    let schnorr_sk_b = SchnorrSecretKey::from(sender_sk.b());
    let sig_b = schnorr_sk_b.sign(&mut rng, payload_hash);

    let sender_blinder_0 = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];
    let sender_blinder_1 = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];

    TestingParameters {
        pp,
        input_notes_info,
        payload_hash,
        root,
        deposit,
        max_fee,
        sender_sk,
        sender_pk,
        output_npk,
        signatures: (sig_a, sig_b),
        sender_blinder: [sender_blinder_0, sender_blinder_1],
    }
});

fn create_and_insert_test_note(
    rng: &mut (impl RngCore + CryptoRng),
    tree: &mut Tree<(), HEIGHT>,
    sender_pk: &PublicKey,
    pos: u64,
    value: u64,
) -> Note {
    let sender_blinder = [
        JubJubScalar::random(&mut *rng),
        JubJubScalar::random(&mut *rng),
    ];

    let mut note =
        Note::transparent(rng, sender_pk, sender_pk, value, sender_blinder);
    note.set_pos(pos);

    let item = Item {
        hash: note.hash(),
        data: (),
    };
    tree.insert(*note.pos(), item);

    note
}

fn create_test_input_notes_information(
    rng: &mut (impl RngCore + CryptoRng),
    tree: &mut Tree<(), HEIGHT>,
    sender_sk: &SecretKey,
    payload_hash: BlsScalar,
) -> Vec<InputNoteInfo<HEIGHT>> {
    let sender_pk = PublicKey::from(sender_sk);
    let sender_vk = ViewKey::from(sender_sk);
    let total_inputs = 4;

    let mut notes = Vec::new();
    for i in 0..total_inputs {
        notes.push(create_and_insert_test_note(
            rng,
            tree,
            &sender_pk,
            i.try_into().unwrap(),
            25,
        ));
    }

    let mut input_notes_info = Vec::new();
    for note in notes.into_iter() {
        let note_sk = sender_sk
            .gen_note_sk(note.stealth_address())
            .expect("sender_sk should own the note");
        let merkle_opening = tree
            .opening(*note.pos())
            .expect("There should be a note at the given position");
        let note_pk_p =
            JubJubAffine::from(GENERATOR_NUMS_EXTENDED * note_sk.as_ref());
        let value = note
            .value(Some(&sender_vk))
            .expect("sender_sk should own the note");
        let value_blinder = note
            .value_blinder(Some(&sender_vk))
            .expect("sender_sk should own the note");
        let nullifier = note
            .gen_nullifier(sender_sk)
            .expect("sender_sk should own the note");
        let signature = note_sk.sign_double(rng, payload_hash);
        input_notes_info.push(InputNoteInfo {
            merkle_opening,
            note,
            note_pk_p,
            value,
            value_blinder,
            nullifier,
            signature,
        });
    }

    input_notes_info
}

// Each test binary uses a different subset of the helpers.
#[allow(dead_code)]
pub fn create_output_note_information(
    rng: &mut (impl RngCore + CryptoRng),
    value: u64,
    note_pk: JubJubAffine,
    sender_blinder: [JubJubScalar; 2],
) -> OutputNoteInfo {
    let value_blinder = JubJubScalar::random(&mut *rng);
    let value_commitment = value_commitment(value, value_blinder);

    let sender_blinder_a = sender_blinder[0];
    let (sender_enc_a, _) = ElGamal::encrypt(
        &note_pk.into(),
        TP.sender_pk.A(),
        None,
        &sender_blinder_a,
    )
    .expect("the sender key encrypts to the note public key");

    let sender_blinder_b = sender_blinder[1];
    let (sender_enc_b, _) = ElGamal::encrypt(
        &note_pk.into(),
        TP.sender_pk.B(),
        None,
        &sender_blinder_b,
    )
    .expect("the sender key encrypts to the note public key");

    let sender_enc_a = (sender_enc_a.c1().into(), sender_enc_a.c2().into());
    let sender_enc_b = (sender_enc_b.c1().into(), sender_enc_b.c2().into());

    OutputNoteInfo {
        value,
        value_commitment,
        value_blinder,
        note_pk,
        sender_enc: [sender_enc_a, sender_enc_b],
        sender_blinder,
    }
}

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2025-02-07

### Changed

- Update `dusk-bls12_381` to v0.14
- Update `dusk-jubjub` to v0.15
- Update `poseidon-merkle` to v0.8
- Update `dusk-poseidon` to v0.41
- Update `jubjub-schnorr` to v0.6
- Update `jubjub-elgamal` to v0.2
- Update `dusk-plonk` to v0.21

## [0.5.0] - 2024-12-18

### Added

- Add jubjub-elgamal dependency [#255]

### Changed

- Update phoenix-core to v0.33

### Removed

- Remove elgamal encryption module [#255]

## [0.4.0] - 2024-08-14

### Changed

- Update dusk-plonk to v0.20
- Update dusk-poseidon to v0.40
- Update jubjub-schnorr to v0.5
- Update poseidon-merkle to v0.7

## [0.3.0] - 2024-08-14

### Removed

- Delete `TxInputNoteWitness` struct [#229]
- Delete `TxCircuit::new` constructor [#229]
- Delete `TxOutputNote::new` constructor [#229]

### Changed

- Make all `TxCircuit` fields public [#229]
- Make all `TxOutputNote` fields public [#229]
- Move `sender_blinder` field from `TxCircuit` to `TxOutputNote` [#229]
- Move `TxCircuit` from `transaction` module to root module [#229]
- Rename `TxInputNote` to `InputNoteInfo` [#229]
- Rename `TxOutputNote` to `OutputNoteInfo` [#229]
- Move `ff` and `rand` dependencies to dev-dependencies [#235]

### Added

- Add `dusk-bytes` dependency at v0.1 [#232]
- Add `TxCircuit::from_slice` and `TxCircuit::to_var_bytes` [#232]
- Add `InputNoteInfo::from_slice` and `InputNoteInfo::to_var_bytes` [#232]
- Add `Serializable` trait implementation for `OutputNoteInfo` [#232]
- Add `Clone` and `PartialEq` derives for `TxCircuit` [#232]
- Add `PartialEq` derive for `InputNoteInfo` [#232]
- Add associated const `TxCircuit::SIZE`
- Add associated const `InputNoteInfo::SIZE`
- Add `PartialEq` derive for `OutputNoteInfo` [#232]
- Add `dusk-bls12_381` dependency [#235]
- Add `"plonk"` feature to add the `dusk-plonk` dependency [#235]
- Add `"plonk"` feature as default feature [#235]
- Add `"rkyv-impl"` feature
- Add rkyv dependencies behind `rkyv-impl` feature
- Add rkyv derives for `TxCircuit`, `InputNoteInfo` and `OutputNoteInfo`

## [0.2.1] - 2024-07-03

### Changed

- Make `TxInputNote` fields public

## [0.2.0] - 2024-06-19

### Added

- Add Recipient gadget [#197]

### Changed

- Rename `recipient` module to `sender_enc` [#214]
- Rename `blinding_factor` to `value_blinder` [#214]
- Add `sender_enc` field to `TxOutputNote` [#214]
- Add `note_pk` field to `TxOutputNote` [#214]
- Add `sender_pk`, `signatures`, `output_npk` and `sender_blinder` fields to `TxCircuit` [#214]
- Remove `ViewKey` from `TxOutputNote::new()` parameters [#191]
- Make `rng` the first param in `TxInputNote::new` [#189]
- Rename `crossover` to `deposit` [#190]
- Remove recomputation of `value_commitment` in `TxOutputNote::New()`
- Rename `skeleton_hash` to `payload_hash` [#188]
- Make `TxCircuit` to use the Recipient gadget

### Removed

- Remove `WitnessTxOutputNote` struct [#214]
- Remove `RecipientParameters` struct [#214]
- Remove `elgamal::encrypt` and `elgamal::decrypt`

## [0.1.0] - 2024-05-22

### Added

- Add `phoenix-circuits` as a workspace member of `phoenix` [#171]
- Add elgamal encryption and decryption gadgets [#171]
- Add the `transaction` module [#169]

### Changed

- Change the gadget input to match the order of the circuits public inputs [#177]
- Update `dusk-poseidon` to v0.39 [#179]
- Update `jubjub-schnorr` to v0.4 [#179]
- Update `poseidon-merkle` to v0.6 [#179]

<!-- ISSUES -->
[#255]: https://github.com/dusk-network/phoenix/issues/255
[#235]: https://github.com/dusk-network/phoenix/issues/235
[#232]: https://github.com/dusk-network/phoenix/issues/232
[#229]: https://github.com/dusk-network/phoenix/issues/229
[#214]: https://github.com/dusk-network/phoenix/issues/214
[#201]: https://github.com/dusk-network/phoenix/issues/201
[#197]: https://github.com/dusk-network/phoenix/issues/197
[#188]: https://github.com/dusk-network/phoenix/issues/188
[#191]: https://github.com/dusk-network/phoenix/issues/191
[#190]: https://github.com/dusk-network/phoenix/issues/190
[#189]: https://github.com/dusk-network/phoenix/issues/189
[#179]: https://github.com/dusk-network/phoenix/issues/179
[#177]: https://github.com/dusk-network/phoenix/issues/177
[#171]: https://github.com/dusk-network/phoenix/issues/171
[#169]: https://github.com/dusk-network/phoenix/issues/169

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/phoenix/compare/circuits_v0.6.0...HEAD
[0.6.0]: https://github.com/dusk-network/phoenix/compare/circuits_v0.5.0...circuits_v0.6.0
[0.5.0]: https://github.com/dusk-network/phoenix/compare/circuits_v0.4.0...circuits_v0.5.0
[0.4.0]: https://github.com/dusk-network/phoenix/compare/circuits_v0.3.0...circuits_v0.4.0
[0.3.0]: https://github.com/dusk-network/phoenix/compare/circuits_v0.2.1...circuits_v0.3.0
[0.2.1]: https://github.com/dusk-network/phoenix/compare/circuits_v0.2.0...circuits_v0.2.1
[0.2.0]: https://github.com/dusk-network/phoenix/compare/circuits_v0.1.0...circuits_v0.2.0
[0.1.0]: https://github.com/dusk-network/phoenix/releases/tag/circuits_v0.1.0

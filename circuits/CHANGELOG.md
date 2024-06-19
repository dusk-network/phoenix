# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
[Unreleased]: https://github.com/dusk-network/phoenix/compare/circuits_v0.1.0...HEAD
[0.2.0]: https://github.com/dusk-network/phoenix/compare/circuits_v0.1.0...circuits_v0.2.0
[0.1.0]: https://github.com/dusk-network/phoenix/releases/tag/circuits_v0.1.0

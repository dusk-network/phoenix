# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Remove `ViewKey` from `TxOutputNote::new()` parameters [#191]

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
[#191]: https://github.com/dusk-network/phoenix/issues/191
[#179]: https://github.com/dusk-network/phoenix/issues/179
[#177]: https://github.com/dusk-network/phoenix/issues/177
[#171]: https://github.com/dusk-network/phoenix/issues/171
[#169]: https://github.com/dusk-network/phoenix/issues/169

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/phoenix/compare/circuits_v0.1.0...HEAD
[0.1.0]: https://github.com/dusk-network/phoenix/releases/tag/circuits_v0.1.0

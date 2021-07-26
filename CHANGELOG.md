# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.13.0] - 2021-07-27

### Changed

- Update dusk-poseidon to `v0.22` [#94]
- Update dusk-pki to `v0.8` [#94]

## [0.12.0] - 2021-07-05

### Added

- Add `dusk-bytes::BadLength` impl for crate Error [#88]
- Add `From<Error>` impl for `dusk-bytes::Error` [#92]

### Changed

- Change `JubJubScalar` for `BlsScalar` for all `nonce` attributes. [#84]

## [0.11.0] - 2021-06-09

### Added

- Add rust-toolchain file set to nightly-2021-06-06 [#85]

### Changed
- Change CI rules to get toolchain from file [#86]
- Change `Crossover` to use all attributes as hash inputs [#69]
- Change `Message` to use all attributes as hash inputs [#69]
- Update `canonical` from `v0.5` to `v0.6` [#72]
- Change note position to reference [#76]
- Change `rand_core` to not use default features [#80]

## [0.10.0] - 2021-04-06

### Changed

- Update dusk-poseidon to `v0.20` [#67]

## [0.9.1] - 2021-02-11

### Changed

- Update dusk-pki to `v0.6` [#61]

## [0.9.0] - 2021-02-11

### Changed

- Update dusk-poseidon to `v0.18` [#61]

## [0.8.0] - 2021-02-11

### Added

- Add conversion from `Remainder` to (transparent) `Note`

### Removed

- Remove `Note::from_remainder` method

## [0.7.4] - 2021-02-09

### Changed

- Bump `dusk-pki` to `v0.5.3`

## [0.7.3] - 2021-02-09

### Changed

- Bump `dusk-pki` to `v0.5.2`

## [0.7.2] - 2021-02-01

### Changed

- Bump `poseidon252` to `v0.17.0`
- Bump `dusk-pki` to `v0.5.1`

## [0.7.1] - 2021-01-29

### Changed

- Implement provable-encryption friendly `Message` type

## [0.7.0] - 2021-01-07

### Added

- Add `dusk_bytes::Serializable` trait to `Note`, `Fee` and `Crossover`

### Removed

- Remove manual implementation of `to_bytes` and `from_bytes`

### Changed

- Bump `canonical` to `v0.5`
- Bump `dusk-bls12_381` to v0.6
- Bump `dusk-jubjub` to `v0.8`
- Bump `poseidon252` to `v0.16.0`
- Bump `dusk-pki` to `v0.5`
- Update CHANGELOG to ISO 8601

## [0.6.0] - 2021-01-07

### Changed

- Blinding factor provided to create obfuscated notes

## [0.5.1] - 2021-01-06

### Fixed

- #41 - Wrong value commitment for transparent notes

## [0.5.0] - 2020-11-27

### Added

- To/From bytes impl for `Fee` & `Crossover`.

## [0.5.0-alpha] - 2020-11-27

### Changed

- No-Std compatibility.
- Removal of anyhow error implementation.
- Canonical implementation shielded by feature.

[#94]: https://github.com/dusk-network/phoenix-core/issues/94
[#92]: https://github.com/dusk-network/phoenix-core/issues/92
[#88]: https://github.com/dusk-network/phoenix-core/issues/88
[#86]: https://github.com/dusk-network/phoenix-core/issues/86
[#85]: https://github.com/dusk-network/phoenix-core/issues/85
[#84]: https://github.com/dusk-network/phoenix-core/issues/84
[#80]: https://github.com/dusk-network/phoenix-core/issues/80
[#76]: https://github.com/dusk-network/phoenix-core/issues/76
[#72]: https://github.com/dusk-network/phoenix-core/issues/72
[#69]: https://github.com/dusk-network/phoenix-core/issues/69
[#67]: https://github.com/dusk-network/phoenix-core/issues/67
[#61]: https://github.com/dusk-network/phoenix-core/issues/61
[unreleased]: https://github.com/dusk-network/phoenix-core/compare/v0.11.0...HEAD
[0.12.0]: https://github.com/dusk-network/phoenix-core/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/dusk-network/phoenix-core/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/dusk-network/phoenix-core/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/dusk-network/phoenix-core/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/dusk-network/phoenix-core/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/dusk-network/phoenix-core/compare/v0.7.4...v0.8.0
[0.7.4]: https://github.com/dusk-network/phoenix-core/compare/v0.7.3...v0.7.4
[0.7.3]: https://github.com/dusk-network/phoenix-core/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/dusk-network/phoenix-core/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/dusk-network/phoenix-core/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/dusk-network/phoenix-core/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/dusk-network/phoenix-core/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/dusk-network/phoenix-core/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/dusk-network/phoenix-core/compare/v0.3.1...v0.5.0
[0.3.1]: https://github.com/dusk-network/phoenix-core/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/dusk-network/phoenix-core/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/dusk-network/phoenix-core/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dusk-network/phoenix-core/releases/tag/v0.1.0

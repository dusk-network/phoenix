# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

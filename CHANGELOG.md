# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.2] - 06-01-21
### Added
- API to decrypt value and blinding factor from a crossover
- Note::new is not part of the public API
- Blinding factor should be returned when creating obfuscated note

## [0.5.1] - 06-01-21
### Fix
- #41 - Wrong value commitment for transparent notes

## [0.5.0] - 27-11-20
### Added
- To/From bytes impl for `Fee` & `Crossover`.

## [0.5.0-alpha] - 27-11-20
### Changed
- No-Std compatibility.
- Removal of anyhow error implementation.
- Canonical implementation shielded by feature.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Removed unnecessary complexity/flexibility by returning `None` instead of `Any` from abstract methods whose return values are not used

## [1.0.3] - 8th of November 2022

### Changed
- Exclude tests from the packages

## [1.0.2] - 5th of November 2022

### Changed
- Fixed a bug in the way the storage models were versioned

## [1.0.1] - 3rd of November 2022

### Added
- Python 3.11 to the list of supported versions

## [1.0.0] - 1st of November 2022

### Added
- Rewrite for modern, type safe Python 3.

### Removed
- Pre-stable (i.e. versions before 1.0.0) changelog omitted.

[Unreleased]: https://github.com/Syndace/python-doubleratchet/compare/v1.0.3...HEAD
[1.0.3]: https://github.com/Syndace/python-doubleratchet/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Syndace/python-doubleratchet/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Syndace/python-doubleratchet/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Syndace/python-doubleratchet/releases/tag/v1.0.0

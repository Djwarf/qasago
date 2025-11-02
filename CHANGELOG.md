# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Concurrent access tests to verify thread safety
- Large data tests for payloads > 1MB (up to 10MB)
- Benchmarks for various data sizes (1KB to 1MB)
- Example tests for godoc documentation
- Key rotation example in README
- Goroutine safety documentation in README
- This CHANGELOG file

### Changed
- Updated test coverage percentage in README from 89.7% to 91.4%

### Fixed
- None

## [1.0.0] - 2025-01-01

### Added
- Initial release of QasaGo
- AES-256-GCM encryption and decryption
- Key generation and management utilities
- Base64 encoding for text-safe storage
- Comprehensive error handling with sentinel errors
- Multiple API styles (functional and object-oriented)
- Type-safe wrappers for encryption primitives
- Extensive test suite with 91.4% coverage
- Performance benchmarks
- CI/CD pipeline with GitHub Actions
- Cross-platform support (Linux, Windows, macOS)
- Security scanning with Gosec and Trivy
- Comprehensive documentation and examples
- MIT License

### Security
- Uses crypto/rand for secure random generation
- Automatic nonce generation for each encryption
- GCM mode provides authentication and integrity
- Generic error messages to prevent information leakage
- Validation against all-zero keys

[Unreleased]: https://github.com/djwarf/qasago/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/djwarf/qasago/releases/tag/v1.0.0
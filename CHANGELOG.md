# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] – 2025-11-21

### Added

- Initial RSA encryption functionality:
    - Loading RSA private and public keys from files
    - RSA encryption and decryption with PKCS1v15 padding
    - Base64 encoding support for encrypted data
- Initial AES encryption functionality:
    - AES-256 encryption in CTR mode
    - Key and IV derivation from secret
    - Support for UUID encryption/decryption
    - Base64 encoding support for encrypted data
- Dependencies:
    - github.com/google/uuid
    - github.com/kuetix/uuid

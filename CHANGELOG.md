# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of SOPS Operator
- SopsSecret CRD for managing SOPS-encrypted secrets
- AGE encryption support via SOPS CLI
- Automatic Secret creation from decrypted data
- Owner references for automatic cleanup on SopsSecret deletion
- Status conditions (Ready, Decrypted) for observability
- Kubernetes Events for reconciliation feedback
- Suspend functionality for maintenance windows
- Multi-arch Docker images (amd64, arm64)
- Comprehensive test suite
- GitHub Actions CI/CD pipeline
- Dependabot for automated dependency updates

### Security
- Context-based timeout for SOPS CLI execution
- No secrets stored in logs or events

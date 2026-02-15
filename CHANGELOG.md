# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1](https://github.com/scalaric/sops-operator/compare/v1.0.0...v1.0.1) (2026-02-09)


### Bug Fixes

* add robots.txt with sitemap reference ([28e65e1](https://github.com/scalaric/sops-operator/commit/28e65e15ebc3174c9b0335ec9967753257be38b9))
* copy Google verification file to site ([4f0ab2d](https://github.com/scalaric/sops-operator/commit/4f0ab2d8905f3ad0fbefe950e7f974a5ab7f8810))
* enable emoji rendering in docs ([bea5f4a](https://github.com/scalaric/sops-operator/commit/bea5f4aae33883659699a3118bdb5f6a02ff0446))
* pin setup-envtest to commit SHA for Scorecard compliance ([#13](https://github.com/scalaric/sops-operator/issues/13)) ([2a6b8b8](https://github.com/scalaric/sops-operator/commit/2a6b8b8a06583a67a35e6d1faaad1da41c732a89))

## 1.0.0 (2026-01-15)


### Features

* add Dependabot auto-merge for patch/minor updates ([d15fd55](https://github.com/scalaric/sops-operator/commit/d15fd55b6531260d6c381695adbaa2afe0975453))
* add Dependabot for automatic dependency updates ([552fc59](https://github.com/scalaric/sops-operator/commit/552fc59113bd4c77bb208bcd79d7156d35e79f64))
* add professional release management ([1edd4cf](https://github.com/scalaric/sops-operator/commit/1edd4cf376586e2af2fd2e6cb5a0f39cb21bf02a))


### Bug Fixes

* CI and lint issues, update for scalaric org ([1498914](https://github.com/scalaric/sops-operator/commit/149891492834cb3182c8834c82744d59483f6e34))
* CI fixes and add Renovate for dependency management ([bccd1cb](https://github.com/scalaric/sops-operator/commit/bccd1cb55c91a116161b72521bcb0a2ccb6df1f7))
* downgrade to Go 1.24 compatible dependencies ([4e1b44d](https://github.com/scalaric/sops-operator/commit/4e1b44d2f10440f9d3a1a573e2f58d3076610b46))
* update golangci-lint-action to v7, fix envtest path ([549e200](https://github.com/scalaric/sops-operator/commit/549e20069abf678de71421ab6c75baaf7f02769a))
* use pinned versions for golangci-lint and setup-envtest ([bac5256](https://github.com/scalaric/sops-operator/commit/bac525669c7b42bc6135983bb00896d5cf871013))
* use release-0.20 branch for setup-envtest ([fd21e76](https://github.com/scalaric/sops-operator/commit/fd21e76f149a0a60e2d3e8aff06bf2d802d53130))

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

# OpenSSF Scorecard

This document describes the security practices implemented in this project and how to achieve a perfect OpenSSF Scorecard score.

## Current Score

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/scalaric/sops-operator/badge)](https://securityscorecards.dev/viewer/?uri=github.com/scalaric/sops-operator)

## Automated Checks (Code)

| Check | Implementation |
|-------|----------------|
| **Pinned-Dependencies** | All GitHub Actions pinned to SHA hashes with version comments |
| **Token-Permissions** | Workflow-level `permissions: {}` with minimal per-job permissions |
| **SAST** | CodeQL analysis (`codeql.yml`) + Gosec security scanner |
| **Fuzzing** | Native Go fuzz tests (`pkg/sops/fuzz_test.go`) |
| **Signed-Releases** | Cosign keyless signatures for all release artifacts |
| **Dangerous-Workflow** | No `pull_request_target` with write permissions |
| **Binary-Artifacts** | No binaries committed to repository |
| **Dependency-Update-Tool** | Dependabot configured for Go, Docker, and GitHub Actions |
| **Vulnerabilities** | Automated scanning via Dependabot and CodeQL |
| **Security-Policy** | `SECURITY.md` with vulnerability reporting process |
| **License** | Apache 2.0 (`LICENSE`) |
| **CI-Tests** | Comprehensive test suite runs on all PRs |

## Manual Configuration Required

### Branch Protection

Configure via **Settings → Branches → Add rule** for `main`:

```
✓ Require pull request before merging
  ✓ Require 1 approval
  ✓ Dismiss stale approvals when new commits are pushed
  ✓ Require review from Code Owners
✓ Require status checks to pass
  ✓ Require branches to be up to date
  → Add checks: Lint, Test, Build, Docker Build, Security Scan, Analyze
✓ Require conversation resolution
✓ Do not allow bypassing the above settings
```

### OpenSSF Best Practices Badge

1. Visit https://www.bestpractices.dev
2. Add project: `github.com/scalaric/sops-operator`
3. Complete the questionnaire
4. Add badge to README

## Verifying Release Signatures

All release artifacts are signed with [Cosign](https://github.com/sigstore/cosign) using keyless signing (Fulcio + Rekor).

```bash
# Install cosign
brew install cosign

# Download release artifacts
VERSION=v1.0.0
curl -sLO "https://github.com/scalaric/sops-operator/releases/download/${VERSION}/install.yaml"
curl -sLO "https://github.com/scalaric/sops-operator/releases/download/${VERSION}/install.yaml.sig"
curl -sLO "https://github.com/scalaric/sops-operator/releases/download/${VERSION}/install.yaml.pem"

# Verify signature
cosign verify-blob \
  --signature install.yaml.sig \
  --certificate install.yaml.pem \
  --certificate-identity-regexp "https://github.com/scalaric/sops-operator/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  install.yaml

# Verify container image
cosign verify ghcr.io/scalaric/sops-operator:${VERSION} \
  --certificate-identity-regexp "https://github.com/scalaric/sops-operator/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

## Workflow Overview

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push, PR | Lint, test, build, security scan |
| `codeql.yml` | Push, PR, weekly | CodeQL static analysis |
| `fuzz.yml` | Push, PR, daily | Go native fuzz testing |
| `release.yml` | Tag push | Build, sign, and publish release |
| `scorecard.yml` | Push to main, weekly | OpenSSF Scorecard analysis |
| `dependabot-auto-merge.yml` | Dependabot PR | Auto-merge patch/minor updates |
| `release-please.yml` | Push to main | Automated release management |

## Local Verification

```bash
# Run scorecard locally
brew install scorecard
scorecard --repo=github.com/scalaric/sops-operator

# Check specific check
scorecard --repo=github.com/scalaric/sops-operator --checks=Pinned-Dependencies

# Run fuzz tests locally
go test -fuzz=FuzzParseDecryptedYAML -fuzztime=30s ./pkg/sops/
go test -fuzz=FuzzValidateEncryptedYAML -fuzztime=30s ./pkg/sops/
```

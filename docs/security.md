# Security

## Overview

SOPS Operator is designed with security as a primary concern. This page documents security considerations and best practices.

## Encryption

### AGE Encryption

SOPS Operator uses [AGE](https://github.com/FiloSottile/age) encryption, which provides:

- **X25519 key exchange** - Modern elliptic curve cryptography
- **ChaCha20-Poly1305** - Authenticated encryption
- **No cloud dependencies** - Works entirely offline

### SOPS Features

The operator leverages SOPS features:

- **Message Authentication Code (MAC)** - Ensures integrity of encrypted data
- **Key rotation support** - Rotate keys without re-encrypting all secrets
- **Audit trail** - SOPS metadata shows encryption details

## Key Management

### Best Practices

1. **Never commit private keys to Git**
   ```bash
   # Add to .gitignore
   echo "*.key" >> .gitignore
   echo "age.key" >> .gitignore
   ```

2. **Use separate keys per environment**
   ```bash
   age-keygen -o age-dev.key
   age-keygen -o age-staging.key
   age-keygen -o age-prod.key
   ```

3. **Store private keys securely**
   - Use a secrets manager (Vault, AWS Secrets Manager)
   - Or Kubernetes Secrets with RBAC restrictions

4. **Rotate keys periodically**
   ```bash
   # Generate new key
   age-keygen -o age-new.key

   # Re-encrypt secrets with new key
   sops updatekeys secret.enc.yaml
   ```

## RBAC

### Operator Permissions

The operator runs with minimal permissions:

- Only accesses `SopsSecret` and `Secret` resources
- Namespace-scoped by default
- No cluster-admin privileges

### Recommended User Permissions

```yaml
# Allow creating SopsSecrets but not reading Secrets
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: sopssecret-creator
rules:
  - apiGroups: ["secrets.scalaric.io"]
    resources: ["sopssecrets"]
    verbs: ["get", "list", "create", "update", "delete"]
```

## Network Security

- Operator makes no outbound network connections
- All decryption happens locally
- No telemetry or data collection

## Supply Chain Security

### Signed Releases

All releases are signed with [Cosign](https://github.com/sigstore/cosign):

```bash
# Verify container image
cosign verify ghcr.io/scalaric/sops-operator:v1.0.0

# Verify release artifacts
cosign verify-blob --signature install.yaml.sig install.yaml
```

### SBOM

Software Bill of Materials (SBOM) is published with each release in SPDX format.

### Provenance

SLSA provenance attestation is attached to release artifacts.

## Reporting Vulnerabilities

Please report security vulnerabilities via GitHub Security Advisories:

[Report a vulnerability](https://github.com/scalaric/sops-operator/security/advisories/new)

See [SECURITY.md](https://github.com/scalaric/sops-operator/blob/main/SECURITY.md) for details.

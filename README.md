# SOPS Operator

A Kubernetes operator that decrypts [SOPS](https://github.com/getsops/sops)-encrypted secrets and creates native Kubernetes Secrets.

[![CI](https://github.com/scalaric/sops-operator/actions/workflows/ci.yml/badge.svg)](https://github.com/scalaric/sops-operator/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/scalaric/sops-operator)](https://goreportcard.com/report/github.com/scalaric/sops-operator)
[![Renovate](https://img.shields.io/badge/renovate-enabled-brightgreen.svg)](https://renovatebot.com)

## Features

- Decrypts SOPS-encrypted YAML and creates Kubernetes Secrets
- Supports AGE encryption (simple, secure, no cloud dependencies)
- Full SOPS YAML stored in CRD (including MAC for integrity verification)
- Automatic Secret recreation if deleted
- Owner references for automatic cleanup
- Status conditions for observability
- Suspend functionality for maintenance

## Quick Start

### Prerequisites

- Kubernetes cluster (1.26+)
- [AGE](https://github.com/FiloSottile/age) key pair
- [SOPS](https://github.com/getsops/sops) CLI (for encrypting secrets)

### 1. Generate an AGE key

```bash
age-keygen -o age.key
# Note the public key (age1xxx...) - you'll use it for encryption
```

### 2. Install the operator

```bash
# Install CRDs and operator
kubectl apply -f https://github.com/scalaric/sops-operator/releases/latest/download/install.yaml

# Create the AGE key secret
kubectl create secret generic sops-age-key \
  --from-file=age.key=./age.key \
  -n sops-operator-system
```

### 3. Create an encrypted secret

```bash
# Create a plain secret file
cat > secret.yaml <<EOF
username: admin
password: super-secret-password
EOF

# Encrypt with SOPS (replace with your public key)
sops -e -a age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p secret.yaml > secret.enc.yaml
```

### 4. Create a SopsSecret

```yaml
apiVersion: secrets.gg.io/v1alpha1
kind: SopsSecret
metadata:
  name: my-secret
  namespace: default
spec:
  sopsSecret: |
    username: ENC[AES256_GCM,data:YWRtaW4=,iv:...,tag:...,type:str]
    password: ENC[AES256_GCM,data:c3VwZXItc2VjcmV0,iv:...,tag:...,type:str]
    sops:
        age:
            - recipient: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
              enc: |
                -----BEGIN AGE ENCRYPTED FILE-----
                ...
                -----END AGE ENCRYPTED FILE-----
        lastmodified: "2024-01-15T00:00:00Z"
        mac: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
        version: 3.9.0
```

The operator will create a Kubernetes Secret named `my-secret` with the decrypted data.

## CRD Reference

### SopsSecret Spec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sopsSecret` | string | Yes | Full SOPS-encrypted YAML including metadata and MAC |
| `secretName` | string | No | Name of the created Secret (defaults to SopsSecret name) |
| `secretType` | string | No | Type of Secret to create (default: `Opaque`) |
| `secretLabels` | map | No | Additional labels for the created Secret |
| `secretAnnotations` | map | No | Additional annotations for the created Secret |
| `suspend` | bool | No | Suspend reconciliation |

### SopsSecret Status

| Field | Type | Description |
|-------|------|-------------|
| `secretName` | string | Name of the created Secret |
| `lastDecryptedHash` | string | Hash of last decrypted data |
| `lastDecryptedTime` | time | Timestamp of last decryption |
| `conditions` | []Condition | Current state (Ready, Decrypted) |

## Configuration

### Environment Variables

The operator reads AGE keys from:

| Variable | Description |
|----------|-------------|
| `SOPS_AGE_KEY` | AGE private key(s), newline-separated |
| `SOPS_AGE_KEY_FILE` | Path to file containing AGE private key(s) |

### Deployment

The default deployment mounts the AGE key from a Secret:

```yaml
volumes:
  - name: age-key
    secret:
      secretName: sops-age-key  # Must contain 'age.key'
```

## Development

### Prerequisites

- Go 1.24+
- Docker
- kubectl
- [kubebuilder](https://book.kubebuilder.io/)

### Build

```bash
# Build binary
make build

# Run tests
make test

# Build Docker image
make docker-build IMG=sops-operator:dev

# Deploy to cluster
make deploy IMG=sops-operator:dev
```

### Project Structure

```
├── api/v1alpha1/          # CRD types
├── cmd/                   # Entry point
├── config/                # Kubernetes manifests
│   ├── crd/              # CustomResourceDefinition
│   ├── manager/          # Deployment
│   ├── rbac/             # RBAC rules
│   └── samples/          # Example resources
├── internal/controller/   # Reconciliation logic
└── pkg/sops/             # SOPS decryption
```

## Why Another SOPS Operator?

Compared to [mozilla/sops-secrets-operator](https://github.com/isindir/sops-secrets-operator):

| Feature | This Operator | Mozilla Operator |
|---------|--------------|------------------|
| CRD Format | Full SOPS YAML in single field | Split into multiple fields |
| MAC Location | Inside `sopsSecret` field | Separate field |
| Encryption Backends | AGE only | AGE, AWS KMS, GCP KMS, Azure, etc. |
| Complexity | Simple, minimal | Feature-rich |

This operator is designed for **simplicity**. The entire SOPS output is stored as-is in the CRD, making it trivial to copy/paste from `sops -e` output.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

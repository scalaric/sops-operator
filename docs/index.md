# SOPS Operator

A Kubernetes operator that decrypts [SOPS](https://github.com/getsops/sops)-encrypted secrets and creates native Kubernetes Secrets.

<div class="grid cards" markdown>

- :material-lock: **Secure by Design**

    ---

    Full SOPS YAML stored in CRD including MAC for integrity verification

- :material-key: **AGE Encryption**

    ---

    Simple, secure encryption with no cloud dependencies

- :material-sync: **GitOps Ready**

    ---

    Store encrypted secrets in Git, operator handles decryption

- :material-kubernetes: **Cloud Native**

    ---

    Built with controller-runtime, follows Kubernetes patterns

</div>

## Quick Start

```bash
# Install the operator
kubectl apply -f https://github.com/scalaric/sops-operator/releases/latest/download/install.yaml
```

[Get Started](getting-started.md){ .md-button .md-button--primary }
[View on GitHub](https://github.com/scalaric/sops-operator){ .md-button }

## Why SOPS Operator?

Managing secrets in Kubernetes with GitOps is challenging. You want to store everything in Git, but secrets need to stay secret. SOPS Operator solves this by:

1. **Encrypting secrets with SOPS** - Store encrypted YAML in Git
2. **Storing encrypted data in CRDs** - Apply encrypted secrets to Kubernetes
3. **Automatic decryption** - Operator decrypts and creates native Secrets

```yaml
apiVersion: secrets.scalaric.io/v1alpha1
kind: SopsSecret
metadata:
  name: my-secret
spec:
  sopsSecret: |
    apiVersion: v1
    kind: Secret
    data:
      password: ENC[AES256_GCM,data:...,type:str]
    sops:
      age:
        - recipient: age1...
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            ...
```

## Features

- :white_check_mark: Decrypts SOPS-encrypted YAML and creates Kubernetes Secrets
- :white_check_mark: Supports AGE encryption
- :white_check_mark: Full SOPS YAML stored in CRD (including MAC)
- :white_check_mark: Automatic Secret recreation if deleted
- :white_check_mark: Owner references for automatic cleanup
- :white_check_mark: Status conditions for observability
- :white_check_mark: Suspend functionality for maintenance

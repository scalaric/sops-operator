# Configuration

## SopsSecret Spec

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `sopsSecret` | string | **Required.** The SOPS-encrypted YAML content | - |
| `secretName` | string | Name of the Kubernetes Secret to create | Same as SopsSecret name |
| `secretType` | string | Type of the Kubernetes Secret | `Opaque` |
| `secretLabels` | map[string]string | Additional labels for the Secret | `{}` |
| `secretAnnotations` | map[string]string | Additional annotations for the Secret | `{}` |
| `suspend` | bool | Suspend reconciliation | `false` |

## Example

```yaml
apiVersion: secrets.scalaric.io/v1alpha1
kind: SopsSecret
metadata:
  name: database-credentials
  namespace: production
spec:
  # Custom secret name (optional)
  secretName: db-secret

  # Secret type (optional)
  secretType: Opaque

  # Additional labels (optional)
  secretLabels:
    app: my-app
    environment: production

  # Additional annotations (optional)
  secretAnnotations:
    description: "Database credentials for production"

  # Suspend reconciliation (optional)
  suspend: false

  # The encrypted SOPS content (required)
  sopsSecret: |
    apiVersion: v1
    kind: Secret
    data:
      username: ENC[AES256_GCM,data:...]
      password: ENC[AES256_GCM,data:...]
    sops:
      age:
        - recipient: age1...
```

## Operator Configuration

The operator is configured via environment variables:

| Variable | Description | Required |
|----------|-------------|----------|
| `SOPS_AGE_KEY` | AGE private key content | Yes* |
| `SOPS_AGE_KEY_FILE` | Path to AGE private key file | Yes* |

*One of `SOPS_AGE_KEY` or `SOPS_AGE_KEY_FILE` is required.

## Status Conditions

The operator sets the following conditions on SopsSecret:

| Condition | Description |
|-----------|-------------|
| `Decrypted` | Whether the SOPS data was successfully decrypted |
| `Ready` | Whether the Secret is up to date |

Example status:

```yaml
status:
  conditions:
    - type: Decrypted
      status: "True"
      reason: Success
      message: Successfully decrypted SOPS data
    - type: Ready
      status: "True"
      reason: Success
      message: Secret my-secret is up to date
  secretName: my-secret
  lastDecryptedHash: "abc123..."
  lastDecryptedTime: "2024-01-15T10:30:00Z"
  observedGeneration: 1
```

# API Reference

## SopsSecret

`SopsSecret` is the primary custom resource for managing SOPS-encrypted secrets.

### Metadata

```yaml
apiVersion: secrets.scalaric.io/v1alpha1
kind: SopsSecret
```

### Spec

```yaml
spec:
  # Required: The SOPS-encrypted secret content
  sopsSecret: string

  # Optional: Name for the generated Secret (defaults to SopsSecret name)
  secretName: string

  # Optional: Type of the generated Secret (defaults to Opaque)
  secretType: string

  # Optional: Additional labels for the generated Secret
  secretLabels:
    key: value

  # Optional: Additional annotations for the generated Secret
  secretAnnotations:
    key: value

  # Optional: Suspend reconciliation (defaults to false)
  suspend: bool
```

### Status

```yaml
status:
  # Conditions indicating the state of the SopsSecret
  conditions:
    - type: string      # Decrypted, Ready
      status: string    # True, False, Unknown
      reason: string
      message: string
      lastTransitionTime: string
      observedGeneration: int

  # Name of the managed Secret
  secretName: string

  # SHA256 hash of the encrypted content
  lastDecryptedHash: string

  # Timestamp of last successful decryption
  lastDecryptedTime: string

  # Generation that was last observed
  observedGeneration: int
```

## RBAC

The operator requires the following permissions:

```yaml
# For SopsSecret resources
- apiGroups: ["secrets.scalaric.io"]
  resources: ["sopssecrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

- apiGroups: ["secrets.scalaric.io"]
  resources: ["sopssecrets/status"]
  verbs: ["get", "update", "patch"]

- apiGroups: ["secrets.scalaric.io"]
  resources: ["sopssecrets/finalizers"]
  verbs: ["update"]

# For managed Secrets
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

# For events
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]
```

## Events

The operator emits the following events:

| Reason | Type | Description |
|--------|------|-------------|
| `Decrypted` | Normal | Successfully decrypted SOPS data |
| `DecryptFailed` | Warning | Failed to decrypt SOPS data |
| `SecretCreated` | Normal | Created new Secret |
| `SecretUpdated` | Normal | Updated existing Secret |
| `SecretDeleted` | Normal | Deleted managed Secret |
| `ValidationFailed` | Warning | SOPS YAML validation failed |

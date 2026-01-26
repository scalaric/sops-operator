# Getting Started

This guide will help you install SOPS Operator and create your first encrypted secret.

## Prerequisites

- Kubernetes cluster (1.26+)
- [AGE](https://github.com/FiloSottile/age) key pair
- [SOPS](https://github.com/getsops/sops) CLI (for encrypting secrets)
- kubectl configured to access your cluster

## Installation

### 1. Generate an AGE key

```bash
age-keygen -o age.key
# Note the public key (age1xxx...) - you'll use it for encryption
```

### 2. Install the operator

```bash
kubectl apply -f https://github.com/scalaric/sops-operator/releases/latest/download/install.yaml
```

### 3. Create the AGE key secret

```bash
kubectl create secret generic sops-age-key \
  --from-file=age.key=./age.key \
  -n sops-operator-system
```

## Create Your First Secret

### 1. Create a secret file

```yaml title="secret.yaml"
apiVersion: v1
kind: Secret
metadata:
  name: my-app-secret
type: Opaque
stringData:
  username: admin
  password: super-secret-password
  api-key: sk-1234567890
```

### 2. Encrypt with SOPS

```bash
export SOPS_AGE_RECIPIENTS="age1your-public-key-here"
sops --encrypt --age $SOPS_AGE_RECIPIENTS secret.yaml > secret.enc.yaml
```

### 3. Create SopsSecret resource

```yaml title="sopssecret.yaml"
apiVersion: secrets.scalaric.io/v1alpha1
kind: SopsSecret
metadata:
  name: my-app-secret
  namespace: default
spec:
  sopsSecret: |
    # Paste the contents of secret.enc.yaml here
```

Or use this one-liner:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: secrets.scalaric.io/v1alpha1
kind: SopsSecret
metadata:
  name: my-app-secret
  namespace: default
spec:
  sopsSecret: |
$(cat secret.enc.yaml | sed 's/^/    /')
EOF
```

### 4. Verify

```bash
# Check the SopsSecret status
kubectl get sopssecret my-app-secret -o yaml

# Check the created Secret
kubectl get secret my-app-secret -o yaml
```

## What's Next?

- [Configuration](configuration.md) - Learn about all configuration options
- [API Reference](api-reference.md) - Complete API documentation
- [Security](security.md) - Security best practices

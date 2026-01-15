# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it by:

1. **Do NOT** open a public GitHub issue
2. Send an email to security@example.com (replace with actual contact)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes

We will acknowledge your report within 48 hours and provide a detailed response within 7 days.

## Security Considerations

### Secrets Handling

- The operator decrypts SOPS data in-memory only
- Decrypted data is immediately written to Kubernetes Secrets
- Temporary files used during decryption are immediately deleted
- AGE private keys should be stored in Kubernetes Secrets with appropriate RBAC

### RBAC

The operator requires the following permissions:
- Read/write access to `SopsSecret` custom resources
- Read/write access to `Secret` resources (to create decrypted secrets)
- Create events

### Best Practices

1. **Limit AGE key access**: Only the operator should have access to the AGE private key
2. **Use namespaced secrets**: Deploy the operator in a dedicated namespace
3. **Enable audit logging**: Monitor access to secrets
4. **Rotate keys regularly**: Periodically rotate AGE keys

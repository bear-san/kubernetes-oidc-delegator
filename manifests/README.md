# Kubernetes Manifests

This directory contains Kubernetes manifests for deploying the kubernetes-oidc-delegator application using Kustomize.

## Structure

```
manifests/
├── base/                    # Base manifests
│   ├── deployment.yaml      # Main deployment configuration
│   ├── service.yaml         # Service configuration
│   ├── serviceaccount.yaml  # ServiceAccount for the application
│   ├── rbac.yaml           # RBAC permissions
│   ├── configmap.yaml      # Configuration data
│   └── kustomization.yaml  # Base kustomization
└── overlays/               # Environment-specific overlays
    ├── development/        # Development environment
    │   ├── kustomization.yaml
    │   ├── deployment-patch.yaml
    │   └── configmap-patch.yaml
    └── production/         # Production environment
        ├── kustomization.yaml
        ├── deployment-patch.yaml
        └── configmap-patch.yaml
```

## Usage

### Deploy to Development Environment

```bash
kubectl apply -k manifests/overlays/development
```

### Deploy to Production Environment

```bash
kubectl apply -k manifests/overlays/production
```

### Deploy Base Configuration

```bash
kubectl apply -k manifests/base
```

## Configuration

The application requires the following configuration via ConfigMap:

- `server-host`: The public URL where the OIDC delegator is accessible
- `namespace-prefix`: Optional prefix for namespace names (default: "")
- `namespace-suffix`: Optional suffix for namespace names (default: "")

### Example Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubernetes-oidc-delegator-config
data:
  server-host: "https://oidc-delegator.example.com"
  namespace-prefix: "prod-"
  namespace-suffix: ""
```

## RBAC Permissions

The application requires the following permissions:

- `get` and `list` access to `secrets` in all namespaces (to read ServiceAccount signing keys)

## Service Account

The application runs with a dedicated ServiceAccount (`kubernetes-oidc-delegator`) that has the necessary RBAC permissions to access Kubernetes secrets containing the ServiceAccount signing keys.

## Security Context

The deployment includes security best practices:

- Runs as non-root user (UID 65534)
- Read-only root filesystem
- Drops all capabilities
- Disables privilege escalation

## Health Checks

The application includes liveness and readiness probes that check the `/health` endpoint.
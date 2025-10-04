# Kubernetes Manifests

This directory contains Kubernetes manifests for deploying the kubernetes-oidc-delegator application using Kustomize.

## Structure

```
manifests/
├── base/                    # Base manifests
│   ├── deployment.yaml      # Main deployment configuration
│   ├── service.yaml         # Service configuration
│   ├── serviceaccount.yaml  # ServiceAccount for the application
│   ├── rbac.yaml           # RBAC (currently not needed)
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

## Prerequisites

Before deploying, you need to:

1. Have an existing Kubernetes Secret containing the ServiceAccount signing public key
2. Update the deployment.yaml to reference your existing Secret

### Using Existing Secret

The application expects to mount a public key from an existing Secret. Update the `deployment.yaml` to reference your Secret:

```yaml
volumes:
- name: signing-keys
  secret:
    secretName: your-existing-secret-name  # Replace with your secret name
    items:
    - key: your-public-key-field         # Replace with the key name in your secret
      path: public.pem                   # Must be public.pem (matches --public-key argument)
```

Common scenarios:

1. **Using Cluster API generated keys:**
   ```yaml
   secretName: cluster-name-sa
   items:
   - key: tls.crt
     path: public.pem
   ```

2. **Using custom signing keys:**
   ```yaml
   secretName: serviceaccount-signing-keys
   items:
   - key: sa.pub
     path: public.pem
   ```

3. **Using kube-apiserver certificates:**
   ```yaml
   secretName: kube-apiserver-certs
   items:
   - key: sa-pub.pem
     path: public.pem
   ```

## Deployment

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

### Using Kustomize Build

```bash
# Preview the generated manifests
kustomize build manifests/overlays/production

# Apply the generated manifests
kustomize build manifests/overlays/production | kubectl apply -f -
```

## Configuration

The application requires the following configuration via ConfigMap:

- `server-host`: The public URL where the OIDC delegator is accessible (required)
- `issuer`: The token issuer URL (default: "https://kubernetes.default.svc.cluster.local")

### Example Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubernetes-oidc-delegator-config
data:
  server-host: "https://oidc-delegator.example.com"
  issuer: "https://kubernetes.default.svc.cluster.local"
```


## Environment-Specific Configuration

### Development
- Namespace: `development`
- Server Host: `https://dev-oidc-delegator.example.com`
- Image Tag: `dev`
- Replicas: 1

### Production
- Namespace: `production`
- Server Host: `https://oidc-delegator.example.com`
- Image Tag: `v1.0.0`
- Replicas: 3 (for high availability)

## Security Context

The deployment includes security best practices:

- Runs as non-root user (UID 65534)
- Read-only root filesystem
- Drops all capabilities
- Disables privilege escalation
- Public key is mounted as read-only volume

## Health Checks

The application includes liveness and readiness probes that check the `/health` endpoint:

- Liveness Probe: Initial delay 30s, period 10s
- Readiness Probe: Initial delay 5s, period 5s

## Verification

After deployment, verify the application:

```bash
# Check pod status
kubectl get pods -l app=kubernetes-oidc-delegator -n <namespace>

# Check service
kubectl get svc kubernetes-oidc-delegator -n <namespace>

# Port-forward for local testing
kubectl port-forward -n <namespace> svc/kubernetes-oidc-delegator 8080:80

# Test endpoints (in another terminal)
curl http://localhost:8080/.well-known/openid-configuration
curl http://localhost:8080/keys
curl http://localhost:8080/health
```

## Troubleshooting

### Check logs
```bash
kubectl logs -l app=kubernetes-oidc-delegator -n <namespace>
```

### Verify Secret is mounted correctly
```bash
kubectl describe pod -l app=kubernetes-oidc-delegator -n <namespace>
```

### Ensure public key is correctly mounted
```bash
# Check that the referenced secret exists
kubectl get secret <your-secret-name> -n <namespace>

# Verify the secret contains the expected key
kubectl get secret <your-secret-name> -n <namespace> -o jsonpath='{.data}' | jq 'keys'

# Decode and verify the public key from the secret
kubectl get secret <your-secret-name> -n <namespace> -o jsonpath='{.data.<your-key-name>}' | base64 -d
```
# Kubernetes OIDC Delegator

An API server that exposes Kubernetes API Server's ServiceAccount Token Signing Keys in JWKs format.

## Overview

This project provides an API to enable external validation of ServiceAccount tokens issued by a Kubernetes cluster. While Kubernetes API is typically only accessible locally, this API allows external Identity Providers (IdPs) like AWS to validate tokens issued to Kubernetes ServiceAccounts.

## Features

- OpenID Configuration endpoint (`/.well-known/openid-configuration`)
- JWKs endpoint (`/keys`)
- Support for PEM format signing keys
- Health check endpoint

## Prerequisites

- Kubernetes cluster ServiceAccount signing keys (PEM format)
- Go 1.24 or higher

## Build

```bash
go build -o kubernetes-oidc-delegator cmd/server/main.go
```

Build Docker image:
```bash
docker build -t kubernetes-oidc-delegator:latest .
```

## Run

### Local Execution
```bash
./kubernetes-oidc-delegator \
  --public-key /path/to/public.pem \
  --server-host https://oidc-delegator.example.com \
  --port 8080
```

### Options
- `--public-key`: Path to the public key file in PEM format (required)
- `--server-host`: Server host URL (required)
- `--port`: Server port (default: 8080)
- `--issuer`: Token issuer URL (default: https://kubernetes.default.svc.cluster.local)

## Generate Test Keys

```bash
# Generate RSA private key
openssl genrsa -out private.pem 2048

# Extract public key
openssl rsa -in private.pem -pubout -out public.pem
```

## Endpoints

### OpenID Configuration
```
GET /.well-known/openid-configuration
```

Response:
```json
{
  "issuer": "https://kubernetes.default.svc.cluster.local",
  "jwks_uri": "https://oidc-delegator.example.com/keys",
  "response_types_supported": ["id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

### JWKs
```
GET /keys
```

Response:
```json
{
  "keys": [
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "XBRQklg6V4uMi9zGXrC1d_gqrT4tKWKyM6iZzXKiYhQ",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### Health Check
```
GET /health
```

## License

MIT
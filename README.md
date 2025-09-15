# AAA Microservice

> A minimal authentication, authorization, and accounting service built on FusionAuth

## Overview

Enterprise-grade authentication microservice that provides JWT-based stateless authentication with local role-based access control. Built for distributed architectures where consuming services verify tokens independently.

## Features

- **Stateless Authentication** — JWT tokens with embedded roles
- **Local Authorization** — No centralized authorization calls
- **Token Management** — Access and refresh token lifecycle
- **JWKS Proxy** — Public key distribution for token verification
- **Role-Based Access** — User and admin roles with extensibility
- **Production Ready** — Docker containerization with health checks

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client App    │───▶│  AAA Service    │───▶│   FusionAuth    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │ Consuming       │    │   PostgreSQL    │
                       │ Services        │    │   Database      │
                       └─────────────────┘    └─────────────────┘
```

## Quick Start

```bash
# Start all services
docker compose up -d

# Verify health
curl http://localhost:8080/health

# Create user
curl -X POST http://localhost:8080/v1/users \
  -H "Content-Type: application/json" \
  -d '{"username": "john", "password": "secure123", "roles": ["user"]}'

# Authenticate
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "john", "password": "secure123"}'
```

## API Reference

### Authentication

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/auth/login` | POST | Authenticate user |
| `/v1/auth/refresh` | POST | Refresh access token |
| `/v1/auth/logout` | POST | Revoke tokens |
| `/v1/auth/me` | GET | Get user info |

### User Management

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/users` | POST | Create user with roles |

### Token Verification

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/.well-known/jwks.json` | GET | Public keys for JWT verification |

## Configuration

Required environment variables:

```env
FUSIONAUTH_BASE_URL=http://fusionauth:9011
FUSIONAUTH_API_KEY=changeme-api-key
FUSIONAUTH_APPLICATION_ID=6bd5d02c-99b4-4338-9336-3f7572fd3c40
JWT_EXPECTED_ISS=acme.com
JWT_EXPECTED_AUD=6bd5d02c-99b4-4338-9336-3f7572fd3c40
```

## Local Verification

Consuming services verify JWTs locally using the JWKS endpoint:

```python
import jwt
import requests

# Get public keys
jwks = requests.get("http://localhost:8080/v1/.well-known/jwks.json").json()

# Verify token locally
payload = jwt.decode(
    token,
    jwks,
    algorithms=["RS256"],
    issuer="acme.com",
    audience="6bd5d02c-99b4-4338-9336-3f7572fd3c40"
)

# Check roles
if "admin" in payload.get("roles", []):
    # Grant admin access
```

## Technology Stack

- **Runtime**: Python 3.12, FastAPI, Uvicorn
- **Authentication**: FusionAuth, PostgreSQL
- **Tokens**: JWT with RS256 signatures
- **Caching**: TTL-based JWKS caching
- **Deployment**: Docker, Docker Compose

## Production Considerations

- **Security**: Rotate JWT signing keys regularly
- **Monitoring**: Health checks on `/health` endpoint
- **Scaling**: Stateless design supports horizontal scaling
- **Secrets**: Use proper secret management for API keys
- **TLS**: Enable HTTPS in production environments

## License

MIT
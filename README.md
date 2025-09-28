# SnapAuth

> A minimal authentication layer for FusionAuth that ships with batteries-included defaults

## Overview

SnapAuth delivers a ready-to-run authentication backend on top of FusionAuth. It exposes a tiny HTTP surface, handles bootstrap, and lets downstream services verify JWTs locally without touching FusionAuth’s admin UI.

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
│   Client App    │───▶│    SnapAuth     │───▶│   FusionAuth    │
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
cp .env.example .env
python scripts/bootstrap.py  # generates secrets and kickstart configuration
docker compose up --build

# Verify health
curl http://localhost:8080/health

# Create user
curl -X POST http://localhost:8080/v1/users \\
  -H "Content-Type: application/json" \\
  -d '{"username": "john", "password": "secure123", "roles": ["user"]}'

# Authenticate
curl -X POST http://localhost:8080/v1/auth/login \\
  -H "Content-Type: application/json" \\
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

Configuration is driven by `.env`. Provide any overrides (for example a custom admin username or redirect URL) in that file, then run `python scripts/bootstrap.py`. The bootstrap script will:

- create unique IDs and secrets for FusionAuth (API key, client secret, application ID, admin password)
- synchronise those values into `kickstart/kickstart.json` so FusionAuth provisions itself on startup
- set database credentials that the bundled Postgres container and FusionAuth share

Whenever you tweak `.env`, rerun the script to keep both files aligned.

## Local Verification

Consuming services verify JWTs locally using the JWKS endpoint:

```python
import os
import jwt
import requests

# Get public keys
jwks = requests.get("http://localhost:8080/v1/.well-known/jwks.json").json()

# Verify token locally using generated configuration
payload = jwt.decode(
    token,
    jwks,
    algorithms=["RS256"],
    issuer=os.environ["JWT_EXPECTED_ISS"],
    audience=os.environ["JWT_EXPECTED_AUD"],
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

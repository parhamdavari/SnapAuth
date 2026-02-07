## Why

The current SnapAuth implementation has **critical security vulnerabilities** that prevent production deployment and make it unsuitable for organizations requiring air-gapped or isolated server deployments. Security analysis identified 7 CRITICAL findings including unauthenticated admin endpoints (anyone can create admin users), no TLS enforcement (cleartext password transmission), and zero rate limiting (trivial brute force attacks). Additionally, the git-submodule distribution model is incompatible with air-gapped environments and ops teams need pre-built artifacts, not build toolchains.

## What Changes

### Security Hardening (CRITICAL - Phase 0)
- Add **API Key authentication** with constant-time comparison for all administrative endpoints (`POST /v1/users`, `DELETE /v1/admin/users/{id}`, `PUT /v1/users/{id}/reset-password`)
- Implement **IP Whitelisting** with CIDR notation support for admin operations
- Add **tiered rate limiting**: 10 req/min (public auth), 30 req/min (admin), 60 req/min (authenticated)
- Implement **structured JSON audit logging** for all security events (user creation, deletion, login success/failure)
- Add **security headers middleware** (X-Frame-Options, CSP, HSTS, X-Content-Type-Options)
- Enforce **TLS/HTTPS** via Nginx reverse proxy in production deployments
- Fix authorization bugs: `DELETE /v1/users/{id}` must enforce self-only access (or admin with API key)
- Remove JWT token content from all log statements

### Distribution & Deployment
- Shift from git submodules to **pre-built release tarballs** containing all Docker images (SnapAuth, FusionAuth, PostgreSQL, Bootstrap)
- Create `offline-install.sh` script for air-gapped image loading
- Default to **isolated network mode** (only port 8080/443 exposed), with optional microservices mode via override file
- Add resource limits to all containers (CPU/Memory caps)

### Operational Tooling
- Automated **backup/restore scripts** with encrypted .env files and PostgreSQL dumps
- **Secrets management** with zero-downtime API key rotation (support multiple active keys)
- Bootstrap auto-generation of admin API key (256-bit entropy)
- Health check endpoints verify FusionAuth and database connectivity

### Documentation
- Comprehensive guides: AIR-GAPPED-DEPLOYMENT.md, SECURITY.md, NETWORK-MODES.md, INSTALLATION.md
- .env.example with security configuration documentation
- VERSION.yml manifest with component versions and checksums

## Capabilities

### New Capabilities

- `admin-api-key-auth`: API key authentication for administrative endpoints with constant-time comparison, support for multiple keys, and automatic generation during bootstrap
- `ip-whitelisting`: IP address access control with CIDR notation support, IPv4/IPv6, and X-Forwarded-For proxy handling
- `rate-limiting`: Tiered request rate limits (10/min public auth, 30/min admin, 60/min authenticated) with configurable thresholds
- `audit-logging`: Structured JSON logging for security events (user.created, user.deleted, auth.failed) with timestamp, client IP, and event details
- `security-headers`: HTTP security headers middleware (X-Frame-Options, X-Content-Type-Options, CSP, HSTS)
- `backup-restore`: Automated backup scripts for PostgreSQL dumps, configuration archives, and encrypted secrets with restoration procedures
- `offline-deployment`: Air-gapped deployment capability via pre-built release tarballs with offline-install.sh image loader
- `tls-enforcement`: HTTPS-only access via Nginx reverse proxy with certificate management
- `secrets-rotation`: Zero-downtime API key rotation supporting multiple active keys simultaneously
- `resource-limits`: Container resource constraints (CPU/Memory) to prevent host exhaustion

### Modified Capabilities

- `user-management`: **BREAKING** - `POST /v1/users` now requires `X-SnapAuth-API-Key` header (previously unauthenticated)
- `user-management`: **BREAKING** - `DELETE /v1/users/{id}` now enforces self-only access OR admin API key (previously any authenticated user could delete any user)
- `authentication`: Rate limiting added to `POST /v1/auth/login` endpoint (10 requests per minute)

## Impact

### SnapAuth Codebase
- **New modules**: `snapauth/app/security/` directory with api_key.py, ip_whitelist.py, dependencies.py, rate_limit.py, middleware.py, audit.py
- **Modified files**: `main.py` (add authentication decorators), `settings.py` (security config fields), `requirements.txt` (add slowapi)
- **New tests**: `tests/test_security.py` covering API key auth, IP whitelist, rate limits, authorization rules

### Platform Deployment (snapauth-platform)
- **New files**: docker-compose.microservices.yml, nginx.conf, offline-install.sh, VERSION.yml, scripts/backup.sh, scripts/restore.sh, scripts/manage-secrets.sh
- **Modified files**: docker-compose.yml (isolated network, resource limits, nginx service), Makefile (deployment modes), README.md (security documentation)
- **New documentation**: docs/SECURITY.md, docs/AIR-GAPPED-DEPLOYMENT.md, docs/NETWORK-MODES.md

### Bootstrap Process
- `scripts/bootstrap.py` generates `SNAPAUTH_ADMIN_API_KEY` with 256-bit entropy (secrets.token_urlsafe(32))
- `.env.example` updated with security configuration variables

### CI/CD Pipeline
- Build process exports Docker images to tarballs (snapauth-v1.0.x.tar, bootstrap-v1.0.x.tar, fusionauth-1.50.1.tar, postgres-16-alpine.tar)
- Release artifacts bundled into snapauth-release-v1.0.x.tar.gz with VERSION.yml manifest

### API Contract Changes
- **BREAKING**: Administrative endpoints require `X-SnapAuth-API-Key` header
- **BREAKING**: Authorization rules tightened on DELETE endpoint
- Rate limiting enforced (may return 429 Too Many Requests)
- Audit logs generated as side-effect of security events

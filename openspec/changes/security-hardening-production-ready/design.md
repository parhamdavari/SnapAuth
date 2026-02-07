## Context

SnapAuth is a FastAPI-based authentication facade that provides a simplified API over FusionAuth. The current implementation has critical security vulnerabilities that make it unsuitable for production deployment, particularly in air-gapped or isolated server environments where organizations need a turnkey auth solution.

**Current State:**
- FastAPI application (`snapauth/app/main.py`) with endpoints for user management and authentication
- No authentication on administrative endpoints (POST /v1/users)
- No rate limiting on any endpoints
- Authorization bugs allowing any user to delete any other user
- Distribution via git submodules and external registries (ghcr.io)
- No operational tooling for backup/restore or secrets management

**Constraints:**
- Must maintain backward compatibility for public endpoints (health, JWKS, token verification)
- Must support air-gapped deployments (no internet access during installation)
- Must work with existing FusionAuth integration (fusionauth-client library)
- Python 3.12+ with FastAPI ecosystem
- Docker Compose for orchestration

**Stakeholders:**
- **Operations Teams**: Need pre-built artifacts, clear deployment procedures, backup/restore capabilities
- **Security Teams**: Require audit logs, TLS enforcement, IP whitelisting, rate limiting
- **API Consumers**: Need stable public endpoints, clear error messages, predictable rate limits

## Goals / Non-Goals

**Goals:**
- Secure all administrative endpoints with API key authentication (constant-time comparison)
- Implement IP whitelisting with CIDR notation for admin operations
- Add tiered rate limiting (10/min auth, 30/min admin, 60/min general)
- Provide structured JSON audit logging for compliance
- Enable air-gapped deployment via pre-built release tarballs
- Create operational tooling (backup/restore, secrets rotation)
- Enforce TLS/HTTPS in production deployments
- Fix authorization bugs (self-only delete)

**Non-Goals:**
- Multi-provider support (FusionAuth remains the only backend for this release)
- Multi-tenancy (single-tenant deployments only)
- UI for SnapAuth administration (API-only management)
- Hot-swapping authentication providers
- OAuth provider capabilities (SnapAuth remains a client of FusionAuth)

## Decisions

### Decision 1: FastAPI Security Dependencies for Layered Authentication

**Choice**: Use FastAPI's dependency injection system with layered security dependencies combining API key validation, IP whitelisting, and JWT authentication.

**Rationale**:
- FastAPI dependencies compose well and can be combined with `Depends()`
- Clear separation of concerns (each security check is a separate function)
- Testable in isolation
- Declarative endpoint security via `dependencies=[Depends(...)]`

**Implementation**:
```python
# snapauth/app/security/dependencies.py
async def require_admin_access(
    request: Request,
    api_key: str = Depends(require_admin_api_key),
    client_ip: str = Depends(require_ip_whitelist),
) -> Dict[str, str]:
    """Both API key AND IP whitelist required."""
    return {"api_key": api_key[:8] + "...", "client_ip": client_ip}

# Usage in main.py
@app.post("/v1/users", dependencies=[Depends(require_admin_access)])
async def create_user(...):
```

**Alternatives Considered**:
- **Middleware-based auth**: Rejected because it's less granular (all-or-nothing for all endpoints)
- **Decorator-based auth**: Rejected because FastAPI dependencies are more idiomatic and composable
- **Custom request handler wrapper**: Rejected as overly complex and harder to test

**Trade-offs**:
- ✅ Clear, testable, composable
- ❌ Slightly more verbose than decorators

---

### Decision 2: slowapi Library for Rate Limiting

**Choice**: Use the `slowapi` library (Flask-Limiter port for FastAPI) with sliding window algorithm and Redis-like storage.

**Rationale**:
- Well-established library with FastAPI integration
- Supports sliding window algorithm (prevents bucket boundary abuse)
- Per-route rate limit configuration
- Built-in `Retry-After` header support
- Configurable key functions (can combine IP + API key)

**Implementation**:
```python
# snapauth/app/security/rate_limit.py
from slowapi import Limiter
from slowapi.util import get_remote_address

def get_client_identifier(request: Request) -> str:
    """Combine IP and API key for rate limit tracking."""
    client_ip = get_client_ip(request)
    api_key = request.headers.get("X-SnapAuth-API-Key", "")
    return f"{client_ip}:{api_key[:8]}" if api_key else client_ip

limiter = Limiter(
    key_func=get_client_identifier,
    enabled=settings.rate_limit_enabled,
)

# Usage
@limiter.limit("10/minute")
@app.post("/v1/auth/login")
async def login(...):
```

**Alternatives Considered**:
- **Custom rate limiter with Redis**: More control but significant development effort
- **fastapi-limiter**: Less mature, fewer features
- **Nginx rate limiting**: Rejected because it can't differentiate by API key

**Trade-offs**:
- ✅ Battle-tested, feature-rich
- ✅ Sliding window prevents burst attacks
- ❌ In-memory storage (doesn't scale horizontally without Redis backend)

---

### Decision 3: Constant-Time API Key Comparison with `secrets.compare_digest()`

**Choice**: Use Python's `secrets.compare_digest()` for all API key comparisons to prevent timing attacks.

**Rationale**:
- Standard library function specifically designed for this purpose
- Constant-time comparison prevents attackers from learning key prefixes via timing analysis
- Zero dependencies
- Simple to implement correctly

**Implementation**:
```python
# snapauth/app/security/api_key.py
import secrets

def verify_api_key(api_key: str) -> bool:
    valid_keys = settings.snapauth_admin_api_keys.split(',')
    for valid_key in valid_keys:
        if secrets.compare_digest(api_key, valid_key.strip()):
            return True
    return False
```

**Alternatives Considered**:
- **String equality `==`**: Rejected due to timing attack vulnerability
- **Hashing both keys and comparing hashes**: Unnecessary complexity for this use case
- **HMAC-based comparison**: Overkill for simple key verification

**Trade-offs**:
- ✅ Secure by default
- ✅ Simple implementation
- ❌ Slightly slower than `==` (but microseconds, not user-facing)

---

### Decision 4: IP Whitelisting with `ipaddress` Module

**Choice**: Use Python's standard `ipaddress` module for CIDR parsing and IP matching.

**Rationale**:
- Handles both IPv4 and IPv6 transparently
- Built-in CIDR notation support (`IPv4Network`, `IPv6Network`)
- Type-safe network calculations
- No external dependencies

**Implementation**:
```python
# snapauth/app/security/ip_whitelist.py
import ipaddress
from typing import Set

def parse_ip_whitelist() -> Set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    whitelist = settings.admin_allowed_ips.split(',')
    networks = set()
    for entry in whitelist:
        entry = entry.strip()
        if '/' in entry:
            networks.add(ipaddress.ip_network(entry))
        else:
            networks.add(ipaddress.ip_network(f"{entry}/32" if ':' not in entry else f"{entry}/128"))
    return networks

def is_ip_allowed(client_ip: str) -> bool:
    ip_obj = ipaddress.ip_address(client_ip)
    for network in parse_ip_whitelist():
        if ip_obj in network:
            return True
    return False
```

**Alternatives Considered**:
- **Regex-based IP matching**: Error-prone, doesn't handle CIDR
- **netaddr library**: More features but external dependency
- **Manual CIDR calculation**: Complex and error-prone

**Trade-offs**:
- ✅ Correct IPv4/IPv6 handling
- ✅ Standard library
- ❌ Parses whitelist on every request (could cache)

---

### Decision 5: Structured JSON Audit Logging via Python's logging Module

**Choice**: Use Python's standard `logging` module with JSON formatting for audit events, outputting to stdout for Docker collection.

**Rationale**:
- Docker's JSON log driver can parse and forward structured logs
- Standard logging module integrates with FastAPI's existing logging
- JSON format queryable by log aggregation tools (Loki, Elasticsearch)
- No external dependencies for basic use case

**Implementation**:
```python
# snapauth/app/security/audit.py
import logging
import json
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

def log_audit_event(
    event_type: str,
    request: Request,
    user_id: Optional[str] = None,
    details: Optional[Dict] = None,
    success: bool = True,
):
    audit_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "client_ip": get_client_ip(request),
        "user_id": user_id,
        "success": success,
        "details": details or {},
    }
    logger.info(json.dumps(audit_data))
```

**Alternatives Considered**:
- **python-json-logger library**: Adds dependency for minimal benefit
- **Direct database logging**: Adds latency and complexity to request path
- **Separate audit service**: Overkill for current requirements

**Trade-offs**:
- ✅ Simple, standard, Docker-compatible
- ✅ Queryable via `docker logs <container> | jq`
- ❌ No built-in log rotation (delegated to Docker log driver)

---

### Decision 6: Pre-Built Release Tarballs for Air-Gapped Deployment

**Choice**: Build Docker images in CI/CD, export to tarballs with `docker save`, bundle all images and deployment files into a single release tarball.

**Rationale**:
- Air-gapped servers can't pull from registries or clone git repos
- `docker save` / `docker load` is the standard offline Docker workflow
- Single tarball is easy to transfer (USB, secure courier)
- VERSION.yml manifest provides integrity verification

**Implementation**:
```yaml
# .github/workflows/release.yml
- name: Build and export images
  run: |
    docker build -t snapauth:$VERSION snapauth/
    docker build -t snapauth-bootstrap:$VERSION scripts/
    docker save snapauth:$VERSION > images/snapauth-$VERSION.tar
    docker save snapauth-bootstrap:$VERSION > images/bootstrap-$VERSION.tar

    docker pull fusionauth/fusionauth-app:1.50.1
    docker save fusionauth/fusionauth-app:1.50.1 > images/fusionauth-1.50.1.tar

    docker pull postgres:16-alpine
    docker save postgres:16-alpine > images/postgres-16-alpine.tar

    tar czf snapauth-release-$VERSION.tar.gz images/ docker-compose.yml Makefile offline-install.sh VERSION.yml docs/
```

**Alternatives Considered**:
- **Git submodules with local build**: Requires build tools and dependencies on air-gapped server
- **Docker registry in tarball**: Complex setup, unnecessary for this use case
- **Separate tarballs per image**: More files to transfer, easier to lose pieces

**Trade-offs**:
- ✅ Works in completely offline environments
- ✅ Reproducible builds
- ❌ Large tarball size (~2-3GB)

---

### Decision 7: Nginx Reverse Proxy for TLS Termination

**Choice**: Add an Nginx container to docker-compose.yml for TLS termination in production, keeping SnapAuth on HTTP internally.

**Rationale**:
- Separates TLS concerns from application code
- Nginx is battle-tested for TLS performance
- Enables HTTP/2 support
- Easier certificate management (volume mount)
- SnapAuth FastAPI code remains simpler (no TLS config)

**Implementation**:
```yaml
# docker-compose.yml
services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs/:/etc/nginx/certs/:ro
    depends_on:
      - snapauth

  snapauth:
    # No ports exposed externally in production
    expose:
      - "8080"
```

```nginx
# nginx.conf
server {
    listen 443 ssl http2;
    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://snapauth:8080;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }
}
```

**Alternatives Considered**:
- **TLS in FastAPI (uvicorn)**: Adds complexity to app code, harder to manage certificates
- **Traefik**: Heavier, more complex for this simple use case
- **Cloud load balancer TLS**: Assumes cloud deployment, doesn't work air-gapped

**Trade-offs**:
- ✅ Industry standard, simple, performant
- ✅ Certificate management via volume mount
- ❌ Extra container to manage

---

### Decision 8: Isolated Network by Default, Microservices Mode Optional

**Choice**: Default docker-compose.yml uses isolated bridge networks. Microservices mode enabled via `docker-compose.microservices.yml` override file.

**Rationale**:
- Security by default (only port 8080/443 exposed)
- Prevents accidental exposure of FusionAuth/PostgreSQL
- Optional integration doesn't complicate default deployment
- Explicit opt-in for shared-services network

**Implementation**:
```yaml
# docker-compose.yml (default - isolated)
networks:
  snapauth-internal:
    driver: bridge
  fusionauth-backend:
    driver: bridge
    internal: true  # No external access

services:
  snapauth:
    networks: [snapauth-internal, fusionauth-backend]
  fusionauth:
    networks: [fusionauth-backend]  # Isolated
  db:
    networks: [fusionauth-backend]  # Isolated

# docker-compose.microservices.yml (opt-in)
services:
  snapauth:
    networks:
      - shared-services
networks:
  shared-services:
    external: true
```

```makefile
# Makefile
MODE ?= isolated
up:
    @if [ "$(MODE)" = "microservices" ]; then \
        $(COMPOSE) -f docker-compose.yml -f docker-compose.microservices.yml up -d; \
    else \
        $(COMPOSE) up -d; \
    fi
```

**Alternatives Considered**:
- **Shared network by default**: Rejected for security (exposes backend services)
- **Single network for everything**: Simpler but less secure
- **Environment variable to enable**: Rejected as less explicit than override file

**Trade-offs**:
- ✅ Secure by default
- ✅ Explicit opt-in for integration
- ❌ Slightly more complex deployment command for microservices mode

---

### Decision 9: Zero-Downtime API Key Rotation via Comma-Separated List

**Choice**: Support multiple active API keys in `SNAPAUTH_ADMIN_API_KEYS` environment variable, validated in sequence.

**Rationale**:
- During rotation, both old and new keys are valid (grace period)
- Allows client migration without service interruption
- Simple implementation (split on comma, check each)
- No additional infrastructure needed (no database, no Redis)

**Implementation**:
```python
# snapauth/app/settings.py
snapauth_admin_api_keys: str = Field(default="")

# snapauth/app/security/api_key.py
def verify_api_key(api_key: str) -> bool:
    valid_keys = [k.strip() for k in settings.snapauth_admin_api_keys.split(',') if k.strip()]
    for valid_key in valid_keys:
        if secrets.compare_digest(api_key, valid_key):
            return True
    return False
```

**Rotation Procedure**:
1. Generate new key: `new_key=$(python -c "import secrets; print(secrets.token_urlsafe(32))")`
2. Update .env: `SNAPAUTH_ADMIN_API_KEYS=old_key,new_key`
3. Restart service: `docker-compose restart snapauth`
4. Migrate clients to new_key
5. Update .env: `SNAPAUTH_ADMIN_API_KEYS=new_key`
6. Restart service again

**Alternatives Considered**:
- **Database-stored keys with active/inactive flag**: Adds DB dependency for auth check (latency)
- **Dual environment variables (PRIMARY/SECONDARY)**: More complex, same functionality
- **Versioned keys with expiration dates**: Overkill for current requirements

**Trade-offs**:
- ✅ Zero downtime, no external dependencies
- ✅ Simple implementation
- ❌ Manual rotation process (could be scripted)

---

### Decision 10: Resource Limits in docker-compose.yml `deploy` Section

**Choice**: Define CPU and memory limits using Docker Compose `deploy.resources` section.

**Rationale**:
- Prevents any single container from exhausting host resources
- Defined in version-controlled config (not runtime flags)
- Works with Docker Compose in both Swarm and non-Swarm modes (when using `docker-compose --compatibility`)
- Clear documentation of resource expectations

**Implementation**:
```yaml
# docker-compose.yml
services:
  snapauth:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M

  fusionauth:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 1G
        reservations:
          cpus: '1.0'
          memory: 512M
    environment:
      FUSIONAUTH_APP_MEMORY: 512M
```

**Alternatives Considered**:
- **cgroup limits via Docker run flags**: Not declarative, not in version control
- **Kubernetes resource quotas**: Overkill for Docker Compose deployments
- **No limits**: Rejected due to resource exhaustion risk

**Trade-offs**:
- ✅ Predictable resource usage
- ✅ Protects host from runaway containers
- ❌ May need tuning for large deployments

## Risks / Trade-offs

### Risk 1: API Key Leakage via Environment Variables
**Risk**: API keys stored in `.env` file could be exposed via process listings or Docker inspect.

**Mitigation**:
- Document `.env` file permissions (chmod 600)
- Provide secrets rotation script for rapid key invalidation
- Add `.env.enc` encrypted backup option
- Future: Support external secrets management (Vault, AWS Secrets Manager)

---

### Risk 2: Rate Limiting in-Memory Storage Doesn't Scale Horizontally
**Risk**: slowapi uses in-memory storage, so rate limits are per-instance. If multiple SnapAuth instances run, each has independent rate limit counters.

**Mitigation**:
- Document as single-instance limitation
- For multi-instance deployments, suggest Redis backend for slowapi
- Current target deployments are single-instance (air-gapped servers)
- Future: Add Redis support as optional configuration

---

### Risk 3: Backup Encryption Passphrase Management
**Risk**: If operators lose the backup encryption passphrase, backups are irrecoverable.

**Mitigation**:
- Document passphrase management in docs/SECURITY.md
- Recommend passphrase storage in organizational password manager
- Support `BACKUP_ENCRYPTION_KEY` environment variable for automated backups
- Create unencrypted backup option for non-sensitive dev environments

---

### Risk 4: Air-Gapped Update Process Complexity
**Risk**: Applying security patches in air-gapped environments requires manual tarball transfer and image loading.

**Mitigation**:
- Create incremental patch tarballs (only changed images, not full release)
- Document update procedure in docs/AIR-GAPPED-DEPLOYMENT.md
- Provide `update.sh` script for automated patch application
- Include CHANGELOG.md and SECURITY-ADVISORY.md in patch tarballs

---

### Risk 5: TLS Certificate Management Complexity
**Risk**: Operators may deploy with self-signed certificates or expired certificates.

**Mitigation**:
- Provide self-signed certificate generation script for development
- Document Let's Encrypt integration in docs/SECURITY.md
- Add Nginx health check that validates certificate expiration
- Log warnings when certificate expires within 30 days

---

### Risk 6: Breaking Changes to API Contract
**Risk**: Requiring API key on `POST /v1/users` breaks existing clients.

**Mitigation**:
- Clearly mark as BREAKING in release notes
- Provide migration guide with example curl commands
- Version the release as 2.0.0 (semantic versioning major bump)
- Consider grace period with warning headers (future enhancement)

---

### Risk 7: Audit Log Volume on High-Traffic Deployments
**Risk**: Logging every authentication event could generate excessive log volume.

**Mitigation**:
- Use Docker JSON log driver with log rotation (max-size, max-file)
- Document log retention policies in docs/INSTALLATION.md
- Support log sampling for high-volume events (future enhancement)
- Recommend external log aggregation (Loki, Elasticsearch) for large deployments

## Migration Plan

### Phase 0: Security Fixes (Week 1 - BLOCKER)
**Goal**: Fix critical vulnerabilities in SnapAuth codebase before platform deployment.

**Steps**:
1. Create `snapauth/app/security/` module with all security components
2. Update `requirements.txt` to add `slowapi==0.1.9`
3. Modify `main.py` to add auth dependencies to admin endpoints
4. Update `settings.py` with security configuration fields
5. Remove token logging from all log statements
6. Write comprehensive security tests in `tests/test_security.py`
7. Build new SnapAuth image (v1.1.0 or v2.0.0)
8. Export image to tarball for air-gapped deployment

**Validation**:
- Run security test suite (all tests pass)
- Manual testing: verify POST /v1/users returns 401 without API key
- Manual testing: verify rate limiting triggers on 11th login attempt
- Manual testing: verify audit logs appear in `docker logs`

**Rollback**:
- If critical bugs found, revert to previous image tag
- No database migrations, so rollback is safe

---

### Phase 1: Platform Infrastructure (Week 2)
**Goal**: Update snapauth-platform with isolated networking, Nginx, resource limits.

**Steps**:
1. Modify `docker-compose.yml`:
   - Add isolated networks (snapauth-internal, fusionauth-backend)
   - Add Nginx service with TLS config
   - Add resource limits to all services
   - Remove port 8080 exposure (only Nginx 443 exposed)
2. Create `docker-compose.microservices.yml` override
3. Create `nginx.conf` with TLS configuration
4. Update `Makefile` with MODE support
5. Test both isolated and microservices modes

**Validation**:
- `make up` → only port 443 exposed
- `make up MODE=microservices` → snapauth on shared-services network
- `docker network inspect` shows correct network isolation
- `curl https://localhost:443/health` works with TLS

**Rollback**:
- `git revert` the docker-compose.yml changes
- Restart with previous version

---

### Phase 2: Operational Tooling (Week 3)
**Goal**: Add backup/restore scripts and secrets management.

**Steps**:
1. Create `scripts/backup.sh` with database dump and encryption
2. Create `scripts/restore.sh` with decryption and import
3. Create `scripts/manage-secrets.sh` with rotation commands
4. Update `Makefile` with backup/restore targets
5. Test full backup/restore cycle

**Validation**:
- `make backup` creates timestamped backup files
- `make clean && make restore` recovers all data
- Backup encryption requires passphrase
- Old backups >30 days are cleaned up

**Rollback**:
- Scripts don't modify existing infrastructure
- Can be removed without impacting service

---

### Phase 3: Release Distribution (Week 4)
**Goal**: Build and test complete release tarball with offline installation.

**Steps**:
1. Update `.github/workflows/publish.yml` to export images
2. Create `offline-install.sh` script
3. Create `VERSION.yml` manifest template
4. Build complete release tarball
5. Test on clean VM without internet

**Validation**:
- Extract tarball on air-gapped VM
- `./offline-install.sh` loads all images
- `make up` starts all services successfully
- `docker images` shows 4 loaded images
- No network calls to external registries

**Rollback**:
- Release artifacts are additive (old versions still downloadable)
- Users can continue using old image pull method

---

### Phase 4: Documentation (Week 5)
**Goal**: Comprehensive documentation for all deployment scenarios.

**Steps**:
1. Create `docs/SECURITY.md` with API key management, TLS setup
2. Create `docs/AIR-GAPPED-DEPLOYMENT.md` with offline procedure
3. Create `docs/NETWORK-MODES.md` with isolated vs microservices
4. Update `docs/INSTALLATION.md` with resource limits and recommendations
5. Create `.env.example` with all security variables documented

**Validation**:
- Fresh operator can follow docs and deploy successfully
- All deployment modes documented with examples
- Security hardening checklist complete

**Rollback**:
- Documentation changes are non-breaking

---

### Deployment Rollback Strategy
If issues are discovered in production:

1. **Application issues**:
   - Rollback to previous Docker image tag
   - Update `docker-compose.yml` image tags
   - `docker-compose up -d --force-recreate`

2. **Configuration issues**:
   - Restore previous `.env` file from backup
   - `docker-compose restart`

3. **Database corruption**:
   - Run `make restore BACKUP_PATH=<latest-backup>`
   - Restores PostgreSQL dump and configuration

4. **Network issues**:
   - `git revert` docker-compose.yml network changes
   - `docker-compose down && docker-compose up -d`

## Open Questions

### Q1: Should we support OAuth client credentials flow for API key auth?
**Context**: Currently using simple API key in header. OAuth client credentials would be more standardized.

**Trade-off**: More complex but more interoperable

**Decision needed**: Week 1

---

### Q2: Should audit logs be sent to a separate audit database?
**Context**: Currently using JSON stdout logging. Separate database would improve queryability but add complexity.

**Trade-off**: Better compliance vs. operational overhead

**Decision needed**: Week 3

---

### Q3: Should we provide a web UI for viewing audit logs?
**Context**: Currently operators must use `docker logs` or log aggregation tools.

**Trade-off**: Better UX vs. scope creep

**Decision needed**: Post-MVP (out of scope for this release)

---

### Q4: Should Redis backend for rate limiting be included in docker-compose.yml?
**Context**: slowapi supports Redis but adds another service to manage.

**Trade-off**: Horizontal scalability vs. deployment simplicity

**Decision needed**: Week 2 (lean toward optional for now)

---

### Q5: Should we bundle Grafana dashboards for monitoring in the release?
**Context**: Observability stack (Prometheus, Grafana) is optional. Should we provide pre-built dashboards?

**Trade-off**: Better operator experience vs. maintenance burden

**Decision needed**: Week 4 (lean toward yes, as separate observability guide)

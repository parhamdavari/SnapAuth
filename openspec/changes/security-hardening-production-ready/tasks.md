## 1. Security Module Setup (SnapAuth Codebase)

- [x] 1.1 Create `snapauth/app/security/` directory structure
- [x] 1.2 Create `snapauth/app/security/__init__.py` module initialization
- [x] 1.3 Add `slowapi==0.1.9` to `snapauth/requirements.txt`
- [x] 1.4 Update `snapauth/app/settings.py` to add security configuration fields (SNAPAUTH_ADMIN_API_KEYS, ADMIN_ALLOWED_IPS, TRUST_PROXY, RATE_LIMIT_ENABLED, etc.)

## 2. API Key Authentication Implementation

- [x] 2.1 Implement `snapauth/app/security/api_key.py` with `verify_api_key()` using `secrets.compare_digest()`
- [x] 2.2 Implement `require_admin_api_key()` FastAPI dependency in api_key.py
- [x] 2.3 Add support for comma-separated multiple API keys in `verify_api_key()`
- [x] 2.4 Implement API key redaction for logging (first 8 chars + "...")

## 3. IP Whitelisting Implementation

- [x] 3.1 Implement `snapauth/app/security/ip_whitelist.py` with `parse_ip_whitelist()` using `ipaddress` module
- [x] 3.2 Implement `get_client_ip()` function with X-Forwarded-For support (respects TRUST_PROXY)
- [x] 3.3 Implement `is_ip_allowed()` function for CIDR matching (IPv4 and IPv6)
- [x] 3.4 Implement `require_ip_whitelist()` FastAPI dependency

## 4. Combined Security Dependencies

- [x] 4.1 Implement `snapauth/app/security/dependencies.py` with `require_admin_access()` combining API key + IP whitelist
- [x] 4.2 Implement `require_self_or_admin()` dependency for user-specific endpoints (checks JWT sub claim OR admin API key)
- [x] 4.3 Import and expose security dependencies in `snapauth/app/security/__init__.py`

## 5. Rate Limiting Implementation

- [x] 5.1 Implement `snapauth/app/security/rate_limit.py` with slowapi Limiter configuration
- [x] 5.2 Implement `get_client_identifier()` combining IP + API key for rate limit tracking
- [x] 5.3 Create rate limit decorators: `@limiter.limit("10/minute")` for auth, `@limiter.limit("30/minute")` for admin
- [x] 5.4 Configure Limiter with `enabled=settings.rate_limit_enabled` for dev/prod toggle

## 6. Security Headers Middleware

- [x] 6.1 Implement `snapauth/app/security/middleware.py` with `SecurityHeadersMiddleware` class
- [x] 6.2 Add security headers: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Content-Security-Policy
- [x] 6.3 Add conditional HSTS header (only when HTTPS detected)
- [x] 6.4 Register middleware in `snapauth/app/main.py`

## 7. Audit Logging Implementation

- [x] 7.1 Implement `snapauth/app/security/audit.py` with `log_audit_event()` function
- [x] 7.2 Implement JSON audit log formatting (timestamp, event_type, client_ip, user_id, success, details)
- [x] 7.3 Ensure timestamp uses ISO 8601 format with UTC timezone
- [x] 7.4 Implement sensitive data redaction (passwords, full API keys, JWT tokens never logged)

## 8. Update Main Application Endpoints

- [x] 8.1 Add `dependencies=[Depends(require_admin_access)]` to `POST /v1/users` endpoint
- [x] 8.2 Update `DELETE /v1/users/{id}` endpoint to use `require_self_or_admin` dependency
- [x] 8.3 Create new `DELETE /v1/admin/users/{id}` endpoint with `require_admin_access` dependency
- [x] 8.4 Add rate limiting decorators to `POST /v1/auth/login` (10/min), admin endpoints (30/min), authenticated endpoints (60/min)
- [x] 8.5 Remove JWT token content from all log statements in `snapauth/app/main.py`
- [x] 8.6 Add audit logging calls to user creation, deletion, login success, and login failure

## 9. Security Testing

- [x] 9.1 Create `snapauth/tests/test_security.py` test file
- [x] 9.2 Write test: `test_create_user_without_api_key()` expects 401
- [x] 9.3 Write test: `test_create_user_with_invalid_api_key()` expects 401
- [x] 9.4 Write test: `test_create_user_with_valid_api_key()` expects 201
- [x] 9.5 Write test: `test_user_cannot_delete_others()` expects 403
- [x] 9.6 Write test: `test_admin_can_delete_any_user()` expects 200
- [x] 9.7 Write test: `test_rate_limit_login()` expects 429 after 11 requests
- [x] 9.8 Write test: `test_ip_whitelist_blocks_unauthorized_ip()` expects 403
- [x] 9.9 Write test: `test_ip_whitelist_allows_whitelisted_ip()` expects success
- [x] 9.10 Write test: `test_security_headers_present()` validates all headers
- [x] 9.11 Write test: `test_audit_log_created()` validates JSON structure

## 10. Bootstrap Secret Generation

- [x] 10.1 Update `scripts/bootstrap.py` to generate `SNAPAUTH_ADMIN_API_KEY` using `secrets.token_urlsafe(32)`
- [x] 10.2 Add `ADMIN_ALLOWED_IPS` default value (10.0.0.0/8,172.16.0.0/12,192.168.0.0/16) to bootstrap
- [x] 10.3 Add security configuration variables to bootstrap output
- [x] 10.4 Test bootstrap generates .env file with admin API key

## 11. Build and Export SnapAuth Images

- [x] 11.1 Run full security test suite and verify all tests pass
- [x] 11.2 Build SnapAuth Docker image with security fixes (tag as v1.1.0 or v2.0.0)
- [x] 11.3 Build Bootstrap Docker image
- [x] 11.4 Test images locally with docker-compose
- [x] 11.5 Export SnapAuth image to tarball: `docker save snapauth:v1.1.0 > snapauth-v1.1.0.tar`
- [x] 11.6 Export Bootstrap image to tarball: `docker save snapauth-bootstrap:v1.1.0 > bootstrap-v1.1.0.tar`

## 12. Platform Network Architecture (snapauth-platform)

- [x] 12.1 Update `docker-compose.yml` to define `snapauth-internal` bridge network
- [x] 12.2 Update `docker-compose.yml` to define `fusionauth-backend` internal bridge network
- [x] 12.3 Configure `snapauth` service on both networks (snapauth-internal, fusionauth-backend)
- [x] 12.4 Configure `fusionauth` service on fusionauth-backend network only (no external exposure)
- [x] 12.5 Configure `db` service on fusionauth-backend network only (no external exposure)
- [x] 12.6 Remove port exposure from snapauth service (will be proxied via Nginx)

## 13. Nginx Reverse Proxy for TLS

- [x] 13.1 Create `nginx.conf` file with TLS configuration
- [x] 13.2 Configure Nginx to listen on port 443 with SSL
- [x] 13.3 Configure SSL protocols (TLSv1.2, TLSv1.3) and strong cipher suites
- [x] 13.4 Configure proxy_pass to `http://snapauth:8080`
- [x] 13.5 Add proxy headers (X-Forwarded-For, Host)
- [x] 13.6 Add HSTS header to HTTPS responses
- [x] 13.7 Add Nginx service to `docker-compose.yml` with volume mounts for certs and config
- [x] 13.8 Expose only port 443 from Nginx container

## 14. TLS Certificate Management

- [x] 14.1 Create `certs/` directory
- [x] 14.2 Create `certs/generate-self-signed.sh` script for development certificates
- [x] 14.3 Test self-signed certificate generation
- [x] 14.4 Add `certs/` to `.gitignore`
- [ ] 14.5 Document Let's Encrypt integration in `docs/SECURITY.md`

## 15. Resource Limits Configuration

- [x] 15.1 Add `deploy.resources.limits` to snapauth service (1.0 CPU, 512M memory)
- [x] 15.2 Add `deploy.resources.reservations` to snapauth service (0.5 CPU, 256M memory)
- [x] 15.3 Add `deploy.resources.limits` to fusionauth service (2.0 CPU, 1G memory)
- [x] 15.4 Add `deploy.resources.reservations` to fusionauth service (1.0 CPU, 512M memory)
- [x] 15.5 Configure `FUSIONAUTH_APP_MEMORY=512M` environment variable
- [x] 15.6 Add `deploy.resources.limits` to db service (2.0 CPU, 2G memory)
- [x] 15.7 Add `deploy.resources.reservations` to db service (1.0 CPU, 1G memory)
- [x] 15.8 Configure PostgreSQL with `shared_buffers=256MB` and `max_connections=100`
- [x] 15.9 Add `shm_size: 256mb` to db service

## 16. Microservices Integration Mode

- [x] 16.1 Create `docker-compose.microservices.yml` override file
- [x] 16.2 Add `shared-services` external network to microservices override
- [x] 16.3 Configure snapauth service to join shared-services network in override
- [x] 16.4 Update `Makefile` to add `MODE` variable (isolated/microservices)
- [x] 16.5 Update `make up` target to use `-f docker-compose.yml -f docker-compose.microservices.yml` when MODE=microservices
- [ ] 16.6 Test both deployment modes

## 17. Backup and Restore Scripts

- [x] 17.1 Create `scripts/backup.sh` script
- [x] 17.2 Implement PostgreSQL dump with gzip compression
- [x] 17.3 Implement configuration tarball creation (.env, kickstart/, docker-compose.yml)
- [x] 17.4 Implement .env encryption with AES-256-CBC using openssl
- [x] 17.5 Create backup MANIFEST.txt with metadata (timestamp, version, sizes)
- [x] 17.6 Implement 30-day backup retention cleanup
- [x] 17.7 Create `scripts/restore.sh` script
- [x] 17.8 Implement service stop before restore
- [x] 17.9 Implement configuration extraction from backup tarball
- [x] 17.10 Implement .env decryption
- [x] 17.11 Implement PostgreSQL database restoration
- [x] 17.12 Implement service restart after restore
- [x] 17.13 Add `make backup` and `make restore` targets to Makefile
- [ ] 17.14 Test full backup and restore cycle

## 18. Secrets Management and Rotation

- [x] 18.1 Create `scripts/manage-secrets.sh` script
- [x] 18.2 Implement `init` command (run bootstrap.py, encrypt .env)
- [x] 18.3 Implement `rotate` command (generate new API key, append to SNAPAUTH_ADMIN_API_KEYS)
- [x] 18.4 Implement `backup` command (create encrypted secrets tarball)
- [x] 18.5 Add prompt for old key removal after rotation
- [x] 18.6 Implement service restart after rotation
- [ ] 18.7 Test zero-downtime API key rotation workflow

## 19. Offline Deployment System

- [x] 19.1 Create `offline-install.sh` script
- [x] 19.2 Implement image loading loop (`docker load < images/*.tar`)
- [x] 19.3 Add image verification after loading
- [x] 19.4 Add error handling for missing image files
- [x] 19.5 Create `VERSION.yml` manifest template
- [x] 19.6 Add component versions and image digests to VERSION.yml
- [x] 19.7 Add checksums for all files to VERSION.yml
- [ ] 19.8 Test offline installation on air-gapped VM

## 20. CI/CD Release Pipeline

- [ ] 20.1 Update `.github/workflows/publish.yml` to build SnapAuth and Bootstrap images
- [ ] 20.2 Add step to export images with `docker save`
- [ ] 20.3 Add step to pull FusionAuth and PostgreSQL images
- [ ] 20.4 Add step to export third-party images to tarballs
- [ ] 20.5 Add step to generate VERSION.yml with checksums
- [ ] 20.6 Add step to create release tarball (tar czf snapauth-release-v1.1.0.tar.gz ...)
- [ ] 20.7 Add step to upload release tarball as GitHub release artifact
- [ ] 20.8 Test CI/CD pipeline builds complete release

## 21. Environment Configuration Template

- [x] 21.1 Create `.env.example` file in snapauth-platform
- [x] 21.2 Document SNAPAUTH_ADMIN_API_KEY variable
- [x] 21.3 Document SNAPAUTH_ADMIN_API_KEYS variable (for rotation)
- [x] 21.4 Document ADMIN_ALLOWED_IPS variable with CIDR examples
- [x] 21.5 Document TRUST_PROXY variable
- [x] 21.6 Document RATE_LIMIT_ENABLED variable
- [x] 21.7 Document RATE_LIMIT_PER_MINUTE_AUTH, RATE_LIMIT_PER_MINUTE_ADMIN, RATE_LIMIT_PER_MINUTE variables
- [x] 21.8 Document BACKUP_ENCRYPTION_KEY variable
- [x] 21.9 Add security warnings and best practices comments

## 22. Documentation - Security Guide

- [ ] 22.1 Create `docs/SECURITY.md` file
- [ ] 22.2 Document API key authentication architecture
- [ ] 22.3 Document API key generation and rotation procedures
- [ ] 22.4 Document IP whitelisting configuration with CIDR examples
- [ ] 22.5 Document TLS/HTTPS setup with Nginx
- [ ] 22.6 Document Let's Encrypt integration for certificate renewal
- [ ] 22.7 Document self-signed certificate generation for development
- [ ] 22.8 Document security headers and their purpose
- [ ] 22.9 Document audit logging format and querying examples
- [ ] 22.10 Document rate limiting configuration and tuning

## 23. Documentation - Air-Gapped Deployment

- [ ] 23.1 Create `docs/AIR-GAPPED-DEPLOYMENT.md` file
- [ ] 23.2 Document prerequisites for air-gapped deployment
- [ ] 23.3 Document release tarball transfer methods (USB, courier, etc.)
- [ ] 23.4 Document offline-install.sh usage
- [ ] 23.5 Document image verification with VERSION.yml checksums
- [ ] 23.6 Document deployment without internet access
- [ ] 23.7 Document patching and updates in air-gapped environments
- [ ] 23.8 Document troubleshooting offline deployments

## 24. Documentation - Network Modes

- [ ] 24.1 Create `docs/NETWORK-MODES.md` file
- [ ] 24.2 Document isolated mode architecture (default)
- [ ] 24.3 Document network isolation (only port 8080/443 exposed)
- [ ] 24.4 Document microservices integration mode
- [ ] 24.5 Document shared-services network configuration
- [ ] 24.6 Document deployment commands for each mode
- [ ] 24.7 Document network security considerations

## 25. Documentation - Installation Guide

- [ ] 25.1 Update `docs/INSTALLATION.md` (or create if not exists)
- [ ] 25.2 Document standard installation procedure
- [ ] 25.3 Document resource requirements and limits
- [ ] 25.4 Document deployment size recommendations (small/medium/large)
- [ ] 25.5 Document health check verification
- [ ] 25.6 Document backup/restore procedures
- [ ] 25.7 Document upgrade and rollback procedures

## 26. README Updates

- [ ] 26.1 Update main `README.md` to reference new security features
- [ ] 26.2 Add quick start section for air-gapped deployment
- [ ] 26.3 Add security highlights section
- [ ] 26.4 Add links to SECURITY.md, AIR-GAPPED-DEPLOYMENT.md, NETWORK-MODES.md
- [ ] 26.5 Update port documentation (8080/443 for SnapAuth, 9011 internal only)
- [ ] 26.6 Add breaking changes notice for v2.0.0

## 27. End-to-End Testing

- [ ] 27.1 Test isolated mode deployment from release tarball
- [ ] 27.2 Test microservices mode deployment
- [ ] 27.3 Test air-gapped deployment (no internet connectivity)
- [ ] 27.4 Test API key authentication (valid key returns 201, invalid returns 401)
- [ ] 27.5 Test IP whitelisting (whitelisted IP allowed, non-whitelisted blocked)
- [ ] 27.6 Test rate limiting (11th login attempt returns 429)
- [ ] 27.7 Test audit logging (events appear in docker logs as JSON)
- [ ] 27.8 Test security headers (X-Frame-Options, CSP, etc. present)
- [ ] 27.9 Test TLS/HTTPS (Nginx terminates TLS, proxies to SnapAuth)
- [ ] 27.10 Test backup and restore (complete data recovery)
- [ ] 27.11 Test API key rotation (zero downtime with multiple keys)
- [ ] 27.12 Test resource limits (containers respect CPU/memory limits)

## 28. Migration and Release Preparation

- [ ] 28.1 Create CHANGELOG.md with breaking changes highlighted
- [ ] 28.2 Create MIGRATION.md guide for upgrading from v1.x to v2.0
- [ ] 28.3 Document API contract changes (new headers required)
- [ ] 28.4 Provide example curl commands for new authentication
- [ ] 28.5 Tag release as v2.0.0 (semantic versioning major bump)
- [ ] 28.6 Create GitHub release with tarball artifact
- [ ] 28.7 Update release notes with security advisory information

## ADDED Requirements

### Requirement: Production deployments use HTTPS via Nginx reverse proxy
Production deployments SHALL use an Nginx reverse proxy configured for TLS/HTTPS to encrypt all traffic to and from SnapAuth on port 443.

#### Scenario: Nginx reverse proxy configured
- **WHEN** the stack is deployed in production mode
- **THEN** an Nginx container is running with TLS configuration

#### Scenario: HTTPS traffic proxied to SnapAuth
- **WHEN** a request is made to `https://snapauth.example.com/health`
- **THEN** Nginx terminates TLS and proxies the request to `http://snapauth:8080/health`

#### Scenario: HTTP port not exposed in production
- **WHEN** the stack is deployed in production mode
- **THEN** port 8080 is NOT exposed to the host (only Nginx's port 443 is exposed)

### Requirement: TLS 1.2+ enforced with strong ciphers
The Nginx configuration SHALL enforce TLS 1.2 as the minimum protocol version and SHALL use only strong cipher suites to prevent downgrade attacks.

#### Scenario: TLS 1.2 minimum version
- **WHEN** a client attempts to connect using TLS 1.1
- **THEN** Nginx rejects the connection

#### Scenario: Strong ciphers configured
- **WHEN** Nginx is configured
- **THEN** it uses cipher suites from Mozilla's "Modern" or "Intermediate" compatibility profile

### Requirement: Certificate management via volume mounts
TLS certificates and private keys SHALL be provided to Nginx via Docker volume mounts at `/etc/nginx/certs/` to enable external certificate management.

#### Scenario: Custom certificates mounted
- **WHEN** an operator places `server.crt` and `server.key` in `./certs/` directory
- **THEN** Nginx uses those certificates for TLS

#### Scenario: Certificate renewal via volume
- **WHEN** an operator replaces certificates in `./certs/` and reloads Nginx
- **THEN** Nginx uses the new certificates without container rebuild

### Requirement: Self-signed certificate generation for development
The system SHALL provide a script (`certs/generate-self-signed.sh`) to generate self-signed certificates for development and testing purposes.

#### Scenario: Self-signed certificate generation
- **WHEN** `./certs/generate-self-signed.sh` is executed
- **THEN** `certs/server.crt` and `certs/server.key` are created with a 365-day validity

#### Scenario: Development mode uses self-signed cert
- **WHEN** the stack is deployed in development mode without custom certificates
- **THEN** the system uses the generated self-signed certificate

### Requirement: X-Forwarded-For header set by Nginx
Nginx SHALL set the `X-Forwarded-For` header to preserve the original client IP address when proxying requests to SnapAuth.

#### Scenario: Nginx sets X-Forwarded-For
- **WHEN** a request arrives at Nginx from IP 203.0.113.50
- **THEN** Nginx adds header `X-Forwarded-For: 203.0.113.50` when proxying to SnapAuth

#### Scenario: SnapAuth uses proxied IP
- **WHEN** `TRUST_PROXY=true` and a request is proxied through Nginx
- **THEN** SnapAuth logs and rate-limits based on the IP from `X-Forwarded-For`

### Requirement: HSTS header enforced by Nginx
Nginx SHALL add the `Strict-Transport-Security` header to all HTTPS responses to enforce HTTPS for future requests.

#### Scenario: HSTS header on HTTPS responses
- **WHEN** a request is made over HTTPS
- **THEN** Nginx adds header `Strict-Transport-Security: max-age=31536000; includeSubDomains`

#### Scenario: HSTS header not sent on HTTP
- **WHEN** a request is made to port 80 (HTTP) in development mode
- **THEN** Nginx SHALL NOT add the HSTS header

### Requirement: HTTP to HTTPS redirect in production
In production mode, Nginx SHALL redirect all HTTP requests (port 80) to HTTPS (port 443) to enforce encrypted connections.

#### Scenario: HTTP request redirected to HTTPS
- **WHEN** a request is made to `http://snapauth.example.com/health`
- **THEN** Nginx returns HTTP 301 redirect to `https://snapauth.example.com/health`

#### Scenario: Development mode allows HTTP
- **WHEN** development mode is configured
- **THEN** HTTP requests on port 8080 are processed without redirect

### Requirement: Documentation for certificate management
The system SHALL provide documentation in `docs/SECURITY.md` explaining how to configure TLS certificates, including Let's Encrypt integration and certificate renewal.

#### Scenario: Certificate documentation includes Let's Encrypt
- **WHEN** an operator reads `docs/SECURITY.md`
- **THEN** it includes instructions for using certbot with Nginx for automated certificate renewal

#### Scenario: Certificate renewal documented
- **WHEN** an operator needs to renew certificates
- **THEN** `docs/SECURITY.md` explains the renewal process and how to reload Nginx

## ADDED Requirements

### Requirement: X-Frame-Options header prevents clickjacking
All HTTP responses SHALL include the `X-Frame-Options: DENY` header to prevent the application from being embedded in iframes and protect against clickjacking attacks.

#### Scenario: Response includes X-Frame-Options
- **WHEN** any request is made to any endpoint
- **THEN** the response includes header `X-Frame-Options: DENY`

#### Scenario: Browser enforces frame denial
- **WHEN** an attacker attempts to embed SnapAuth in an iframe
- **THEN** the browser blocks the embedding due to the X-Frame-Options header

### Requirement: X-Content-Type-Options prevents MIME sniffing
All HTTP responses SHALL include the `X-Content-Type-Options: nosniff` header to prevent browsers from MIME-sniffing responses and interpreting files as a different content type.

#### Scenario: Response includes nosniff header
- **WHEN** any request is made
- **THEN** the response includes header `X-Content-Type-Options: nosniff`

### Requirement: Content-Security-Policy restricts resource loading
All HTTP responses SHALL include a `Content-Security-Policy` header with `default-src 'none'` to prevent loading of external resources and mitigate XSS attacks.

#### Scenario: Response includes CSP header
- **WHEN** any request is made
- **THEN** the response includes header `Content-Security-Policy: default-src 'none'`

### Requirement: Strict-Transport-Security enforces HTTPS
When TLS is enabled, all HTTP responses SHALL include the `Strict-Transport-Security` header with `max-age=31536000` to enforce HTTPS for one year.

#### Scenario: HSTS header on HTTPS responses
- **WHEN** a request is made over HTTPS
- **THEN** the response includes header `Strict-Transport-Security: max-age=31536000`

#### Scenario: HSTS not sent on HTTP responses
- **WHEN** a request is made over HTTP (development mode)
- **THEN** the response SHALL NOT include the Strict-Transport-Security header

### Requirement: X-XSS-Protection header enabled
All HTTP responses SHALL include the `X-XSS-Protection: 1; mode=block` header to enable browser XSS filtering.

#### Scenario: Response includes XSS protection header
- **WHEN** any request is made
- **THEN** the response includes header `X-XSS-Protection: 1; mode=block`

### Requirement: Security headers applied via middleware
Security headers SHALL be applied to all responses via a middleware component to ensure consistent application across all endpoints including error responses.

#### Scenario: Headers present on successful response
- **WHEN** a request to `GET /health` returns HTTP 200
- **THEN** all security headers are present in the response

#### Scenario: Headers present on error response
- **WHEN** a request to `POST /v1/users` returns HTTP 401
- **THEN** all security headers are present in the error response

#### Scenario: Headers present on rate-limited response
- **WHEN** a request returns HTTP 429 due to rate limiting
- **THEN** all security headers are present in the rate limit response

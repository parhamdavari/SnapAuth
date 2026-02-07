## ADDED Requirements

### Requirement: Tiered rate limits by endpoint category
The system SHALL enforce three tiers of rate limits based on endpoint sensitivity: public authentication endpoints (10 requests per minute), admin endpoints (30 requests per minute), and authenticated user endpoints (60 requests per minute).

#### Scenario: Public auth endpoint rate limit
- **WHEN** a client makes 11 requests to `POST /v1/auth/login` within 1 minute
- **THEN** the 11th request returns HTTP 429 Too Many Requests

#### Scenario: Admin endpoint rate limit
- **WHEN** a client makes 31 requests to `POST /v1/users` within 1 minute with a valid API key
- **THEN** the 31st request returns HTTP 429 Too Many Requests

#### Scenario: Authenticated endpoint rate limit
- **WHEN** an authenticated user makes 61 requests to `PATCH /v1/users/{id}` within 1 minute
- **THEN** the 61st request returns HTTP 429 Too Many Requests

#### Scenario: Under rate limit threshold
- **WHEN** a client makes 9 requests to `POST /v1/auth/login` within 1 minute
- **THEN** all requests are processed normally (under 10/min limit)

### Requirement: Rate limit enforcement enabled by configuration
Rate limiting SHALL be controlled by the `RATE_LIMIT_ENABLED` environment variable. When set to `false`, rate limits SHALL NOT be enforced (useful for development environments).

#### Scenario: Rate limiting enabled
- **WHEN** `RATE_LIMIT_ENABLED=true` and a client exceeds the rate limit
- **THEN** the system returns HTTP 429 Too Many Requests

#### Scenario: Rate limiting disabled
- **WHEN** `RATE_LIMIT_ENABLED=false` and a client exceeds the configured rate limit
- **THEN** the system processes all requests normally without rate limiting

### Requirement: Configurable rate limit thresholds
The system SHALL support configurable rate limit thresholds via environment variables: `RATE_LIMIT_PER_MINUTE_AUTH` (default 10), `RATE_LIMIT_PER_MINUTE_ADMIN` (default 30), `RATE_LIMIT_PER_MINUTE` (default 60 for authenticated endpoints).

#### Scenario: Custom auth rate limit
- **WHEN** `RATE_LIMIT_PER_MINUTE_AUTH=5` and a client makes 6 requests to `POST /v1/auth/login` within 1 minute
- **THEN** the 6th request returns HTTP 429 Too Many Requests

#### Scenario: Custom admin rate limit
- **WHEN** `RATE_LIMIT_PER_MINUTE_ADMIN=100` and a client makes 99 requests to `POST /v1/users` within 1 minute
- **THEN** all requests are processed normally (under custom 100/min limit)

### Requirement: Rate limit identification by client IP and API key
Rate limits SHALL be tracked per unique client identifier, combining IP address and API key (if present). This prevents a single malicious client from exhausting rate limits for all users while allowing legitimate distributed systems with shared API keys.

#### Scenario: Different IP addresses with same API key
- **WHEN** Client A (IP: 192.168.1.100) makes 30 admin requests and Client B (IP: 192.168.1.101) makes 30 admin requests with the same API key
- **THEN** both clients' requests are processed normally (tracked separately by IP)

#### Scenario: Same IP address with different API keys
- **WHEN** Client A makes 30 admin requests with API Key 1 and 30 admin requests with API Key 2 from the same IP
- **THEN** both request sets are processed normally (tracked separately by API key)

#### Scenario: Unauthenticated requests tracked by IP only
- **WHEN** Client A (IP: 192.168.1.100) makes 10 login requests
- **THEN** the rate limit applies to that IP address only

### Requirement: 429 response includes retry-after header
When a request is rate-limited, the HTTP 429 response SHALL include a `Retry-After` header indicating the number of seconds until the rate limit resets.

#### Scenario: Rate limit response with retry-after
- **WHEN** a client exceeds the rate limit at 10:00:30
- **THEN** the HTTP 429 response includes header `Retry-After: 30` (30 seconds until 10:01:00)

#### Scenario: Client retries after waiting
- **WHEN** a client receives HTTP 429 at 10:00:30 and waits until 10:01:05 before retrying
- **THEN** the retry request is processed normally (rate limit window reset)

### Requirement: Rate limit windows use sliding window algorithm
The system SHALL implement rate limiting using a sliding window algorithm (not fixed time buckets) to provide smooth rate limiting and prevent burst attacks at window boundaries.

#### Scenario: Sliding window prevents bucket boundary abuse
- **WHEN** a client makes 10 requests between 10:00:50 and 10:01:00 and then 10 more requests between 10:01:00 and 10:01:10
- **THEN** some requests in the second batch are rate-limited (sliding window counts both periods)

#### Scenario: Gradual cooldown
- **WHEN** a client makes 10 requests at 10:00:00 and then waits until 10:00:40 to make another request
- **THEN** the request at 10:00:40 is processed normally (some capacity has freed up in the sliding window)

### Requirement: Public endpoints without rate limiting
Health check endpoints (`GET /health`, `GET /health/jwt-config`) and JWKS endpoints (`GET /.well-known/jwks.json`) SHALL NOT be subject to rate limiting to ensure monitoring and token verification remain available.

#### Scenario: Health check unlimited requests
- **WHEN** a monitoring system makes 1000 requests to `GET /health` within 1 minute
- **THEN** all requests return HTTP 200 (no rate limiting applied)

#### Scenario: JWKS endpoint unlimited requests
- **WHEN** multiple services make frequent requests to `GET /.well-known/jwks.json`
- **THEN** all requests return HTTP 200 with JWKS configuration (no rate limiting applied)

### Requirement: Rate limit metrics for monitoring
The system SHALL expose rate limit metrics including current request counts, rate limit hits, and per-endpoint statistics for monitoring and capacity planning.

#### Scenario: Rate limit hit metric incremented
- **WHEN** a client receives HTTP 429 due to rate limiting
- **THEN** the `snapauth_rate_limit_hits_total` metric is incremented for that endpoint

#### Scenario: Request count metric tracked
- **WHEN** a request is processed
- **THEN** the current request count for that client identifier is available in metrics

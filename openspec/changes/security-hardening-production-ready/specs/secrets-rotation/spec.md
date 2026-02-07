## ADDED Requirements

### Requirement: Zero-downtime API key rotation via multiple active keys
The system SHALL support multiple active API keys simultaneously to enable zero-downtime key rotation. API keys are configured in the `SNAPAUTH_ADMIN_API_KEYS` environment variable as a comma-separated list.

#### Scenario: Two API keys both valid
- **WHEN** `SNAPAUTH_ADMIN_API_KEYS=key1,key2` and a request uses either key1 or key2
- **THEN** the system authenticates successfully with either key

#### Scenario: Add new key without removing old
- **WHEN** `SNAPAUTH_ADMIN_API_KEYS` is changed from `key1` to `key1,key2` and the service is restarted
- **THEN** both key1 and key2 are valid

#### Scenario: Remove old key after clients migrated
- **WHEN** `SNAPAUTH_ADMIN_API_KEYS` is changed from `key1,key2` to `key2`
- **THEN** only key2 is valid and key1 is rejected with HTTP 401

### Requirement: Secrets rotation script
The system SHALL provide a `scripts/manage-secrets.sh rotate` command that generates a new API key, adds it to the environment, and optionally removes old keys.

#### Scenario: Rotation generates new key
- **WHEN** `./scripts/manage-secrets.sh rotate` is executed
- **THEN** a new API key is generated with 256-bit entropy and appended to `SNAPAUTH_ADMIN_API_KEYS`

#### Scenario: Rotation prompts for old key removal
- **WHEN** rotation completes
- **THEN** the script prompts "Keep old key for grace period? (y/n)" and removes it if user answers 'n'

#### Scenario: Service restart after rotation
- **WHEN** `./scripts/manage-secrets.sh rotate` completes
- **THEN** the script restarts the SnapAuth service with `docker-compose restart snapauth`

### Requirement: Key rotation preserves backward compatibility
During a grace period (when both old and new keys are active), the system SHALL accept requests using either key to prevent breaking existing clients.

#### Scenario: Old clients use old key during migration
- **WHEN** `SNAPAUTH_ADMIN_API_KEYS=key_old,key_new` and Client A uses key_old
- **THEN** requests from Client A succeed during the grace period

#### Scenario: New clients use new key
- **WHEN** `SNAPAUTH_ADMIN_API_KEYS=key_old,key_new` and Client B uses key_new
- **THEN** requests from Client B succeed immediately

### Requirement: Key rotation audit logs
When API keys are rotated, the system SHALL emit audit logs indicating the rotation event with redacted key prefixes.

#### Scenario: Rotation logged in audit
- **WHEN** a new API key is added via rotation
- **THEN** an audit log entry includes `event_type: "secrets.key_rotated"`, old key prefix, and new key prefix

#### Scenario: Old key removal logged
- **WHEN** an old API key is removed from the active list
- **THEN** an audit log entry includes `event_type: "secrets.key_removed"` and the removed key prefix

### Requirement: Encrypted secrets backup before rotation
Before rotating secrets, the `manage-secrets.sh` script SHALL create an encrypted backup of the current `.env` file to enable rollback if rotation fails.

#### Scenario: Backup created before rotation
- **WHEN** `./scripts/manage-secrets.sh rotate` is executed
- **THEN** a backup file `.env.backup-YYYYMMDD-HHMMSS.enc` is created before any changes

#### Scenario: Rollback using backup
- **WHEN** rotation fails and an operator runs `./scripts/manage-secrets.sh rollback`
- **THEN** the most recent backup is decrypted and restored as `.env`

### Requirement: Key naming and identification
When multiple API keys are configured, they SHALL be distinguishable in audit logs and metrics by their prefix (first 8 characters) to enable tracking which key is being used.

#### Scenario: Audit log identifies key by prefix
- **WHEN** a request is made using API key `abc12345xyz67890`
- **THEN** the audit log includes `api_key: "abc12345..."`

#### Scenario: Metrics track usage by key prefix
- **WHEN** monitoring metrics are collected
- **THEN** request counts are tagged with the API key prefix to show which key is in use

### Requirement: Database password rotation requires downtime
The system SHALL document that rotating the `DB_PASSWORD` requires service downtime and provides a procedure in `docs/SECURITY.md`.

#### Scenario: DB password rotation documented
- **WHEN** an operator needs to rotate the database password
- **THEN** `docs/SECURITY.md` explains the procedure: stop services, update FusionAuth and PostgreSQL passwords, update `.env`, restart services

#### Scenario: DB password rotation procedure
- **WHEN** `./scripts/manage-secrets.sh rotate-db-password` is executed
- **THEN** the script stops services, prompts for new password, updates both FusionAuth config and PostgreSQL, and restarts services

### Requirement: FusionAuth client secret rotation
The system SHALL support rotating the `FUSIONAUTH_CLIENT_SECRET` without downtime by updating the secret in both FusionAuth and the SnapAuth `.env` file.

#### Scenario: Client secret rotation via script
- **WHEN** `./scripts/manage-secrets.sh rotate-client-secret` is executed
- **THEN** a new client secret is generated, updated in FusionAuth via API, written to `.env`, and SnapAuth is restarted

#### Scenario: Client secret rotation preserves active sessions
- **WHEN** client secret is rotated
- **THEN** existing JWT tokens remain valid (they were signed with FusionAuth's key, not the client secret)

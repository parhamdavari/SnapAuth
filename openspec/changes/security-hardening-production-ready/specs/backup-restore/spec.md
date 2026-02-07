## ADDED Requirements

### Requirement: Automated database backup script
The system SHALL provide a `scripts/backup.sh` script that creates encrypted backups of the PostgreSQL database, configuration files, and secrets with timestamped filenames.

#### Scenario: Successful database backup
- **WHEN** `make backup` is executed
- **THEN** a gzipped PostgreSQL dump is created at `/opt/snapauth-backups/snapauth-YYYYMMDD-HHMMSS-db.sql.gz`

#### Scenario: Backup includes configuration files
- **WHEN** `make backup` is executed
- **THEN** a tarball containing `.env`, `kickstart/`, and `docker-compose.yml` is created

#### Scenario: Secrets encrypted in backup
- **WHEN** `make backup` is executed
- **THEN** the `.env` file is encrypted using AES-256-CBC and saved as `snapauth-YYYYMMDD-HHMMSS-secrets.enc`

### Requirement: Backup retention and cleanup
The backup script SHALL automatically delete backups older than 30 days to prevent unlimited disk usage.

#### Scenario: Old backups cleaned up
- **WHEN** `make backup` is executed and backups older than 30 days exist
- **THEN** those old backup files are automatically deleted

#### Scenario: Recent backups preserved
- **WHEN** `make backup` is executed and backups from the last 30 days exist
- **THEN** those backup files are preserved

### Requirement: Automated restore script
The system SHALL provide a `scripts/restore.sh` script that restores the PostgreSQL database, configuration files, and decrypted secrets from a backup.

#### Scenario: Successful database restore
- **WHEN** `make restore BACKUP_PATH=/opt/snapauth-backups/snapauth-20250207-120000` is executed
- **THEN** the PostgreSQL database is restored from the backup dump

#### Scenario: Configuration files restored
- **WHEN** restore is executed
- **THEN** `.env`, `kickstart/`, and `docker-compose.yml` are extracted from the backup tarball

#### Scenario: Secrets decrypted during restore
- **WHEN** restore is executed
- **THEN** the encrypted `.env` file is decrypted using the encryption password

### Requirement: Service stop during restore
The restore script SHALL stop all services before restoring data to prevent data corruption and SHALL restart them after restoration completes.

#### Scenario: Services stopped before restore
- **WHEN** restore begins
- **THEN** `make stop` is executed to stop all containers

#### Scenario: Services restarted after restore
- **WHEN** restore completes successfully
- **THEN** `make up` is executed to restart all services

### Requirement: Backup verification
The backup script SHALL verify the integrity of created backups by checking file sizes and testing gzip/encryption operations before considering the backup complete.

#### Scenario: Backup verification successful
- **WHEN** a backup completes
- **THEN** the script verifies that the database dump is non-zero size and gzip-compressed

#### Scenario: Backup verification failure aborts
- **WHEN** a backup operation produces a zero-byte file
- **THEN** the script exits with an error and does not mark the backup as successful

### Requirement: Restore dry-run mode
The restore script SHALL support a `--dry-run` flag that validates the backup without actually restoring data.

#### Scenario: Dry-run validates backup files
- **WHEN** `scripts/restore.sh --dry-run <backup-path>` is executed
- **THEN** the script checks that all backup files exist and are readable without modifying the system

#### Scenario: Dry-run detects missing files
- **WHEN** `scripts/restore.sh --dry-run <backup-path>` is executed and the database dump is missing
- **THEN** the script exits with an error indicating which file is missing

### Requirement: Backup manifests
Each backup SHALL include a `MANIFEST.txt` file containing backup metadata (timestamp, SnapAuth version, database size, backup size).

#### Scenario: Manifest created with backup
- **WHEN** a backup is created
- **THEN** a `MANIFEST.txt` file is created with backup date, version, and file sizes

#### Scenario: Restore validates manifest
- **WHEN** restore is executed
- **THEN** the script reads the manifest to display backup information before proceeding

### Requirement: Encrypted secrets require passphrase
When encrypting or decrypting the `.env` file, the backup/restore scripts SHALL prompt for an encryption passphrase (or read from `BACKUP_ENCRYPTION_KEY` environment variable).

#### Scenario: Backup prompts for passphrase
- **WHEN** `make backup` is executed without `BACKUP_ENCRYPTION_KEY` set
- **THEN** the script prompts the user to enter an encryption passphrase

#### Scenario: Restore prompts for passphrase
- **WHEN** `make restore` is executed without `BACKUP_ENCRYPTION_KEY` set
- **THEN** the script prompts the user to enter the decryption passphrase

#### Scenario: Environment variable provides passphrase
- **WHEN** `BACKUP_ENCRYPTION_KEY=mypassword make backup` is executed
- **THEN** the script uses the environment variable without prompting

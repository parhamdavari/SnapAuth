## ADDED Requirements

### Requirement: Pre-built release tarballs contain all Docker images
Release artifacts SHALL be packaged as tarballs containing all required Docker images (SnapAuth, Bootstrap, FusionAuth, PostgreSQL) with no external dependencies.

#### Scenario: Release tarball structure
- **WHEN** a release tarball is extracted
- **THEN** it contains `images/snapauth-v1.0.0.tar`, `images/bootstrap-v1.0.0.tar`, `images/fusionauth-1.50.1.tar`, and `images/postgres-16-alpine.tar`

#### Scenario: Tarball includes deployment files
- **WHEN** a release tarball is extracted
- **THEN** it contains `docker-compose.yml`, `Makefile`, `.env.example`, `offline-install.sh`, and `VERSION.yml`

### Requirement: offline-install.sh loads images without internet
The system SHALL provide an `offline-install.sh` script that loads all Docker images from tarballs without requiring internet connectivity.

#### Scenario: Offline installation loads all images
- **WHEN** `./offline-install.sh` is executed on an air-gapped server
- **THEN** all four Docker images are loaded into the local Docker daemon

#### Scenario: Script verifies loaded images
- **WHEN** offline installation completes
- **THEN** the script verifies that all images are present using `docker images`

#### Scenario: Script handles missing tarballs
- **WHEN** `./offline-install.sh` is executed and an image tarball is missing
- **THEN** the script exits with an error indicating which image file is missing

### Requirement: VERSION.yml manifest with checksums
Each release SHALL include a `VERSION.yml` file containing component versions, image digests, and checksums for integrity verification.

#### Scenario: VERSION.yml includes image digests
- **WHEN** a release tarball is extracted
- **THEN** `VERSION.yml` contains SHA256 digests for each Docker image

#### Scenario: Checksums verify tarball integrity
- **WHEN** an operator runs checksum verification
- **THEN** the checksums in `VERSION.yml` match the actual file SHA256 hashes

### Requirement: Deployment works without external registries
After loading images with `offline-install.sh`, the deployment SHALL complete successfully with `make up` without accessing external container registries.

#### Scenario: Air-gapped deployment success
- **WHEN** internet connectivity is disabled and `make up` is executed after loading images
- **THEN** all services start successfully without attempting to pull images from registries

#### Scenario: No external registry calls
- **WHEN** deployment is monitored with network capture on an air-gapped system
- **THEN** no DNS lookups or HTTP requests to `docker.io`, `ghcr.io`, or other registries are observed

### Requirement: Release includes documentation
Each release tarball SHALL include documentation for air-gapped deployment in `docs/AIR-GAPPED-DEPLOYMENT.md`.

#### Scenario: Air-gapped deployment guide included
- **WHEN** a release tarball is extracted
- **THEN** it contains `docs/AIR-GAPPED-DEPLOYMENT.md` with step-by-step offline installation instructions

#### Scenario: Documentation explains transfer methods
- **WHEN** the air-gapped deployment guide is read
- **THEN** it describes how to transfer the tarball to isolated servers (USB, secure courier, etc.)

### Requirement: Image tarballs use semantic versioning
Docker image tarballs SHALL be named using semantic versioning (e.g., `snapauth-v1.0.0.tar`) to enable clear version tracking and rollback.

#### Scenario: Image tarball naming convention
- **WHEN** release v1.0.1 is built
- **THEN** the SnapAuth image tarball is named `snapauth-v1.0.1.tar`

#### Scenario: Multiple versions can coexist
- **WHEN** an operator downloads both v1.0.0 and v1.0.1 releases
- **THEN** both tarballs can be stored in the same directory without filename conflicts

### Requirement: CI/CD builds release artifacts
The build pipeline SHALL automatically export Docker images to tarballs and bundle them into release artifacts when code is pushed to the main branch.

#### Scenario: Automated image export
- **WHEN** code is merged to main
- **THEN** the CI/CD pipeline runs `docker save` to export each image to a tarball

#### Scenario: Release tarball uploaded as artifact
- **WHEN** the build pipeline completes
- **THEN** the complete release tarball is uploaded as a GitHub release artifact

### Requirement: Patch releases support incremental updates
For security patches, the system SHALL support smaller patch tarballs containing only changed images rather than requiring full release downloads.

#### Scenario: Patch tarball contains only updated image
- **WHEN** a security patch changes only the SnapAuth service
- **THEN** the patch tarball `snapauth-patch-v1.0.0-to-v1.0.1.tar.gz` contains only `snapauth-v1.0.1.tar`

#### Scenario: Patch includes changelog
- **WHEN** a patch tarball is extracted
- **THEN** it includes `CHANGELOG.md` and `SECURITY-ADVISORY.md` describing the changes

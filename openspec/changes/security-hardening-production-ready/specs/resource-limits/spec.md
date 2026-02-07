## ADDED Requirements

### Requirement: SnapAuth container resource limits
The SnapAuth service container SHALL have resource limits configured: 1.0 CPU and 512MB memory as hard limits, with 0.5 CPU and 256MB as reserved resources.

#### Scenario: SnapAuth memory limit enforced
- **WHEN** the SnapAuth container attempts to allocate more than 512MB of memory
- **THEN** the container is OOM-killed and restarted by Docker

#### Scenario: SnapAuth CPU limit enforced
- **WHEN** the SnapAuth container attempts to use more than 1.0 CPU
- **THEN** Docker throttles the CPU usage to 1.0 CPU maximum

#### Scenario: SnapAuth reserved resources guaranteed
- **WHEN** system resources are contended
- **THEN** Docker guarantees at least 0.5 CPU and 256MB memory for the SnapAuth container

### Requirement: FusionAuth container resource limits
The FusionAuth service container SHALL have resource limits configured: 2.0 CPU and 1GB memory as hard limits, with 1.0 CPU and 512MB as reserved resources.

#### Scenario: FusionAuth memory limit aligned with JVM
- **WHEN** FusionAuth is configured with `FUSIONAUTH_APP_MEMORY=512M`
- **THEN** the JVM max heap is 512MB and the container limit is 1GB (allowing overhead)

#### Scenario: FusionAuth CPU limit enforced
- **WHEN** FusionAuth processes high authentication load
- **THEN** Docker limits CPU usage to 2.0 CPU maximum

### Requirement: PostgreSQL container resource limits
The PostgreSQL database container SHALL have resource limits configured: 2.0 CPU and 2GB memory as hard limits, with 1.0 CPU and 1GB as reserved resources.

#### Scenario: PostgreSQL memory limit enforced
- **WHEN** PostgreSQL attempts to allocate more than 2GB of memory
- **THEN** the container is OOM-killed and restarted

#### Scenario: PostgreSQL shared memory configured
- **WHEN** PostgreSQL is configured with `shared_buffers=256MB`
- **THEN** the container is configured with `shm_size: 256mb` to provide sufficient shared memory

#### Scenario: PostgreSQL connection limit configured
- **WHEN** PostgreSQL starts
- **THEN** it is configured with `max_connections=100` to limit resource usage

### Requirement: Resource limits defined in docker-compose.yml
All resource limits SHALL be defined in the `docker-compose.yml` file using the `deploy.resources` section to ensure consistent enforcement across deployments.

#### Scenario: docker-compose.yml includes resource limits
- **WHEN** the docker-compose.yml file is read
- **THEN** each service includes `deploy.resources.limits` and `deploy.resources.reservations` sections

#### Scenario: Resource limits applied on container start
- **WHEN** `docker-compose up` is executed
- **THEN** all containers start with the configured resource limits active

### Requirement: Resource monitoring enabled
The system SHALL expose container resource usage via Docker stats to enable monitoring and capacity planning.

#### Scenario: Monitor container memory usage
- **WHEN** `docker stats` is executed
- **THEN** memory usage for SnapAuth, FusionAuth, and PostgreSQL containers is displayed

#### Scenario: Monitor CPU usage
- **WHEN** resource metrics are collected
- **THEN** CPU usage percentage for each container is available

### Requirement: Resource limit recommendations documented
The system SHALL provide documentation in `docs/INSTALLATION.md` with recommended resource limits for different deployment sizes (small, medium, large).

#### Scenario: Small deployment recommendations
- **WHEN** deploying for < 100 users
- **THEN** documentation recommends default limits (SnapAuth: 512MB, FusionAuth: 1GB, PostgreSQL: 2GB)

#### Scenario: Large deployment recommendations
- **WHEN** deploying for > 10,000 users
- **THEN** documentation recommends increased limits (SnapAuth: 2GB, FusionAuth: 4GB, PostgreSQL: 8GB)

### Requirement: Graceful degradation under resource pressure
Services SHALL gracefully handle resource constraints without cascading failures. When memory limits are approached, services SHALL log warnings before OOM-kill occurs.

#### Scenario: FusionAuth warns before OOM
- **WHEN** FusionAuth memory usage exceeds 90% of the container limit
- **THEN** FusionAuth logs a warning about high memory usage

#### Scenario: PostgreSQL connection limit prevents resource exhaustion
- **WHEN** the number of database connections reaches `max_connections`
- **THEN** PostgreSQL rejects new connections rather than accepting and exhausting memory

### Requirement: Resource limits tunable via environment variables
While limits are defined in docker-compose.yml, the system SHALL allow environment variable overrides for container memory settings (e.g., `FUSIONAUTH_APP_MEMORY`).

#### Scenario: FusionAuth memory tuned via environment
- **WHEN** `FUSIONAUTH_APP_MEMORY=768M` is set in `.env`
- **THEN** FusionAuth starts with 768MB max heap (within the 1GB container limit)

#### Scenario: PostgreSQL shared buffers tuned via command
- **WHEN** PostgreSQL command includes `-c shared_buffers=512MB`
- **THEN** PostgreSQL uses 512MB for shared buffers (within the 2GB container limit)

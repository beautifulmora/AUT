# AUT — production-oriented identity service

A deliberately small Go identity/authentication service built to demonstrate backend engineering decisions rather than a pile of technologies.

## What is implemented

- password authentication with Argon2id + per-password random salt;
- short-lived JWT access tokens with `iss`, `aud`, `sub`, `jti`, `iat`, `nbf`, `exp`;
- opaque 48-byte refresh tokens stored only as SHA-256 hashes;
- refresh-token rotation and token-family replay detection;
- PostgreSQL constraints for email/username uniqueness (race-safe);
- Redis-backed login/registration rate limiting;
- graceful HTTP shutdown and readiness/liveness endpoints;
- explicit DB connection pool settings;
- parameterized SQL and transaction boundary around refresh rotation;
- minimal dependency surface and standard `net/http`;
- non-root distroless production image;
- migrations committed to the repository;
- `go test`, `go test -race`, `go vet` entry points.

## Architecture

```text
cmd/server
internal/auth          token policy and cryptography boundary
internal/config        environment configuration
internal/domain        domain models/errors
internal/httpapi       transport + middleware
internal/repository    PostgreSQL persistence
internal/service       authentication business logic
pkg/postgres           DB pool
pkg/redisx             Redis primitives
pkg/logger             structured logging
migrations             versioned schema
```

The project intentionally does **not** claim that every production feature is present. OAuth provider integration, OpenTelemetry, Prometheus dashboards and a larger integration-test suite are clear next iterations; they are not fake checklist items in the README.

## Run

```bash
cp .env.example .env
# start dependencies
 docker compose up -d postgres redis
# apply migrations
psql "$DATABASE_URL" -f migrations/001_init.sql
# run service
go run ./cmd/server
```

Or run the full stack:

```bash
docker compose up --build
```

## Security notes

Refresh tokens are never persisted in plaintext. A rotated token is revoked before its replacement is created inside one PostgreSQL transaction. Reuse of a revoked token revokes its entire family.

Access JWTs intentionally contain identity references rather than mutable profile data. User state remains authoritative in PostgreSQL.

The compose JWT secret is intentionally a development placeholder; production deployments must inject a strong secret through a secret manager.

## API

`POST /v1/auth/register`

`POST /v1/auth/login`

`POST /v1/auth/refresh`

`POST /v1/auth/logout`

`POST /v1/auth/logout-all` (Bearer)

`GET /v1/users/me` (Bearer)

`GET /health/live`

`GET /health/ready`

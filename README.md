# Axum-web

Enterprise-grade Rust/Axum licensing platform for administrators, resellers, license-key generation, and device-limited license verification.

## What this system provides

- **Main administrator panel/API** for creating resellers, generating keys, assigning keys, approving/rejecting reseller key requests, and suspending/revoking users or keys.
- **Reseller panel/API** so sellers can log in, request key batches from the main admin, list assigned keys, and manage the lifecycle of their own keys.
- **Licensing verification system** that verifies license keys with a unique device ID, tracks expiry, and enforces the maximum number of simultaneously active devices per key.
- **Secure transport posture** with JWT authentication, Argon2 password hashing, HMAC-hashed license/device identifiers at rest, CORS allowlisting, security headers, request-size limits, timeouts, and audit logs.
- **Production scalability** through stateless HTTP nodes, PostgreSQL connection pooling, transactional device-limit enforcement, health checks, Docker, Kubernetes manifests, CI, JSON logs, and environment-driven configuration.

## Architecture

```text
Browser/API clients
    │
    ▼
Axum-web stateless Rust service ─── PostgreSQL
    │                                ├─ users/admin/resellers
    │                                ├─ license keys (HMAC hashes only)
    │                                ├─ device activations / heartbeats
    │                                ├─ reseller key requests
    │                                └─ audit events
    ▼
Static admin/reseller panel served from /static fallback
```

License keys are only returned once at generation/approval time. The database stores `key_hash` using `LICENSE_KEY_PEPPER`; device IDs are stored as HMAC hashes using `DEVICE_ID_PEPPER`. Keep these peppers stable and stored in a secret manager; rotating them without a migration invalidates existing keys/devices.

## Quick start with Docker Compose

```bash
cp .env.example .env
# For local compose the provided dev values are enough. For production change every secret.
docker compose up --build
```

Open <http://localhost:3000>.

Development bootstrap credentials unless overridden:

- Email: `admin@example.com`
- Password: `ChangeMe123!`

## Production deployment checklist

1. Set `APP_ENV=production`.
2. Use a managed PostgreSQL instance with backups, PITR, and encryption at rest.
3. Set strong unique values for `JWT_SECRET`, `LICENSE_KEY_PEPPER`, and `DEVICE_ID_PEPPER` from a secret manager. Each must be at least 32 characters.
4. Set `ALLOWED_ORIGINS` to real HTTPS origins only; wildcard origins are rejected in production.
5. Set `BOOTSTRAP_ADMIN_EMAIL` and a long one-time `BOOTSTRAP_ADMIN_PASSWORD` before first boot. Rotate or disable it after the first admin is created.
6. Terminate TLS at a load balancer/reverse proxy and forward traffic to the service on port `3000`.
7. Run at least 3 stateless replicas. Use `/health/live` and `/health/ready` for probes.
8. Keep `RUN_MIGRATIONS=true` for simple deployments, or run migrations in a separate release job for stricter change control.
9. Ship JSON logs (`LOG_FORMAT=json`) to your SIEM/observability stack and alert on auth failures, license limit failures, and 5xx responses.

## Configuration

See `.env.example` for all variables.

Important values:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection string. |
| `JWT_SECRET` | HS256 JWT signing secret. Required and length-checked in production. |
| `LICENSE_KEY_PEPPER` | HMAC secret for hashing license keys at rest. |
| `DEVICE_ID_PEPPER` | HMAC secret for hashing device identifiers at rest. |
| `ALLOWED_ORIGINS` | Comma-separated CORS allowlist. |
| `LICENSE_HEARTBEAT_WINDOW_SECONDS` | Active-device window. Devices not seen within this window no longer count as simultaneous. |
| `MAX_KEY_BATCH_SIZE` | Upper bound for generated/approved key batches. |

## Core API flow

### 1. Login

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "admin@example.com",
  "password": "ChangeMe123!"
}
```

Use the returned token as `Authorization: Bearer <token>`.

### 2. Admin creates reseller

```http
POST /api/v1/admin/users
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "email": "seller@example.com",
  "password": "SellerPassword123!"
}
```

### 3. Reseller requests keys

```http
POST /api/v1/reseller/key-requests
Authorization: Bearer <reseller-token>
Content-Type: application/json

{
  "quantity": 10,
  "max_devices": 1,
  "ttl_days": 30,
  "note": "New customer allocation"
}
```

### 4. Admin approves request

```http
POST /api/v1/admin/key-requests/{request_id}/approve
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "admin_note": "Approved"
}
```

The response includes plaintext license keys one time only.

### 5. Client verifies a license

```http
POST /api/v1/licenses/verify
Content-Type: application/json

{
  "license_key": "AXUM-ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ2",
  "device_id": "unique-device-id",
  "app_id": "desktop-client",
  "app_version": "1.0.0"
}
```

A successful response returns `allowed: true`, expiry, max devices, current active device count, and a recommended heartbeat interval. Clients should call verify again before `heartbeat_after_seconds` elapses. To free a device slot immediately:

```http
POST /api/v1/licenses/release
Content-Type: application/json

{
  "license_key": "AXUM-ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ2",
  "device_id": "unique-device-id"
}
```

## Main endpoints

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/health/live` | none | Liveness probe. |
| `GET` | `/health/ready` | none | DB readiness probe. |
| `POST` | `/api/v1/auth/login` | none | Login with email/password. |
| `GET` | `/api/v1/auth/me` | user | Current authenticated user. |
| `GET/POST` | `/api/v1/admin/users` | admin | List users / create reseller. |
| `PATCH` | `/api/v1/admin/users/{id}/status` | admin | Activate/deactivate a user. |
| `GET/POST` | `/api/v1/admin/licenses` | admin | List/generate licenses. |
| `PATCH` | `/api/v1/admin/licenses/{id}/status` | admin | Active/suspend/revoke a license. |
| `GET` | `/api/v1/admin/key-requests` | admin | List reseller requests. |
| `POST` | `/api/v1/admin/key-requests/{id}/approve` | admin | Approve request and generate keys. |
| `POST` | `/api/v1/admin/key-requests/{id}/reject` | admin | Reject request. |
| `GET/POST` | `/api/v1/reseller/key-requests` | reseller | List/create own requests. |
| `GET` | `/api/v1/reseller/licenses` | reseller | List own assigned licenses. |
| `PATCH` | `/api/v1/reseller/licenses/{id}/status` | reseller | Manage own license status. |
| `POST` | `/api/v1/licenses/verify` | none | Verify key + unique device ID. |
| `POST` | `/api/v1/licenses/release` | none | Release a device heartbeat slot. |

More examples are in [`docs/api.http`](docs/api.http).

## Scaling notes

- The service is stateless; scale horizontally behind a load balancer.
- Device-limit enforcement is serialized per license using PostgreSQL transactions and `FOR UPDATE` row locks, preventing race conditions when many devices verify the same key concurrently.
- `LICENSE_HEARTBEAT_WINDOW_SECONDS` controls simultaneous-device behavior. A shorter window frees abandoned devices faster but requires more frequent client heartbeats.
- Use read replicas only for analytics/reporting. License verification must write to the primary DB.
- The supplied Kubernetes manifest includes readiness/liveness probes, non-root containers, read-only filesystem, resource limits, and HPA defaults.

## Local development without Docker

Requires Rust stable and PostgreSQL 16+.

```bash
cp .env.example .env
# edit DATABASE_URL and secrets for your machine
# make sure the database exists first — see "Database migrations" below
cargo run
```

Useful commands:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

## Database migrations

The schema lives in [`migrations/`](migrations/) and is managed by [sqlx-migrate](https://docs.rs/sqlx/latest/sqlx/migrate/index.html). Migrations apply in filename order, and the database keeps a `_sqlx_migrations` table recording which versions have already run — each migration is applied exactly once.

### Running migrations

Migrations run **automatically on app startup** when `RUN_MIGRATIONS=true` (the default): the first `cargo run` or container start applies all pending migrations, bootstraps the admin user, and only then starts serving HTTP.

The one manual prerequisite is that the **database itself exists** — PostgreSQL never creates databases on demand. Create the role and database once before the first run:

```bash
psql -h localhost -U postgres -c "CREATE ROLE axum_web LOGIN PASSWORD '<your-password>';"
psql -h localhost -U postgres -c "CREATE DATABASE axum_web OWNER axum_web;"
```

`docker compose up` does this for you via `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD`.

> **Note:** in `DATABASE_URL` the password is part of a URI, so special characters must be percent-encoded (e.g. `@` → `%40`, `#` → `%23`, `*` → `%2A`). In `psql`/SQL statements you write the password plain, as-is.

You can also apply migrations explicitly, without starting the server:

```bash
cargo install sqlx-cli
export DATABASE_URL='postgres://axum_web:<url-percent-encoded-password>@localhost:5432/axum_web'
sqlx migrate run      # apply pending migrations
sqlx migrate info     # show which versions are applied
```

### Adding a new migration

1. Create the next numbered file, e.g. `migrations/0002_add_something.sql`. Migrations apply in filename order. Never edit a file that has already been applied — add a new one instead (the checksum is stored in `_sqlx_migrations`).
2. **Rebuild.** `sqlx::migrate!` in `src/main.rs` embeds the `migrations/` directory into the binary at *compile time*, so a new or changed file has no effect until you run `cargo build` / rebuild the Docker image.
3. Start the app (or run `sqlx migrate run`) to apply it.

Verify after startup:

```bash
psql -h localhost -U axum_web -d axum_web -c "\dt"
psql -h localhost -U axum_web -d axum_web -c "SELECT version, description, success FROM _sqlx_migrations ORDER BY version;"
```

## Repository layout

```text
src/
  config.rs        Environment configuration and production secret checks
  db.rs            bootstrap admin and audit helpers
  routes/          Auth, admin, reseller, license verification, health endpoints
  services/        Password/JWT and crypto helpers
migrations/        PostgreSQL schema
docker-compose.yml Local PostgreSQL + app
Dockerfile         Production container build
k8s/               Kubernetes deployment reference
static/            Built-in admin/reseller panel
```

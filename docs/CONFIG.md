# Configuration

All settings are configurable via environment variables and CLI flags. Flags override environment variables.

## Common: Database (Postgres)

These flags apply to both the `run` and `migrate` subcommands.

| Env Var | CLI Flag | Default | Description |
|---|---|---|---|
| `DB_HOST` | `--db-host` | `localhost` | Postgres host |
| `DB_PORT` | `--db-port` | `5432` | Postgres port |
| `DB_USER` | `--db-user` | `postgres` | Postgres user |
| `DB_PASSWORD` | `--db-password` | `postgres` | Postgres password |
| `DB_NAME` | `--db-name` | `appdb` | Postgres database name |
| `DB_SSLMODE` | `--db-sslmode` | `disable` | Postgres SSL mode (`disable`, `require`, etc.) |

## `run` Subcommand

### Server

| Env Var | CLI Flag | Default | Description |
|---|---|---|---|
| `HTTP_ADDR` | `--http-addr` | `0.0.0.0` | Bind address |
| `HTTP_PORT` | `--http-port` | `8080` | Bind port |
| `CONTROL_PLANE_ENABLED` | `--control-plane-enabled` | `true` | Enable control plane (admin UI + admin API) |
| `DATA_PLANE_ENABLED` | `--data-plane-enabled` | `true` | Enable data plane (token issuance endpoints) |
| `BOOTSTRAP_ADMIN_PASSWORD` | `--bootstrap-admin-password` | *(none)* | If set, when a user logs in with username "admin" and the account does not exist, it is created if the password matches this value |

### Token Issuer

| Env Var | CLI Flag | Default | Description |
|---|---|---|---|
| `JWT_ISSUER` | `--jwt-issuer` | `http://localhost:8080` | JWT `iss` claim value |
| `JWT_TTL` | `--jwt-ttl` | `60m` | Lifetime for issued JWTs (Go duration format) |

### Signing Keys

| Env Var | CLI Flag | Default | Description |
|---|---|---|---|
| `JWT_SIGNING_KEY_FILE` | `--jwt-signing-key-file` | *(none)* | Path to private key for signing tokens (required when data plane is enabled) |
| `JWT_INACTIVE_SIGNING_KEY_FILES` | `--jwt-inactive-signing-key-files` | *(empty)* | Comma-separated paths to previously used private keys (public keys still served via JWKS) |
| `JWT_VERIFY_KEY_FILES` | `--jwt-verify-key-files` | *(empty)* | Comma-separated paths to public keys for JWKS endpoint |

**Notes:**
- The key ID (`kid`) for each key is derived from a SHA-256 hash of the public key material.
- Both RSA and ECDSA keys are supported (PEM format).
- When `DATA_PLANE_ENABLED=true`, `JWT_SIGNING_KEY_FILE` must be set.

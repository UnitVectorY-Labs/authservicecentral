# Database

`authservicecentral` uses PostgreSQL for persistent storage.

## Setup

Start a PostgreSQL instance:

```bash
docker run --name authservicecentral-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=appdb \
  -p 5432:5432 \
  -d postgres:18
```

## Migrations

Database migrations are embedded in the binary and managed using the `migrate` subcommand.

```bash
# Apply migrations
authservicecentral migrate up

# Roll back migrations
authservicecentral migrate down
```

Migrations use [golang-migrate](https://github.com/golang-migrate/migrate) with SQL files embedded via Go's `embed` package.

## Schema

The database schema includes the following tables:

| Table | Description |
|---|---|
| `applications` | Registered services with subject identifiers for JWT claims |
| `application_scopes` | Scopes offered by an application when it is the audience |
| `application_credentials` | Client credentials (client_id + hashed secret) for applications |
| `identity_providers` | External OIDC identity providers for workload identity |
| `workloads` | Workload definitions with claim selectors under an identity provider |
| `application_workloads` | Links between applications and workload identities |
| `authorizations` | Subject-to-audience authorization rules |
| `authorization_scopes` | Scopes permitted for a specific authorization |
| `jwk_cache` | Cache for external JWKS keys used for token verification |
| `users` | Local user accounts for control plane authentication |
| `control_plane_audit` | Audit log for administrative actions |
| `data_plane_audit` | Audit log for token issuance decisions |

## Audit Logging

- `control_plane_audit` is written by control-plane admin handlers when applications, authorizations, identity providers, or workloads are created, updated, or deleted.
- `data_plane_audit` is written by `/v1/token` grant handlers for both allowed and denied token issuance decisions.

## Credential Hashing

`application_credentials.secret_hash` and `users.password_hash` store hashes in this format:

`pbkdf2_sha256:<iterations>:<salt_hex>:<hash_hex>`

Hashes from older preview builds that used the legacy `sha256:<salt_hex>:<hash_hex>` format are not accepted by the current verifier. Rotate affected client secrets and user passwords after upgrading.

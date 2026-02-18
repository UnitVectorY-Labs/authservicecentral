# Usage

`authservicecentral` provides two subcommands: `run` to start the server and `migrate` to manage database migrations.

## Commands

### `run`

Starts the HTTP server with the configured data plane and control plane.

```bash
authservicecentral run [flags]
```

**Examples:**

```bash
# Start with defaults (localhost:8080)
authservicecentral run --jwt-signing-key-file ./keys/signing.pem

# Start with custom settings
authservicecentral run \
  --http-port 9090 \
  --jwt-issuer https://auth.example.com \
  --jwt-signing-key-file ./keys/signing.pem \
  --jwt-ttl 30m

# Data plane only
authservicecentral run \
  --control-plane-enabled=false \
  --jwt-signing-key-file ./keys/signing.pem
```

### `migrate`

Runs database migrations to create or tear down the database schema.

```bash
authservicecentral migrate <up|down> [flags]
```

**Examples:**

```bash
# Apply all migrations
authservicecentral migrate up

# Roll back all migrations
authservicecentral migrate down

# With custom database settings
authservicecentral migrate up --db-host db.example.com --db-name authdb
```

### `version`

Prints the application version.

```bash
authservicecentral version
```

## Endpoints

### Data Plane

When the data plane is enabled (`--data-plane-enabled=true`, the default), the following endpoints are available:

| Endpoint | Description |
|---|---|
| `GET /.well-known/openid-configuration` | OpenID Connect discovery document |
| `GET /.well-known/jwks.json` | JSON Web Key Set for token verification |

### Health Check

| Endpoint | Description |
|---|---|
| `GET /healthz` | Health check endpoint, returns `{"status": "ok"}` |

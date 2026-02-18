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
| `POST /v1/token` | OAuth 2.0 token endpoint |

#### `POST /v1/token`

Issues JWT access tokens using the OAuth 2.0 token endpoint (RFC 6749).

**Content-Type:** `application/x-www-form-urlencoded`

**Supported grant types:**

- `client_credentials` — authenticate using a client ID and secret

##### Client Credentials Grant

| Parameter | Required | Description |
|---|---|---|
| `grant_type` | yes | Must be `client_credentials` |
| `client_id` | yes | Client identifier for the subject application |
| `client_secret` | yes | Client secret |
| `audience` | yes | Subject identifier of the target (audience) application |
| `scope` | no | Space-delimited list of requested scopes |

**Example:**

```bash
curl -X POST "http://localhost:8080/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=my-client-id" \
  --data-urlencode "client_secret=my-secret" \
  --data-urlencode "audience=service-b" \
  --data-urlencode "scope=read write"
```

**Success Response (200):**

```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

The `scope` field is only present if scopes were granted. The `expires_in` value is in seconds and corresponds to the configured `--jwt-ttl`.

**Error Responses:**

Errors follow RFC 6749 format:

```json
{
  "error": "invalid_request",
  "error_description": "audience is required"
}
```

| Error Code | When |
|---|---|
| `invalid_request` | Missing or invalid parameters (including missing `audience`) |
| `invalid_client` | Client authentication failed, credential disabled, or application locked |
| `invalid_grant` | Invalid assertion (JWT bearer grant, not yet supported) |
| `access_denied` | No authorization exists or authorization is disabled |
| `invalid_scope` | Requested scope is not allowed for the subject-audience pair |

##### Minted JWT Claims

| Claim | Description |
|---|---|
| `iss` | Configured issuer (`--jwt-issuer`) |
| `sub` | Subject application identifier |
| `aud` | Audience application identifier |
| `exp` | Expiration time |
| `iat` | Issued-at time |
| `jti` | Unique token identifier |
| `scope` | Granted scopes (if any) |

### Control Plane (Admin UI)

When the control plane is enabled (`--control-plane-enabled=true`, the default), the admin web interface is available under `/admin/`.

| Endpoint | Description |
|---|---|
| `GET /admin/login` | Login page |
| `POST /admin/login` | Login form submission |
| `GET /admin/logout` | Logout (clears session) |
| `GET /admin/` | Admin dashboard home page |
| `GET /admin/apps` | Applications list with search and pagination |

#### Authentication

The admin interface requires authentication. Users must log in with a valid username and password. Sessions are managed via signed HTTP cookies (8-hour lifetime).

#### Bootstrap Admin

When `--bootstrap-admin-password` is set, the first login with username `admin` and the configured password will automatically create the admin user account. This is intended for initial setup and testing.

### Health Check

| Endpoint | Description |
|---|---|
| `GET /healthz` | Health check endpoint, returns `{"status": "ok"}` |

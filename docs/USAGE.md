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
Each token request also records a `data_plane_audit` entry with allow/deny decision details.

**Content-Type:** `application/x-www-form-urlencoded`

**Supported grant types:**

- `client_credentials` — authenticate using a client ID and secret
- `urn:ietf:params:oauth:grant-type:jwt-bearer` — authenticate using an external JWT assertion (workload identity)

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

##### JWT Bearer Grant

Authenticate using an external JWT assertion for workload identity federation.

| Parameter | Required | Description |
|---|---|---|
| `grant_type` | yes | Must be `urn:ietf:params:oauth:grant-type:jwt-bearer` |
| `client_id` | yes | Subject identifier of the application (application subject, not credential client_id) |
| `assertion` | yes | External JWT token from the identity provider |
| `audience` | yes | Subject identifier of the target (audience) application |
| `scope` | no | Space-delimited list of requested scopes |

**Example:**

```bash
curl -X POST "http://localhost:8080/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  --data-urlencode "client_id=service-a" \
  --data-urlencode "assertion=eyJhbGciOi..." \
  --data-urlencode "audience=service-b" \
  --data-urlencode "scope=read"
```

The assertion JWT is validated against workload selectors linked to the application. The assertion's issuer must match a configured identity provider, and the JWT claims must satisfy the workload selector constraints.

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
| `invalid_grant` | Invalid assertion JWT, workload mismatch, or signature verification failure |
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
| `GET /admin/apps/new` | New application form |
| `POST /admin/apps/new` | Create application |
| `GET /admin/apps/{subject}` | Application detail page with tabs (overview, scopes, credentials, authorizations) |
| `POST /admin/apps/{subject}` | Update application |
| `POST /admin/apps/{subject}/scopes` | Add a scope to an application |
| `POST /admin/apps/{subject}/scopes/delete` | Remove a scope from an application |
| `POST /admin/apps/{subject}/credentials` | Create a client credential (max 2 active per app) |
| `POST /admin/apps/{subject}/credentials/disable` | Disable a client credential |
| `GET /admin/apps/{subject}/authorizations/new` | New outbound authorization form |
| `POST /admin/apps/{subject}/authorizations/new` | Create outbound authorization |
| `GET /admin/apps/{subject}/authorizations/{audience}` | Authorization detail page |
| `POST /admin/apps/{subject}/authorizations/{audience}` | Update authorization (enable/disable) |
| `POST /admin/apps/{subject}/authorizations/{audience}/delete` | Delete authorization |
| `POST /admin/apps/{subject}/authorizations/{audience}/scopes` | Add scope to authorization |
| `POST /admin/apps/{subject}/authorizations/{audience}/scopes/delete` | Remove scope from authorization |
| `GET /admin/providers` | Identity providers list |
| `GET /admin/providers/new` | New identity provider form |
| `POST /admin/providers/new` | Create identity provider |
| `GET /admin/providers/{id}` | Identity provider detail page |
| `POST /admin/providers/{id}` | Update identity provider |
| `POST /admin/providers/{id}/delete` | Delete identity provider |
| `GET /admin/providers/{id}/workloads/new` | New workload form |
| `POST /admin/providers/{id}/workloads/new` | Create workload |
| `GET /admin/providers/{id}/workloads/{workloadID}` | Workload detail page |
| `POST /admin/providers/{id}/workloads/{workloadID}` | Update workload |
| `POST /admin/providers/{id}/workloads/{workloadID}/delete` | Delete workload |
| `POST /admin/providers/{id}/workloads/{workloadID}/link` | Link application to workload |
| `POST /admin/providers/{id}/workloads/{workloadID}/unlink` | Unlink application from workload |

Administrative create/update/delete actions for applications, authorizations, identity providers, and workloads are recorded in `control_plane_audit`.

#### Authentication

The admin interface requires authentication. Users must log in with a valid username and password. Sessions are managed via signed HTTP cookies (8-hour lifetime).

#### Bootstrap Admin

When `--bootstrap-admin-password` is set, the first login with username `admin` and the configured password will automatically create the admin user account. This is intended for initial setup and testing.

### Health Check

| Endpoint | Description |
|---|---|
| `GET /healthz` | Health check endpoint, returns `{"status": "ok"}` |

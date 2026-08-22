# Usage

For complete endpoint schemas and examples, see [API.md](API.md) and the machine-readable [`openapi.yaml`](../openapi.yaml).

## Commands

```text
authservicecentral run       Start the HTTP API (`api` is an alias)
authservicecentral migrate   Apply both schemas and activate the compiled model
authservicecentral bootstrap Create the initial resource-scoped management grant
authservicecentral validate  Strictly validate YAML and print its fingerprint
authservicecentral model     Print deterministic OpenFGA 1.1 JSON
authservicecentral doctor    Probe database, active model, signer, and remote trust
authservicecentral version   Print the build version
```

All commands except `version` accept the process flags in [CONFIG.md](CONFIG.md). `validate` and `model` do not mutate external state. `migrate` is the only command that migrates or activates a model. `doctor` performs network discovery for configured remote issuers.

Typical startup:

```bash
go run . validate --config serviceauth.yaml
go run . migrate --config serviceauth.yaml --database-url "$SERVICEAUTH_DATABASE_URL"
go run . bootstrap --config serviceauth.yaml --database-url "$SERVICEAUTH_DATABASE_URL" \
  --source corporate --subject alice --role serviceauth_admin
go run . doctor --config serviceauth.yaml --database-url "$SERVICEAUTH_DATABASE_URL" --signing-key-file ./platform-key.pem
go run . run --config serviceauth.yaml --database-url "$SERVICEAUTH_DATABASE_URL" --signing-key-file ./platform-key.pem
```

For KMS, replace the signing-key flag with `--signing-provider=gcp-kms --gcp-kms-key='projects/.../cryptoKeyVersions/1'` and provide Application Default Credentials.

## Public endpoints

| Method/path | Purpose |
|---|---|
| `GET /.well-known/oauth-authorization-server` | Issuer, token endpoint, JWKS URI, RFC 8693 grant metadata |
| `GET /.well-known/jwks.json` | Current platform signing public JWK set |
| `POST /oauth2/token` | OAuth 2.0 token exchange; form encoded |
| `GET /health/live` | Process liveness |
| `GET /health/ready` | Database/model/signer readiness |
| `GET /metrics` | Text metrics when enabled |

Token exchange uses `application/x-www-form-urlencoded`:

```bash
curl -sS "$ISSUER/oauth2/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode "subject_token=$EXTERNAL_JWT" \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:jwt' \
  --data-urlencode 'audience=documents-api'
```

For delegation, also send `actor_token` and `actor_token_type=urn:ietf:params:oauth:token-type:jwt`. The response is `{access_token, issued_token_type, token_type, expires_in}` with `Cache-Control: no-store`.

## Management endpoints

All JSON bodies are strict: unknown fields, trailing values, and oversized bodies are rejected. Unless development-only insecure management is enabled, management calls require a platform Bearer token whose audience is `serviceauth-management` and whose `permissions` contains the route-specific `management.*` permission.

| Method/path | Body/result |
|---|---|
| `POST /v1/audiences` | Create/upsert `{id,display_name,token_ttl_seconds,delegation:{enabled,mode}}`; 201 |
| `GET /v1/audiences` | `{audiences:[...]}` |
| `GET/PATCH/DELETE /v1/audiences/{id}` | Read, partial update, delete |
| `POST /v1/resources` | `{type,id,metadata?,relationships?}`; 201 |
| `GET/PATCH/DELETE /v1/resources/{type}/{id}` | Read, metadata update, delete |
| `PUT/DELETE /v1/resources/{type}/{id}/relationships/{relation}` | `{target:{type,id}}` or `{targets:[...]}`; 204 |
| `POST /v1/groups` | `{id,display_name?}`; 201 |
| `GET/DELETE /v1/groups/{id}` | Read or delete |
| `POST/DELETE /v1/groups/{id}/members` | `{member:{type:"principal",source,subject}}` or group member; 204 |
| `POST /v1/grants` | `{id?,subject,role,resource,create_resource_if_missing?}`; 201 |
| `GET /v1/grants` | `{grants:[...]}` |
| `DELETE /v1/grants/{id}` | 204, idempotent catalog deletion semantics |

Relationships on resource creation accept a concise single target or an array. `create_resource_if_missing` can create only a parentless resource whose type does not require relationships; audience/group creation remains explicit.

## Permission checks

`POST /v1/check` requires a valid platform Bearer token and derives subject/actor exclusively from its signed `authorization_context`:

```json
{"checks":[
  {"id":"read-123","permission":"document.read","resource":{"type":"document","id":"123"}}
]}
```

The response preserves order and IDs: `{"results":[{"id":"read-123","allowed":true}]}`. A legitimate denial is HTTP 200 with `allowed:false`. Unknown permission, incompatible resource type, malformed checks, or a batch outside configured bounds is HTTP 400. Missing/invalid Bearer tokens are 401; missing catalog objects are 404; dependency failures are 503/500.

## Platform JWT claims

Issued JWTs contain `iss`, readable `sub` (`source:subject`), one string `aud`, `iat`, `exp`, `jti`, sorted `permissions`, and signed `authorization_context`. Delegated tokens also contain `act:{sub}` and actor context. Explicitly propagated external claims are included without granting authority.

Audience delegation modes are `disabled`, `subject`, `intersection`, `actor`, and `union`. They combine independently evaluated subject/actor permissions both during exchange and fine-grained checks. A direct exchange uses subject semantics. Tokens cache audience-level permission decisions until expiry; resource checks use current OpenFGA state.

## Controlled management bootstrap

After migration, run `bootstrap` from a trusted administrative environment. It verifies the active model fingerprint, validates that the source prefix and role exist, upserts the configured management audience, creates a deterministic principal grant scoped to that audience, reconciles it through OpenFGA, and emits normal audit records. Repeating the same command is idempotent.

The bootstrapped principal still obtains a normal platform token through RFC 8693 for the management audience. No bootstrap HTTP endpoint or permanent bypass is created. `--insecure-management` remains available only for isolated development.

## Errors and security

Errors use `{"error":{"code","message","request_id"}}`; responses carry `X-Request-ID`, 401 responses include `WWW-Authenticate: Bearer`, and rate limiting returns HTTP 429. Do not expose unauthenticated management in production; use the controlled `bootstrap` command.

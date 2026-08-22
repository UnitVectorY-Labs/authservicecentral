# API

The HTTP API exposes OAuth discovery and token exchange, operational probes, batched authorization checks, and authenticated management operations. The machine-readable contract is [`openapi.yaml`](../openapi.yaml).

Examples below assume:

```bash
export SERVICEAUTH_URL=http://localhost:8080
export MANAGEMENT_TOKEN='platform-jwt-for-serviceauth-management'
export APPLICATION_TOKEN='platform-jwt-for-the-application-audience'
```

## HTTP conventions

All successful JSON responses use `Content-Type: application/json`. JSON request bodies are strict: unknown fields, malformed input, trailing JSON values, and bodies over the configured limit are rejected. Identifiers placed in a URL path must be percent-encoded when necessary.

Every response includes `X-Request-ID`. A caller-supplied `X-Request-ID` is retained when it is at most 128 characters and contains only letters, digits, `-`, `_`, or `.`; otherwise the service generates one.

Errors use this envelope:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "description safe to return to the caller",
    "request_id": "hfJ3QJeTzrr2Y7Ou"
  }
}
```

Common statuses are `400` for invalid input, `401` for a missing or invalid token, `403` for the wrong management audience or a missing management permission, `404` for a missing catalog object, `429` when rate limited, `500` for an internal failure, and `503` when storage or authorization dependencies are unavailable. Authorization denial is not an error: `/v1/check` returns HTTP 200 and `allowed:false`.

## Authentication

`POST /v1/check` requires a platform JWT issued by this service. The API ignores caller-supplied identity fields and derives the subject, optional actor, audience, delegation mode, and cached audience permissions from signed claims.

Every `/v1/*` management operation requires a platform Bearer token with:

- `aud` equal to the configured management audience, `serviceauth-management` by default; and
- the exact `management.*` permission listed for the route.

Pass tokens using `Authorization: Bearer <token>`. The development-only `--insecure-management` option bypasses management authentication and must not be enabled in production.

## Discovery, token exchange, and operations

| Method and path | Authentication | Description |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | None | OAuth issuer, token endpoint, JWKS URI, and supported grant metadata. |
| `GET /.well-known/jwks.json` | None | Active and configured inactive public verification keys. |
| `POST /oauth2/token` | Trusted JWT in form | RFC 8693 token exchange. |
| `GET /health/live` | None | Process liveness; returns `{"status":"ok"}`. |
| `GET /health/ready` | None | Database, active-model fingerprint, and signer readiness; returns `{"status":"ready"}` or 503. |
| `GET /metrics` | None | Prometheus text metrics when metrics are enabled. |

Token exchange requires `application/x-www-form-urlencoded`:

```bash
curl -sS "$SERVICEAUTH_URL/oauth2/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode "subject_token=$EXTERNAL_JWT" \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:jwt' \
  --data-urlencode 'audience=documents-api'
```

For delegated exchange, include both `actor_token` and `actor_token_type=urn:ietf:params:oauth:token-type:jwt`. The target audience must enable delegation. The response is never cacheable:

```json
{
  "access_token": "eyJ...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 900
}
```

## Permission checks

`POST /v1/check` evaluates between one and the configured maximum number of checks, preserving request order and caller-provided IDs.

```bash
curl -sS "$SERVICEAUTH_URL/v1/check" \
  -H "Authorization: Bearer $APPLICATION_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"checks":[
    {"id":"read-123","permission":"document.read","resource":{"type":"document","id":"123"}},
    {"id":"edit-123","permission":"document.edit","resource":{"type":"document","id":"123"}}
  ]}'
```

```json
{"results":[{"id":"read-123","allowed":true},{"id":"edit-123","allowed":false}]}
```

Each permission must exist in the deployment schema and apply to the requested resource type.

## Audiences

| Method and path | Required permission | Result |
|---|---|---|
| `POST /v1/audiences` | `management.audiences.write` | Create or update an audience; 201 with the stored audience. |
| `GET /v1/audiences` | `management.audiences.read` | `{"audiences":[...]}`. |
| `GET /v1/audiences/{id}` | `management.audiences.read` | One audience. |
| `PATCH /v1/audiences/{id}` | `management.audiences.write` | Partially update an audience. |
| `DELETE /v1/audiences/{id}` | `management.audiences.write` | Idempotent deletion; 204. |

Create or replace an audience:

```bash
curl -sS "$SERVICEAUTH_URL/v1/audiences" \
  -H "Authorization: Bearer $MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "id":"documents-api",
    "display_name":"Documents API",
    "token_ttl_seconds":900,
    "delegation":{"enabled":true,"mode":"intersection"}
  }'
```

Delegation modes are `disabled`, `subject`, `intersection`, `actor`, and `union`. Setting `enabled:false` stores the audience as `disabled`. A patch may contain any subset of `display_name`, `token_ttl_seconds`, and `delegation`.

## Resources and relationships

| Method and path | Required permission | Result |
|---|---|---|
| `POST /v1/resources` | `management.resources.write` | Create a configured resource; 201. |
| `GET /v1/resources/{type}/{id}` | `management.resources.read` | Resource metadata and relationships. |
| `PATCH /v1/resources/{type}/{id}` | `management.resources.write` | Replace metadata; 200. |
| `DELETE /v1/resources/{type}/{id}` | `management.resources.write` | Delete catalog and authorization state; idempotent 204. |
| `PUT /v1/resources/{type}/{id}/relationships/{relation}` | `management.resources.write` | Add or replace specified targets; 204. |
| `DELETE /v1/resources/{type}/{id}/relationships/{relation}` | `management.resources.write` | Remove specified targets, or all targets when the body is absent; 204. |

Create a resource with relationship targets. A relationship value may be one resource reference or an array:

```bash
curl -sS "$SERVICEAUTH_URL/v1/resources" \
  -H "Authorization: Bearer $MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "type":"document",
    "id":"123",
    "metadata":{"title":"Quarterly plan"},
    "relationships":{"parent":{"type":"folder","id":"finance"}}
  }'
```

Mutate an existing relationship using either `target` or `targets`:

```json
{"target":{"type":"folder","id":"legal"}}
```

Relationship names, target types, cardinality, required relationships, and inherited permissions are enforced from the deployment schema.

## Groups and memberships

| Method and path | Required permission | Result |
|---|---|---|
| `POST /v1/groups` | `management.groups.write` | Create a group; 201. |
| `GET /v1/groups/{id}` | `management.groups.read` | One group. |
| `DELETE /v1/groups/{id}` | `management.groups.write` | Idempotent deletion; 204. |
| `POST /v1/groups/{id}/members` | `management.groups.write` | Add a principal or nested group; 204. |
| `DELETE /v1/groups/{id}/members` | `management.groups.write` | Remove the exact member; 204, or 404 when absent. |

Create a group and add a principal:

```bash
curl -sS "$SERVICEAUTH_URL/v1/groups" \
  -H "Authorization: Bearer $MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"id":"finance","display_name":"Finance"}'

curl -sS "$SERVICEAUTH_URL/v1/groups/finance/members" \
  -H "Authorization: Bearer $MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"member":{"type":"principal","source":"corporate","subject":"alice"}}'
```

A nested group member uses `{"type":"group","group":"group-id"}`. Both groups must already exist, and cycles are rejected.

## Grants

| Method and path | Required permission | Result |
|---|---|---|
| `POST /v1/grants` | `management.grants.write` | Create a resource-scoped role grant; 201. |
| `GET /v1/grants` | `management.grants.read` | `{"grants":[...]}`. |
| `DELETE /v1/grants/{id}` | `management.grants.write` | Idempotent deletion; 204. |

Grant a configured role to a principal:

```bash
curl -sS "$SERVICEAUTH_URL/v1/grants" \
  -H "Authorization: Bearer $MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "subject":{"type":"principal","source":"corporate","subject":"alice"},
    "role":"editor",
    "resource":{"type":"document","id":"123"}
  }'
```

The subject may instead be a group. `id` is optional and generated when absent. `create_resource_if_missing:true` may create only a parentless application resource whose configured type has no required relationships; audiences and groups must be created through their own APIs. Semantically identical retries return the existing grant.

## Consistency and lifecycle behavior

Successful management mutations are committed to PostgreSQL, reconciled synchronously to embedded OpenFGA, and recorded in the audit log before the response is returned. A background reconciler retries interrupted outbox work. Deleting catalog objects removes associated grants and relationship tuples. Platform tokens retain their audience-level permission list until expiry, while `/v1/check` evaluates current resource state.

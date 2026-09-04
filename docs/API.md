---
layout: default
title: API
nav_order: 3
permalink: /api
---

# API

The HTTP API exposes OAuth and OpenID discovery, token exchange, operational probes, batched authorization checks, and authenticated management operations. The machine-readable contract is [openapi.yaml](../openapi.yaml); when the Swagger surface is enabled, the same contract is served at `/openapi.yaml` and browsable at `/`.

Examples below assume:

```bash
export SERVICEAUTH_URL=http://localhost:8080
export MANAGEMENT_TOKEN='platform-jwt-for-serviceauth-management'
export APPLICATION_TOKEN='platform-jwt-for-the-application-audience'
```

## HTTP conventions

Successful JSON responses use `Content-Type: application/json`. JSON request bodies are strict: unknown fields, malformed input, trailing JSON values, and bodies over the configured limit are rejected. Percent-encode identifiers placed in URL paths when necessary.

Every response includes `X-Request-ID`. A caller-supplied ID is retained only when it is at most 128 characters and contains letters, digits, `-`, `_`, or `.`; otherwise the service generates one.

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

Common statuses are `400` invalid input, `401` missing/invalid token, `403` wrong management audience or missing management permission, `404` missing catalog object, `429` rate limited, `500` internal failure, and `503` unavailable storage or authorization dependencies. An authorization denial is not an HTTP error: `/v1/check` returns `200` with `allowed: false`.

## Authentication

`POST /v1/check` requires a platform JWT issued by this service. Subject, optional actor, audience, delegation mode, and cached audience permissions come from signed token context; caller-supplied identity fields are not authoritative.

Every management operation below `/v1/manage/` requires a platform Bearer token with:

- `aud` equal to the configured management audience, `serviceauth-management` by default; and
- the route-family permission configured in YAML, or its conventional `management.<family>.<operation>` default.

Pass tokens as `Authorization: Bearer <token>`. The development-only `--insecure-management` setting bypasses management authentication and must not be enabled in production.

## Discovery, token exchange, and operations

| Method and path | Authentication | Description |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | None | OAuth issuer, token endpoint, JWKS URI, and supported grant metadata. |
| `GET /.well-known/openid-configuration` | None | OpenID discovery-compatible issuer, token endpoint, JWKS URI, and supported grant metadata. This service does not provide interactive OpenID Connect authorization or ID tokens. |
| `GET /.well-known/jwks.json` | None | Active and configured inactive public verification keys. |
| `POST /oauth2/token` | Trusted JWT in form | RFC 8693 token exchange. |
| `GET /health/live` | None | Process liveness; returns `{"status":"ok"}`. |
| `GET /health/ready` | None | Database, active-model, and signer readiness; returns `200` or `503`. |
| `GET /metrics` | None | Prometheus text metrics when enabled. |
| `GET /` | None | Swagger UI when `SERVICEAUTH_SWAGGER_UI`/`--swagger-ui` is enabled. |
| `GET /openapi.yaml` | None | Embedded OpenAPI document when the Swagger surface is enabled, with its `servers` entry set to the configured platform issuer. |

Token exchange uses `application/x-www-form-urlencoded`:

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

`POST /v1/check` evaluates one to the configured maximum number of checks and preserves request order and IDs.

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

Each permission must exist in YAML and apply to the requested resource type. The token’s signed authorization context, rather than a request field, supplies the subject and optional actor.

## Management API

All management paths share the `/v1/manage/` prefix. The required permission names below are defaults; [CONFIG.md](CONFIG.md) describes how a deployment can map each family to a different audience-applicable permission.

### Audiences

| Method and path | Permission | Result |
|---|---|---|
| `POST /v1/manage/audiences` | `management.audiences.write` | Create or replace an audience; `201`. |
| `GET /v1/manage/audiences` | `management.audiences.read` | `{"audiences":[...]}`. |
| `GET /v1/manage/audiences/{id}` | `management.audiences.read` | One audience. |
| `PATCH /v1/manage/audiences/{id}` | `management.audiences.write` | Partial update. |
| `DELETE /v1/manage/audiences/{id}` | `management.audiences.write` | Idempotent deletion; `204`. |

Create or replace an audience:

```bash
curl -sS "$SERVICEAUTH_URL/v1/manage/audiences" \
  -H "Authorization: Bearer $MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"id":"documents-api","display_name":"Documents API","token_ttl_seconds":900,"delegation":{"enabled":true,"mode":"intersection"}}'
```

Delegation modes are `disabled`, `subject`, `intersection`, `actor`, and `union`. A patch may contain any subset of `display_name`, `token_ttl_seconds`, and `delegation`.

### Resources and relationships

| Method and path | Permission | Result |
|---|---|---|
| `POST /v1/manage/resources` | `management.resources.write` | Create a configured resource; `201`. |
| `GET /v1/manage/resources/{type}/{id}` | `management.resources.read` | Resource metadata and relationships. |
| `PATCH /v1/manage/resources/{type}/{id}` | `management.resources.write` | Replace metadata; `200`. |
| `DELETE /v1/manage/resources/{type}/{id}` | `management.resources.write` | Delete catalog and authorization state; idempotent `204`. |
| `PUT /v1/manage/resources/{type}/{id}/relationships/{relation}` | `management.resources.write` | Add or replace relationship targets; `204`. |
| `DELETE /v1/manage/resources/{type}/{id}/relationships/{relation}` | `management.resources.write` | Remove targets, or all targets with no body; `204`. |

Create a resource with optional relationship targets:

```bash
curl -sS "$SERVICEAUTH_URL/v1/manage/resources" \
  -H "Authorization: Bearer $MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"type":"document","id":"123","metadata":{"title":"Quarterly plan"},"relationships":{"parent":{"type":"folder","id":"finance"}}}'
```

A relationship value may be one target or an array. Relationship names, target types, cardinality, requiredness, and inherited permissions come from the active YAML schema.

### Groups and memberships

| Method and path | Permission | Result |
|---|---|---|
| `POST /v1/manage/groups` | `management.groups.write` | Create a group; `201`. |
| `GET /v1/manage/groups/{id}` | `management.groups.read` | One group. |
| `DELETE /v1/manage/groups/{id}` | `management.groups.write` | Idempotent deletion; `204`. |
| `POST /v1/manage/groups/{id}/members` | `management.groups.write` | Add a principal or nested group; `204`. |
| `DELETE /v1/manage/groups/{id}/members` | `management.groups.write` | Remove an exact member; `204`, or `404` if absent. |

Membership examples:

```json
{"member":{"type":"principal","source":"corporate","subject":"alice"}}
```

```json
{"member":{"type":"group","group":"engineering"}}
```

Both groups must exist before a nested membership is added, and cycles are rejected.

### Grants

| Method and path | Permission | Result |
|---|---|---|
| `POST /v1/manage/grants` | `management.grants.write` | Create a resource-scoped role grant; `201`. |
| `GET /v1/manage/grants` | `management.grants.read` | `{"grants":[...]}`. |
| `DELETE /v1/manage/grants/{id}` | `management.grants.write` | Idempotent deletion; `204`. |

Grant a configured role to a principal:

```bash
curl -sS "$SERVICEAUTH_URL/v1/manage/grants" \
  -H "Authorization: Bearer $MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"subject":{"type":"principal","source":"corporate","subject":"alice"},"role":"editor","resource":{"type":"document","id":"123"}}'
```

The subject may instead be a group. `id` is optional and generated when absent. `create_resource_if_missing:true` may create only a parentless application resource whose type has no required relationships; audiences and groups use their own APIs. Semantically identical retries return the existing grant.

## Lifecycle and consistency

Successful management mutations are committed to PostgreSQL, reconciled synchronously to embedded OpenFGA, and recorded in the audit log before success is returned. A background reconciler retries interrupted outbox work. Deleting catalog objects removes associated grants and relationship tuples. Platform tokens retain audience-level permissions until expiry, while `/v1/check` evaluates current resource state.

The API never exposes the private signing key or the complete YAML configuration. The repository’s configuration reference is [CONFIG.md](CONFIG.md); the runtime documentation surface at `/` is API-only.

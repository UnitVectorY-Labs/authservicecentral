# Design

This document represents the design for `authservicecentral`. As pieces of this design are implemented and the relevant documentation under docs/ is created and refined this document will be revised and the various aspects removed and replaced with references to the relevant documentation or implementation. The goal is to eventually have this document deleted as the code and docs should be the source of truth, but this serves as a starting point to capture the overall design and approach.

This design document is meant to be a starting point, it is meant to capture the intent of the design but it may not be perfect. The goal here is to build an Authorization server for Machine-to-Machine authorization use cases.  It is meant to discourage the use of secrets of any type, but it is pragmatic knowing that is challenging.

The goal in implementing this is to not only build out the code in Go to provide it but to perform the pragmatic tests spinning up the Postgres database, generating RSA keys for the application to use, and then using Playwright to log in and test the interface to configure applications as well as using curl to test the endpoints for issuing tokens both for the success and failure paths.

It is recognized that not all of this functionality may be able to be implemented as once therefore your task is to not just to implement the functionality, but use this document as the guide to implementing and before you finish with one set of functionality you should document your findings in this document in the bottom section called "Progress and Next Steps".

-

This is the proposed Database schema for `authservicecentral`. It is designed to support the core features of the service, including application management, authorization, and auditing. The schema is normalized to avoid redundancy and ensure data integrity.

-- -------------------------------------------------------------------
-- Core: applications (services)
-- subject is the value that will populate JWT "sub" or "aud"
-- -------------------------------------------------------------------
CREATE TABLE applications (
  id           BIGSERIAL PRIMARY KEY,

  -- critical identifier used in JWT claims
  subject      VARCHAR(255) NOT NULL UNIQUE,   -- case-sensitive by default
  description  VARCHAR(255),

  app_type     VARCHAR(32) NOT NULL CHECK (app_type IN ('service','admin','user_agent')),
  locked       BOOLEAN NOT NULL DEFAULT FALSE,

  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_applications_subject ON applications (subject);

-- -------------------------------------------------------------------
-- Application scopes (available scopes offered by an audience application)
-- -------------------------------------------------------------------
CREATE TABLE application_scopes (
  application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  scope          VARCHAR(255) NOT NULL,
  description    VARCHAR(255),

  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

  PRIMARY KEY (application_id, scope)
);

CREATE INDEX idx_application_scopes_scope ON application_scopes (scope);

-- -------------------------------------------------------------------
-- Client credentials (normalized out of applications)
-- Store only hashes.
-- -------------------------------------------------------------------
CREATE TABLE application_credentials (
  id              BIGSERIAL PRIMARY KEY,
  application_id  BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,


  credential_type VARCHAR(32) NOT NULL CHECK (credential_type IN ('client_secret')),
  client_id       VARCHAR(255) NOT NULL UNIQUE,   -- case-sensitive by default
  secret_hash     VARCHAR(255) NOT NULL,   -- if you use argon2id/bcrypt, you may want TEXT instead, salted hash that must be a performant hash for verification as this cannot be slowed down with a more time consuming hash.
  label           VARCHAR(255),

  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  rotated_at      TIMESTAMPTZ,
  disabled_at     TIMESTAMPTZ
);

CREATE INDEX idx_app_credentials_active
  ON application_credentials (application_id)
  WHERE disabled_at IS NULL;

-- -------------------------------------------------------------------
-- Workload identity providers and workloads
-- -------------------------------------------------------------------
CREATE TABLE identity_providers (
  id            BIGSERIAL PRIMARY KEY,
  name          VARCHAR(255) NOT NULL UNIQUE,  -- friendly name
  provider_type VARCHAR(32) NOT NULL CHECK (provider_type IN ('oidc')),
  issuer_url    VARCHAR(255) NOT NULL,
  jwks_url      VARCHAR(255),

  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE (provider_type, issuer_url)
);

CREATE TABLE workloads (
  id                   BIGSERIAL PRIMARY KEY,
  identity_provider_id BIGINT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,

  name                 VARCHAR(255) NOT NULL,
  selector             JSONB NOT NULL,

  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE (identity_provider_id, name)
);

CREATE INDEX idx_workloads_provider ON workloads (identity_provider_id);
CREATE INDEX idx_workloads_selector_gin ON workloads USING GIN (selector);

CREATE TABLE application_workloads (
  application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  workload_id    BIGINT NOT NULL REFERENCES workloads(id) ON DELETE CASCADE,

  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

  PRIMARY KEY (application_id, workload_id)
);

CREATE INDEX idx_application_workloads_workload ON application_workloads (workload_id);

-- -------------------------------------------------------------------
-- Authorizations: subject app (A) is allowed to call audience app (B)
-- allow self-authorization
-- -------------------------------------------------------------------
CREATE TABLE authorizations (
  subject_application_id  BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  audience_application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,

  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  description  VARCHAR(255),

  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

  PRIMARY KEY (subject_application_id, audience_application_id)
);

CREATE INDEX idx_authorizations_subject
  ON authorizations (subject_application_id);

CREATE INDEX idx_authorizations_audience
  ON authorizations (audience_application_id);

-- -------------------------------------------------------------------
-- Authorized scopes per (subject,audience)
-- constrained to scopes defined on the audience application
-- -------------------------------------------------------------------
CREATE TABLE authorization_scopes (
  subject_application_id  BIGINT NOT NULL,
  audience_application_id BIGINT NOT NULL,
  scope                   VARCHAR(255) NOT NULL,

  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

  PRIMARY KEY (subject_application_id, audience_application_id, scope),

  FOREIGN KEY (subject_application_id, audience_application_id)
    REFERENCES authorizations(subject_application_id, audience_application_id)
    ON DELETE CASCADE,

  FOREIGN KEY (audience_application_id, scope)
    REFERENCES application_scopes(application_id, scope)
    ON DELETE CASCADE
);

CREATE INDEX idx_authorization_scopes_lookup
  ON authorization_scopes (subject_application_id, audience_application_id, scope);

CREATE INDEX idx_authorization_scopes_by_audience_scope
  ON authorization_scopes (audience_application_id, scope);

-- -------------------------------------------------------------------
-- JWK cache (verification cache)
-- -------------------------------------------------------------------
CREATE TABLE jwk_cache (
  jwks_url    VARCHAR(255) NOT NULL,
  kid         VARCHAR(255) NOT NULL,

  found       BOOLEAN NOT NULL DEFAULT TRUE,
  jwk         JSONB,
  fetched_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL,

  PRIMARY KEY (jwks_url, kid)
);

CREATE INDEX idx_jwk_cache_url ON jwk_cache (jwks_url);
CREATE INDEX idx_jwk_cache_expires ON jwk_cache (expires_at);

-- -------------------------------------------------------------------
-- Local user accounts (backup auth)
-- No permissions model yet; this is purely for authentication.
-- -------------------------------------------------------------------
CREATE TABLE users (
  id             BIGSERIAL PRIMARY KEY,

  username       VARCHAR(255) NOT NULL UNIQUE,
  password_hash  VARCHAR(255) NOT NULL,  -- if argon2id/bcrypt strings exceed 255, switch to TEXT
  locked         BOOLEAN NOT NULL DEFAULT FALSE,

  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at  TIMESTAMPTZ
);

CREATE INDEX idx_users_username ON users (username);

-- -------------------------------------------------------------------
-- Auditing
-- -------------------------------------------------------------------
CREATE TABLE control_plane_audit (
  id               BIGSERIAL PRIMARY KEY,
  occurred_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

  actor_type       VARCHAR(32) NOT NULL CHECK (actor_type IN ('user','api_key','system')),
  actor_id         VARCHAR(255),
  actor_ip         INET,
  actor_user_agent VARCHAR(255),

  action           VARCHAR(255) NOT NULL,
  target_type      VARCHAR(64) NOT NULL,
  target_pk        JSONB NOT NULL,

  before           JSONB,
  after            JSONB,
  metadata         JSONB
);

CREATE INDEX idx_cpa_occurred_at ON control_plane_audit (occurred_at);
CREATE INDEX idx_cpa_target_type ON control_plane_audit (target_type);
CREATE INDEX idx_cpa_target_pk_gin ON control_plane_audit USING GIN (target_pk);

CREATE TABLE data_plane_audit (
  id                     BIGSERIAL PRIMARY KEY,
  occurred_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

  subject_application_id  BIGINT REFERENCES applications(id) ON DELETE SET NULL,
  audience_application_id BIGINT REFERENCES applications(id) ON DELETE SET NULL,

  scopes                 VARCHAR(255)[],
  decision               VARCHAR(16) NOT NULL CHECK (decision IN ('allow','deny')),
  reason                 VARCHAR(255),
  request_id             VARCHAR(255),

  details                JSONB
);

CREATE INDEX idx_dpa_occurred_at ON data_plane_audit (occurred_at);
CREATE INDEX idx_dpa_subject ON data_plane_audit (subject_application_id);
CREATE INDEX idx_dpa_audience ON data_plane_audit (audience_application_id);


---

## Token endpoint

### `POST /v1/token`

OAuth 2.0 token endpoint (RFC 6749) issuing JWT access tokens (RFC 7519). Supports Client Credentials (RFC 6749) and JWT Bearer (RFC 7523).

**Request**
- `Content-Type: application/x-www-form-urlencoded`

#### Parameters (all grants)

| Name | Required | Notes |
|---|---:|---|
| `grant_type` | yes | `client_credentials` or `urn:ietf:params:oauth:grant-type:jwt-bearer` |
| `audience` | **yes** | Target application identifier (resource service B) |
| `scope` | no | Space-delimited; must be permitted for `(A,B)` and defined by B |

#### Client Credentials grant

| Name | Required | Notes |
|---|---:|---|
| `client_id` | yes | Subject application identifier (service A) |
| `client_secret` | yes | Valid secret for `client_id` (hashed storage) |

Example:

```bash
curl -X POST "https://token.example.com/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=service-a" \
  --data-urlencode "client_secret=REDACTED" \
  --data-urlencode "audience=service-b" \
  --data-urlencode "scope=read write"
```

#### JWT Bearer grant (preferred)

| Name | Required | Notes |
|---|---:|---|
| `client_id` | yes | Subject application identifier (service A) |
| `assertion` | yes | External JWT used for workload identity authentication |

Example:

```bash
curl -X POST "https://token.example.com/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  --data-urlencode "assertion=eyJhbGciOi..." \
  --data-urlencode "client_id=service-a" \
  --data-urlencode "audience=service-b" \
  --data-urlencode "scope=read"
```

The assertion token that is provided is matched against the workloads and those worklaod issuers that are registered in the database. The primary validation could would be to validate that the token is in fact by an authorized issuer for that application and verify the claim constraints on the workload by matching the required claims that are defined for equality. This can be accoss any of the possible claims but the expected ones would be things like `sub` and `aud` but others could be used as well. The signature of the JWT is obviously validated as well and the issuer's public JWKS keys are cached in the database to avoid excessive network calls to the issuer.

---

## Authorization enforcement

Token issuance requires:

| Check | Requirement |
|---|---|
| Audience resolution | `audience` maps to an application B |
| Subject authentication | `client_id` authenticated via secret or workload assertion |
| Relationship allowed | `(A -> B)` exists and is enabled |
| Scopes allowed | Each requested scope is in `authorization_scopes(A,B)` and `application_scopes(B)` |

RFC 6749 (OAuth 2.0): if the requested scope is invalid, unknown, malformed, or exceeds what’s granted, the authorization server should return invalid_scope. (Section 5.2; also scope definition in Section 3.3.)

---

## Minted access token (JWT)

| Claim | Required | Value |
|---|---:|---|
| `iss` | yes | Configured issuer |
| `sub` | yes | Subject application (A) |
| `aud` | yes | Audience application (B) |
| `exp` | yes | Now + `JWT_TTL` |
| `iat` | yes | Issued-at time |
| `jti` | recommended | Unique token id |
| `scope` | if any | Space-delimited granted scopes |

---

## Responses

### Success (RFC 6749)

| Field | Notes |
|---|---|
| `access_token` | JWT |
| `token_type` | `Bearer` |
| `expires_in` | Seconds |
| `scope` | Present if scopes granted |

Example:

```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

### Errors (RFC 6749)

| Error | When |
|---|---|
| `invalid_request` | Missing/invalid parameters (including missing `audience`) |
| `invalid_client` | Client authentication failed / locked / no active credential |
| `invalid_grant` | Invalid `assertion` or workload mismatch |
| `unauthorized_client` | Grant type not allowed for client |
| `access_denied` | `(A -> B)` missing/disabled |
| `invalid_scope` | Any requested scope not allowed/defined |

Example:

```json
{
  "error": "invalid_request",
  "error_description": "audience is required"
}
```

---


The web interface for the control plane will be under the `/admin/` path. The main sections will be Applications, Identity Providers, Workloads, Authorizations, Audit, and Settings. Each section will have a list view and a detail view, and there will be links between related entities for easy navigation. The home page will provide quick access to the main sections and surface recent activity.

A user must authenticate to access any part of the admin interface if a user is not already authenticated they will be redirected to the login page located at `/admin/login`. For simplicity, we can start with a single local user store and later add support for external authentication providers in the future. For the initial implementation and testing this will use the bootstrap admin password mechanism for logging in and testing the functionality.

## `/admin/` page map

### Global layout (applies to every page)
All admin URLs render a full page when loaded directly, using shared templates:
- `base.html`: shell with header, footer, and a single main content container (for example `#main`)
- `partials/`: reusable segments such as:
  - `header.html` (top nav, current user, logout)
  - `footer.html`
  - `flash.html` (messages)
  - `tabs.html` (shared tab bar pattern)
  - `tables/*.html` (common table row patterns)

**HTMX rule:** every route below supports:
- Full page render (direct navigation)
- Partial render (when `HX-Request: true`) returning only the content for `#main` (or a smaller target inside `#main`)

This means links inside admin pages can be normal `<a href>` links and optionally include HTMX attributes to swap the relevant container, while still working without HTMX.

---

## Primary navigation (top bar)

- Home
- Applications
- Identity Providers

Workloads are accessed through Identity Providers.
Authorizations are accessed through Applications.

---

## 1) Home
- **`/admin/`**
  - Summary and jump links to:
    - `/admin/apps`
    - `/admin/providers`
    - `/admin/settings`

Nav: primarily outbound to the list pages.

---

## 2) Applications (hub for authorizations)

- **`/admin/apps`** (list + search) paginated list of all applications with search by subject and description
  - Click app → `/admin/apps/{subject}`
  - New app → `/admin/apps/new`

- **`/admin/apps/new`** (create)
  - On create → `/admin/apps/{subject}`

- **`/admin/apps/{subject}`** (detail hub)
  Sections or tabs on one page:
  - Overview (type, locked)
  - Offered scopes (scopes this app exposes when it is the audience)
  - Credentials (client secrets, if applicable) 
  - Limit of having 2 active client ids and client secrets per application. These are able to be edited. Once a client secret is created the page clearly indicates it must be copied immediately as only a hash of this is stored in the database.
  - Linked workload identities (read-only list with links to the provider workload page)
  - **Authorizations**
    - **Outbound**: apps this application (as subject) is authorized to access
    - **Inbound**: apps authorized to access this application (as audience)

Nav from app detail:
- Create new outbound authorization:
  - `/admin/apps/{subject}/authorizations/new` (audience chosen in form)
- Create new inbound authorization:
  - `/admin/apps/{subject}/authorized-clients/new` (subject chosen in form)
- Manage an existing authorization rule:
  - `/admin/apps/{subject}/authorizations/{audience}` (outbound detail)
  - `/admin/apps/{subject}/authorized-clients/{client}` (inbound detail)

---

## 3) Authorizations (always under an application)

You want to show both directions from the same app page, but edits should be focused and direct.

### Outbound authorizations (subject-centric)
- **`/admin/apps/{subject}/authorizations`** (optional list page) paginated list
  - Usually redundant if the app detail page already shows the list, but useful for direct linking.
- **`/admin/apps/{subject}/authorizations/new`**
  - Select audience B
  - Select allowed scopes (from B’s offered scopes)
  - Create → `/admin/apps/{subject}/authorizations/{audience}`
- **`/admin/apps/{subject}/authorizations/{audience}`** (detail/edit)
  - Enabled toggle
  - Allowed scopes editor
  - Link to audience app: `/admin/apps/{audience}`

### Inbound authorizations (audience-centric)
- **`/admin/apps/{audience}/authorized-clients`** (optional list page)
- **`/admin/apps/{audience}/authorized-clients/new`**
  - Select subject A
  - Select allowed scopes (from this audience app’s offered scopes)
  - Create → `/admin/apps/{audience}/authorized-clients/{subject}`
- **`/admin/apps/{audience}/authorized-clients/{subject}`** (detail/edit)
  - Same underlying rule, different viewpoint
  - Enabled toggle
  - Allowed scopes editor
  - Link to subject app: `/admin/apps/{subject}`

Implementation note: both “detail/edit” pages can render the same underlying template with swapped labels, because they refer to the same `(subject, audience)` row.

---

## 4) Identity Providers (workloads nested underneath)

- **`/admin/providers`** (list)
  - Click provider → `/admin/providers/{id}`
  - New provider → `/admin/providers/new`

- **`/admin/providers/new`** (create)
  - On create → `/admin/providers/{id}`

- **`/admin/providers/{id}`** (detail hub)
  - Overview (issuer_url, jwks_url)
  - Workloads list (within this provider)
    - Link to workload detail
    - New workload

### Workloads nested under provider
- **`/admin/providers/{id}/workloads/new`** (create workload for this provider)
  - Create → `/admin/providers/{id}/workloads/{workload_id}`

- **`/admin/providers/{id}/workloads/{workload_id}`** (workload detail)
  - Selector editor (JSON equality rules)
  - Linked applications list (links to `/admin/apps/{subject}`)

Optional (if you want a standalone list):
- **`/admin/providers/{id}/workloads`** (list)
  - Might be redundant if provider detail shows the list inline.

No global `/admin/workloads` page.

---

## HTMX navigation model (explicit)

- Every URL above is directly reachable and renders a complete page via `base.html`.
- The same URL, when requested via HTMX, returns only:
  - The content fragment for `#main`, or
  - A smaller fragment within the page (for example updating only the authorizations table on the app detail page after an edit).

Practical conventions:
- Use normal anchors for routing: `<a href="/admin/apps/service-a">Service A</a>`
- Add HTMX progressively for in-page swaps:
  - `hx-get` to fetch the same URL
  - `hx-target="#main"`
  - `hx-push-url="true"` so the address bar stays correct

---


# Progress and Next Steps

## Completed

### Foundation (CLI, Database, Data Plane Discovery)

The following foundational pieces have been implemented:

- **CLI structure**: `run`, `migrate`, and `version` subcommands with all configuration via environment variables and CLI flags (flags override env vars). See `docs/CONFIG.md` and `docs/USAGE.md`.
- **Database migrations**: Full schema from this design document implemented as embedded SQL migrations using `golang-migrate`. All 12 tables created. See `docs/DATABASE.md`.
- **Data plane discovery endpoints**:
  - `GET /.well-known/openid-configuration` returns the OpenID Connect discovery document
  - `GET /.well-known/jwks.json` returns the JSON Web Key Set with all configured keys
- **JWT key management**: Supports loading RSA and ECDSA private/public keys from PEM files. Key IDs (`kid`) are derived from a SHA-256 hash of the public key material. Supports active signing key, inactive signing keys (still in JWKS), and verify-only public keys.
- **Health check**: `GET /healthz` endpoint
- **Documentation**: `docs/USAGE.md`, `docs/CONFIG.md`, `docs/DATABASE.md`
- **Unit tests**: Configuration parsing, JWT key loading/serialization, web endpoint responses

### Token Endpoint (`POST /v1/token`) — Client Credentials Grant

The token endpoint has been implemented for the `client_credentials` grant type. See `docs/USAGE.md` for full endpoint documentation.

- **JWT minting**: Tokens are signed using the configured signing key (RSA or ECDSA) with standard JWT claims (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `scope`).
- **Client authentication**: Credentials are verified against salted SHA-256 hashes stored in the `application_credentials` table. Disabled credentials are rejected.
- **Authorization enforcement**: The `(subject → audience)` relationship is checked in the `authorizations` table; disabled authorizations are rejected.
- **Scope validation**: Requested scopes are validated against allowed scopes in `authorization_scopes` and `application_scopes`. Invalid scopes return `invalid_scope`.
- **OAuth 2.0 error responses**: Standard error format per RFC 6749 with `error` and `error_description` fields.
- **Credential hashing**: `internal/credential` package provides salted SHA-256 hashing (`sha256:<salt_hex>:<hash_hex>`) with constant-time comparison for verification.
- **Unit tests**: JWT signing/verification, credential hashing, token endpoint parameter validation.
- **Integration tested**: Full flow verified against PostgreSQL (applications, credentials, authorizations, scopes).

## Next Steps

The following items from the design remain to be implemented, roughly in priority order:

1. **Control plane admin UI**: Login page, authentication with bootstrap admin password, session management, and the HTMX-based admin interface (applications list/detail, identity providers, etc.).
2. **JWT Bearer grant**: Workload identity authentication via external JWT assertions with JWKS caching.
3. **Audit logging**: Control plane and data plane audit trail recording.
4. **Admin UI features**: Application management (CRUD, credentials, scopes), authorization management (inbound/outbound), identity provider and workload management.

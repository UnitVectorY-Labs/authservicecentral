-- Core: applications (services)
CREATE TABLE applications (
  id           BIGSERIAL PRIMARY KEY,
  subject      VARCHAR(255) NOT NULL UNIQUE,
  description  VARCHAR(255),
  app_type     VARCHAR(32) NOT NULL CHECK (app_type IN ('service','admin','user_agent')),
  locked       BOOLEAN NOT NULL DEFAULT FALSE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_applications_subject ON applications (subject);

-- Application scopes
CREATE TABLE application_scopes (
  application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  scope          VARCHAR(255) NOT NULL,
  description    VARCHAR(255),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (application_id, scope)
);

CREATE INDEX idx_application_scopes_scope ON application_scopes (scope);

-- Client credentials
CREATE TABLE application_credentials (
  id              BIGSERIAL PRIMARY KEY,
  application_id  BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  credential_type VARCHAR(32) NOT NULL CHECK (credential_type IN ('client_secret')),
  client_id       VARCHAR(255) NOT NULL UNIQUE,
  secret_hash     VARCHAR(255) NOT NULL,
  label           VARCHAR(255),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  rotated_at      TIMESTAMPTZ,
  disabled_at     TIMESTAMPTZ
);

CREATE INDEX idx_app_credentials_active
  ON application_credentials (application_id)
  WHERE disabled_at IS NULL;

-- Identity providers
CREATE TABLE identity_providers (
  id            BIGSERIAL PRIMARY KEY,
  name          VARCHAR(255) NOT NULL UNIQUE,
  provider_type VARCHAR(32) NOT NULL CHECK (provider_type IN ('oidc')),
  issuer_url    VARCHAR(255) NOT NULL,
  jwks_url      VARCHAR(255),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (provider_type, issuer_url)
);

-- Workloads
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

-- Application workloads
CREATE TABLE application_workloads (
  application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  workload_id    BIGINT NOT NULL REFERENCES workloads(id) ON DELETE CASCADE,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (application_id, workload_id)
);

CREATE INDEX idx_application_workloads_workload ON application_workloads (workload_id);

-- Authorizations
CREATE TABLE authorizations (
  subject_application_id  BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  audience_application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  description  VARCHAR(255),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (subject_application_id, audience_application_id)
);

CREATE INDEX idx_authorizations_subject ON authorizations (subject_application_id);
CREATE INDEX idx_authorizations_audience ON authorizations (audience_application_id);

-- Authorization scopes
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

-- JWK cache
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

-- Users
CREATE TABLE users (
  id             BIGSERIAL PRIMARY KEY,
  username       VARCHAR(255) NOT NULL UNIQUE,
  password_hash  VARCHAR(255) NOT NULL,
  locked         BOOLEAN NOT NULL DEFAULT FALSE,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at  TIMESTAMPTZ
);

CREATE INDEX idx_users_username ON users (username);

-- Control plane audit
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

-- Data plane audit
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

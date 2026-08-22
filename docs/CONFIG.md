# Configuration

Configuration has two layers: process settings from `SERVICEAUTH_*` environment variables/flags and a strict versioned YAML authorization schema. Flags override environment variables. Unknown YAML fields, duplicate keys, and multiple YAML documents are rejected.

## Process settings

| Environment variable | Flag | Default |
|---|---|---|
| `SERVICEAUTH_CONFIG` | `--config` | `serviceauth.yaml` |
| `SERVICEAUTH_DATABASE_URL` | `--database-url` | `postgres://postgres:postgres@localhost:5432/authservicecentral?sslmode=disable` |
| `SERVICEAUTH_ISSUER` | `--issuer` | `http://localhost:8080` |
| `SERVICEAUTH_LISTEN_ADDRESS` | `--listen-address` | `:8080` |
| `SERVICEAUTH_SIGNING_KEY_FILE` | `--signing-key-file` | none; required by `run` and `doctor` |
| `SERVICEAUTH_SIGNING_PROVIDER` | `--signing-provider` | `local`; `local` or `gcp-kms` |
| `SERVICEAUTH_GCP_KMS_KEY` | `--gcp-kms-key` | none; required for `gcp-kms` runtime/doctor |
| `SERVICEAUTH_INACTIVE_SIGNING_KEY_FILES` | `--inactive-signing-key-files` | empty comma-separated PEM paths |
| `SERVICEAUTH_INSECURE_MANAGEMENT` | `--insecure-management` | `false` |
| `SERVICEAUTH_MAX_BATCH_SIZE` | `--max-batch-size` | `100` (1–1000) |
| `SERVICEAUTH_HTTP_TIMEOUT` | `--http-timeout` | `15s` |
| `SERVICEAUTH_SHUTDOWN_TIMEOUT` | `--shutdown-timeout` | `15s` |
| `SERVICEAUTH_RECONCILE_INTERVAL` | `--reconcile-interval` | `2s` |
| `SERVICEAUTH_RECONCILE_BATCH` | `--reconcile-batch` | `100` (1–1000) |
| `SERVICEAUTH_METRICS` | `--metrics` | `true` |
| `SERVICEAUTH_RATE_LIMIT_PER_SECOND` | `--rate-limit-per-second` | `0` (disabled) |
| `SERVICEAUTH_RATE_LIMIT_BURST` | `--rate-limit-burst` | `0` (disabled) |
| `SERVICEAUTH_BOOTSTRAP_SOURCE` | `--source` | none; required by `bootstrap` |
| `SERVICEAUTH_BOOTSTRAP_SUBJECT` | `--subject` | none; required by `bootstrap` |
| `SERVICEAUTH_BOOTSTRAP_ROLE` | `--role` | none; required by `bootstrap` |
| `SERVICEAUTH_MANAGEMENT_AUDIENCE` | `--management-audience` | `serviceauth-management` |
| `SERVICEAUTH_MANAGEMENT_DISPLAY_NAME` | `--management-display-name` | `ServiceAuth Management` |
| `SERVICEAUTH_MANAGEMENT_TTL` | `--management-ttl` | `900` seconds |

Durations use Go syntax (`500ms`, `15s`, `2m`). Rate and burst must both be zero or both positive. Invalid environment values currently fall back to defaults; invalid flags fail parsing. `--insecure-management` bypasses management authentication only and is strictly for isolated development.

## YAML version 1

See [`examples/serviceauth.yaml`](../examples/serviceauth.yaml). Token-source, role, resource, and relationship identifiers use lowercase letters, digits, and underscores and begin with a letter. Permission names contain at least two lowercase dot-separated segments. `principal`, `group`, and `audience` are intrinsic/reserved resource types; `audience` may be referenced by permissions but is not declared under `resources`.

### Token sources

Each source requires an absolute HTTPS `issuer`, exactly one key mode (`discovery`, `jwks_url`, inline `jwks`, or PEM `public_key`), an asymmetric algorithm allowlist, and `identity.subject_claim` plus a unique identity `prefix`. Discovery verifies issuer equality. Remote keys are cached and unknown `kid` values cause bounded refresh.

Audience validation accepts `equals`, `one_of`, or `any_of`. Arbitrary claim rules allow exactly one of `exists`, `equals`, `not_equals`, `one_of`, `any_of`, `prefix`, `suffix`, `regex`, or `contains`. Validation occurs before a JWT establishes identity.

Claim propagation is allowlist-only:

```yaml
propagate_claims:
  repository:
    from: repository
```

Reserved JWT/platform claims cannot be overwritten: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `act`, `permissions`, and `authorization_context`.

### Permissions and roles

```yaml
permissions:
  document.read: {resources: [document]}
  api.invoke: {resources: [audience]}
roles:
  reader: {permissions: [document.read, api.invoke]}
```

Every permission declares at least one configured resource type (or `audience`), and every role contains at least one known permission. Roles may span resource types. On a grant, only permissions applicable to the target type are effective; a role with none applicable is rejected.

### Resources, relationships, and inheritance

```yaml
resources:
  folder:
    relationships: {}
  document:
    relationships:
      parent: {targets: [folder], cardinality: one, required: false}
    inheritance:
      - relationship: parent
        permissions: [document.read]
```

Targets must be configured resource types. `cardinality` is `one` or `many`; `required` is lifecycle-enforced. Self-relationships and nested-group cycles are rejected. OpenFGA performs group expansion and graph traversal safely through longer application resource graphs.

## Fingerprints and signing

Canonical validated YAML receives a SHA-256 fingerprint. `migrate` compiles and activates an immutable OpenFGA model. `run` verifies that exact fingerprint/model and fails closed; it never migrates automatically.

The `local` provider loads an RSA or P-256 PEM private key. The `gcp-kms` provider uses Application Default Credentials and an explicit asymmetric key-version resource supporting RSA PKCS#1 SHA-256 or P-256 SHA-256; private material never leaves KMS. `kid` is base64url(SHA-256 of DER SubjectPublicKeyInfo) for both providers. Inactive local key files are verification-only keys published in JWKS during rotation.

The management audience setting must match the audience created by `bootstrap`. The bootstrap role must be defined in YAML and contain at least one `management.*` permission applicable to `audience`.

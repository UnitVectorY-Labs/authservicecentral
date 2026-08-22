# Validation

Validation should prove both the configuration compiler and the running service contract. Use a disposable PostgreSQL 18-compatible environment for integration tests. The environment may be local, Docker-based, supplied by another container runtime, CI-managed, or remote; the test procedure does not depend on one tool.

## Unit and static checks

```bash
go test ./...
go vet ./...
go build ./...
```

Validate a deployment file after replacing the example public key:

```bash
authservicecentral validate --config examples/serviceauth.yaml
authservicecentral model --config examples/serviceauth.yaml
authservicecentral config-docs --config examples/serviceauth.yaml --output-dir ./config-reference
```

Expected evidence is a 64-character configuration fingerprint from `validate` and an OpenFGA 1.1 JSON model from `model`, including intrinsic principal/group/audience behavior, role relations, permission relations, and configured resource relationships.

The configuration documentation command should report seven generated pages. Review `configuration.html` to confirm JWK/key material and private PEM material are redacted while non-sensitive trust metadata such as issuer, key mode, and JWKS URL remains visible.

## PostgreSQL-backed integration

Set `SERVICEAUTH_TEST_DATABASE_URL` to an administrative PostgreSQL URL for a disposable test environment, then run the guarded end-to-end suite:

```bash
SERVICEAUTH_TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' \
go test -v ./internal/integration -run TestPostgresEndToEnd -count=1
```

The suite creates and removes an isolated database. It covers:

- application and supported OpenFGA migrations/model activation;
- deterministic, idempotent management bootstrap;
- liveness, readiness, OAuth metadata, JWKS, Swagger gating, and strict HTTP transport;
- the `/v1/manage/` audience, resource, relationship, group, membership, and grant APIs;
- signed external JWT trust, RFC 8693 exchange, claim propagation, and platform claims;
- inherited allow/deny decisions, relationship moves, validation errors, deletion cleanup, and implicit resource creation;
- direct exchange and delegation modes; and
- persistence across restart, fail-closed fingerprint mismatch, and model continuity.

Expected evidence is `--- PASS: TestPostgresEndToEnd` with no skipped security or lifecycle assertions.

## Manual HTTP verification

Use any HTTP client, such as curl, Postman, a browser, or an application test harness, to verify:

1. `GET /` and `GET /openapi.yaml` when Swagger is enabled.
2. `404` for those two paths when Swagger is disabled.
3. OAuth metadata, JWKS, liveness, and readiness.
4. Token exchange with a valid trusted external JWT.
5. `401` for missing/invalid bearer tokens on `/v1/check` and `/v1/manage/...`.
6. `403` for a valid token with the wrong audience or missing route permission.
7. Management mutations under `/v1/manage/`, never the old root-level management paths.
8. HTTP `200` with `allowed:false` for a legitimate denied permission check.

## Key-handling checks

For local testing, use a dedicated RSA key and configure only its public SubjectPublicKeyInfo PEM in `token_sources.*.keys.public_key`. The external token must match the configured issuer, audience, algorithm, key ID, required claims, expiry, and subject.

Never put an external private test key or platform private signing key into YAML, source control, logs, JWKS, or tokens. KMS deployments must not export private key material.

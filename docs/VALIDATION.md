# Validation

This file records the reproducible validation path. Unit tests are hermetic; the end-to-end test is explicitly guarded because it creates and drops a PostgreSQL database.

## Unit and static validation

```bash
GOCACHE=/tmp/authservicecentral-go-cache go test ./...
GOCACHE=/tmp/authservicecentral-go-cache go vet ./...
```

Expected evidence: every package prints `ok` or `[no test files]`; no build, test, or vet failures.

Validate a deployment file after replacing the example public key:

```bash
go run . validate --config examples/serviceauth.yaml
go run . model --config examples/serviceauth.yaml
```

Expected evidence: `validate` prints a 64-character fingerprint; `model` prints OpenFGA schema `1.1` with intrinsic `principal`, recursive `group#member`, `audience`, role relations, permission relations, and relationship tuple-to-userset rewrites.

## PostgreSQL 18 end to end

Start PostgreSQL with `container`:

```bash
container run --name authservicecentral-test-postgres \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=postgres -p 5432:5432 -d postgres:18
container logs authservicecentral-test-postgres
```

Once the log reports that PostgreSQL is ready:

```bash
SERVICEAUTH_TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' \
GOCACHE=/tmp/authservicecentral-go-cache \
go test -v ./internal/integration -run TestPostgresEndToEnd -count=1
```

The test creates a random database and records subtests for:

- application and official OpenFGA migrations/model activation;
- deterministic, idempotent management-audience bootstrap and initial administrator grant;
- liveness, readiness, metadata, JWKS, and strict management transport;
- audiences, resources, relationships, nested groups, memberships, grants, and outbox drain;
- locally signed external RSA JWT trust, RFC 8693 exchange, claim propagation, and platform claims;
- inherited allow and HTTP-200 denial, relationship move revocation, validation errors, deletion cleanup, and implicit resource creation;
- direct exchange and all delegation modes;
- persistence across runtime restart, fail-closed fingerprint mismatch, and model N→N+1 tuple continuity.

Expected final evidence is `--- PASS: TestPostgresEndToEnd`. The test aborts rather than weakening an assertion if a required runtime surface is missing.

Stop the container afterward:

```bash
container stop authservicecentral-test-postgres
```

## Manual signed external token

For local testing, generate an RSA key and configure its public SubjectPublicKeyInfo PEM in `token_sources.*.keys.public_key`. Create a compact RS256 JWT with matching `kid`, configured `iss`/`aud`, future `exp`, required claims, and a subject. Sign the ASCII `base64url(header).base64url(payload)` SHA-256 digest with RSA PKCS#1 v1.5. The integration test contains a standard-library-only implementation suitable as executable reference.

Never put the external private test key or the platform private signing key into YAML, source control, logs, JWKS, or tokens.

## Recorded validation

On 2026-08-21 the repository passed `go test ./...`, `go vet ./...`, `go build ./...`, the PostgreSQL-backed OpenFGA integration tests, and the complete `TestPostgresEndToEnd` suite against the `postgres:18` image launched with `container`. The end-to-end run included the controlled bootstrap command and every subtest listed above.

# Database

PostgreSQL 18 is the supported persistent store. One database contains two ownership domains: application-owned `platform.*` tables and OpenFGA-owned tables. Application code accesses and migrates OpenFGA data through supported OpenFGA APIs and does not depend on private OpenFGA table details.

## Provisioning

Provide a disposable PostgreSQL instance for development and integration verification. It may be local, supplied by Docker or another container runtime, a CI service, or a managed PostgreSQL environment. The application needs a database URL with permission to create its schemas and, for guarded integration tests, permission to create and remove an isolated test database.

The documentation intentionally does not prescribe a host-specific database launch command. Keep credentials, network exposure, and data lifecycle appropriate to the environment, and never use an irreplaceable production database for integration tests.

## Migrations

```bash
authservicecentral migrate --config serviceauth.yaml \
  --database-url 'postgres://postgres:postgres@localhost:5432/authservicecentral?sslmode=disable'
```

`migrate` validates and fingerprints the YAML, applies embedded application migrations with a checksum ledger, invokes the supported OpenFGA datastore migration, writes a new immutable model only when required, and activates the matching fingerprint/model ID. There is no automatic down command. Back up PostgreSQL before upgrades.

## Application-owned data

- `configuration_versions`: canonical configuration fingerprint, immutable OpenFGA model ID, and active pointer.
- `audiences`: runtime audiences, token TTL, and delegation mode.
- `resources` and `resource_relationships`: typed resource catalog and graph edges.
- `groups` and `group_memberships`: principal and nested-group membership.
- `grants`: resource-scoped role assignments.
- `authorization_operations`: transactional outbox for tuple writes and deletes.
- `audit_events`: append-only management mutation history.

Catalog rows retain exact tuple object, relation, and subject values. Foreign keys clean up related catalog data; the reconciler applies queued tuple mutations through OpenFGA and records completion or retry errors. Schema evolution does not silently grant access from stale state.

## Startup and readiness

`run` requires completed migration and model activation, drains a bounded amount of outbox work, and starts periodic reconciliation. Startup and `/health/ready` fail when PostgreSQL is unavailable, signing material cannot publish a JWK, or the supplied YAML fingerprint differs from the active model.

## Integration isolation

The guarded integration test reads `SERVICEAUTH_TEST_DATABASE_URL` as an administrative PostgreSQL URL, creates a random database, applies both migration systems, runs the end-to-end suite, and removes the temporary database. Use a disposable PostgreSQL environment and confirm the URL before running it.
